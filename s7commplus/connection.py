"""S7CommPlusConnection — high-level connection to a Siemens S7-1200/1500 PLC.

Ported from S7CommPlusConnection.cs.  Orchestrates the 7-step handshake
(TCP+COTP → InitSSL → TLS → CreateObject → SetMultiVariables →
ReadSystemLimits → Legitimation), PDU framing / fragmentation,
sequence/integrity counters, and batch read/write operations.
"""

from __future__ import annotations

import logging
import struct
import threading
import time
from collections import deque
from typing import Any

from s7commplus.auth.legitimation import legitimate
from s7commplus.client_api.comm_resources import CommResources
from s7commplus.messages import (
    CreateObjectRequest,
    CreateObjectResponse,
    DeleteObjectRequest,
    DeleteObjectResponse,
    GetMultiVariablesRequest,
    GetMultiVariablesResponse,
    InitSslRequest,
    InitSslResponse,
    SetMultiVariablesRequest,
    SetMultiVariablesResponse,
    SetVariableRequest,
    SetVariableResponse,
)
from s7commplus.messages.system_event import SystemEvent
from s7commplus.protocol.constants import (
    FunctionCode,
    Ids,
    ProtocolVersion,
)
from s7commplus.protocol.errors import (
    ERR_ISO_INVALID_PDU,
    ERR_TCP_DATA_RECEIVE,
)
from s7commplus.protocol.pobject import ItemAddress
from s7commplus.protocol.values import PValue, ValueDInt, ValueStruct
from s7commplus.transport.client import S7Client

logger = logging.getLogger(__name__)

# S7CommPlus PDU header/trailer magic byte
_S7PLUS_MAGIC = 0x72

# Negotiated ISO PDU size (TPKT)
_NEGOTIATED_ISO_PDU_SIZE = 1024

# Overhead: 4 TPKT + 3 COTP + 5 TLS header + 17 TLS overhead + 4 S7+ header + 4 S7+ trailer
_PDU_OVERHEAD = 4 + 3 + 5 + 17 + 4 + 4

# Function codes that use the "set" integrity counter
_SET_FUNCTION_CODES = frozenset({
    FunctionCode.SET_MULTI_VARIABLES,
    FunctionCode.SET_VARIABLE,
    FunctionCode.SET_VAR_SUB_STREAMED,
    FunctionCode.DELETE_OBJECT,
    FunctionCode.CREATE_OBJECT,
})


class S7CommPlusConnection:
    """High-level S7CommPlus PLC connection.

    Usage::

        conn = S7CommPlusConnection()
        err = conn.connect("192.168.1.1", password="secret")
        if err == 0:
            values, errors, err = conn.read_values(address_list)
            conn.disconnect()
    """

    def __init__(self) -> None:
        self._client = S7Client()
        self._session_id: int = 0
        self._session_id2: int = 0
        self._sequence_number: int = 0
        self._integrity_id: int = 0
        self._integrity_id_set: int = 0
        self._read_timeout: float = 5.0  # seconds
        self._comm_resources = CommResources()
        self._last_error: int = 0

        # OMS secret for new-style legitimation (rolled each auth attempt)
        self.oms_secret: bytes | None = None

        # PDU receive state
        self._received_temp_pdu = bytearray()
        self._need_more_data: bool = False
        self._received_pdus: deque[bytes] = deque()
        self._pdu_event = threading.Event()
        self._lock = threading.Lock()

    # -- Properties ----------------------------------------------------------

    @property
    def session_id(self) -> int:
        return self._session_id

    @property
    def session_id2(self) -> int:
        return self._session_id2

    @property
    def last_error(self) -> int:
        return self._last_error

    @property
    def client(self) -> S7Client:
        return self._client

    @property
    def comm_resources(self) -> CommResources:
        return self._comm_resources

    # -- Sequence / Integrity counters ---------------------------------------

    def _next_sequence_number(self) -> int:
        if self._sequence_number >= 0xFFFF:
            self._sequence_number = 1
        else:
            self._sequence_number += 1
        return self._sequence_number

    def _next_integrity_id(self, function_code: int) -> int:
        if function_code in _SET_FUNCTION_CODES:
            if self._integrity_id_set >= 0xFFFFFFFF:
                self._integrity_id_set = 0
            else:
                self._integrity_id_set += 1
            return self._integrity_id_set
        else:
            if self._integrity_id >= 0xFFFFFFFF:
                self._integrity_id = 0
            else:
                self._integrity_id += 1
            return self._integrity_id

    # -- PDU send/receive ----------------------------------------------------

    def send_request(self, request: Any) -> int:
        """Serialize and send a request object through the S7CommPlus stack.

        Sets session_id, sequence_number, and integrity_id on the request
        before serializing.  Returns 0 on success.
        """
        # Session ID
        if self._session_id == 0:
            request.session_id = Ids.OBJECT_NULL_SERVER_SESSION
        else:
            request.session_id = self._session_id

        # Sequence and integrity
        request.sequence_number = self._next_sequence_number()
        if request.with_integrity_id:
            fc = getattr(request, 'function_code', None)
            if fc is None:
                # Derive function code from class attribute
                fc = getattr(type(request), 'function_code', 0)
            request.integrity_id = self._next_integrity_id(fc)

        # Serialize
        buf = bytearray()
        request.serialize(buf)

        return self._send_pdu_data(
            bytes(buf), request.protocol_version,
        )

    def _send_pdu_data(self, data: bytes, proto_version: int) -> int:
        """Frame data as S7CommPlus PDU(s) with header/trailer and send."""
        self._last_error = 0
        max_size = _NEGOTIATED_ISO_PDU_SIZE - _PDU_OVERHEAD
        source_pos = 0
        bytes_remaining = len(data)

        while bytes_remaining > 0:
            cur_size = min(bytes_remaining, max_size)
            bytes_remaining -= cur_size

            # 4-byte S7CommPlus header
            header = struct.pack(
                ">BBH",
                _S7PLUS_MAGIC,
                proto_version,
                cur_size,
            )

            chunk = data[source_pos:source_pos + cur_size]
            source_pos += cur_size

            # Trailer only in last packet
            if bytes_remaining == 0:
                trailer = struct.pack(">BBH", _S7PLUS_MAGIC, proto_version, 0)
                packet = header + chunk + trailer
            else:
                packet = header + chunk

            err = self._client.send(packet)
            if err != 0:
                self._last_error = err
                return err

        return 0

    def _on_data_received(self, pdu: bytes, length: int) -> None:
        """Callback invoked by the transport layer's background thread.

        Handles S7CommPlus PDU fragmentation and pushes complete PDUs
        to the receive queue.
        """
        pos = 0

        if not self._need_more_data:
            self._received_temp_pdu = bytearray()

        # Validate header magic
        if pdu[pos] != _S7PLUS_MAGIC:
            self._need_more_data = False
            self._last_error = ERR_ISO_INVALID_PDU
            return
        pos += 1

        proto_version = pdu[pos]
        valid_versions = (
            ProtocolVersion.V1, ProtocolVersion.V2,
            ProtocolVersion.V3, ProtocolVersion.SYSTEM_EVENT,
        )
        if proto_version not in valid_versions:
            self._need_more_data = False
            self._last_error = ERR_ISO_INVALID_PDU
            return

        # Write protocol version for the first fragment
        if not self._need_more_data:
            self._received_temp_pdu.append(proto_version)
        pos += 1

        # Data length from header
        data_len = (pdu[pos] << 8) | pdu[pos + 1]
        pos += 2

        if data_len > 0:
            if proto_version == ProtocolVersion.SYSTEM_EVENT:
                # SystemEvent: no trailer, never fragmented
                self._received_temp_pdu.extend(pdu[pos:pos + data_len])
                self._need_more_data = False

                sysevt = SystemEvent.from_pdu(bytes(self._received_temp_pdu))
                if sysevt is not None and sysevt.is_fatal_error():
                    logger.error("SystemEvent: fatal error received")
                    self._last_error = ERR_ISO_INVALID_PDU
                else:
                    logger.debug("SystemEvent: non-fatal, ignoring")
                return
            else:
                # Copy data part
                self._received_temp_pdu.extend(pdu[pos:pos + data_len])
                pos += data_len

                # Check for fragmentation:
                # If (total_len - header(4) - trailer(4)) == data_len, PDU is complete
                if (length - 8) == data_len:
                    # Complete PDU
                    self._need_more_data = False
                    complete_pdu = bytes(self._received_temp_pdu)
                    with self._lock:
                        self._received_pdus.append(complete_pdu)
                    self._pdu_event.set()
                else:
                    # Fragmented — need more data
                    self._need_more_data = True

    def wait_for_response(self, timeout: float | None = None) -> bytes | None:
        """Block until a complete S7CommPlus PDU is available.

        Returns the raw PDU bytes (starting with protocol_version byte),
        or None on timeout.
        """
        if timeout is None:
            timeout = self._read_timeout

        deadline = time.monotonic() + timeout

        while True:
            with self._lock:
                if self._received_pdus:
                    return self._received_pdus.popleft()

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                logger.error("Timeout waiting for S7CommPlus PDU")
                self._last_error = ERR_TCP_DATA_RECEIVE
                return None

            self._pdu_event.wait(timeout=min(remaining, 0.05))
            self._pdu_event.clear()

    # -- Integrity check -----------------------------------------------------

    def _check_response_integrity(self, request: Any, response: Any) -> int:
        """Validate response sequence number and integrity ID."""
        if response is None:
            logger.error("Response is None")
            return ERR_ISO_INVALID_PDU
        if request.sequence_number != response.sequence_number:
            logger.error(
                "Sequence number mismatch: request=%d, response=%d",
                request.sequence_number, response.sequence_number,
            )
            return ERR_ISO_INVALID_PDU

        # Integrity check (overflow allowed)
        expected = (request.sequence_number + request.integrity_id) & 0xFFFFFFFF
        if response.integrity_id != expected:
            logger.warning(
                "Integrity ID mismatch: expected=%d, got=%d",
                expected, response.integrity_id,
            )
            # C# code logs this but doesn't return error
        return 0

    # -- Connect / Disconnect ------------------------------------------------

    def connect(
        self,
        address: str,
        password: str = "",
        username: str = "",
        timeout_ms: int = 5000,
        keylog_file: str | None = None,
    ) -> int:
        """Establish a full connection to the PLC.

        Implements the 7-step handshake:
        1. TCP + COTP connect
        2. InitSSL request/response (unencrypted)
        3. TLS activation
        4. CreateObject (server session)
        5. SetMultiVariables (session setup)
        6. Read system limits (CommResources)
        7. Legitimation (auth)

        Returns 0 on success or an error code.
        """
        if timeout_ms > 0:
            self._read_timeout = timeout_ms / 1000.0

        self._last_error = 0
        start = time.monotonic()

        # Configure transport
        self._client.set_connection_params(
            address, 0x0600, b"SIMATIC-ROOT-HMI",
        )
        self._client.on_data_received = self._on_data_received

        # Step 0: TCP + COTP
        res = self._client.connect()
        if res != 0:
            self._client.disconnect()
            return res

        # Step 1: InitSSL (unencrypted)
        ssl_req = InitSslRequest(ProtocolVersion.V1, 0, 0)
        res = self.send_request(ssl_req)
        if res != 0:
            self._client.disconnect()
            return res

        pdu_data = self.wait_for_response()
        if pdu_data is None:
            self._client.disconnect()
            return self._last_error or ERR_TCP_DATA_RECEIVE

        ssl_resp = InitSslResponse.from_pdu(pdu_data)
        if ssl_resp is None:
            logger.error("InitSslResponse failed")
            self._client.disconnect()
            return ERR_ISO_INVALID_PDU

        # Step 2: Activate TLS
        res = self._client.ssl_activate(keylog_file=keylog_file)
        if res != 0:
            self._client.disconnect()
            return res

        # Step 3: CreateObject (server session)
        create_req = CreateObjectRequest(ProtocolVersion.V1, 0, False)
        create_req.set_null_server_session_data()
        res = self.send_request(create_req)
        if res != 0:
            self._client.disconnect()
            return res

        pdu_data = self.wait_for_response()
        if pdu_data is None:
            self._client.disconnect()
            return self._last_error or ERR_TCP_DATA_RECEIVE

        create_resp = CreateObjectResponse.from_pdu(pdu_data)
        if create_resp is None:
            logger.error("CreateObjectResponse failed")
            self._client.disconnect()
            return ERR_ISO_INVALID_PDU

        # Extract session IDs
        if len(create_resp.object_ids) >= 2:
            self._session_id = create_resp.object_ids[0]
            self._session_id2 = create_resp.object_ids[1]
        elif len(create_resp.object_ids) >= 1:
            self._session_id = create_resp.object_ids[0]

        logger.info("SessionId=0x%08X", self._session_id)

        # Extract server session version struct (attribute 306)
        server_session = create_resp.response_object.get_attribute(
            Ids.SERVER_SESSION_VERSION,
        )

        # Step 4: SetMultiVariables (session setup)
        set_req = SetMultiVariablesRequest(ProtocolVersion.V2)
        set_req.set_session_setup_data(self._session_id, server_session)
        res = self.send_request(set_req)
        if res != 0:
            self._client.disconnect()
            return res

        pdu_data = self.wait_for_response()
        if pdu_data is None:
            self._client.disconnect()
            return self._last_error or ERR_TCP_DATA_RECEIVE

        set_resp = SetMultiVariablesResponse.from_pdu(pdu_data)
        if set_resp is None:
            logger.error("SetMultiVariablesResponse (session setup) failed")
            self._client.disconnect()
            return ERR_ISO_INVALID_PDU

        # Step 5: Read system limits
        res = self._comm_resources.read_max(self)
        if res != 0:
            self._client.disconnect()
            return res

        # Step 6: Legitimation
        res = legitimate(self, server_session, password, username)
        if res != 0:
            self._client.disconnect()
            return res

        elapsed = int((time.monotonic() - start) * 1000)
        logger.info("Connection established in %d ms", elapsed)
        return 0

    def disconnect(self) -> None:
        """Disconnect from the PLC.

        Sends a DeleteObjectRequest for the session, then closes transport.
        """
        if self._session_id != 0:
            self._delete_object(self._session_id)
        self._client.disconnect()

    def _delete_object(self, object_id: int) -> int:
        """Delete an object on the PLC."""
        del_req = DeleteObjectRequest(ProtocolVersion.V2)
        del_req.delete_object_id = object_id
        res = self.send_request(del_req)
        if res != 0:
            return res

        pdu_data = self.wait_for_response()
        if pdu_data is None:
            return self._last_error or ERR_TCP_DATA_RECEIVE

        if object_id == self._session_id:
            # Deleting own session — no integrity check, clear IDs
            DeleteObjectResponse.from_pdu(pdu_data, with_integrity_id=False)
            logger.info("Deleted own session object")
            self._session_id = 0
            self._session_id2 = 0
        else:
            del_resp = DeleteObjectResponse.from_pdu(pdu_data, with_integrity_id=True)
            res = self._check_response_integrity(del_req, del_resp)
            if res != 0:
                return res
            if del_resp.return_value != 0:
                logger.error("DeleteObject error: ReturnValue=%d", del_resp.return_value)
                return -1

        return 0

    # -- Read / Write values -------------------------------------------------

    def read_values(
        self, address_list: list[ItemAddress],
    ) -> tuple[list[PValue | None], list[int], int]:
        """Read multiple variables, respecting CommResources chunk limits.

        Returns ``(values, errors, result_code)`` where values[i] is the
        PValue (or None on error) and errors[i] is 0 on success or an
        error code.
        """
        count = len(address_list)
        values: list[PValue | None] = [None] * count
        errors: list[int] = [0xFFFFFFFFFFFFFFFF] * count

        chunk_start = 0
        while chunk_start < count:
            chunk_end = min(
                chunk_start + self._comm_resources.tags_per_read_max,
                count,
            )
            chunk = address_list[chunk_start:chunk_end]

            req = GetMultiVariablesRequest(ProtocolVersion.V2)
            req.address_list = list(chunk)

            res = self.send_request(req)
            if res != 0:
                return values, errors, res

            pdu_data = self.wait_for_response()
            if pdu_data is None:
                return values, errors, self._last_error or ERR_TCP_DATA_RECEIVE

            resp = GetMultiVariablesResponse.from_pdu(pdu_data)
            res = self._check_response_integrity(req, resp)
            if res != 0:
                return values, errors, res

            if resp.return_value != 0:
                logger.warning("ReadValues: ReturnValue=%d", resp.return_value)

            # Map 1-based item numbers back to our 0-based list
            for item_nr, val in resp.values.items():
                idx = chunk_start + item_nr - 1
                values[idx] = val
                errors[idx] = 0

            for item_nr, err_val in resp.error_values.items():
                idx = chunk_start + item_nr - 1
                errors[idx] = err_val

            chunk_start = chunk_end

        return values, errors, self._last_error

    def write_values(
        self,
        address_list: list[ItemAddress],
        value_list: list[PValue],
    ) -> tuple[list[int], int]:
        """Write multiple variables, respecting CommResources chunk limits.

        Returns ``(errors, result_code)`` where errors[i] is 0 on success.
        """
        count = len(address_list)
        errors: list[int] = [0] * count

        chunk_start = 0
        while chunk_start < count:
            chunk_end = min(
                chunk_start + self._comm_resources.tags_per_write_max,
                count,
            )

            req = SetMultiVariablesRequest(ProtocolVersion.V2)
            req.address_list_var = list(address_list[chunk_start:chunk_end])
            req.value_list = list(value_list[chunk_start:chunk_end])

            res = self.send_request(req)
            if res != 0:
                return errors, res

            pdu_data = self.wait_for_response()
            if pdu_data is None:
                return errors, self._last_error or ERR_TCP_DATA_RECEIVE

            resp = SetMultiVariablesResponse.from_pdu(pdu_data)
            res = self._check_response_integrity(req, resp)
            if res != 0:
                return errors, res

            if resp.return_value != 0:
                logger.warning("WriteValues: ReturnValue=%d", resp.return_value)

            for item_nr, err_val in resp.error_values.items():
                idx = chunk_start + item_nr - 1
                errors[idx] = err_val

            chunk_start = chunk_end

        return errors, self._last_error

    def set_plc_operating_state(self, state: int) -> int:
        """Set the CPU operating state (RUN/STOP)."""
        req = SetVariableRequest(ProtocolVersion.V2)
        req.in_object_id = Ids.NATIVE_OBJECTS_THE_CPU_EXEC_UNIT_RID
        req.address = Ids.CPU_EXEC_UNIT_OPERATING_STATE_REQ
        req.value = ValueDInt(state)

        res = self.send_request(req)
        if res != 0:
            return res

        pdu_data = self.wait_for_response()
        if pdu_data is None:
            return self._last_error or ERR_TCP_DATA_RECEIVE

        resp = SetVariableResponse.from_pdu(pdu_data)
        if resp is None:
            return ERR_ISO_INVALID_PDU

        return 0
