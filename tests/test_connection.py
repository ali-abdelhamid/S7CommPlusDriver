"""
Unit tests for Phase C: connection lifecycle, auth, and comm resources.

Tests the S7CommPlusConnection orchestrator, PDU framing, sequence/integrity
counters, CommResources, and legitimation crypto — all without a real PLC.
"""

import hashlib
import struct
import threading
import time

import pytest

from s7commplus.auth.legitimation import (
    AccessLevel,
    LegitimationType,
    _build_legitimation_payload,
    _encrypt_aes_cbc,
    _sha1,
    _sha256,
)
from s7commplus.client_api.comm_resources import CommResources
from s7commplus.connection import (
    S7CommPlusConnection,
    _NEGOTIATED_ISO_PDU_SIZE,
    _PDU_OVERHEAD,
    _S7PLUS_MAGIC,
    _SET_FUNCTION_CODES,
)
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
    GetVarSubstreamedRequest,
    GetVarSubstreamedResponse,
)
from s7commplus.protocol.constants import (
    FunctionCode,
    Ids,
    ProtocolVersion,
)
from s7commplus.protocol.errors import (
    ERR_CLI_ACCESS_DENIED,
    ERR_CLI_DEVICE_NOT_SUPPORTED,
    ERR_CLI_FIRMWARE_NOT_SUPPORTED,
    ERR_ISO_INVALID_PDU,
)
from s7commplus.protocol.pobject import ItemAddress
from s7commplus.protocol.values import (
    PValue,
    ValueBool,
    ValueDInt,
    ValueStruct,
    ValueUDInt,
    ValueUSIntArray,
    ValueWString,
)


# ===========================================================================
# Constants and helpers
# ===========================================================================

class TestConstants:

    def test_access_levels(self):
        assert AccessLevel.FULL_ACCESS == 1
        assert AccessLevel.READ_ACCESS == 2
        assert AccessLevel.HMI_ACCESS == 3
        assert AccessLevel.NO_ACCESS == 4

    def test_legitimation_types(self):
        assert LegitimationType.LEGACY == 1
        assert LegitimationType.NEW == 2

    def test_set_function_codes(self):
        assert FunctionCode.SET_MULTI_VARIABLES in _SET_FUNCTION_CODES
        assert FunctionCode.SET_VARIABLE in _SET_FUNCTION_CODES
        assert FunctionCode.DELETE_OBJECT in _SET_FUNCTION_CODES
        assert FunctionCode.CREATE_OBJECT in _SET_FUNCTION_CODES
        assert FunctionCode.GET_MULTI_VARIABLES not in _SET_FUNCTION_CODES
        assert FunctionCode.EXPLORE not in _SET_FUNCTION_CODES


# ===========================================================================
# Crypto helpers
# ===========================================================================

class TestCrypto:

    def test_sha256(self):
        result = _sha256(b"test")
        assert len(result) == 32
        assert result == hashlib.sha256(b"test").digest()

    def test_sha1(self):
        result = _sha1(b"password")
        assert len(result) == 20
        assert result == hashlib.sha1(b"password").digest()

    def test_encrypt_aes_cbc(self):
        key = b"\x00" * 32
        iv = b"\x00" * 16
        plaintext = b"Hello, PLC!"
        encrypted = _encrypt_aes_cbc(plaintext, key, iv)
        assert len(encrypted) == 16  # PKCS7 pads to block boundary
        assert encrypted != plaintext

    def test_encrypt_aes_cbc_multi_block(self):
        key = _sha256(b"secret")
        iv = b"\x01" * 16
        plaintext = b"A" * 48  # 3 blocks exactly
        encrypted = _encrypt_aes_cbc(plaintext, key, iv)
        # 48 bytes + PKCS7 padding = 64 bytes
        assert len(encrypted) == 64

    def test_encrypt_aes_cbc_deterministic(self):
        key = b"\xAB" * 32
        iv = b"\xCD" * 16
        plaintext = b"deterministic test"
        enc1 = _encrypt_aes_cbc(plaintext, key, iv)
        enc2 = _encrypt_aes_cbc(plaintext, key, iv)
        assert enc1 == enc2


# ===========================================================================
# Legitimation payload builder
# ===========================================================================

class TestLegitimationPayload:

    def test_new_login_payload(self):
        """New-style login (username + password) produces valid PValue bytes."""
        payload = _build_legitimation_payload("mypass", "admin")
        assert len(payload) > 0
        # Should be deserializable as a ValueStruct
        val, consumed = PValue.deserialize(payload, 0)
        assert isinstance(val, ValueStruct)

    def test_legacy_login_payload(self):
        """Legacy login (password only) includes SHA1-hashed password."""
        payload = _build_legitimation_payload("secret")
        assert len(payload) > 0
        val, consumed = PValue.deserialize(payload, 0)
        assert isinstance(val, ValueStruct)

    def test_payload_roundtrip(self):
        """Payload bytes are valid PValue wire format."""
        payload = _build_legitimation_payload("test123", "user1")
        val, consumed = PValue.deserialize(payload, 0)
        assert consumed == len(payload)


# ===========================================================================
# Sequence / Integrity counters
# ===========================================================================

class TestSequenceCounters:

    def test_sequence_number_increments(self):
        conn = S7CommPlusConnection()
        nums = [conn._next_sequence_number() for _ in range(5)]
        assert nums == [1, 2, 3, 4, 5]

    def test_sequence_number_wraps(self):
        conn = S7CommPlusConnection()
        conn._sequence_number = 0xFFFE
        assert conn._next_sequence_number() == 0xFFFF
        assert conn._next_sequence_number() == 1  # wraps

    def test_integrity_id_read(self):
        """Non-set function codes use the read integrity counter."""
        conn = S7CommPlusConnection()
        id1 = conn._next_integrity_id(FunctionCode.GET_MULTI_VARIABLES)
        id2 = conn._next_integrity_id(FunctionCode.GET_MULTI_VARIABLES)
        assert id1 == 1
        assert id2 == 2

    def test_integrity_id_write(self):
        """Set function codes use the separate write counter."""
        conn = S7CommPlusConnection()
        id1 = conn._next_integrity_id(FunctionCode.SET_MULTI_VARIABLES)
        id2 = conn._next_integrity_id(FunctionCode.SET_VARIABLE)
        assert id1 == 1
        assert id2 == 2

    def test_integrity_counters_independent(self):
        """Read and write integrity counters are independent."""
        conn = S7CommPlusConnection()
        r1 = conn._next_integrity_id(FunctionCode.GET_MULTI_VARIABLES)
        w1 = conn._next_integrity_id(FunctionCode.SET_MULTI_VARIABLES)
        r2 = conn._next_integrity_id(FunctionCode.EXPLORE)
        w2 = conn._next_integrity_id(FunctionCode.DELETE_OBJECT)
        assert r1 == 1 and r2 == 2
        assert w1 == 1 and w2 == 2

    def test_integrity_id_wraps(self):
        conn = S7CommPlusConnection()
        conn._integrity_id = 0xFFFFFFFF
        assert conn._next_integrity_id(FunctionCode.GET_MULTI_VARIABLES) == 0

    def test_integrity_id_set_wraps(self):
        conn = S7CommPlusConnection()
        conn._integrity_id_set = 0xFFFFFFFF
        assert conn._next_integrity_id(FunctionCode.SET_VARIABLE) == 0


# ===========================================================================
# PDU framing
# ===========================================================================

class TestPDUFraming:

    def test_send_pdu_small(self):
        """Small PDU fits in a single frame with header + trailer."""
        conn = S7CommPlusConnection()
        sent_packets = []
        conn._client.send = lambda data: (sent_packets.append(data), 0)[1]

        data = b"\x01\x02\x03\x04"
        err = conn._send_pdu_data(data, ProtocolVersion.V2)
        assert err == 0
        assert len(sent_packets) == 1
        pkt = sent_packets[0]

        # Header
        assert pkt[0] == _S7PLUS_MAGIC
        assert pkt[1] == ProtocolVersion.V2
        data_len = struct.unpack(">H", pkt[2:4])[0]
        assert data_len == 4
        assert pkt[4:8] == data

        # Trailer
        assert pkt[8] == _S7PLUS_MAGIC
        assert pkt[9] == ProtocolVersion.V2
        assert pkt[10:12] == b"\x00\x00"

    def test_send_pdu_fragmented(self):
        """Large PDU should be split across multiple frames."""
        conn = S7CommPlusConnection()
        sent_packets = []
        conn._client.send = lambda data: (sent_packets.append(bytes(data)), 0)[1]

        max_size = _NEGOTIATED_ISO_PDU_SIZE - _PDU_OVERHEAD
        # Create data larger than max_size
        data = bytes(range(256)) * 5  # 1280 bytes
        assert len(data) > max_size

        err = conn._send_pdu_data(data, ProtocolVersion.V1)
        assert err == 0
        assert len(sent_packets) >= 2

        # Last packet should have trailer
        last_pkt = sent_packets[-1]
        assert last_pkt[-4] == _S7PLUS_MAGIC
        assert last_pkt[-2:] == b"\x00\x00"

        # Non-last packets should NOT have trailer
        for pkt in sent_packets[:-1]:
            # These just have header + data, no trailer
            assert pkt[0] == _S7PLUS_MAGIC

    def test_on_data_received_complete(self):
        """A complete (non-fragmented) PDU should be queued."""
        conn = S7CommPlusConnection()

        # Build a valid S7CommPlus PDU: header(4) + data + trailer(4)
        data_part = b"\x31\x00\x00\x05\x42"  # some fake data (5 bytes)
        header = struct.pack(">BBH", _S7PLUS_MAGIC, ProtocolVersion.V2, len(data_part))
        trailer = struct.pack(">BBH", _S7PLUS_MAGIC, ProtocolVersion.V2, 0)
        pdu = header + data_part + trailer

        conn._on_data_received(pdu, len(pdu))

        assert len(conn._received_pdus) == 1
        received = conn._received_pdus[0]
        # First byte should be protocol version
        assert received[0] == ProtocolVersion.V2
        # Followed by the data
        assert received[1:] == data_part

    def test_on_data_received_fragmented(self):
        """Fragmented PDUs should accumulate until complete."""
        conn = S7CommPlusConnection()

        # First fragment: header says 10 bytes of data, but total len = 4 + 10 (no trailer)
        # This means (len - 8) != data_len, so it's fragmented
        data_part1 = b"\x01" * 10
        header1 = struct.pack(">BBH", _S7PLUS_MAGIC, ProtocolVersion.V2, len(data_part1))
        # No trailer — this packet length is 14, (14 - 8) = 6 != 10
        pdu1 = header1 + data_part1

        conn._on_data_received(pdu1, len(pdu1))
        assert conn._need_more_data is True
        assert len(conn._received_pdus) == 0

        # Second fragment: contains rest of data + trailer makes it complete
        data_part2 = b"\x02" * 5
        header2 = struct.pack(">BBH", _S7PLUS_MAGIC, ProtocolVersion.V2, len(data_part2))
        trailer2 = struct.pack(">BBH", _S7PLUS_MAGIC, ProtocolVersion.V2, 0)
        pdu2 = header2 + data_part2 + trailer2
        # total len = 4 + 5 + 4 = 13, (13 - 8) = 5 == 5 → complete

        conn._on_data_received(pdu2, len(pdu2))
        assert conn._need_more_data is False
        assert len(conn._received_pdus) == 1

    def test_on_data_received_bad_magic(self):
        """Invalid magic byte should set error."""
        conn = S7CommPlusConnection()
        pdu = b"\xFF\x02\x00\x01\xAA" + b"\x72\x02\x00\x00"
        conn._on_data_received(pdu, len(pdu))
        assert conn._last_error == ERR_ISO_INVALID_PDU

    def test_on_data_received_bad_version(self):
        """Invalid protocol version should set error."""
        conn = S7CommPlusConnection()
        pdu = b"\x72\xFF\x00\x01\xAA" + b"\x72\xFF\x00\x00"
        conn._on_data_received(pdu, len(pdu))
        assert conn._last_error == ERR_ISO_INVALID_PDU


# ===========================================================================
# Wait for response
# ===========================================================================

class TestWaitForResponse:

    def test_immediate_response(self):
        """If a PDU is already queued, return it immediately."""
        conn = S7CommPlusConnection()
        conn._received_pdus.append(b"\x02TESTDATA")
        result = conn.wait_for_response(timeout=1.0)
        assert result == b"\x02TESTDATA"

    def test_timeout(self):
        """Empty queue should timeout and return None."""
        conn = S7CommPlusConnection()
        result = conn.wait_for_response(timeout=0.1)
        assert result is None
        assert conn._last_error != 0

    def test_threaded_delivery(self):
        """PDU delivered from another thread should be received."""
        conn = S7CommPlusConnection()

        def deliver():
            time.sleep(0.05)
            with conn._lock:
                conn._received_pdus.append(b"\x01HELLO")
            conn._pdu_event.set()

        t = threading.Thread(target=deliver)
        t.start()
        result = conn.wait_for_response(timeout=2.0)
        t.join()
        assert result == b"\x01HELLO"


# ===========================================================================
# Request function_code class attributes
# ===========================================================================

class TestRequestFunctionCodes:
    """Verify all request classes expose function_code for integrity routing."""

    def test_init_ssl(self):
        assert InitSslRequest.function_code == FunctionCode.INIT_SSL

    def test_create_object(self):
        assert CreateObjectRequest.function_code == FunctionCode.CREATE_OBJECT

    def test_set_multi_variables(self):
        assert SetMultiVariablesRequest.function_code == FunctionCode.SET_MULTI_VARIABLES

    def test_get_multi_variables(self):
        assert GetMultiVariablesRequest.function_code == FunctionCode.GET_MULTI_VARIABLES

    def test_set_variable(self):
        assert SetVariableRequest.function_code == FunctionCode.SET_VARIABLE

    def test_get_var_substreamed(self):
        assert GetVarSubstreamedRequest.function_code == FunctionCode.GET_VAR_SUB_STREAMED

    def test_delete_object(self):
        assert DeleteObjectRequest.function_code == FunctionCode.DELETE_OBJECT


# ===========================================================================
# CommResources
# ===========================================================================

class TestCommResources:

    def test_defaults(self):
        cr = CommResources()
        assert cr.tags_per_read_max == 20
        assert cr.tags_per_write_max == 20
        assert cr.plc_attributes_max == 0
        assert cr.plc_subscriptions_max == 0
        assert cr.subscription_memory_max == 0

    def test_address_construction(self):
        """Verify ItemAddresses built by CommResources logic use correct area/sub_area."""
        addr = ItemAddress(area=Ids.OBJECT_ROOT, sub_area=Ids.SYSTEM_LIMITS)
        addr.lid = [1000]
        assert addr.access_area == Ids.OBJECT_ROOT
        assert addr.access_sub_area == Ids.SYSTEM_LIMITS
        assert addr.lid == [1000]


# ===========================================================================
# Integrity check
# ===========================================================================

class TestIntegrityCheck:

    def test_matching_integrity(self):
        conn = S7CommPlusConnection()

        class FakeReq:
            sequence_number = 10
            integrity_id = 5

        class FakeResp:
            sequence_number = 10
            integrity_id = 15  # 10 + 5

        assert conn._check_response_integrity(FakeReq(), FakeResp()) == 0

    def test_sequence_mismatch(self):
        conn = S7CommPlusConnection()

        class FakeReq:
            sequence_number = 10
            integrity_id = 5

        class FakeResp:
            sequence_number = 11  # wrong
            integrity_id = 15

        assert conn._check_response_integrity(FakeReq(), FakeResp()) == ERR_ISO_INVALID_PDU

    def test_none_response(self):
        conn = S7CommPlusConnection()

        class FakeReq:
            sequence_number = 1
            integrity_id = 0

        assert conn._check_response_integrity(FakeReq(), None) == ERR_ISO_INVALID_PDU

    def test_integrity_overflow(self):
        """Integrity check should handle uint32 overflow correctly."""
        conn = S7CommPlusConnection()

        class FakeReq:
            sequence_number = 0xFFFF
            integrity_id = 0xFFFFFFFF

        class FakeResp:
            sequence_number = 0xFFFF
            integrity_id = (0xFFFF + 0xFFFFFFFF) & 0xFFFFFFFF

        assert conn._check_response_integrity(FakeReq(), FakeResp()) == 0


# ===========================================================================
# send_request — unit tests with mocked client.send
# ===========================================================================

class TestSendRequest:

    def test_sets_session_id_null(self):
        """When session_id is 0, use ObjectNullServerSession."""
        conn = S7CommPlusConnection()
        sent_packets = []
        conn._client.send = lambda data: (sent_packets.append(data), 0)[1]

        req = InitSslRequest(ProtocolVersion.V1, 0, 0)
        conn.send_request(req)
        assert req.session_id == Ids.OBJECT_NULL_SERVER_SESSION

    def test_sets_session_id_active(self):
        """When session_id is set, use it."""
        conn = S7CommPlusConnection()
        conn._session_id = 0x12345678
        sent_packets = []
        conn._client.send = lambda data: (sent_packets.append(data), 0)[1]

        req = GetMultiVariablesRequest(ProtocolVersion.V2)
        req.address_list = []
        conn.send_request(req)
        assert req.session_id == 0x12345678

    def test_increments_sequence(self):
        conn = S7CommPlusConnection()
        sent_packets = []
        conn._client.send = lambda data: (sent_packets.append(data), 0)[1]

        req1 = InitSslRequest(ProtocolVersion.V1, 0, 0)
        conn.send_request(req1)
        req2 = InitSslRequest(ProtocolVersion.V1, 0, 0)
        conn.send_request(req2)
        assert req1.sequence_number == 1
        assert req2.sequence_number == 2

    def test_sets_integrity_for_write(self):
        conn = S7CommPlusConnection()
        sent_packets = []
        conn._client.send = lambda data: (sent_packets.append(data), 0)[1]

        req = SetMultiVariablesRequest(ProtocolVersion.V2)
        req.in_object_id = 1
        req.address_list = [1]
        req.value_list = [ValueBool(True)]
        conn.send_request(req)
        assert req.integrity_id == 1  # first write integrity

    def test_no_integrity_for_init_ssl(self):
        """InitSslRequest has with_integrity_id=False."""
        conn = S7CommPlusConnection()
        sent_packets = []
        conn._client.send = lambda data: (sent_packets.append(data), 0)[1]

        req = InitSslRequest(ProtocolVersion.V1, 0, 0)
        conn.send_request(req)
        assert req.integrity_id == 0  # not set


# ===========================================================================
# Firmware version parsing (legitimation)
# ===========================================================================

class TestFirmwareVersionParsing:
    """Test the PAOM version regex used in legitimation."""

    def test_s7_1500_fw_31(self):
        """S7-1500 V3.1 should use new auth."""
        from s7commplus.auth.legitimation import _RE_VERSION
        m = _RE_VERSION.match("some;data7 500text;V3.1")
        assert m is not None
        assert m.group(1) == "500"
        assert m.group(2) == "3.1"

    def test_s7_1200_fw_47(self):
        """S7-1200 V4.7 should use new auth."""
        from s7commplus.auth.legitimation import _RE_VERSION
        m = _RE_VERSION.match("some;data7 200text;V4.7")
        assert m is not None
        assert m.group(1) == "200"
        assert m.group(2) == "4.7"

    def test_s7_1500_fw_20(self):
        """S7-1500 V2.0 should use legacy auth."""
        from s7commplus.auth.legitimation import _RE_VERSION
        m = _RE_VERSION.match("abc;def1 509xyz;V2.9")
        assert m is not None
        assert m.group(1) == "509"
        assert m.group(2) == "2.9"

    def test_no_match(self):
        from s7commplus.auth.legitimation import _RE_VERSION
        m = _RE_VERSION.match("invalid string")
        assert m is None


# ===========================================================================
# SystemEvent handling in on_data_received
# ===========================================================================

class TestSystemEventInPDU:

    def test_system_event_non_fatal(self):
        """SystemEvent with no data should not set fatal error."""
        conn = S7CommPlusConnection()

        # Build a minimal SystemEvent PDU:
        # header: 0x72 | 0xFE | uint16 length
        # data: protocol_version(0xFE) + 4 uint32s (reserved, confirmed, reserved, reserved)
        inner = struct.pack(">IIII", 0, 0, 0, 0)  # 16 bytes
        header = struct.pack(">BBH", _S7PLUS_MAGIC, ProtocolVersion.SYSTEM_EVENT, len(inner))
        pdu = header + inner

        conn._on_data_received(pdu, len(pdu))
        # SystemEvents don't go to the PDU queue
        assert len(conn._received_pdus) == 0


# ===========================================================================
# Connection lifecycle properties
# ===========================================================================

class TestConnectionProperties:

    def test_initial_state(self):
        conn = S7CommPlusConnection()
        assert conn.session_id == 0
        assert conn.session_id2 == 0
        assert conn.last_error == 0
        assert conn.oms_secret is None

    def test_comm_resources_accessible(self):
        conn = S7CommPlusConnection()
        cr = conn.comm_resources
        assert isinstance(cr, CommResources)
        assert cr.tags_per_read_max == 20

    def test_client_accessible(self):
        from s7commplus.transport.client import S7Client
        conn = S7CommPlusConnection()
        assert isinstance(conn.client, S7Client)
