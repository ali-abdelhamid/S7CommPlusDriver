"""CreateObject request/response — session and object creation."""

from __future__ import annotations

from s7commplus.protocol import s7p
from s7commplus.protocol.constants import Opcode, FunctionCode, Ids
from s7commplus.protocol.pobject import PObject, decode_object
from s7commplus.protocol.values import PValue, ValueUDInt, ValueRID
from s7commplus.messages.base import (
    encode_request_header, decode_response_pdu_header,
    decode_response_common, ERROR_EXTENSION_FLAG,
)


class CreateObjectRequest:
    """Request to create a server session object on the PLC."""

    transport_flags = 0x36
    function_code = FunctionCode.CREATE_OBJECT

    def __init__(self, protocol_version: int, seq_num: int,
                 with_integrity_id: bool = False) -> None:

        """Initialize a CreateObjectRequest.

        Args:
            protocol_version: Wire protocol version.
            seq_num: Initial sequence number.
            with_integrity_id: Whether to include integrity ID.
        """
        self.protocol_version = protocol_version
        self.sequence_number = seq_num
        self.session_id: int = 0
        self.with_integrity_id = with_integrity_id
        self.integrity_id: int = 0
        self.request_id: int = 0
        self.request_value: PValue | None = None
        self.request_object: PObject | None = None

    def set_null_server_session_data(self) -> None:
        """Configure for Null Server Session creation at connection setup."""
        self.transport_flags = 0x36
        self.request_id = Ids.OBJECT_SERVER_SESSION_CONTAINER
        self.request_value = ValueUDInt(0)
        self.request_object = PObject(
            rid=Ids.GET_NEW_RID_ON_SERVER,
            cls_id=Ids.CLASS_SERVER_SESSION,
            aid=Ids.NONE,
        )
        self.request_object.add_attribute(
            Ids.SERVER_SESSION_CLIENT_RID, ValueRID(0x80C3C901),
        )
        self.request_object.add_object(PObject(
            rid=Ids.GET_NEW_RID_ON_SERVER,
            cls_id=Ids.CLASS_SUBSCRIPTIONS,
            aid=Ids.NONE,
        ))

    def serialize(self, buf: bytearray) -> int:

        """Serialize this request into *buf*.

        Args:
            buf: Target buffer to append to.

        Returns:
            Number of bytes written.
        """
        ret = encode_request_header(
            buf, FunctionCode.CREATE_OBJECT,
            self.sequence_number, self.session_id, self.transport_flags,
        )
        ret += s7p.encode_uint32(buf, self.request_id)
        ret += self.request_value.serialize(buf)
        ret += s7p.encode_uint32(buf, 0)  # unknown value 1
        if self.with_integrity_id:
            ret += s7p.encode_uint32_vlq(buf, self.integrity_id)
        ret += self.request_object.serialize(buf)
        ret += s7p.encode_uint32(buf, 0)  # fill
        return ret


class CreateObjectResponse:
    """Response carrying the created session object and server session data."""

    def __init__(self, protocol_version: int = 0) -> None:

        """Initialize a CreateObjectResponse.

        Args:
            protocol_version: Wire protocol version.
        """
        self.protocol_version = protocol_version
        self.sequence_number: int = 0
        self.transport_flags: int = 0
        self.return_value: int = 0
        self.object_id_count: int = 0
        self.object_ids: list[int] = []
        self.response_object: PObject | None = None
        self.with_integrity_id = False
        self.integrity_id: int = 0

    def deserialize(self, data: bytes, offset: int) -> int:

        """Deserialize this response from wire data.

        Args:
            data: Source byte buffer.
            offset: Position to read from.

        Returns:
            Number of bytes consumed.
        """
        start = offset
        self.sequence_number, self.transport_flags, offset = \
            decode_response_common(data, offset)
        self.return_value, n = s7p.decode_uint64_vlq(data, offset); offset += n
        self.object_id_count, n = s7p.decode_byte(data, offset); offset += n
        self.object_ids = []
        for _ in range(self.object_id_count):
            oid, n = s7p.decode_uint32_vlq(data, offset); offset += n
            self.object_ids.append(oid)
        self.response_object, n = decode_object(data, offset)
        offset += n
        return offset - start

    @classmethod
    def from_pdu(cls, data: bytes, offset: int = 0) -> CreateObjectResponse | None:

        """Construct a response from a complete PDU.

        Args:
            data: Raw PDU bytes.
            offset: Starting offset.

        Returns:
            Populated response, or ``None`` on parse failure.
        """
        proto_ver, offset = decode_response_pdu_header(
            data, offset, Opcode.RESPONSE, FunctionCode.CREATE_OBJECT,
        )
        resp = cls(proto_ver)
        resp.deserialize(data, offset)
        return resp
