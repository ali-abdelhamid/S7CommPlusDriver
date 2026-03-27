"""SetVariable request/response — write a single variable."""

from __future__ import annotations

from s7commplus.protocol import s7p
from s7commplus.protocol.constants import Opcode, FunctionCode
from s7commplus.protocol.pobject import encode_object_qualifier
from s7commplus.protocol.values import PValue
from s7commplus.messages.base import (
    encode_request_header, decode_response_pdu_header,
    decode_response_common,
)


class SetVariableRequest:
    """Request to write a single variable (used for legitimation)."""

    transport_flags = 0x34
    function_code = FunctionCode.SET_VARIABLE

    def __init__(self, protocol_version: int) -> None:

        """Initialize a SetVariableRequest.

        Args:
            protocol_version: Wire protocol version.
        """
        self.protocol_version = protocol_version
        self.sequence_number: int = 0
        self.session_id: int = 0
        self.with_integrity_id = True
        self.integrity_id: int = 0
        self.in_object_id: int = 0
        self.address: int = 0
        self.value: PValue | None = None

    def serialize(self, buf: bytearray) -> int:

        """Serialize this request into *buf*.

        Args:
            buf: Target buffer to append to.

        Returns:
            Number of bytes written.
        """
        ret = encode_request_header(
            buf, FunctionCode.SET_VARIABLE,
            self.sequence_number, self.session_id, self.transport_flags,
        )
        ret += s7p.encode_uint32(buf, self.in_object_id)
        ret += s7p.encode_uint32_vlq(buf, 1)  # always 1
        ret += s7p.encode_uint32_vlq(buf, self.address)
        ret += self.value.serialize(buf)
        ret += encode_object_qualifier(buf)
        ret += s7p.encode_byte(buf, 0x00)  # unknown
        if self.with_integrity_id:
            ret += s7p.encode_uint32_vlq(buf, self.integrity_id)
        ret += s7p.encode_uint32(buf, 0)  # fill
        return ret


class SetVariableResponse:
    """Response carrying the write result and return value."""

    def __init__(self, protocol_version: int = 0) -> None:

        """Initialize a SetVariableResponse.

        Args:
            protocol_version: Wire protocol version.
        """
        self.protocol_version = protocol_version
        self.sequence_number: int = 0
        self.transport_flags: int = 0
        self.return_value: int = 0
        self.with_integrity_id = True
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
        self.integrity_id, n = s7p.decode_uint32_vlq(data, offset); offset += n
        return offset - start

    @classmethod
    def from_pdu(cls, data: bytes, offset: int = 0) -> SetVariableResponse | None:

        """Construct a response from a complete PDU.

        Args:
            data: Raw PDU bytes.
            offset: Starting offset.

        Returns:
            Populated response, or ``None`` on parse failure.
        """
        proto_ver, offset = decode_response_pdu_header(
            data, offset, Opcode.RESPONSE, FunctionCode.SET_VARIABLE,
        )
        resp = cls(proto_ver)
        resp.deserialize(data, offset)
        return resp
