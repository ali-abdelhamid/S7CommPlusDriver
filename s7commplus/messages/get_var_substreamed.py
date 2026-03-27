"""GetVarSubstreamed request/response — substreamed variable read."""

from __future__ import annotations

from s7commplus.protocol import s7p
from s7commplus.protocol.constants import Opcode, FunctionCode, Datatype
from s7commplus.protocol.pobject import encode_object_qualifier
from s7commplus.protocol.values import PValue
from s7commplus.messages.base import (
    encode_request_header, decode_response_pdu_header,
    decode_response_common,
)


class GetVarSubstreamedRequest:
    """Request to read a single substreamed variable (e.g. protection level)."""

    transport_flags = 0x34
    function_code = FunctionCode.GET_VAR_SUB_STREAMED

    def __init__(self, protocol_version: int) -> None:

        """Initialize a GetVarSubstreamedRequest.

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

    def serialize(self, buf: bytearray) -> int:

        """Serialize this request into *buf*.

        Args:
            buf: Target buffer to append to.

        Returns:
            Number of bytes written.
        """
        ret = encode_request_header(
            buf, FunctionCode.GET_VAR_SUB_STREAMED,
            self.sequence_number, self.session_id, self.transport_flags,
        )
        ret += s7p.encode_uint32(buf, self.in_object_id)
        ret += s7p.encode_byte(buf, 0x20)  # address array flag
        ret += s7p.encode_byte(buf, Datatype.UDINT)
        ret += s7p.encode_byte(buf, 1)     # array size
        ret += s7p.encode_uint32_vlq(buf, self.address)
        ret += encode_object_qualifier(buf)
        ret += s7p.encode_uint16(buf, 0x0001)  # 2 unknown bytes
        if self.with_integrity_id:
            ret += s7p.encode_uint32_vlq(buf, self.integrity_id)
        ret += s7p.encode_uint32(buf, 0)  # fill
        return ret


class GetVarSubstreamedResponse:
    """Response carrying a single substreamed variable value."""

    def __init__(self, protocol_version: int = 0) -> None:

        """Initialize a GetVarSubstreamedResponse.

        Args:
            protocol_version: Wire protocol version.
        """
        self.protocol_version = protocol_version
        self.sequence_number: int = 0
        self.transport_flags: int = 0
        self.return_value: int = 0
        self.with_integrity_id = True
        self.integrity_id: int = 0
        self.value: PValue | None = None

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
        _, n = s7p.decode_byte(data, offset); offset += n  # unknown byte
        self.value, n = PValue.deserialize(data, offset); offset += n
        self.integrity_id, n = s7p.decode_uint32_vlq(data, offset); offset += n
        return offset - start

    @classmethod
    def from_pdu(cls, data: bytes, offset: int = 0) -> GetVarSubstreamedResponse | None:

        """Construct a response from a complete PDU.

        Args:
            data: Raw PDU bytes.
            offset: Starting offset.

        Returns:
            Populated response, or ``None`` on parse failure.
        """
        proto_ver, offset = decode_response_pdu_header(
            data, offset, Opcode.RESPONSE, FunctionCode.GET_VAR_SUB_STREAMED,
        )
        resp = cls(proto_ver)
        resp.deserialize(data, offset)
        return resp
