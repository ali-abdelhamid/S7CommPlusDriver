"""Explore request/response — object hierarchy exploration."""

from __future__ import annotations

from s7commplus.protocol import s7p
from s7commplus.protocol.constants import Opcode, FunctionCode
from s7commplus.protocol.pobject import PObject, decode_object_list
from s7commplus.protocol.values import ValueStruct
from s7commplus.messages.base import (
    encode_request_header, decode_response_pdu_header,
    decode_response_common,
)


class ExploreRequest:
    """Request to explore PLC object tree and read variable type information."""

    transport_flags = 0x34
    function_code = FunctionCode.EXPLORE

    def __init__(self, protocol_version: int) -> None:

        """Initialize an ExploreRequest.

        Args:
            protocol_version: Wire protocol version.
        """
        self.protocol_version = protocol_version
        self.sequence_number: int = 0
        self.session_id: int = 0
        self.with_integrity_id = True
        self.integrity_id: int = 0
        self.explore_id: int = 0
        self.explore_request_id: int = 0
        self.explore_children_recursive: int = 0
        self.explore_parents: int = 0
        self.filter_data: ValueStruct | None = None
        self.address_list: list[int] = []

    def serialize(self, buf: bytearray) -> int:

        """Serialize this request into *buf*.

        Args:
            buf: Target buffer to append to.

        Returns:
            Number of bytes written.
        """
        ret = encode_request_header(
            buf, FunctionCode.EXPLORE,
            self.sequence_number, self.session_id, self.transport_flags,
        )
        ret += s7p.encode_uint32(buf, self.explore_id)
        ret += s7p.encode_uint32_vlq(buf, self.explore_request_id)
        ret += s7p.encode_byte(buf, self.explore_children_recursive)
        ret += s7p.encode_byte(buf, 1)  # unknown
        ret += s7p.encode_byte(buf, self.explore_parents)

        if self.filter_data is not None:
            ret += s7p.encode_byte(buf, 1)  # 1 object/value
            ret += self.filter_data.serialize(buf)

        ret += s7p.encode_byte(buf, 0)  # number of following objects

        ret += s7p.encode_uint32_vlq(buf, len(self.address_list))
        for addr_id in self.address_list:
            ret += s7p.encode_uint32_vlq(buf, addr_id)

        if self.with_integrity_id:
            ret += s7p.encode_uint32_vlq(buf, self.integrity_id)
        ret += s7p.encode_uint32(buf, 0)  # fill
        ret += s7p.encode_byte(buf, 0)    # extra byte for PLCSim compat
        return ret


class ExploreResponse:
    """Response carrying explored objects, vartype lists, and varname lists."""

    def __init__(self, protocol_version: int = 0) -> None:

        """Initialize an ExploreResponse.

        Args:
            protocol_version: Wire protocol version.
        """
        self.protocol_version = protocol_version
        self.sequence_number: int = 0
        self.transport_flags: int = 0
        self.return_value: int = 0
        self.explore_id: int = 0
        self.with_integrity_id = False
        self.integrity_id: int = 0
        self.objects: list[PObject] = []

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
        self.explore_id, n = s7p.decode_uint32(data, offset); offset += n
        if self.with_integrity_id:
            self.integrity_id, n = s7p.decode_uint32_vlq(data, offset); offset += n
        self.objects, n = decode_object_list(data, offset); offset += n
        return offset - start

    @classmethod
    def from_pdu(cls, data: bytes, offset: int = 0,
                 with_integrity_id: bool = False) -> ExploreResponse | None:

        """Construct a response from a complete PDU.

        Args:
            data: Raw PDU bytes.
            offset: Starting offset.
            with_integrity_id: Whether integrity ID is present.

        Returns:
            Populated response, or ``None`` on parse failure.
        """
        proto_ver, offset = decode_response_pdu_header(
            data, offset, Opcode.RESPONSE, FunctionCode.EXPLORE,
        )
        resp = cls(proto_ver)
        resp.with_integrity_id = with_integrity_id
        resp.deserialize(data, offset)
        return resp
