"""GetMultiVariables request/response — read multiple variables."""

from __future__ import annotations

from s7commplus.protocol import s7p
from s7commplus.protocol.constants import Opcode, FunctionCode
from s7commplus.protocol.pobject import ItemAddress, encode_object_qualifier
from s7commplus.protocol.values import PValue
from s7commplus.messages.base import (
    encode_request_header, decode_response_pdu_header,
    decode_response_common,
)


class GetMultiVariablesRequest:
    """Request to read multiple PLC variables in a single PDU."""

    transport_flags = 0x34
    function_code = FunctionCode.GET_MULTI_VARIABLES

    def __init__(self, protocol_version: int) -> None:

        """Initialize a GetMultiVariablesRequest.

        Args:
            protocol_version: Wire protocol version.
        """
        self.protocol_version = protocol_version
        self.sequence_number: int = 0
        self.session_id: int = 0
        self.with_integrity_id = True
        self.integrity_id: int = 0
        self.link_id: int = 0
        self.address_list: list[ItemAddress] = []

    def serialize(self, buf: bytearray) -> int:

        """Serialize this request into *buf*.

        Args:
            buf: Target buffer to append to.

        Returns:
            Number of bytes written.
        """
        ret = encode_request_header(
            buf, FunctionCode.GET_MULTI_VARIABLES,
            self.sequence_number, self.session_id, self.transport_flags,
        )
        ret += s7p.encode_uint32(buf, self.link_id)
        ret += s7p.encode_uint32_vlq(buf, len(self.address_list))
        field_count = sum(a.get_number_of_fields() for a in self.address_list)
        ret += s7p.encode_uint32_vlq(buf, field_count)
        for addr in self.address_list:
            ret += addr.serialize(buf)
        ret += encode_object_qualifier(buf)
        if self.with_integrity_id:
            ret += s7p.encode_uint32_vlq(buf, self.integrity_id)
        ret += s7p.encode_uint32(buf, 0)  # fill
        return ret


class GetMultiVariablesResponse:
    """Response carrying multiple variable values and per-item error codes."""

    def __init__(self, protocol_version: int = 0) -> None:

        """Initialize a GetMultiVariablesResponse.

        Args:
            protocol_version: Wire protocol version.
        """
        self.protocol_version = protocol_version
        self.sequence_number: int = 0
        self.transport_flags: int = 0
        self.return_value: int = 0
        self.with_integrity_id = True
        self.integrity_id: int = 0
        self.values: dict[int, PValue] = {}
        self.error_values: dict[int, int] = {}

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

        # Value list
        item_nr, n = s7p.decode_uint32_vlq(data, offset); offset += n
        while item_nr > 0:
            val, n = PValue.deserialize(data, offset); offset += n
            self.values[item_nr] = val
            item_nr, n = s7p.decode_uint32_vlq(data, offset); offset += n

        # Error value list
        item_nr, n = s7p.decode_uint32_vlq(data, offset); offset += n
        while item_nr > 0:
            retval, n = s7p.decode_uint64_vlq(data, offset); offset += n
            self.error_values[item_nr] = retval
            item_nr, n = s7p.decode_uint32_vlq(data, offset); offset += n

        self.integrity_id, n = s7p.decode_uint32_vlq(data, offset); offset += n
        return offset - start

    @classmethod
    def from_pdu(cls, data: bytes, offset: int = 0) -> GetMultiVariablesResponse | None:

        """Construct a response from a complete PDU.

        Args:
            data: Raw PDU bytes.
            offset: Starting offset.

        Returns:
            Populated response, or ``None`` on parse failure.
        """
        proto_ver, offset = decode_response_pdu_header(
            data, offset, Opcode.RESPONSE, FunctionCode.GET_MULTI_VARIABLES,
        )
        resp = cls(proto_ver)
        resp.deserialize(data, offset)
        return resp
