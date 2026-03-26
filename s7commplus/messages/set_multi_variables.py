"""SetMultiVariables request/response — write multiple variables."""

from __future__ import annotations

from s7commplus.protocol import s7p
from s7commplus.protocol.constants import Opcode, FunctionCode, Ids
from s7commplus.protocol.pobject import ItemAddress, encode_object_qualifier
from s7commplus.protocol.values import PValue, ValueStruct
from s7commplus.messages.base import (
    encode_request_header, decode_response_pdu_header,
    decode_response_common,
)


class SetMultiVariablesRequest:
    """Request to write multiple PLC variables in a single PDU."""

    transport_flags = 0x34
    function_code = FunctionCode.SET_MULTI_VARIABLES

    def __init__(self, protocol_version: int) -> None:

        """Initialize a SetMultiVariablesRequest.

        Args:
            protocol_version: Wire protocol version.
        """
        self.protocol_version = protocol_version
        self.sequence_number: int = 0
        self.session_id: int = 0
        self.with_integrity_id = True
        self.integrity_id: int = 0
        self.in_object_id: int = 0
        self.address_list: list[int] = []           # for object values (InObjectId > 0)
        self.address_list_var: list[ItemAddress] = []  # for plain variables
        self.value_list: list[PValue] = []

    def set_session_setup_data(self, session_id: int,
                               session_version: ValueStruct) -> None:
        """Configure for session setup (SetMultiVariables on the session object)."""
        self.session_id = session_id
        self.in_object_id = session_id
        self.address_list = [Ids.SERVER_SESSION_VERSION]
        self.value_list = [session_version]
        self.with_integrity_id = False

    def serialize(self, buf: bytearray) -> int:

        """Serialize this request into *buf*.

        Args:
            buf: Target buffer to append to.

        Returns:
            Number of bytes written.
        """
        ret = encode_request_header(
            buf, FunctionCode.SET_MULTI_VARIABLES,
            self.sequence_number, self.session_id, self.transport_flags,
        )
        ret += s7p.encode_uint32(buf, self.in_object_id)
        ret += s7p.encode_uint32_vlq(buf, len(self.value_list))

        if self.in_object_id > 0:
            ret += s7p.encode_uint32_vlq(buf, len(self.address_list))
            for addr_id in self.address_list:
                ret += s7p.encode_uint32_vlq(buf, addr_id)
        else:
            field_count = sum(a.get_number_of_fields() for a in self.address_list_var)
            ret += s7p.encode_uint32_vlq(buf, field_count)
            for addr in self.address_list_var:
                ret += addr.serialize(buf)

        for i, val in enumerate(self.value_list, start=1):
            ret += s7p.encode_uint32_vlq(buf, i)
            ret += val.serialize(buf)

        ret += s7p.encode_byte(buf, 0x00)  # fill byte
        ret += encode_object_qualifier(buf)

        if self.with_integrity_id:
            ret += s7p.encode_uint32_vlq(buf, self.integrity_id)
        ret += s7p.encode_uint32(buf, 0)  # fill
        return ret


class SetMultiVariablesResponse:
    """Response carrying per-item write error codes."""

    def __init__(self, protocol_version: int = 0) -> None:

        """Initialize a SetMultiVariablesResponse.

        Args:
            protocol_version: Wire protocol version.
        """
        self.protocol_version = protocol_version
        self.sequence_number: int = 0
        self.transport_flags: int = 0
        self.return_value: int = 0
        self.with_integrity_id = True
        self.integrity_id: int = 0
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

        item_nr, n = s7p.decode_uint32_vlq(data, offset); offset += n
        while item_nr > 0:
            retval, n = s7p.decode_uint64_vlq(data, offset); offset += n
            self.error_values[item_nr] = retval
            item_nr, n = s7p.decode_uint32_vlq(data, offset); offset += n

        self.integrity_id, n = s7p.decode_uint32_vlq(data, offset); offset += n
        return offset - start

    @classmethod
    def from_pdu(cls, data: bytes, offset: int = 0) -> SetMultiVariablesResponse | None:

        """Construct a response from a complete PDU.

        Args:
            data: Raw PDU bytes.
            offset: Starting offset.

        Returns:
            Populated response, or ``None`` on parse failure.
        """
        proto_ver, offset = decode_response_pdu_header(
            data, offset, Opcode.RESPONSE, FunctionCode.SET_MULTI_VARIABLES,
        )
        resp = cls(proto_ver)
        resp.deserialize(data, offset)
        return resp
