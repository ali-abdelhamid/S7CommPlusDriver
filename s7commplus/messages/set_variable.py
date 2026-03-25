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
    transport_flags = 0x34
    function_code = FunctionCode.SET_VARIABLE

    def __init__(self, protocol_version: int) -> None:
        self.protocol_version = protocol_version
        self.sequence_number: int = 0
        self.session_id: int = 0
        self.with_integrity_id = True
        self.integrity_id: int = 0
        self.in_object_id: int = 0
        self.address: int = 0
        self.value: PValue | None = None

    def serialize(self, buf: bytearray) -> int:
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
    def __init__(self, protocol_version: int = 0) -> None:
        self.protocol_version = protocol_version
        self.sequence_number: int = 0
        self.transport_flags: int = 0
        self.return_value: int = 0
        self.with_integrity_id = True
        self.integrity_id: int = 0

    def deserialize(self, data: bytes, offset: int) -> int:
        start = offset
        self.sequence_number, self.transport_flags, offset = \
            decode_response_common(data, offset)
        self.return_value, n = s7p.decode_uint64_vlq(data, offset); offset += n
        self.integrity_id, n = s7p.decode_uint32_vlq(data, offset); offset += n
        return offset - start

    @classmethod
    def from_pdu(cls, data: bytes, offset: int = 0) -> SetVariableResponse | None:
        proto_ver, offset = decode_response_pdu_header(
            data, offset, Opcode.RESPONSE, FunctionCode.SET_VARIABLE,
        )
        resp = cls(proto_ver)
        resp.deserialize(data, offset)
        return resp
