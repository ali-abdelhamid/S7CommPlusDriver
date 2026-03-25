"""DeleteObject request/response — object deletion."""

from __future__ import annotations

from s7commplus.protocol import s7p
from s7commplus.protocol.constants import Opcode, FunctionCode
from s7commplus.protocol.pobject import decode_object, encode_object_qualifier
from s7commplus.messages.base import (
    encode_request_header, decode_response_pdu_header,
    decode_response_common, ERROR_EXTENSION_FLAG,
)


class DeleteObjectRequest:
    transport_flags = 0x34

    def __init__(self, protocol_version: int) -> None:
        self.protocol_version = protocol_version
        self.sequence_number: int = 0
        self.session_id: int = 0
        self.with_integrity_id = True
        self.integrity_id: int = 0
        self.delete_object_id: int = 0

    def serialize(self, buf: bytearray) -> int:
        ret = encode_request_header(
            buf, FunctionCode.DELETE_OBJECT,
            self.sequence_number, self.session_id, self.transport_flags,
        )
        ret += s7p.encode_uint32(buf, self.delete_object_id)
        ret += s7p.encode_byte(buf, 0x00)
        ret += encode_object_qualifier(buf)
        if self.with_integrity_id:
            ret += s7p.encode_uint32_vlq(buf, self.integrity_id)
        ret += s7p.encode_uint32(buf, 0)  # fill
        return ret


class DeleteObjectResponse:
    def __init__(self, protocol_version: int = 0,
                 with_integrity_id: bool = True) -> None:
        self.protocol_version = protocol_version
        self.sequence_number: int = 0
        self.transport_flags: int = 0
        self.return_value: int = 0
        self.delete_object_id: int = 0
        self.with_integrity_id = with_integrity_id
        self.integrity_id: int = 0
        self.error_object = None

    def deserialize(self, data: bytes, offset: int) -> int:
        start = offset
        self.sequence_number, self.transport_flags, offset = \
            decode_response_common(data, offset)
        self.return_value, n = s7p.decode_uint64_vlq(data, offset); offset += n
        self.delete_object_id, n = s7p.decode_uint32(data, offset); offset += n
        if self.return_value & ERROR_EXTENSION_FLAG:
            self.error_object, n = decode_object(data, offset)
            offset += n
        if self.with_integrity_id:
            self.integrity_id, n = s7p.decode_uint32_vlq(data, offset); offset += n
        return offset - start

    @classmethod
    def from_pdu(cls, data: bytes, offset: int = 0,
                 with_integrity_id: bool = True) -> DeleteObjectResponse | None:
        proto_ver, offset = decode_response_pdu_header(
            data, offset, Opcode.RESPONSE, FunctionCode.DELETE_OBJECT,
        )
        resp = cls(proto_ver, with_integrity_id)
        resp.deserialize(data, offset)
        return resp
