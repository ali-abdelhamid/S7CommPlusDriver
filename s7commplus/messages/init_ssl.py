"""InitSsl request/response — TLS handshake initiation."""

from __future__ import annotations

from s7commplus.protocol import s7p
from s7commplus.protocol.constants import Opcode, FunctionCode
from s7commplus.protocol.pobject import decode_object
from s7commplus.messages.base import (
    encode_request_header, decode_response_pdu_header,
    decode_response_common, ERROR_EXTENSION_FLAG,
)


class InitSslRequest:
    transport_flags = 0x30

    def __init__(self, protocol_version: int, seq_num: int, session_id: int) -> None:
        self.protocol_version = protocol_version
        self.sequence_number = seq_num
        self.session_id = session_id
        self.with_integrity_id = False
        self.integrity_id: int = 0

    def serialize(self, buf: bytearray) -> int:
        ret = encode_request_header(
            buf, FunctionCode.INIT_SSL,
            self.sequence_number, self.session_id, self.transport_flags,
        )
        ret += s7p.encode_uint32(buf, 0)  # fill
        return ret


class InitSslResponse:
    def __init__(self, protocol_version: int = 0) -> None:
        self.protocol_version = protocol_version
        self.sequence_number: int = 0
        self.transport_flags: int = 0
        self.return_value: int = 0
        self.error_object = None
        self.with_integrity_id = False
        self.integrity_id: int = 0

    def deserialize(self, data: bytes, offset: int) -> int:
        start = offset
        self.sequence_number, self.transport_flags, offset = \
            decode_response_common(data, offset)
        self.return_value, n = s7p.decode_uint64_vlq(data, offset); offset += n
        if self.return_value & ERROR_EXTENSION_FLAG:
            self.error_object, n = decode_object(data, offset)
            offset += n
        return offset - start

    @classmethod
    def from_pdu(cls, data: bytes, offset: int = 0) -> InitSslResponse | None:
        proto_ver, offset = decode_response_pdu_header(
            data, offset, Opcode.RESPONSE, FunctionCode.INIT_SSL,
        )
        resp = cls(proto_ver)
        resp.deserialize(data, offset)
        return resp
