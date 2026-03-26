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
    """Request to initiate TLS handshake on the S7CommPlus connection."""

    transport_flags = 0x30
    function_code = FunctionCode.INIT_SSL

    def __init__(self, protocol_version: int, seq_num: int, session_id: int) -> None:

        """Initialize an InitSslRequest.

        Args:
            protocol_version: Wire protocol version.
            seq_num: Sequence number.
            session_id: Session ID.
        """
        self.protocol_version = protocol_version
        self.sequence_number = seq_num
        self.session_id = session_id
        self.with_integrity_id = False
        self.integrity_id: int = 0

    def serialize(self, buf: bytearray) -> int:

        """Serialize this request into *buf*.

        Args:
            buf: Target buffer to append to.

        Returns:
            Number of bytes written.
        """
        ret = encode_request_header(
            buf, FunctionCode.INIT_SSL,
            self.sequence_number, self.session_id, self.transport_flags,
        )
        ret += s7p.encode_uint32(buf, 0)  # fill
        return ret


class InitSslResponse:
    """Response acknowledging TLS initiation."""

    def __init__(self, protocol_version: int = 0) -> None:

        """Initialize an InitSslResponse.

        Args:
            protocol_version: Wire protocol version.
        """
        self.protocol_version = protocol_version
        self.sequence_number: int = 0
        self.transport_flags: int = 0
        self.return_value: int = 0
        self.error_object = None
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
        if self.return_value & ERROR_EXTENSION_FLAG:
            self.error_object, n = decode_object(data, offset)
            offset += n
        return offset - start

    @classmethod
    def from_pdu(cls, data: bytes, offset: int = 0) -> InitSslResponse | None:

        """Construct a response from a complete PDU.

        Args:
            data: Raw PDU bytes.
            offset: Starting offset.

        Returns:
            Populated response, or ``None`` on parse failure.
        """
        proto_ver, offset = decode_response_pdu_header(
            data, offset, Opcode.RESPONSE, FunctionCode.INIT_SSL,
        )
        resp = cls(proto_ver)
        resp.deserialize(data, offset)
        return resp
