"""
Common header encode/decode for all S7CommPlus messages.

Every request shares:
    Opcode(1) | Reserved(2) | FunctionCode(2) | Reserved(2) |
    SequenceNumber(2) | SessionId(4) | TransportFlags(1)

Every response PDU starts:
    ProtocolVersion(1) | Opcode(1) | Reserved(2) | FunctionCode(2) | Reserved(2)
followed by message-specific deserialization.
"""

from s7commplus.protocol import s7p
from s7commplus.protocol.constants import Opcode

# Error extension flag: bit 62 of the uint64 ReturnValue
ERROR_EXTENSION_FLAG = 0x4000000000000000


def encode_request_header(
    buf: bytearray,
    function_code: int,
    seq_num: int,
    session_id: int,
    transport_flags: int,
) -> int:
    """Encode the common 14-byte request header.

    Args:
        buf: Target buffer to append to.
        function_code: S7CommPlus function code.
        seq_num: Sequence number for this request.
        session_id: Session ID (uint32).
        transport_flags: Transport flags byte.

    Returns:
        Number of bytes written (always 14).
    """
    ret = 0
    ret += s7p.encode_byte(buf, Opcode.REQUEST)
    ret += s7p.encode_uint16(buf, 0)           # reserved
    ret += s7p.encode_uint16(buf, function_code)
    ret += s7p.encode_uint16(buf, 0)           # reserved
    ret += s7p.encode_uint16(buf, seq_num)
    ret += s7p.encode_uint32(buf, session_id)
    ret += s7p.encode_byte(buf, transport_flags)
    return ret


def decode_response_pdu_header(
    data: bytes,
    offset: int,
    expected_opcode: int,
    expected_function: int,
) -> tuple[int, int]:
    """Decode and validate a response PDU header.

    Args:
        data: Source byte buffer.
        offset: Position to read from.
        expected_opcode: Expected opcode value.
        expected_function: Expected function code value.

    Returns:
        Tuple of ``(protocol_version, new_offset)``.

    Raises:
        ValueError: If opcode or function code does not match.
    """
    start = offset
    proto_ver, n = s7p.decode_byte(data, offset); offset += n
    opcode, n = s7p.decode_byte(data, offset); offset += n
    if opcode != expected_opcode:
        raise ValueError(
            f"Expected opcode 0x{expected_opcode:02X}, got 0x{opcode:02X}"
        )
    _, n = s7p.decode_uint16(data, offset); offset += n  # reserved
    func, n = s7p.decode_uint16(data, offset); offset += n
    if func != expected_function:
        raise ValueError(
            f"Expected function 0x{expected_function:04X}, got 0x{func:04X}"
        )
    _, n = s7p.decode_uint16(data, offset); offset += n  # reserved
    return proto_ver, offset


def decode_response_common(data: bytes, offset: int) -> tuple[int, int, int]:
    """Decode the common response fields after the PDU header.

    Args:
        data: Source byte buffer.
        offset: Position to read from.

    Returns:
        Tuple of ``(sequence_number, transport_flags, new_offset)``.
    """
    seq_num, n = s7p.decode_uint16(data, offset); offset += n
    transport_flags, n = s7p.decode_byte(data, offset); offset += n
    return seq_num, transport_flags, offset
