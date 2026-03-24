"""
S7CommPlus serialization engine.

Ported from S7p.cs — provides encode/decode for all wire-level types including
the non-standard VLQ (Variable Length Quantity) encoding used by S7CommPlus.

All encode functions write to a bytearray and return bytes written.
All decode functions read from a memoryview/bytes-like and return (value, bytes_consumed).
"""

import struct
from io import BytesIO


# ===========================================================================
# Fixed-width encode  (big-endian)
# ===========================================================================

def encode_byte(buf: bytearray, value: int) -> int:
    buf.append(value & 0xFF)
    return 1


def encode_uint16(buf: bytearray, value: int) -> int:
    buf.extend(struct.pack(">H", value & 0xFFFF))
    return 2


def encode_int16(buf: bytearray, value: int) -> int:
    buf.extend(struct.pack(">h", value))
    return 2


def encode_uint32(buf: bytearray, value: int) -> int:
    buf.extend(struct.pack(">I", value & 0xFFFFFFFF))
    return 4


def encode_int32(buf: bytearray, value: int) -> int:
    buf.extend(struct.pack(">i", value))
    return 4


def encode_uint64(buf: bytearray, value: int) -> int:
    buf.extend(struct.pack(">Q", value & 0xFFFFFFFFFFFFFFFF))
    return 8


def encode_int64(buf: bytearray, value: int) -> int:
    buf.extend(struct.pack(">q", value))
    return 8


# ===========================================================================
# Fixed-width decode  (big-endian)
# ===========================================================================

def decode_byte(data: bytes, offset: int) -> tuple[int, int]:
    """Returns (value, bytes_consumed)."""
    if offset >= len(data):
        return 0, 0
    return data[offset], 1


def decode_uint16(data: bytes, offset: int) -> tuple[int, int]:
    if offset + 2 > len(data):
        return 0, 0
    return struct.unpack_from(">H", data, offset)[0], 2


def decode_int16(data: bytes, offset: int) -> tuple[int, int]:
    if offset + 2 > len(data):
        return 0, 0
    return struct.unpack_from(">h", data, offset)[0], 2


def decode_uint32(data: bytes, offset: int) -> tuple[int, int]:
    if offset + 4 > len(data):
        return 0, 0
    return struct.unpack_from(">I", data, offset)[0], 4


def decode_int32(data: bytes, offset: int) -> tuple[int, int]:
    if offset + 4 > len(data):
        return 0, 0
    return struct.unpack_from(">i", data, offset)[0], 4


def decode_uint64(data: bytes, offset: int) -> tuple[int, int]:
    if offset + 8 > len(data):
        return 0, 0
    return struct.unpack_from(">Q", data, offset)[0], 8


def decode_int64(data: bytes, offset: int) -> tuple[int, int]:
    if offset + 8 > len(data):
        return 0, 0
    return struct.unpack_from(">q", data, offset)[0], 8


# ===========================================================================
# Little-endian decode
# ===========================================================================

def decode_uint16_le(data: bytes, offset: int) -> tuple[int, int]:
    if offset + 2 > len(data):
        return 0, 0
    return struct.unpack_from("<H", data, offset)[0], 2


def decode_uint32_le(data: bytes, offset: int) -> tuple[int, int]:
    if offset + 4 > len(data):
        return 0, 0
    return struct.unpack_from("<I", data, offset)[0], 4


def decode_int32_le(data: bytes, offset: int) -> tuple[int, int]:
    if offset + 4 > len(data):
        return 0, 0
    return struct.unpack_from("<i", data, offset)[0], 4


# ===========================================================================
# Float / Double
# ===========================================================================

def encode_float(buf: bytearray, value: float) -> int:
    buf.extend(struct.pack(">f", value))
    return 4


def decode_float(data: bytes, offset: int) -> tuple[float, int]:
    if offset + 4 > len(data):
        return 0.0, 0
    return struct.unpack_from(">f", data, offset)[0], 4


def encode_double(buf: bytearray, value: float) -> int:
    buf.extend(struct.pack(">d", value))
    return 8


def decode_double(data: bytes, offset: int) -> tuple[float, int]:
    if offset + 8 > len(data):
        return 0.0, 0
    return struct.unpack_from(">d", data, offset)[0], 8


# ===========================================================================
# String / Octets
# ===========================================================================

def encode_wstring(buf: bytearray, value: str) -> int:
    encoded = value.encode("utf-8")
    buf.extend(encoded)
    return len(encoded)


def decode_wstring(data: bytes, offset: int, length: int) -> tuple[str, int]:
    if offset + length > len(data):
        return "", 0
    return data[offset:offset + length].decode("utf-8"), length


def encode_octets(buf: bytearray, value: bytes) -> int:
    if not value:
        return 0
    buf.extend(value)
    return len(value)


def decode_octets(data: bytes, offset: int, length: int) -> tuple[bytes, int]:
    if length <= 0 or offset + length > len(data):
        return b"", 0
    return bytes(data[offset:offset + length]), length


# ===========================================================================
# VLQ — Variable Length Quantity encoding (unsigned 32-bit)
#
# Standard VLQ: 7 bits per byte, high bit = continuation flag.
# Max 5 bytes for 32-bit values.
# ===========================================================================

def encode_uint32_vlq(buf: bytearray, value: int) -> int:
    value &= 0xFFFFFFFF
    b = [0] * 5

    # Find highest non-zero 7-bit group
    i = 4
    while i > 0:
        if (value & (0x7F << (i * 7))) > 0:
            break
        i -= 1

    # Encode each 7-bit group with continuation bit
    for j in range(i + 1):
        b[j] = ((value >> ((i - j) * 7)) & 0x7F) | 0x80

    # Clear continuation bit on last byte
    b[i] ^= 0x80

    buf.extend(b[:i + 1])
    return i + 1


def decode_uint32_vlq(data: bytes, offset: int) -> tuple[int, int]:
    val = 0
    length = 0
    for _ in range(5):
        if offset + length >= len(data):
            break
        octet = data[offset + length]
        length += 1
        val = (val << 7) | (octet & 0x7F)
        if (octet & 0x80) == 0:
            break
    return val & 0xFFFFFFFF, length


# ===========================================================================
# VLQ — Signed 32-bit
#
# Non-standard: bit 6 of the first byte is a sign flag.
# If set, the value is negative. The decoder pre-loads with -64 (one's
# complement excluding the first 6 bits) and does NOT left-shift on the
# first iteration.
# ===========================================================================

def encode_int32_vlq(buf: bytearray, value: int) -> int:
    # Encode in compact variant (same as PLC read-back encoding).
    # The decoder handles both full-complement and compact forms.
    b = [0] * 5

    if value == -2147483648:  # int32 min
        abs_v = 2147483648
    else:
        abs_v = abs(value)

    # Work with the raw 32-bit representation for negative values
    raw = value & 0xFFFFFFFF

    b[0] = raw & 0x7F
    length = 1
    for i in range(1, 5):
        if abs_v >= 0x40:
            length += 1
            abs_v >>= 7
            raw >>= 7
            b[i] = (raw & 0x7F) | 0x80
        else:
            break

    # Write in reverse order
    for i in range(length - 1, -1, -1):
        buf.append(b[i] & 0xFF)
    return length


def decode_int32_vlq(data: bytes, offset: int) -> tuple[int, int]:
    val = 0
    length = 0
    for counter in range(1, 6):
        if offset + length >= len(data):
            break
        octet = data[offset + length]
        length += 1

        if counter == 1 and (octet & 0x40) != 0:
            # Sign bit set — negative value
            octet &= 0xBF  # clear sign bit
            val = -64  # pre-load with one's complement
        else:
            val <<= 7

        val += octet & 0x7F

        if (octet & 0x80) == 0:
            break

    # Clamp to int32 range
    if val > 0x7FFFFFFF:
        val -= 0x100000000
    return val, length


# ===========================================================================
# VLQ — Unsigned 64-bit
#
# Special handling: values > 0x00FFFFFFFFFFFFFF need 9 bytes.
# The 9th byte uses all 8 bits (no continuation flag) because
# 8×7 + 8 = 64 bits exactly.
# ===========================================================================

def encode_uint64_vlq(buf: bytearray, value: int) -> int:
    value &= 0xFFFFFFFFFFFFFFFF
    b = [0] * 9

    special = value > 0x00FFFFFFFFFFFFFF
    if special:
        b[0] = value & 0xFF
    else:
        b[0] = value & 0x7F

    length = 1
    for i in range(1, 9):
        if value >= 0x80:
            length += 1
            if i == 1 and special:
                value >>= 8
            else:
                value >>= 7
            b[i] = (value & 0x7F) | 0x80
        else:
            break

    if special and length == 8:
        # Need extra continuation byte (see C# comment on edge cases)
        length += 1
        b[8] = 0x80

    # Write in reverse order
    for i in range(length - 1, -1, -1):
        buf.append(b[i] & 0xFF)
    return length


def decode_uint64_vlq(data: bytes, offset: int) -> tuple[int, int]:
    val = 0
    length = 0
    cont = 0
    for _ in range(8):
        if offset + length >= len(data):
            break
        octet = data[offset + length]
        length += 1
        val = (val << 7) | (octet & 0x7F)
        cont = octet & 0x80
        if cont == 0:
            break

    if cont > 0:
        # 9th byte: special case, use all 8 bits
        if offset + length < len(data):
            octet = data[offset + length]
            length += 1
            val = (val << 8) | octet

    return val & 0xFFFFFFFFFFFFFFFF, length


# ===========================================================================
# VLQ — Signed 64-bit
# ===========================================================================

def encode_int64_vlq(buf: bytearray, value: int) -> int:
    b = [0] * 9

    if value == -9223372036854775808:  # int64 min
        abs_v = 9223372036854775808
    else:
        abs_v = abs(value)

    raw = value & 0xFFFFFFFFFFFFFFFF

    special = abs_v > 0x007FFFFFFFFFFFFF
    if special:
        b[0] = raw & 0xFF
    else:
        b[0] = raw & 0x7F

    length = 1
    for i in range(1, 9):
        if abs_v >= 0x40:
            length += 1
            if i == 1 and special:
                abs_v >>= 8
                raw >>= 8
            else:
                abs_v >>= 7
                raw >>= 7
            b[i] = (raw & 0x7F) | 0x80
        else:
            break

    if special and length == 8:
        length += 1
        if value >= 0:
            b[8] = 0x80
        else:
            b[8] = 0xFF

    # Write in reverse order
    for i in range(length - 1, -1, -1):
        buf.append(b[i] & 0xFF)
    return length


def decode_int64_vlq(data: bytes, offset: int) -> tuple[int, int]:
    val = 0
    length = 0
    cont = 0
    for counter in range(1, 9):
        if offset + length >= len(data):
            break
        octet = data[offset + length]
        length += 1

        if counter == 1 and (octet & 0x40) != 0:
            # Sign bit set
            octet &= 0xBF
            val = -64
        else:
            val <<= 7

        val += octet & 0x7F
        cont = octet & 0x80
        if cont == 0:
            break

    if cont > 0:
        # 9th byte: special case, use all 8 bits
        if offset + length < len(data):
            octet = data[offset + length]
            length += 1
            val = (val << 8) | octet

    # Clamp to int64 range
    if val > 0x7FFFFFFFFFFFFFFF:
        val -= 0x10000000000000000
    return val, length


# ===========================================================================
# S7CommPlus PDU Header
# ===========================================================================

def encode_header(buf: bytearray, version: int, length: int) -> int:
    buf.append(0x72)
    buf.append(version & 0xFF)
    encode_uint16(buf, length)
    return 4


def decode_header(data: bytes, offset: int) -> tuple[int, int, int]:
    """Returns (version, payload_length, bytes_consumed).

    The first byte (0x72) is skipped (protocol magic).
    """
    if offset + 4 > len(data):
        return 0, 0, 0
    version = data[offset + 1]
    length, _ = decode_uint16(data, offset + 2)
    return version, length, 4
