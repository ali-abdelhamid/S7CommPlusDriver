"""
Utility functions for S7CommPlus.

Ported from Utils.cs.
"""

import struct
from datetime import datetime, timezone

# Unix epoch in .NET ticks (100ns units since 0001-01-01)
_EPOCH_TICKS = 621355968000000000


def hex_dump(data: bytes, bytes_per_line: int = 16) -> str:
    """Format *data* as a hex dump with address, hex, and ASCII columns.

    Args:
        data: Raw bytes to format.
        bytes_per_line: Number of bytes per output line.

    Returns:
        Multi-line hex dump string, or ``"<empty>"`` if *data* is empty.
    """
    if not data:
        return "<empty>"

    lines: list[str] = []
    for offset in range(0, len(data), bytes_per_line):
        chunk = data[offset:offset + bytes_per_line]
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{offset:08X}   {hex_part:<{bytes_per_line * 3}}  {ascii_part}")
    return "\n".join(lines)


def dt_from_value_timestamp(value: int) -> datetime:
    """Convert a protocol ValueTimestamp (nanoseconds since Unix epoch) to datetime.

    Args:
        value: Nanoseconds since the Unix epoch.

    Returns:
        UTC-aware :class:`datetime` instance.
    """
    seconds = value / 1_000_000_000
    return datetime.fromtimestamp(seconds, tz=timezone.utc)


# ---------------------------------------------------------------------------
# Byte-array accessor helpers  (big-endian unless noted)
# ---------------------------------------------------------------------------

def get_uint8(data: bytes, pos: int) -> int:
    """Read an unsigned 8-bit integer from *data* at *pos*.

    Args:
        data: Source byte buffer.
        pos: Byte offset.

    Returns:
        Unsigned integer value (0–255).
    """
    return data[pos]


def get_uint16(data: bytes, pos: int) -> int:
    """Read an unsigned 16-bit integer from *data* at *pos* (big-endian).

    Args:
        data: Source byte buffer.
        pos: Byte offset.

    Returns:
        Unsigned integer value.
    """
    return struct.unpack_from(">H", data, pos)[0]


def get_uint16_le(data: bytes, pos: int) -> int:
    """Read an unsigned 16-bit integer from *data* at *pos* (little-endian).

    Args:
        data: Source byte buffer.
        pos: Byte offset.

    Returns:
        Unsigned integer value.
    """
    return struct.unpack_from("<H", data, pos)[0]


def get_int16(data: bytes, pos: int) -> int:
    """Read a signed 16-bit integer from *data* at *pos* (big-endian).

    Args:
        data: Source byte buffer.
        pos: Byte offset.

    Returns:
        Signed integer value.
    """
    return struct.unpack_from(">h", data, pos)[0]


def get_uint32(data: bytes, pos: int) -> int:
    """Read an unsigned 32-bit integer from *data* at *pos* (big-endian).

    Args:
        data: Source byte buffer.
        pos: Byte offset.

    Returns:
        Unsigned integer value.
    """
    return struct.unpack_from(">I", data, pos)[0]


def get_uint32_le(data: bytes, pos: int) -> int:
    """Read an unsigned 32-bit integer from *data* at *pos* (little-endian).

    Args:
        data: Source byte buffer.
        pos: Byte offset.

    Returns:
        Unsigned integer value.
    """
    return struct.unpack_from("<I", data, pos)[0]


def get_int32(data: bytes, pos: int) -> int:
    """Read a signed 32-bit integer from *data* at *pos* (big-endian).

    Args:
        data: Source byte buffer.
        pos: Byte offset.

    Returns:
        Signed integer value.
    """
    return struct.unpack_from(">i", data, pos)[0]


def get_float(data: bytes, pos: int) -> float:
    """Read a 32-bit IEEE 754 float from *data* at *pos* (big-endian).

    Args:
        data: Source byte buffer.
        pos: Byte offset.

    Returns:
        Float value.
    """
    return struct.unpack_from(">f", data, pos)[0]


def get_double(data: bytes, pos: int) -> float:
    """Read a 64-bit IEEE 754 double from *data* at *pos* (big-endian).

    Args:
        data: Source byte buffer.
        pos: Byte offset.

    Returns:
        Float value.
    """
    return struct.unpack_from(">d", data, pos)[0]


def get_utf_string(data: bytes, pos: int, length: int) -> str:
    """Read a UTF-8 string of *length* bytes from *data* at *pos*.

    Args:
        data: Source byte buffer.
        pos: Byte offset.
        length: Number of bytes to decode.

    Returns:
        Decoded string.
    """
    return data[pos:pos + length].decode("utf-8")
