"""
Unit tests for s7commplus.protocol.s7p — the serialization engine.

Covers fixed-width encode/decode, VLQ encode/decode (unsigned and signed,
32-bit and 64-bit), float/double, string/octets, and header codec.

VLQ edge cases are critical — the signed variant uses a non-standard
sign flag in bit 6 of the first byte with one's complement pre-loading.
"""

import struct
import pytest

from s7commplus.protocol.s7p import (
    # Fixed-width
    encode_byte, decode_byte,
    encode_uint16, decode_uint16,
    encode_int16, decode_int16,
    encode_uint32, decode_uint32,
    encode_int32, decode_int32,
    encode_uint64, decode_uint64,
    encode_int64, decode_int64,
    # Little-endian
    decode_uint16_le, decode_uint32_le, decode_int32_le,
    # Float / Double
    encode_float, decode_float,
    encode_double, decode_double,
    # String / Octets
    encode_wstring, decode_wstring,
    encode_octets, decode_octets,
    # VLQ
    encode_uint32_vlq, decode_uint32_vlq,
    encode_int32_vlq, decode_int32_vlq,
    encode_uint64_vlq, decode_uint64_vlq,
    encode_int64_vlq, decode_int64_vlq,
    # Header
    encode_header, decode_header,
)


# ===================================================================
# Helpers
# ===================================================================

def roundtrip_encode_decode(encode_fn, decode_fn, value, expected_len):
    """Encode a value, then decode it and verify the roundtrip."""
    buf = bytearray()
    written = encode_fn(buf, value)
    assert written == expected_len, f"Expected {expected_len} bytes, got {written}"
    decoded, consumed = decode_fn(bytes(buf), 0)
    assert consumed == expected_len, f"Expected {expected_len} consumed, got {consumed}"
    return decoded


# ===================================================================
# Fixed-width encode/decode
# ===================================================================

class TestFixedWidth:

    def test_byte_roundtrip(self):
        for val in [0, 1, 127, 128, 255]:
            result = roundtrip_encode_decode(encode_byte, decode_byte, val, 1)
            assert result == val

    def test_uint16_roundtrip(self):
        for val in [0, 1, 255, 256, 0xFFFF]:
            result = roundtrip_encode_decode(encode_uint16, decode_uint16, val, 2)
            assert result == val

    def test_int16_roundtrip(self):
        for val in [0, 1, -1, 32767, -32768]:
            result = roundtrip_encode_decode(encode_int16, decode_int16, val, 2)
            assert result == val

    def test_uint32_roundtrip(self):
        for val in [0, 1, 0xFFFF, 0xFFFFFFFF]:
            result = roundtrip_encode_decode(encode_uint32, decode_uint32, val, 4)
            assert result == val

    def test_int32_roundtrip(self):
        for val in [0, 1, -1, 2147483647, -2147483648]:
            result = roundtrip_encode_decode(encode_int32, decode_int32, val, 4)
            assert result == val

    def test_uint64_roundtrip(self):
        for val in [0, 1, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF]:
            result = roundtrip_encode_decode(encode_uint64, decode_uint64, val, 8)
            assert result == val

    def test_int64_roundtrip(self):
        for val in [0, 1, -1, 2**63 - 1, -(2**63)]:
            result = roundtrip_encode_decode(encode_int64, decode_int64, val, 8)
            assert result == val

    def test_big_endian_byte_order(self):
        buf = bytearray()
        encode_uint16(buf, 0x0102)
        assert buf == b'\x01\x02'

        buf = bytearray()
        encode_uint32(buf, 0x01020304)
        assert buf == b'\x01\x02\x03\x04'

    def test_decode_short_buffer(self):
        """Decoding from too-short buffer should return (0, 0)."""
        assert decode_uint16(b'\x00', 0) == (0, 0)
        assert decode_uint32(b'\x00\x01', 0) == (0, 0)
        assert decode_uint64(b'\x00' * 7, 0) == (0, 0)
        assert decode_byte(b'', 0) == (0, 0)

    def test_decode_with_offset(self):
        data = b'\xFF\xFF\x00\x2A\xFF\xFF'
        val, consumed = decode_uint16(data, 2)
        assert val == 42
        assert consumed == 2


# ===================================================================
# Little-endian decode
# ===================================================================

class TestLittleEndian:

    def test_uint16_le(self):
        data = b'\x02\x01'  # 0x0102 in LE
        val, consumed = decode_uint16_le(data, 0)
        assert val == 0x0102
        assert consumed == 2

    def test_uint32_le(self):
        data = b'\x04\x03\x02\x01'  # 0x01020304 in LE
        val, consumed = decode_uint32_le(data, 0)
        assert val == 0x01020304
        assert consumed == 4

    def test_int32_le(self):
        # -1 in LE
        data = b'\xFF\xFF\xFF\xFF'
        val, consumed = decode_int32_le(data, 0)
        assert val == -1
        assert consumed == 4


# ===================================================================
# Float / Double
# ===================================================================

class TestFloatDouble:

    def test_float_roundtrip(self):
        for val in [0.0, 1.0, -1.0, 3.14]:
            buf = bytearray()
            encode_float(buf, val)
            decoded, consumed = decode_float(bytes(buf), 0)
            assert consumed == 4
            assert abs(decoded - val) < 1e-5

    def test_double_roundtrip(self):
        for val in [0.0, 1.0, -1.0, 3.141592653589793]:
            buf = bytearray()
            encode_double(buf, val)
            decoded, consumed = decode_double(bytes(buf), 0)
            assert consumed == 8
            assert abs(decoded - val) < 1e-12

    def test_float_short_buffer(self):
        assert decode_float(b'\x00\x00', 0) == (0.0, 0)

    def test_double_short_buffer(self):
        assert decode_double(b'\x00' * 4, 0) == (0.0, 0)


# ===================================================================
# String / Octets
# ===================================================================

class TestStringOctets:

    def test_wstring_roundtrip(self):
        buf = bytearray()
        text = "Hello"
        written = encode_wstring(buf, text)
        assert written == 5
        decoded, consumed = decode_wstring(bytes(buf), 0, 5)
        assert decoded == text
        assert consumed == 5

    def test_wstring_utf8(self):
        buf = bytearray()
        text = "Ä"  # 2 bytes in UTF-8
        written = encode_wstring(buf, text)
        assert written == 2
        decoded, consumed = decode_wstring(bytes(buf), 0, 2)
        assert decoded == text

    def test_wstring_empty(self):
        buf = bytearray()
        written = encode_wstring(buf, "")
        assert written == 0

    def test_octets_roundtrip(self):
        buf = bytearray()
        data = b'\x01\x02\x03\x04'
        written = encode_octets(buf, data)
        assert written == 4
        decoded, consumed = decode_octets(bytes(buf), 0, 4)
        assert decoded == data
        assert consumed == 4

    def test_octets_empty(self):
        buf = bytearray()
        written = encode_octets(buf, b'')
        assert written == 0

    def test_decode_wstring_short_buffer(self):
        assert decode_wstring(b'\x00', 0, 5) == ("", 0)

    def test_decode_octets_short_buffer(self):
        assert decode_octets(b'\x00', 0, 5) == (b"", 0)


# ===================================================================
# VLQ — Unsigned 32-bit
# ===================================================================

class TestUint32VLQ:

    def test_single_byte_values(self):
        """Values 0..127 encode to exactly 1 byte."""
        for val in [0, 1, 63, 64, 127]:
            buf = bytearray()
            written = encode_uint32_vlq(buf, val)
            assert written == 1, f"val={val} should be 1 byte, got {written}"
            decoded, consumed = decode_uint32_vlq(bytes(buf), 0)
            assert decoded == val
            assert consumed == 1

    def test_two_byte_values(self):
        """Values 128..16383 encode to 2 bytes."""
        for val in [128, 255, 256, 16383]:
            buf = bytearray()
            written = encode_uint32_vlq(buf, val)
            assert written == 2, f"val={val} should be 2 bytes, got {written}"
            decoded, consumed = decode_uint32_vlq(bytes(buf), 0)
            assert decoded == val
            assert consumed == 2

    def test_three_byte_values(self):
        for val in [16384, 0x1FFFFF]:
            buf = bytearray()
            written = encode_uint32_vlq(buf, val)
            assert written == 3
            decoded, consumed = decode_uint32_vlq(bytes(buf), 0)
            assert decoded == val

    def test_four_byte_values(self):
        for val in [0x200000, 0x0FFFFFFF]:
            buf = bytearray()
            written = encode_uint32_vlq(buf, val)
            assert written == 4
            decoded, consumed = decode_uint32_vlq(bytes(buf), 0)
            assert decoded == val

    def test_five_byte_values(self):
        for val in [0x10000000, 0xFFFFFFFF]:
            buf = bytearray()
            written = encode_uint32_vlq(buf, val)
            assert written == 5
            decoded, consumed = decode_uint32_vlq(bytes(buf), 0)
            assert decoded == val

    def test_zero(self):
        buf = bytearray()
        written = encode_uint32_vlq(buf, 0)
        assert written == 1
        assert buf == b'\x00'
        decoded, consumed = decode_uint32_vlq(buf, 0)
        assert decoded == 0

    def test_max_uint32(self):
        buf = bytearray()
        written = encode_uint32_vlq(buf, 0xFFFFFFFF)
        decoded, consumed = decode_uint32_vlq(bytes(buf), 0)
        assert decoded == 0xFFFFFFFF

    def test_roundtrip_powers_of_two(self):
        for exp in range(32):
            val = 1 << exp
            buf = bytearray()
            encode_uint32_vlq(buf, val)
            decoded, _ = decode_uint32_vlq(bytes(buf), 0)
            assert decoded == val, f"Failed at 2^{exp} = {val}"


# ===================================================================
# VLQ — Signed 32-bit
# ===================================================================

class TestInt32VLQ:

    def test_positive_values(self):
        for val in [0, 1, 63, 127, 255, 1000, 0x7FFFFFFF]:
            buf = bytearray()
            encode_int32_vlq(buf, val)
            decoded, _ = decode_int32_vlq(bytes(buf), 0)
            assert decoded == val, f"Failed roundtrip for {val}"

    def test_negative_values(self):
        for val in [-1, -2, -63, -64, -128, -1000, -2147483648]:
            buf = bytearray()
            encode_int32_vlq(buf, val)
            decoded, _ = decode_int32_vlq(bytes(buf), 0)
            assert decoded == val, f"Failed roundtrip for {val}"

    def test_sign_bit_encoding(self):
        """Negative values should have bit 6 set in the first byte."""
        buf = bytearray()
        encode_int32_vlq(buf, -1)
        # First byte should have bit 6 set (0x40)
        first_byte = buf[0]
        assert (first_byte & 0x40) != 0, f"Sign bit not set: 0x{first_byte:02X}"

    def test_positive_no_sign_bit(self):
        """Positive values should NOT have bit 6 set in the first byte
        (unless it's a data bit, which only happens for values >= 64)."""
        buf = bytearray()
        encode_int32_vlq(buf, 1)
        first_byte = buf[0]
        # For small positive values, bit 6 should not be set
        assert (first_byte & 0x40) == 0

    def test_int32_min(self):
        buf = bytearray()
        encode_int32_vlq(buf, -2147483648)
        decoded, _ = decode_int32_vlq(bytes(buf), 0)
        assert decoded == -2147483648

    def test_int32_max(self):
        buf = bytearray()
        encode_int32_vlq(buf, 2147483647)
        decoded, _ = decode_int32_vlq(bytes(buf), 0)
        assert decoded == 2147483647

    def test_minus_one(self):
        buf = bytearray()
        encode_int32_vlq(buf, -1)
        decoded, _ = decode_int32_vlq(bytes(buf), 0)
        assert decoded == -1

    def test_boundary_values(self):
        """Test around the 7-bit group boundaries."""
        for val in [-64, -65, 63, 64, -128, -129, 128]:
            buf = bytearray()
            encode_int32_vlq(buf, val)
            decoded, _ = decode_int32_vlq(bytes(buf), 0)
            assert decoded == val, f"Failed roundtrip for {val}"


# ===================================================================
# VLQ — Unsigned 64-bit
# ===================================================================

class TestUint64VLQ:

    def test_small_values(self):
        for val in [0, 1, 127]:
            buf = bytearray()
            written = encode_uint64_vlq(buf, val)
            assert written == 1
            decoded, _ = decode_uint64_vlq(bytes(buf), 0)
            assert decoded == val

    def test_medium_values(self):
        for val in [128, 0xFFFF, 0xFFFFFFFF]:
            buf = bytearray()
            encode_uint64_vlq(buf, val)
            decoded, _ = decode_uint64_vlq(bytes(buf), 0)
            assert decoded == val

    def test_large_values(self):
        """Values > 0x00FFFFFFFFFFFFFF need 9 bytes (special case)."""
        val = 0x00FFFFFFFFFFFFFF + 1
        buf = bytearray()
        written = encode_uint64_vlq(buf, val)
        decoded, consumed = decode_uint64_vlq(bytes(buf), 0)
        assert decoded == val, f"Expected {val:#x}, got {decoded:#x}"

    def test_max_uint64(self):
        buf = bytearray()
        encode_uint64_vlq(buf, 0xFFFFFFFFFFFFFFFF)
        decoded, _ = decode_uint64_vlq(bytes(buf), 0)
        assert decoded == 0xFFFFFFFFFFFFFFFF

    def test_roundtrip_powers_of_two(self):
        for exp in range(64):
            val = 1 << exp
            buf = bytearray()
            encode_uint64_vlq(buf, val)
            decoded, _ = decode_uint64_vlq(bytes(buf), 0)
            assert decoded == val, f"Failed at 2^{exp} = {val:#x}"


# ===================================================================
# VLQ — Signed 64-bit
# ===================================================================

class TestInt64VLQ:

    def test_positive_values(self):
        for val in [0, 1, 63, 127, 0x7FFFFFFFFFFFFFFF]:
            buf = bytearray()
            encode_int64_vlq(buf, val)
            decoded, _ = decode_int64_vlq(bytes(buf), 0)
            assert decoded == val, f"Failed roundtrip for {val:#x}"

    def test_negative_values(self):
        for val in [-1, -64, -128, -0x8000000000000000]:
            buf = bytearray()
            encode_int64_vlq(buf, val)
            decoded, _ = decode_int64_vlq(bytes(buf), 0)
            assert decoded == val, f"Failed roundtrip for {val}"

    def test_int64_min(self):
        buf = bytearray()
        encode_int64_vlq(buf, -9223372036854775808)
        decoded, _ = decode_int64_vlq(bytes(buf), 0)
        assert decoded == -9223372036854775808

    def test_int64_max(self):
        buf = bytearray()
        encode_int64_vlq(buf, 9223372036854775807)
        decoded, _ = decode_int64_vlq(bytes(buf), 0)
        assert decoded == 9223372036854775807


# ===================================================================
# Header
# ===================================================================

class TestHeader:

    def test_header_encode(self):
        buf = bytearray()
        written = encode_header(buf, 0x02, 100)
        assert written == 4
        assert buf[0] == 0x72  # protocol magic
        assert buf[1] == 0x02  # version
        # Payload length in big-endian
        length = struct.unpack_from(">H", buf, 2)[0]
        assert length == 100

    def test_header_decode(self):
        data = bytes([0x72, 0x03, 0x00, 0x64])  # version=3, length=100
        version, length, consumed = decode_header(data, 0)
        assert version == 0x03
        assert length == 100
        assert consumed == 4

    def test_header_roundtrip(self):
        buf = bytearray()
        encode_header(buf, 0x01, 512)
        version, length, consumed = decode_header(bytes(buf), 0)
        assert version == 0x01
        assert length == 512
        assert consumed == 4

    def test_header_short_buffer(self):
        assert decode_header(b'\x72\x01', 0) == (0, 0, 0)


# ===================================================================
# Offset handling
# ===================================================================

class TestOffset:
    """Verify that decode functions correctly handle non-zero offsets."""

    def test_vlq_at_offset(self):
        prefix = b'\xFF\xFF\xFF'
        buf = bytearray()
        encode_uint32_vlq(buf, 12345)
        data = prefix + bytes(buf)
        decoded, consumed = decode_uint32_vlq(data, 3)
        assert decoded == 12345

    def test_fixed_at_offset(self):
        prefix = b'\x00\x00'
        buf = bytearray()
        encode_uint32(buf, 0xDEADBEEF)
        data = prefix + bytes(buf)
        decoded, consumed = decode_uint32(data, 2)
        assert decoded == 0xDEADBEEF
        assert consumed == 4
