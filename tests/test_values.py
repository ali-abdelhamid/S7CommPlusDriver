"""
Unit tests for s7commplus.protocol.values — PValue type hierarchy.

Tests the registry-based deserialization, serialization round-trips,
arrays, sparse arrays, and struct types.
"""

import struct
import pytest

from s7commplus.protocol import s7p
from s7commplus.protocol.constants import Datatype
from s7commplus.protocol.values import (
    PValue, FLAGS_ARRAY, FLAGS_ADDRESSARRAY, FLAGS_SPARSEARRAY,
    ValueNull, ValueBool, ValueUSInt, ValueUInt, ValueUDInt, ValueULInt,
    ValueSInt, ValueInt, ValueDInt, ValueLInt,
    ValueByte, ValueWord, ValueDWord, ValueLWord,
    ValueReal, ValueLReal, ValueTimestamp, ValueTimespan,
    ValueRID, ValueAID, ValueBlob, ValueWString, ValueVariant,
    ValueStruct,
    ValueBoolArray, ValueUSIntArray, ValueUIntArray, ValueUDIntArray,
    ValueIntArray, ValueDIntArray, ValueByteArray, ValueRealArray,
    ValueRIDArray, ValueWStringArray,
    ValueDIntSparseArray, ValueUDIntSparseArray,
)


# ===========================================================================
# Helpers
# ===========================================================================

def _serialize(val: PValue) -> bytes:
    """Serialize a PValue and return the raw bytes."""
    buf = bytearray()
    val.serialize(buf)
    return bytes(buf)


def _roundtrip(val: PValue) -> PValue:
    """Serialize → deserialize round-trip."""
    data = _serialize(val)
    result, consumed = PValue.deserialize(data, 0)
    assert consumed == len(data), f"consumed {consumed} != len {len(data)}"
    return result


# ===========================================================================
# Scalar types
# ===========================================================================

class TestScalarTypes:

    def test_null_roundtrip(self):
        v = _roundtrip(ValueNull())
        assert isinstance(v, ValueNull)
        assert v.value is None

    def test_bool_true(self):
        v = _roundtrip(ValueBool(True))
        assert isinstance(v, ValueBool)
        assert v.value is True

    def test_bool_false(self):
        v = _roundtrip(ValueBool(False))
        assert v.value is False

    def test_usint(self):
        v = _roundtrip(ValueUSInt(200))
        assert v.value == 200

    def test_uint(self):
        v = _roundtrip(ValueUInt(60000))
        assert v.value == 60000

    def test_udint(self):
        v = _roundtrip(ValueUDInt(3_000_000))
        assert v.value == 3_000_000

    def test_ulint(self):
        v = _roundtrip(ValueULInt(2**48))
        assert v.value == 2**48

    def test_sint_positive(self):
        v = _roundtrip(ValueSInt(42))
        assert v.value == 42

    def test_sint_negative(self):
        v = _roundtrip(ValueSInt(-100))
        assert v.value == -100

    def test_int(self):
        v = _roundtrip(ValueInt(-12345))
        assert v.value == -12345

    def test_dint(self):
        v = _roundtrip(ValueDInt(-100000))
        assert v.value == -100000

    def test_lint(self):
        v = _roundtrip(ValueLInt(-999999999))
        assert v.value == -999999999

    def test_byte(self):
        v = _roundtrip(ValueByte(0xAB))
        assert v.value == 0xAB

    def test_word(self):
        v = _roundtrip(ValueWord(0xBEEF))
        assert v.value == 0xBEEF

    def test_dword(self):
        v = _roundtrip(ValueDWord(0xDEADBEEF))
        assert v.value == 0xDEADBEEF

    def test_lword(self):
        v = _roundtrip(ValueLWord(0xCAFEBABEDEADBEEF))
        assert v.value == 0xCAFEBABEDEADBEEF

    def test_real(self):
        v = _roundtrip(ValueReal(3.14))
        assert abs(v.value - 3.14) < 1e-5

    def test_lreal(self):
        v = _roundtrip(ValueLReal(3.141592653589793))
        assert abs(v.value - 3.141592653589793) < 1e-12

    def test_timestamp(self):
        v = _roundtrip(ValueTimestamp(1_000_000_000))
        assert v.value == 1_000_000_000

    def test_timespan(self):
        v = _roundtrip(ValueTimespan(-500))
        assert v.value == -500

    def test_rid(self):
        v = _roundtrip(ValueRID(0x80C3C901))
        assert v.value == 0x80C3C901

    def test_aid(self):
        v = _roundtrip(ValueAID(1256))
        assert v.value == 1256

    def test_variant(self):
        v = _roundtrip(ValueVariant())
        assert isinstance(v, ValueVariant)


class TestBlobAndWString:

    def test_blob_simple(self):
        blob = ValueBlob((0, b"\xDE\xAD\xBE\xEF", False, 0))
        v = _roundtrip(blob)
        assert isinstance(v, ValueBlob)
        assert v.blob_data == b"\xDE\xAD\xBE\xEF"

    def test_wstring(self):
        v = _roundtrip(ValueWString("Hello, PLC!"))
        assert v.value == "Hello, PLC!"

    def test_wstring_empty(self):
        v = _roundtrip(ValueWString(""))
        assert v.value == ""

    def test_wstring_unicode(self):
        v = _roundtrip(ValueWString("S7-1500 \u2192 TLS"))
        assert v.value == "S7-1500 \u2192 TLS"


# ===========================================================================
# Wire format verification
# ===========================================================================

class TestWireFormat:

    def test_bool_wire_format(self):
        data = _serialize(ValueBool(True))
        assert data[0] == 0x00  # flags
        assert data[1] == Datatype.BOOL
        assert data[2] == 0x01

    def test_uint_wire_format(self):
        data = _serialize(ValueUInt(0x1234))
        assert data[0] == 0x00  # flags
        assert data[1] == Datatype.UINT
        assert data[2:4] == b"\x12\x34"

    def test_rid_wire_format(self):
        """RID is always fixed 4-byte big-endian."""
        data = _serialize(ValueRID(0x01020304))
        assert data[0] == 0x00
        assert data[1] == Datatype.RID
        assert data[2:6] == b"\x01\x02\x03\x04"

    def test_flags_byte_in_header(self):
        """Array values should set the flags byte."""
        arr = ValueBoolArray([True, False, True], flags=FLAGS_ARRAY)
        data = _serialize(arr)
        assert data[0] == FLAGS_ARRAY


# ===========================================================================
# Deserialization from raw bytes
# ===========================================================================

class TestDeserialization:

    def test_deserialize_bool(self):
        data = bytes([0x00, Datatype.BOOL, 0x01])
        val, consumed = PValue.deserialize(data, 0)
        assert consumed == 3
        assert isinstance(val, ValueBool)
        assert val.value is True

    def test_deserialize_udint_vlq(self):
        """UDInt uses VLQ encoding on the wire."""
        buf = bytearray([0x00, Datatype.UDINT])
        s7p.encode_uint32_vlq(buf, 300)
        val, consumed = PValue.deserialize(bytes(buf), 0)
        assert isinstance(val, ValueUDInt)
        assert val.value == 300

    def test_deserialize_udint_disable_vlq(self):
        """With disable_vlq=True, UDInt uses fixed 4-byte encoding."""
        buf = bytearray([0x00, Datatype.UDINT])
        s7p.encode_uint32(buf, 300)
        val, consumed = PValue.deserialize(bytes(buf), 0, disable_vlq=True)
        assert isinstance(val, ValueUDInt)
        assert val.value == 300

    def test_deserialize_unknown_type(self):
        """Unknown datatype falls back to ValueNull."""
        data = bytes([0x00, 0xFF])  # 0xFF not registered
        val, consumed = PValue.deserialize(data, 0)
        assert isinstance(val, ValueNull)

    def test_deserialize_with_offset(self):
        """Deserialize should work with a nonzero offset."""
        prefix = b"\xFF\xFF\xFF"  # 3 junk bytes
        data = prefix + bytes([0x00, Datatype.BOOL, 0x00])
        val, consumed = PValue.deserialize(data, 3)
        assert consumed == 3
        assert isinstance(val, ValueBool)
        assert val.value is False


# ===========================================================================
# Array types
# ===========================================================================

class TestArrayTypes:

    def test_bool_array(self):
        v = _roundtrip(ValueBoolArray([True, False, True], flags=FLAGS_ARRAY))
        assert v.value == [True, False, True]

    def test_usint_array(self):
        v = _roundtrip(ValueUSIntArray([1, 2, 3, 255], flags=FLAGS_ARRAY))
        assert v.value == [1, 2, 3, 255]

    def test_uint_array(self):
        v = _roundtrip(ValueUIntArray([1000, 2000], flags=FLAGS_ARRAY))
        assert v.value == [1000, 2000]

    def test_udint_array(self):
        v = _roundtrip(ValueUDIntArray([100000, 200000], flags=FLAGS_ARRAY))
        assert v.value == [100000, 200000]

    def test_int_array(self):
        v = _roundtrip(ValueIntArray([-1, 0, 1], flags=FLAGS_ARRAY))
        assert v.value == [-1, 0, 1]

    def test_dint_array(self):
        v = _roundtrip(ValueDIntArray([-50000, 50000], flags=FLAGS_ARRAY))
        assert v.value == [-50000, 50000]

    def test_byte_array(self):
        v = _roundtrip(ValueByteArray([0xDE, 0xAD, 0xBE, 0xEF], flags=FLAGS_ARRAY))
        assert v.value == [0xDE, 0xAD, 0xBE, 0xEF]

    def test_real_array(self):
        v = _roundtrip(ValueRealArray([1.0, 2.0, 3.0], flags=FLAGS_ARRAY))
        for a, b in zip(v.value, [1.0, 2.0, 3.0]):
            assert abs(a - b) < 1e-5

    def test_rid_array(self):
        v = _roundtrip(ValueRIDArray([0x100, 0x200], flags=FLAGS_ARRAY))
        assert v.value == [0x100, 0x200]

    def test_empty_array(self):
        v = _roundtrip(ValueBoolArray([], flags=FLAGS_ARRAY))
        assert v.value == []

    def test_address_array_flag(self):
        """ADDRESS_ARRAY flag should also deserialize as array."""
        arr = ValueByteArray([1, 2, 3], flags=FLAGS_ADDRESSARRAY)
        data = _serialize(arr)
        val, consumed = PValue.deserialize(data, 0)
        assert val.value == [1, 2, 3]


# ===========================================================================
# Sparse array types
# ===========================================================================

class TestSparseArrayTypes:

    def test_dint_sparse(self):
        v = _roundtrip(ValueDIntSparseArray({1: -10, 5: 20}, flags=FLAGS_SPARSEARRAY))
        assert v.value == {1: -10, 5: 20}

    def test_udint_sparse(self):
        v = _roundtrip(ValueUDIntSparseArray({100: 42}, flags=FLAGS_SPARSEARRAY))
        assert v.value == {100: 42}

    def test_empty_sparse(self):
        v = _roundtrip(ValueDIntSparseArray({}, flags=FLAGS_SPARSEARRAY))
        assert v.value == {}


# ===========================================================================
# Struct types
# ===========================================================================

class TestStructTypes:

    def test_regular_struct_roundtrip(self):
        stru = ValueStruct(0x00000001)
        stru.add_element(100, ValueUDInt(42))
        stru.add_element(200, ValueBool(True))
        v = _roundtrip(stru)
        assert isinstance(v, ValueStruct)
        assert v.get_element(100).value == 42
        assert v.get_element(200).value is True

    def test_regular_struct_nested(self):
        inner = ValueStruct(0x00000002)
        inner.add_element(1, ValueInt(-5))
        outer = ValueStruct(0x00000003)
        outer.add_element(10, inner)
        v = _roundtrip(outer)
        inner_result = v.get_element(10)
        assert isinstance(inner_result, ValueStruct)
        assert inner_result.get_element(1).value == -5

    def test_packed_struct_roundtrip(self):
        """Packed structs use raw byte arrays."""
        stru = ValueStruct(0x92000001)  # in packed range
        stru.add_element(0x92000001, ValueByteArray([0x01, 0x02, 0x03]))
        v = _roundtrip(stru)
        assert isinstance(v, ValueStruct)
        assert ValueStruct._is_packed(v.value)

    def test_is_packed(self):
        assert ValueStruct._is_packed(0x90000001)
        assert ValueStruct._is_packed(0x9FFFFFFE)
        assert ValueStruct._is_packed(0x02000001)
        assert ValueStruct._is_packed(0x02FFFFFE)
        assert not ValueStruct._is_packed(0x00000001)
        assert not ValueStruct._is_packed(0x80000001)


# ===========================================================================
# Properties
# ===========================================================================

class TestProperties:

    def test_is_array(self):
        v = ValueBoolArray([True], flags=FLAGS_ARRAY)
        assert v.is_array
        assert not v.is_sparse_array

    def test_is_address_array(self):
        v = ValueByteArray([1], flags=FLAGS_ADDRESSARRAY)
        assert v.is_array

    def test_is_sparse_array(self):
        v = ValueDIntSparseArray({1: 2}, flags=FLAGS_SPARSEARRAY)
        assert v.is_sparse_array
        assert not v.is_array

    def test_scalar_flags(self):
        v = ValueBool(True)
        assert not v.is_array
        assert not v.is_sparse_array
