"""
PValue type hierarchy — the S7CommPlus value type system.

Ported from PValue.cs (3,294 lines).  Uses a registry/factory pattern instead
of 50+ separate classes:  a ``@value_type`` decorator registers each class by
its ``(datatype, flags_kind)`` tuple, and ``PValue.deserialize()`` dispatches
through the registry.

Wire format for every value:
    [flags_byte] [datatype_byte] [type-specific payload]

Flags byte bits:
    0x10 — regular array
    0x20 — address array (same as 0x10 for decode; used by Blob/WString)
    0x40 — sparse array (dict of key→value)
"""

from __future__ import annotations

from io import BytesIO
from typing import Any

from s7commplus.protocol import s7p
from s7commplus.protocol.constants import Datatype


# ---------------------------------------------------------------------------
# Flags constants
# ---------------------------------------------------------------------------

FLAGS_ARRAY = 0x10
FLAGS_ADDRESSARRAY = 0x20
FLAGS_SPARSEARRAY = 0x40

# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

# Key: (datatype_id, kind) where kind is "scalar", "array", or "sparse"
_REGISTRY: dict[tuple[int, str], type["PValue"]] = {}


def _register(datatype: int, kind: str = "scalar"):
    """Decorator to register a PValue subclass."""
    def decorator(cls):
        _REGISTRY[(datatype, kind)] = cls
        return cls
    return decorator


# ---------------------------------------------------------------------------
# Base class
# ---------------------------------------------------------------------------

class PValue:
    """Abstract base for all S7CommPlus wire-level values."""

    datatype: int = Datatype.NULL
    flags: int = 0

    def __init__(self, value: Any = None, flags: int = 0) -> None:
        self.value = value
        self.flags = flags

    @property
    def is_array(self) -> bool:
        return (self.flags & (FLAGS_ARRAY | FLAGS_ADDRESSARRAY)) != 0

    @property
    def is_sparse_array(self) -> bool:
        return (self.flags & FLAGS_SPARSEARRAY) != 0

    # -- Serialization -------------------------------------------------------

    def serialize(self, buf: bytearray) -> int:
        """Encode this value into *buf*.  Returns bytes written."""
        raise NotImplementedError

    def _write_header(self, buf: bytearray) -> int:
        """Write the common [flags][datatype] header."""
        ret = s7p.encode_byte(buf, self.flags)
        ret += s7p.encode_byte(buf, self.datatype)
        return ret

    # -- Deserialization (factory) -------------------------------------------

    @staticmethod
    def deserialize(data: bytes, offset: int, disable_vlq: bool = False) -> tuple["PValue", int]:
        """Read a PValue from *data* at *offset*.

        Returns ``(value, bytes_consumed)``.

        :param disable_vlq: If ``True``, use fixed-width decoding instead of
            VLQ (for SystemEvent compatibility).
        """
        start = offset
        flags, n = s7p.decode_byte(data, offset); offset += n
        dt, n = s7p.decode_byte(data, offset); offset += n

        if flags & FLAGS_SPARSEARRAY:
            kind = "sparse"
        elif flags & (FLAGS_ARRAY | FLAGS_ADDRESSARRAY):
            kind = "array"
        else:
            kind = "scalar"

        cls = _REGISTRY.get((dt, kind))
        if cls is None:
            # Fallback: try scalar
            cls = _REGISTRY.get((dt, "scalar"))
        if cls is None:
            return ValueNull(flags=flags), offset - start

        val, n = cls._deserialize(data, offset, flags, disable_vlq)
        offset += n
        return val, offset - start

    @classmethod
    def _deserialize(cls, data: bytes, offset: int, flags: int,
                     disable_vlq: bool) -> tuple["PValue", int]:
        """Subclass hook for type-specific deserialization."""
        raise NotImplementedError


# ===========================================================================
# Scalar types
# ===========================================================================

@_register(Datatype.NULL)
class ValueNull(PValue):
    datatype = Datatype.NULL

    def serialize(self, buf: bytearray) -> int:
        return self._write_header(buf)

    @classmethod
    def _deserialize(cls, data, offset, flags, disable_vlq):
        return cls(None, flags), 0


@_register(Datatype.BOOL)
class ValueBool(PValue):
    datatype = Datatype.BOOL

    def serialize(self, buf: bytearray) -> int:
        ret = self._write_header(buf)
        ret += s7p.encode_byte(buf, 1 if self.value else 0)
        return ret

    @classmethod
    def _deserialize(cls, data, offset, flags, disable_vlq):
        v, n = s7p.decode_byte(data, offset)
        return cls(bool(v), flags), n


@_register(Datatype.USINT)
class ValueUSInt(PValue):
    datatype = Datatype.USINT

    def serialize(self, buf: bytearray) -> int:
        ret = self._write_header(buf)
        ret += s7p.encode_byte(buf, self.value & 0xFF)
        return ret

    @classmethod
    def _deserialize(cls, data, offset, flags, disable_vlq):
        v, n = s7p.decode_byte(data, offset)
        return cls(v, flags), n


@_register(Datatype.UINT)
class ValueUInt(PValue):
    datatype = Datatype.UINT

    def serialize(self, buf: bytearray) -> int:
        ret = self._write_header(buf)
        ret += s7p.encode_uint16(buf, self.value)
        return ret

    @classmethod
    def _deserialize(cls, data, offset, flags, disable_vlq):
        v, n = s7p.decode_uint16(data, offset)
        return cls(v, flags), n


@_register(Datatype.UDINT)
class ValueUDInt(PValue):
    datatype = Datatype.UDINT

    def serialize(self, buf: bytearray) -> int:
        ret = self._write_header(buf)
        ret += s7p.encode_uint32_vlq(buf, self.value)
        return ret

    @classmethod
    def _deserialize(cls, data, offset, flags, disable_vlq):
        if disable_vlq:
            v, n = s7p.decode_uint32(data, offset)
        else:
            v, n = s7p.decode_uint32_vlq(data, offset)
        return cls(v, flags), n


@_register(Datatype.ULINT)
class ValueULInt(PValue):
    datatype = Datatype.ULINT

    def serialize(self, buf: bytearray) -> int:
        ret = self._write_header(buf)
        ret += s7p.encode_uint64_vlq(buf, self.value)
        return ret

    @classmethod
    def _deserialize(cls, data, offset, flags, disable_vlq):
        if disable_vlq:
            v, n = s7p.decode_uint64(data, offset)
        else:
            v, n = s7p.decode_uint64_vlq(data, offset)
        return cls(v, flags), n


@_register(Datatype.SINT)
class ValueSInt(PValue):
    datatype = Datatype.SINT

    def serialize(self, buf: bytearray) -> int:
        ret = self._write_header(buf)
        ret += s7p.encode_byte(buf, self.value & 0xFF)
        return ret

    @classmethod
    def _deserialize(cls, data, offset, flags, disable_vlq):
        v, n = s7p.decode_byte(data, offset)
        if v > 127:
            v -= 256
        return cls(v, flags), n


@_register(Datatype.INT)
class ValueInt(PValue):
    datatype = Datatype.INT

    def serialize(self, buf: bytearray) -> int:
        ret = self._write_header(buf)
        ret += s7p.encode_int16(buf, self.value)
        return ret

    @classmethod
    def _deserialize(cls, data, offset, flags, disable_vlq):
        v, n = s7p.decode_int16(data, offset)
        return cls(v, flags), n


@_register(Datatype.DINT)
class ValueDInt(PValue):
    datatype = Datatype.DINT

    def serialize(self, buf: bytearray) -> int:
        ret = self._write_header(buf)
        ret += s7p.encode_int32_vlq(buf, self.value)
        return ret

    @classmethod
    def _deserialize(cls, data, offset, flags, disable_vlq):
        if disable_vlq:
            v, n = s7p.decode_int32(data, offset)
        else:
            v, n = s7p.decode_int32_vlq(data, offset)
        return cls(v, flags), n


@_register(Datatype.LINT)
class ValueLInt(PValue):
    datatype = Datatype.LINT

    def serialize(self, buf: bytearray) -> int:
        ret = self._write_header(buf)
        ret += s7p.encode_int64_vlq(buf, self.value)
        return ret

    @classmethod
    def _deserialize(cls, data, offset, flags, disable_vlq):
        if disable_vlq:
            v, n = s7p.decode_int64(data, offset)
        else:
            v, n = s7p.decode_int64_vlq(data, offset)
        return cls(v, flags), n


# Byte/Word/DWord/LWord — same wire format as unsigned, different semantic

@_register(Datatype.BYTE)
class ValueByte(PValue):
    datatype = Datatype.BYTE

    def serialize(self, buf: bytearray) -> int:
        ret = self._write_header(buf)
        ret += s7p.encode_byte(buf, self.value & 0xFF)
        return ret

    @classmethod
    def _deserialize(cls, data, offset, flags, disable_vlq):
        v, n = s7p.decode_byte(data, offset)
        return cls(v, flags), n


@_register(Datatype.WORD)
class ValueWord(PValue):
    datatype = Datatype.WORD

    def serialize(self, buf: bytearray) -> int:
        ret = self._write_header(buf)
        ret += s7p.encode_uint16(buf, self.value)
        return ret

    @classmethod
    def _deserialize(cls, data, offset, flags, disable_vlq):
        v, n = s7p.decode_uint16(data, offset)
        return cls(v, flags), n


@_register(Datatype.DWORD)
class ValueDWord(PValue):
    datatype = Datatype.DWORD

    def serialize(self, buf: bytearray) -> int:
        ret = self._write_header(buf)
        ret += s7p.encode_uint32_vlq(buf, self.value)
        return ret

    @classmethod
    def _deserialize(cls, data, offset, flags, disable_vlq):
        if disable_vlq:
            v, n = s7p.decode_uint32(data, offset)
        else:
            v, n = s7p.decode_uint32_vlq(data, offset)
        return cls(v, flags), n


@_register(Datatype.LWORD)
class ValueLWord(PValue):
    datatype = Datatype.LWORD

    def serialize(self, buf: bytearray) -> int:
        ret = self._write_header(buf)
        ret += s7p.encode_uint64_vlq(buf, self.value)
        return ret

    @classmethod
    def _deserialize(cls, data, offset, flags, disable_vlq):
        if disable_vlq:
            v, n = s7p.decode_uint64(data, offset)
        else:
            v, n = s7p.decode_uint64_vlq(data, offset)
        return cls(v, flags), n


@_register(Datatype.REAL)
class ValueReal(PValue):
    datatype = Datatype.REAL

    def serialize(self, buf: bytearray) -> int:
        ret = self._write_header(buf)
        ret += s7p.encode_float(buf, self.value)
        return ret

    @classmethod
    def _deserialize(cls, data, offset, flags, disable_vlq):
        v, n = s7p.decode_float(data, offset)
        return cls(v, flags), n


@_register(Datatype.LREAL)
class ValueLReal(PValue):
    datatype = Datatype.LREAL

    def serialize(self, buf: bytearray) -> int:
        ret = self._write_header(buf)
        ret += s7p.encode_double(buf, self.value)
        return ret

    @classmethod
    def _deserialize(cls, data, offset, flags, disable_vlq):
        v, n = s7p.decode_double(data, offset)
        return cls(v, flags), n


@_register(Datatype.TIMESTAMP)
class ValueTimestamp(PValue):
    datatype = Datatype.TIMESTAMP

    def serialize(self, buf: bytearray) -> int:
        ret = self._write_header(buf)
        ret += s7p.encode_uint64(buf, self.value)
        return ret

    @classmethod
    def _deserialize(cls, data, offset, flags, disable_vlq):
        v, n = s7p.decode_uint64(data, offset)
        return cls(v, flags), n


@_register(Datatype.TIMESPAN)
class ValueTimespan(PValue):
    datatype = Datatype.TIMESPAN

    def serialize(self, buf: bytearray) -> int:
        ret = self._write_header(buf)
        ret += s7p.encode_int64_vlq(buf, self.value)
        return ret

    @classmethod
    def _deserialize(cls, data, offset, flags, disable_vlq):
        if disable_vlq:
            v, n = s7p.decode_int64(data, offset)
        else:
            v, n = s7p.decode_int64_vlq(data, offset)
        return cls(v, flags), n


@_register(Datatype.RID)
class ValueRID(PValue):
    datatype = Datatype.RID

    def serialize(self, buf: bytearray) -> int:
        ret = self._write_header(buf)
        ret += s7p.encode_uint32(buf, self.value)
        return ret

    @classmethod
    def _deserialize(cls, data, offset, flags, disable_vlq):
        v, n = s7p.decode_uint32(data, offset)
        return cls(v, flags), n


@_register(Datatype.AID)
class ValueAID(PValue):
    datatype = Datatype.AID

    def serialize(self, buf: bytearray) -> int:
        ret = self._write_header(buf)
        ret += s7p.encode_uint32_vlq(buf, self.value)
        return ret

    @classmethod
    def _deserialize(cls, data, offset, flags, disable_vlq):
        if disable_vlq:
            v, n = s7p.decode_uint32(data, offset)
        else:
            v, n = s7p.decode_uint32_vlq(data, offset)
        return cls(v, flags), n


@_register(Datatype.BLOB)
class ValueBlob(PValue):
    """Binary large object.

    ``value`` is a tuple of ``(blob_root_id, blob_data, has_blob_type, blob_type)``.
    For simple blobs, ``blob_root_id`` is 0 or 1.
    """
    datatype = Datatype.BLOB

    def __init__(self, value=None, flags=0):
        if value is None:
            value = (0, b"", False, 0)
        super().__init__(value, flags)

    @property
    def blob_root_id(self) -> int:
        return self.value[0]

    @property
    def blob_data(self) -> bytes:
        return self.value[1]

    def serialize(self, buf: bytearray) -> int:
        ret = self._write_header(buf)
        root_id, data, _, _ = self.value
        ret += s7p.encode_uint32_vlq(buf, root_id)
        ret += s7p.encode_uint32_vlq(buf, len(data))
        ret += s7p.encode_octets(buf, data)
        return ret

    @classmethod
    def _deserialize(cls, data, offset, flags, disable_vlq):
        start = offset
        if disable_vlq:
            root_id, n = s7p.decode_uint32(data, offset)
        else:
            root_id, n = s7p.decode_uint32_vlq(data, offset)
        offset += n

        has_blob_type = False
        blob_type = 0
        if root_id > 1:
            has_blob_type = True
            _, n = s7p.decode_uint64(data, offset); offset += n
            blob_type, n = s7p.decode_byte(data, offset); offset += n

        if disable_vlq:
            size, n = s7p.decode_uint32(data, offset)
        else:
            size, n = s7p.decode_uint32_vlq(data, offset)
        offset += n
        blob_data, n = s7p.decode_octets(data, offset, size)
        offset += n
        return cls((root_id, blob_data, has_blob_type, blob_type), flags), offset - start


@_register(Datatype.WSTRING)
class ValueWString(PValue):
    datatype = Datatype.WSTRING

    def serialize(self, buf: bytearray) -> int:
        ret = self._write_header(buf)
        encoded = self.value.encode("utf-8") if self.value else b""
        ret += s7p.encode_uint32_vlq(buf, len(encoded))
        ret += s7p.encode_octets(buf, encoded)
        return ret

    @classmethod
    def _deserialize(cls, data, offset, flags, disable_vlq):
        start = offset
        if disable_vlq:
            strlen, n = s7p.decode_uint32(data, offset)
        else:
            strlen, n = s7p.decode_uint32_vlq(data, offset)
        offset += n
        text, n = s7p.decode_wstring(data, offset, strlen)
        offset += n
        return cls(text, flags), offset - start


@_register(Datatype.VARIANT)
class ValueVariant(PValue):
    datatype = Datatype.VARIANT

    def serialize(self, buf: bytearray) -> int:
        return self._write_header(buf)

    @classmethod
    def _deserialize(cls, data, offset, flags, disable_vlq):
        return cls(None, flags), 0


# ===========================================================================
# Struct type (recursive)
# ===========================================================================

@_register(Datatype.STRUCT)
class ValueStruct(PValue):
    """Recursive struct — maps element IDs to PValue instances.

    For packed structs (system types with IDs in 0x9xxxxxxx or 0x02xxxxxx
    ranges), ``value`` is the struct type ID and ``elements`` holds a single
    ``ValueByteArray`` with the raw packed bytes.

    For regular structs, ``elements`` maps uint32 IDs → PValue (recursive).
    """
    datatype = Datatype.STRUCT

    def __init__(self, value=0, flags=0):
        super().__init__(value, flags)
        self.elements: dict[int, PValue] = {}
        self.packed_interface_timestamp: int = 0
        self.packed_transport_flags: int = 0x02  # AlwaysSet

    def add_element(self, element_id: int, element: PValue) -> None:
        self.elements[element_id] = element

    def get_element(self, element_id: int) -> PValue | None:
        return self.elements.get(element_id)

    @staticmethod
    def _is_packed(struct_id: int) -> bool:
        return ((0x90000000 < struct_id < 0x9FFFFFFF) or
                (0x02000000 < struct_id < 0x02FFFFFF))

    def serialize(self, buf: bytearray) -> int:
        ret = self._write_header(buf)
        ret += s7p.encode_uint32(buf, self.value)

        if self._is_packed(self.value):
            for elem in self.elements.values():
                ret += s7p.encode_uint64(buf, self.packed_interface_timestamp)
                ret += s7p.encode_uint32_vlq(buf, self.packed_transport_flags)
                if isinstance(elem, ValueByteArray):
                    arr = elem.value
                    ret += s7p.encode_uint32_vlq(buf, len(arr))
                    for b in arr:
                        ret += s7p.encode_byte(buf, b)
        else:
            for eid, elem in self.elements.items():
                ret += s7p.encode_uint32_vlq(buf, eid)
                ret += elem.serialize(buf)
            ret += s7p.encode_byte(buf, 0)  # list terminator
        return ret

    @classmethod
    def _deserialize(cls, data, offset, flags, disable_vlq):
        start = offset
        struct_id, n = s7p.decode_uint32(data, offset); offset += n

        stru = cls(struct_id, flags)

        if cls._is_packed(struct_id):
            ts, n = s7p.decode_uint64(data, offset); offset += n
            stru.packed_interface_timestamp = ts

            if disable_vlq:
                tf, n = s7p.decode_uint32(data, offset)
            else:
                tf, n = s7p.decode_uint32_vlq(data, offset)
            offset += n
            stru.packed_transport_flags = tf

            if disable_vlq:
                count, n = s7p.decode_uint32(data, offset)
            else:
                count, n = s7p.decode_uint32_vlq(data, offset)
            offset += n

            # Check Count2Present flag (bit 10)
            if tf & (1 << 10):
                if disable_vlq:
                    count, n = s7p.decode_uint32(data, offset)
                else:
                    count, n = s7p.decode_uint32_vlq(data, offset)
                offset += n

            arr = bytearray(count)
            for i in range(count):
                arr[i], n = s7p.decode_byte(data, offset); offset += n
            stru.add_element(struct_id, ValueByteArray(bytes(arr), flags=0))
        else:
            if disable_vlq:
                key, n = s7p.decode_uint32(data, offset)
            else:
                key, n = s7p.decode_uint32_vlq(data, offset)
            offset += n
            while key > 0:
                elem, n = PValue.deserialize(data, offset, disable_vlq)
                offset += n
                stru.add_element(key, elem)
                if disable_vlq:
                    key, n = s7p.decode_uint32(data, offset)
                else:
                    key, n = s7p.decode_uint32_vlq(data, offset)
                offset += n
        return stru, offset - start


# ===========================================================================
# Array types — generic implementation
# ===========================================================================

def _make_array_type(scalar_cls: type[PValue], dt: int):
    """Generate an array type for any scalar PValue class."""

    @_register(dt, "array")
    class _ArrayType(PValue):
        datatype = dt

        def serialize(self, buf: bytearray) -> int:
            ret = self._write_header(buf)
            arr = self.value or []
            ret += s7p.encode_uint32_vlq(buf, len(arr))
            for item in arr:
                tmp = scalar_cls(item, 0)
                # Write only the payload, not the header
                payload_buf = bytearray()
                tmp.serialize(payload_buf)
                # Skip the 2-byte header (flags + datatype)
                buf.extend(payload_buf[2:])
                ret += len(payload_buf) - 2
            return ret

        @classmethod
        def _deserialize(cls, data, offset, flags, disable_vlq):
            start = offset
            if disable_vlq:
                count, n = s7p.decode_uint32(data, offset)
            else:
                count, n = s7p.decode_uint32_vlq(data, offset)
            offset += n
            arr = []
            for _ in range(count):
                # Deserialize just the payload (no flags+datatype header)
                elem, n = scalar_cls._deserialize(data, offset, 0, disable_vlq)
                offset += n
                arr.append(elem.value)
            return cls(arr, flags), offset - start

    _ArrayType.__name__ = f"Value{scalar_cls.__name__[5:]}Array"
    _ArrayType.__qualname__ = _ArrayType.__name__
    return _ArrayType


# Register array types for all scalar types
ValueBoolArray = _make_array_type(ValueBool, Datatype.BOOL)
ValueUSIntArray = _make_array_type(ValueUSInt, Datatype.USINT)
ValueUIntArray = _make_array_type(ValueUInt, Datatype.UINT)
ValueUDIntArray = _make_array_type(ValueUDInt, Datatype.UDINT)
ValueULIntArray = _make_array_type(ValueULInt, Datatype.ULINT)
ValueSIntArray = _make_array_type(ValueSInt, Datatype.SINT)
ValueIntArray = _make_array_type(ValueInt, Datatype.INT)
ValueDIntArray = _make_array_type(ValueDInt, Datatype.DINT)
ValueLIntArray = _make_array_type(ValueLInt, Datatype.LINT)
ValueByteArray = _make_array_type(ValueByte, Datatype.BYTE)
ValueWordArray = _make_array_type(ValueWord, Datatype.WORD)
ValueDWordArray = _make_array_type(ValueDWord, Datatype.DWORD)
ValueLWordArray = _make_array_type(ValueLWord, Datatype.LWORD)
ValueRealArray = _make_array_type(ValueReal, Datatype.REAL)
ValueLRealArray = _make_array_type(ValueLReal, Datatype.LREAL)
ValueTimestampArray = _make_array_type(ValueTimestamp, Datatype.TIMESTAMP)
ValueTimespanArray = _make_array_type(ValueTimespan, Datatype.TIMESPAN)
ValueRIDArray = _make_array_type(ValueRID, Datatype.RID)
ValueAIDArray = _make_array_type(ValueAID, Datatype.AID)
ValueBlobArray = _make_array_type(ValueBlob, Datatype.BLOB)
ValueWStringArray = _make_array_type(ValueWString, Datatype.WSTRING)


# ===========================================================================
# Sparse array types
# ===========================================================================

def _make_sparse_type(scalar_cls: type[PValue], dt: int):
    """Generate a sparse array type (dict[uint32, value])."""

    @_register(dt, "sparse")
    class _SparseType(PValue):
        datatype = dt

        def serialize(self, buf: bytearray) -> int:
            ret = self._write_header(buf)
            d = self.value or {}
            for k, v in d.items():
                ret += s7p.encode_uint32_vlq(buf, k)
                tmp = scalar_cls(v, 0)
                payload = bytearray()
                tmp.serialize(payload)
                buf.extend(payload[2:])
                ret += len(payload) - 2
            ret += s7p.encode_byte(buf, 0)  # terminator
            return ret

        @classmethod
        def _deserialize(cls, data, offset, flags, disable_vlq):
            start = offset
            d: dict[int, Any] = {}
            if disable_vlq:
                k, n = s7p.decode_uint32(data, offset)
            else:
                k, n = s7p.decode_uint32_vlq(data, offset)
            offset += n
            while k > 0:
                elem, n = scalar_cls._deserialize(data, offset, 0, disable_vlq)
                offset += n
                d[k] = elem.value
                if disable_vlq:
                    k, n = s7p.decode_uint32(data, offset)
                else:
                    k, n = s7p.decode_uint32_vlq(data, offset)
                offset += n
            return cls(d, flags), offset - start

    _SparseType.__name__ = f"Value{scalar_cls.__name__[5:]}SparseArray"
    _SparseType.__qualname__ = _SparseType.__name__
    return _SparseType


ValueDIntSparseArray = _make_sparse_type(ValueDInt, Datatype.DINT)
ValueUDIntSparseArray = _make_sparse_type(ValueUDInt, Datatype.UDINT)
ValueBlobSparseArray = _make_sparse_type(ValueBlob, Datatype.BLOB)
ValueWStringSparseArray = _make_sparse_type(ValueWString, Datatype.WSTRING)
