"""PLC tag — type-aware read/write wrapper around ItemAddress and PValue.

Ported from PlcTag.cs (2,412 lines), PlcTags.cs (279 lines), PlcTagQC.cs (42 lines).
Python's dynamic typing collapses the 40+ C# subclasses into a compact data-driven design.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from s7commplus.protocol.constants import Softdatatype
from s7commplus.protocol.pobject import ItemAddress
from s7commplus.protocol.values import (
    PValue,
    ValueBool, ValueByte, ValueWord, ValueDWord, ValueLWord,
    ValueUSInt, ValueUInt, ValueUDInt, ValueULInt,
    ValueSInt, ValueInt, ValueDInt, ValueLInt,
    ValueReal, ValueLReal, ValueTimestamp, ValueTimespan,
    ValueStruct, ValueByteArray,
    ValueBoolArray, ValueUSIntArray, ValueUIntArray, ValueUDIntArray,
    ValueSIntArray, ValueIntArray, ValueDIntArray,
    ValueByteArray, ValueWordArray, ValueDWordArray,
    ValueRealArray,
)


# ---------------------------------------------------------------------------
# Quality codes (OPC DA based) — from PlcTagQC.cs
# ---------------------------------------------------------------------------

class Quality:
    """OPC DA quality-code constants for tag read results."""

    MASK = 0xC0
    STATUS_MASK = 0xFC
    LIMIT_MASK = 0x03

    BAD = 0x00
    UNCERTAIN = 0x40
    GOOD = 0xC0

    CONFIG_ERROR = 0x04
    NOT_CONNECTED = 0x08
    DEVICE_FAILURE = 0x0C
    SENSOR_FAILURE = 0x10
    LAST_KNOWN = 0x14
    COMM_FAILURE = 0x18
    OUT_OF_SERVICE = 0x1C
    WAITING_FOR_INITIAL_DATA = 0x20

    LOCAL_OVERRIDE = 0xD8


# ---------------------------------------------------------------------------
# BCD helpers
# ---------------------------------------------------------------------------

def _bcd_byte_to_int(value: int) -> int:
    """Convert a BCD-encoded byte to integer.

    Args:
        value: BCD byte (0x00–0x99).

    Returns:
        Decoded integer (0–99).
    """
    return 10 * (value // 16) + (value % 16)


def _int_to_bcd_byte(value: int) -> int:
    """Convert an integer (0–99) to BCD-encoded byte.

    Args:
        value: Integer to encode.

    Returns:
        BCD byte (``int``).
    """
    return (value // 10 * 16) + (value % 10)


def _bcd_ushort_to_ushort(value: int) -> int:
    """Convert a BCD-encoded 16-bit value to integer.

    Args:
        value: BCD uint16.

    Returns:
        Decoded integer (0–9999).
    """
    return ((value & 0x000F)
            + ((value & 0x00F0) >> 4) * 10
            + ((value & 0x0F00) >> 8) * 100
            + ((value & 0xF000) >> 12) * 1000)


def _ushort_to_bcd_ushort(value: int) -> int:
    """Convert an integer (0–9999) to BCD-encoded 16-bit value.

    Args:
        value: Integer to encode.

    Returns:
        BCD uint16 (``int``).
    """
    b = [0] * 4
    for i in range(4):
        b[i] = value % 10
        value //= 10
    return b[0] + (b[1] << 4) + (b[2] << 8) + (b[3] << 12)


# ---------------------------------------------------------------------------
# PlcTag — base class
# ---------------------------------------------------------------------------

class PlcTag:
    """Type-aware PLC tag with address, value, and quality.

    For most datatypes, ``process_read_result`` extracts ``pvalue.value``
    directly and ``get_write_value`` wraps ``self.value`` with the
    appropriate PValue constructor.
    """

    def __init__(
        self, name: str, address: ItemAddress, softdatatype: int,
        *, write_cls: type | None = None,
    ) -> None:
        """Initialize a PlcTag.

        Args:
            name: Human-readable tag name.
            address: Item address for PLC access.
            softdatatype: Softdatatype constant.
            write_cls: PValue subclass used to wrap values for writing.
        """
        self.name = name
        self.address = address
        self.softdatatype = softdatatype
        self.value: Any = None
        self.quality: int = Quality.WAITING_FOR_INITIAL_DATA
        self.last_read_error: int = 0
        self.last_write_error: int = 0
        self._write_cls = write_cls

    def process_read_result(self, pvalue: PValue, error: int) -> None:
        """Update this tag from a read response.

        Args:
            pvalue: Decoded PValue from the PLC.
            error: Error code (0 = success).
        """
        self.last_read_error = error
        if error != 0:
            self.quality = Quality.BAD
            return
        self.value = pvalue.value
        self.quality = Quality.GOOD

    def process_write_result(self, error: int) -> None:
        """Record the result of a write operation.

        Args:
            error: Error code (0 = success).
        """
        self.last_write_error = error

    def get_write_value(self) -> PValue:
        """Wrap the current value in the appropriate PValue for writing.

        Returns:
            PValue instance ready for serialization.

        Raises:
            TypeError: If no write class is configured.
        """
        if self._write_cls is None:
            raise TypeError(f"No write class configured for softdatatype {self.softdatatype}")
        return self._write_cls(self.value)

    def __repr__(self) -> str:
        """Return a debug-friendly string representation.

        Returns:
            String with name, softdatatype, and quality.
        """
        return f"PlcTag({self.name!r}, sdt={self.softdatatype}, q=0x{self.quality:02X})"


# ---------------------------------------------------------------------------
# Specialized PlcTag subclasses for types needing custom encoding
# ---------------------------------------------------------------------------

class PlcTagChar(PlcTag):
    """CHAR — single byte character, ISO-8859-1 encoded."""

    def __init__(self, name: str, address: ItemAddress, softdatatype: int) -> None:
        """Initialize a CHAR tag."""
        super().__init__(name, address, softdatatype)
        self.encoding = "iso-8859-1"
        self.value = "\x00"

    def process_read_result(self, pvalue: PValue, error: int) -> None:
        """Decode the PValue from a read response and update this tag.

        Args:
            pvalue: Wire-level value returned by the PLC.
            error: Per-item error code from the read response (0 = success).
        """
        self.last_read_error = error
        if error != 0:
            self.quality = Quality.BAD
            return
        self.value = bytes([pvalue.value]).decode(self.encoding)
        self.quality = Quality.GOOD

    def get_write_value(self) -> PValue:
        """Build the PValue to send in a write request.

        Returns:
            PValue with this tag\'s current value encoded for the wire.
        """
        return ValueUSInt(self.value.encode(self.encoding)[0])


class PlcTagWChar(PlcTag):
    """WCHAR — single 16-bit Unicode character."""

    def __init__(self, name: str, address: ItemAddress, softdatatype: int) -> None:
        """Initialize a WCHAR tag."""
        super().__init__(name, address, softdatatype)
        self.value = "\x00"

    def process_read_result(self, pvalue: PValue, error: int) -> None:
        """Decode the PValue from a read response and update this tag.

        Args:
            pvalue: Wire-level value returned by the PLC.
            error: Per-item error code from the read response (0 = success).
        """
        self.last_read_error = error
        if error != 0:
            self.quality = Quality.BAD
            return
        self.value = chr(pvalue.value)
        self.quality = Quality.GOOD

    def get_write_value(self) -> PValue:
        """Build the PValue to send in a write request.

        Returns:
            PValue with this tag\'s current value encoded for the wire.
        """
        return ValueUInt(ord(self.value))


class PlcTagString(PlcTag):
    """STRING — S7 string with max_length header, ISO-8859-1 encoded."""

    def __init__(self, name: str, address: ItemAddress, softdatatype: int,
                 max_length: int = 254) -> None:
        """Initialize a STRING tag."""
        super().__init__(name, address, softdatatype)
        self.max_length = max_length
        self.encoding = "iso-8859-1"
        self.value = ""

    def process_read_result(self, pvalue: PValue, error: int) -> None:
        """Decode the PValue from a read response and update this tag.

        Args:
            pvalue: Wire-level value returned by the PLC.
            error: Per-item error code from the read response (0 = success).
        """
        self.last_read_error = error
        if error != 0:
            self.quality = Quality.BAD
            return
        v = pvalue.value  # list of int (USIntArray)
        act_len = v[1]
        self.value = bytes(v[2:2 + act_len]).decode(self.encoding)
        self.quality = Quality.GOOD

    def get_write_value(self) -> PValue:
        """Build the PValue to send in a write request.

        Returns:
            PValue with this tag\'s current value encoded for the wire.
        """
        sb = self.value.encode(self.encoding)
        b = [0] * (self.max_length + 2)
        b[0] = self.max_length
        b[1] = len(sb)
        for i, byte_val in enumerate(sb):
            b[i + 2] = byte_val
        return ValueUSIntArray(b)


class PlcTagWString(PlcTag):
    """WSTRING — wide string with max_length header, UTF-16LE encoded."""

    def __init__(self, name: str, address: ItemAddress, softdatatype: int,
                 max_length: int = 254) -> None:
        """Initialize a WSTRING tag."""
        super().__init__(name, address, softdatatype)
        self.max_length = max_length
        self.value = ""

    def process_read_result(self, pvalue: PValue, error: int) -> None:
        """Decode the PValue from a read response and update this tag.

        Args:
            pvalue: Wire-level value returned by the PLC.
            error: Per-item error code from the read response (0 = success).
        """
        self.last_read_error = error
        if error != 0:
            self.quality = Quality.BAD
            return
        v = pvalue.value  # list of int (UIntArray)
        act_len = v[1]
        chars = v[2:2 + act_len]
        self.value = "".join(chr(c) for c in chars)
        self.quality = Quality.GOOD

    def get_write_value(self) -> PValue:
        """Build the PValue to send in a write request.

        Returns:
            PValue with this tag\'s current value encoded for the wire.
        """
        b = [0] * (len(self.value) + 2)
        b[0] = self.max_length
        b[1] = len(self.value)
        for i, ch in enumerate(self.value):
            b[i + 2] = ord(ch)
        return ValueUIntArray(b)


class PlcTagDate(PlcTag):
    """DATE — days since 1990-01-01 as UInt."""

    _EPOCH = datetime(1990, 1, 1)

    def __init__(self, name: str, address: ItemAddress, softdatatype: int) -> None:
        """Initialize a DATE tag."""
        super().__init__(name, address, softdatatype)
        self.value = self._EPOCH

    def process_read_result(self, pvalue: PValue, error: int) -> None:
        """Decode the PValue from a read response and update this tag.

        Args:
            pvalue: Wire-level value returned by the PLC.
            error: Per-item error code from the read response (0 = success).
        """
        self.last_read_error = error
        if error != 0:
            self.quality = Quality.BAD
            return
        self.value = self._EPOCH + timedelta(days=pvalue.value)
        self.quality = Quality.GOOD

    def get_write_value(self) -> PValue:
        """Build the PValue to send in a write request.

        Returns:
            PValue with this tag\'s current value encoded for the wire.
        """
        return ValueUInt((self.value - self._EPOCH).days)


class PlcTagTimeOfDay(PlcTag):
    """TIME_OF_DAY — milliseconds since midnight as UDInt."""

    def __init__(self, name: str, address: ItemAddress, softdatatype: int) -> None:
        """Initialize a TIME_OF_DAY tag."""
        super().__init__(name, address, softdatatype, write_cls=ValueUDInt)
        self.value = 0


class PlcTagTime(PlcTag):
    """TIME — milliseconds (signed) as DInt."""

    def __init__(self, name: str, address: ItemAddress, softdatatype: int) -> None:
        """Initialize a TIME tag."""
        super().__init__(name, address, softdatatype, write_cls=ValueDInt)
        self.value = 0


class PlcTagS5Time(PlcTag):
    """S5TIME — BCD-encoded time value with time base."""

    def __init__(self, name: str, address: ItemAddress, softdatatype: int) -> None:
        """Initialize an S5TIME tag."""
        super().__init__(name, address, softdatatype)
        self.time_value: int = 0
        self.time_base: int = 0
        self.value = 0  # raw Word value

    def process_read_result(self, pvalue: PValue, error: int) -> None:
        """Decode the PValue from a read response and update this tag.

        Args:
            pvalue: Wire-level value returned by the PLC.
            error: Per-item error code from the read response (0 = success).
        """
        self.last_read_error = error
        if error != 0:
            self.quality = Quality.BAD
            return
        v = pvalue.value
        self.time_value = _bcd_ushort_to_ushort(v & 0x0FFF)
        self.time_base = (v & 0x3000) >> 12
        self.value = v
        self.quality = Quality.GOOD

    def get_write_value(self) -> PValue:
        """Build the PValue to send in a write request.

        Returns:
            PValue with this tag\'s current value encoded for the wire.
        """
        v = _ushort_to_bcd_ushort(self.time_value)
        v |= (self.time_base & 0x3) << 12
        return ValueWord(v)

    @property
    def milliseconds(self) -> int:
        """Converted time value in milliseconds (``int``)."""
        multipliers = {0: 10, 1: 100, 2: 1000, 3: 10000}
        return self.time_value * multipliers.get(self.time_base, 0)


class PlcTagDateAndTime(PlcTag):
    """DATE_AND_TIME — 8-byte BCD-encoded datetime."""

    def __init__(self, name: str, address: ItemAddress, softdatatype: int) -> None:
        """Initialize a DATE_AND_TIME tag."""
        super().__init__(name, address, softdatatype)
        self.value = datetime(1990, 1, 1)

    def process_read_result(self, pvalue: PValue, error: int) -> None:
        """Decode the PValue from a read response and update this tag.

        Args:
            pvalue: Wire-level value returned by the PLC.
            error: Per-item error code from the read response (0 = success).
        """
        self.last_read_error = error
        if error != 0:
            self.quality = Quality.BAD
            return
        v = pvalue.value  # list of int (USIntArray)
        ts = [_bcd_byte_to_int(v[i]) for i in range(7)]
        ms_lsd = v[7] >> 4
        year = (1900 + ts[0]) if ts[0] >= 90 else (2000 + ts[0])
        self.value = datetime(year, ts[1], ts[2], ts[3], ts[4], ts[5])
        self.value += timedelta(milliseconds=ts[6] * 10 + ms_lsd)
        self.quality = Quality.GOOD

    def get_write_value(self) -> PValue:
        """Build the PValue to send in a write request.

        Returns:
            PValue with this tag\'s current value encoded for the wire.
        """
        dt = self.value
        year_2d = dt.year - 1900 if dt.year < 2000 else dt.year - 2000
        ts = [year_2d, dt.month, dt.day, dt.hour, dt.minute, dt.second,
              dt.microsecond // 10000]
        b = [_int_to_bcd_byte(x) for x in ts]
        b.append((dt.microsecond // 1000 % 10) << 4)
        return ValueUSIntArray(b)


class PlcTagLTime(PlcTag):
    """LTIME — nanoseconds as Timespan (int64)."""

    def __init__(self, name: str, address: ItemAddress, softdatatype: int) -> None:
        """Initialize an LTIME tag."""
        super().__init__(name, address, softdatatype, write_cls=ValueTimespan)
        self.value = 0


class PlcTagLTOD(PlcTag):
    """LTOD — nanoseconds since midnight as ULInt."""

    def __init__(self, name: str, address: ItemAddress, softdatatype: int) -> None:
        """Initialize an LTOD tag."""
        super().__init__(name, address, softdatatype, write_cls=ValueULInt)
        self.value = 0


class PlcTagLDT(PlcTag):
    """LDT — nanoseconds since epoch as Timestamp (uint64)."""

    def __init__(self, name: str, address: ItemAddress, softdatatype: int) -> None:
        """Initialize an LDT tag."""
        super().__init__(name, address, softdatatype, write_cls=ValueTimestamp)
        self.value = 0


class PlcTagDTL(PlcTag):
    """DTL — 12-byte struct (year, month, day, weekday, hour, min, sec, nanosec)."""

    DTL_TYPE_ID = 0x02000043

    def __init__(self, name: str, address: ItemAddress, softdatatype: int) -> None:
        """Initialize a DTL tag."""
        super().__init__(name, address, softdatatype)
        self.value = datetime(1970, 1, 1)
        self.nanosecond: int = 0
        self.interface_timestamp: int = 0x10FF4AD6DFD5774C

    def process_read_result(self, pvalue: PValue, error: int) -> None:
        """Decode the PValue from a read response and update this tag.

        Args:
            pvalue: Wire-level value returned by the PLC.
            error: Per-item error code from the read response (0 = success).
        """
        self.last_read_error = error
        if error != 0:
            self.quality = Quality.BAD
            return
        if not isinstance(pvalue, ValueStruct):
            self.quality = Quality.BAD
            return
        self.interface_timestamp = pvalue.packed_interface_timestamp
        elem = pvalue.get_element(self.DTL_TYPE_ID)
        if elem is None or not isinstance(elem, ValueByteArray):
            self.quality = Quality.BAD
            return
        barr = elem.value
        year = barr[0] * 256 + barr[1]
        self.nanosecond = (barr[8] * 16777216 + barr[9] * 65536
                           + barr[10] * 256 + barr[11])
        self.value = datetime(year, barr[2], barr[3], barr[5], barr[6], barr[7])
        self.quality = Quality.GOOD

    def get_write_value(self) -> PValue:
        """Build the PValue to send in a write request.

        Returns:
            PValue with this tag\'s current value encoded for the wire.
        """
        dt = self.value
        struct_val = ValueStruct(self.DTL_TYPE_ID)
        struct_val.packed_interface_timestamp = self.interface_timestamp
        barr = bytearray(12)
        barr[0] = dt.year >> 8
        barr[1] = dt.year & 0xFF
        barr[2] = dt.month
        barr[3] = dt.day
        barr[4] = 0  # weekday
        barr[5] = dt.hour
        barr[6] = dt.minute
        barr[7] = dt.second
        ns = self.nanosecond
        barr[8] = (ns >> 24) & 0xFF
        barr[9] = (ns >> 16) & 0xFF
        barr[10] = (ns >> 8) & 0xFF
        barr[11] = ns & 0xFF
        struct_val.add_element(self.DTL_TYPE_ID, ValueByteArray(bytes(barr), flags=0))
        return struct_val


class PlcTagRawBytes(PlcTag):
    """POINTER / ANY / REMOTE — raw byte array stored as USIntArray."""

    def __init__(self, name: str, address: ItemAddress, softdatatype: int,
                 size: int = 0) -> None:
        """Initialize a raw bytes tag."""
        super().__init__(name, address, softdatatype)
        self.value = [0] * size

    def process_read_result(self, pvalue: PValue, error: int) -> None:
        """Decode the PValue from a read response and update this tag.

        Args:
            pvalue: Wire-level value returned by the PLC.
            error: Per-item error code from the read response (0 = success).
        """
        self.last_read_error = error
        if error != 0:
            self.quality = Quality.BAD
            return
        self.value = list(pvalue.value)
        self.quality = Quality.GOOD

    def get_write_value(self) -> PValue:
        """Build the PValue to send in a write request.

        Returns:
            PValue with this tag\'s current value encoded for the wire.
        """
        return ValueUSIntArray(self.value)


# ---------------------------------------------------------------------------
# Tag factory — softdatatype → PlcTag
# ---------------------------------------------------------------------------

# Mapping: softdatatype → (write_pvalue_class, array_write_pvalue_class_or_None)
_SIMPLE_TAG_MAP: dict[int, tuple[type, type | None]] = {
    Softdatatype.BOOL:     (ValueBool,  ValueBoolArray),
    Softdatatype.BYTE:     (ValueByte,  ValueByteArray),
    Softdatatype.WORD:     (ValueWord,  ValueWordArray),
    Softdatatype.INT:      (ValueInt,   ValueIntArray),
    Softdatatype.DWORD:    (ValueDWord, ValueDWordArray),
    Softdatatype.DINT:     (ValueDInt,  ValueDIntArray),
    Softdatatype.REAL:     (ValueReal,  ValueRealArray),
    Softdatatype.BBOOL:    (ValueBool,  ValueBoolArray),
    Softdatatype.LREAL:    (ValueLReal, None),
    Softdatatype.ULINT:    (ValueULInt, None),
    Softdatatype.LINT:     (ValueLInt,  None),
    Softdatatype.LWORD:    (ValueLWord, None),
    Softdatatype.USINT:    (ValueUSInt, ValueUSIntArray),
    Softdatatype.UINT:     (ValueUInt,  ValueUIntArray),
    Softdatatype.UDINT:    (ValueUDInt, ValueUDIntArray),
    Softdatatype.SINT:     (ValueSInt,  ValueSIntArray),
    # Types that map to simple PValue types (no special encoding)
    Softdatatype.BLOCK_FB:      (ValueUInt, None),
    Softdatatype.BLOCK_FC:      (ValueUInt, None),
    Softdatatype.COUNTER:       (ValueUInt, None),
    Softdatatype.TIMER:         (ValueUInt, None),
    Softdatatype.AOM_IDENT:     (ValueDWord, None),
    Softdatatype.EVENT_ANY:     (ValueDWord, None),
    Softdatatype.EVENT_ATT:     (ValueDWord, None),
    Softdatatype.AOM_AID:       (ValueDWord, None),
    Softdatatype.AOM_LINK:      (ValueDWord, None),
    Softdatatype.EVENT_HWINT:   (ValueDWord, None),
    Softdatatype.CONN_R_ID:     (ValueDWord, None),
    Softdatatype.HW_ANY:        (ValueWord, None),
    Softdatatype.HW_IOSYSTEM:   (ValueWord, None),
    Softdatatype.HW_DPMASTER:   (ValueWord, None),
    Softdatatype.HW_DEVICE:     (ValueWord, None),
    Softdatatype.HW_DPSLAVE:    (ValueWord, None),
    Softdatatype.HW_IO:         (ValueWord, None),
    Softdatatype.HW_MODULE:     (ValueWord, None),
    Softdatatype.HW_SUBMODULE:  (ValueWord, None),
    Softdatatype.HW_HSC:        (ValueWord, None),
    Softdatatype.HW_PWM:        (ValueWord, None),
    Softdatatype.HW_PTO:        (ValueWord, None),
    Softdatatype.HW_INTERFACE:  (ValueWord, None),
    Softdatatype.HW_IEPORT:     (ValueWord, None),
    Softdatatype.OB_ANY:        (ValueInt, None),
    Softdatatype.OB_DELAY:      (ValueInt, None),
    Softdatatype.OB_TOD:        (ValueInt, None),
    Softdatatype.OB_CYCLIC:     (ValueInt, None),
    Softdatatype.OB_ATT:        (ValueInt, None),
    Softdatatype.CONN_ANY:      (ValueWord, None),
    Softdatatype.CONN_PRG:      (ValueWord, None),
    Softdatatype.CONN_OUC:      (ValueWord, None),
    Softdatatype.PORT:          (ValueUInt, None),
    Softdatatype.RTM:           (ValueUInt, None),
    Softdatatype.PIP:           (ValueUInt, None),
    Softdatatype.OB_PCYCLE:     (ValueInt, None),
    Softdatatype.OB_HWINT:      (ValueInt, None),
    Softdatatype.OB_DIAG:       (ValueInt, None),
    Softdatatype.OB_TIMEERROR:  (ValueInt, None),
    Softdatatype.OB_STARTUP:    (ValueInt, None),
    Softdatatype.DB_ANY:        (ValueUInt, None),
    Softdatatype.DB_WWW:        (ValueUInt, None),
    Softdatatype.DB_DYN:        (ValueUInt, None),
}


def tag_factory(
    name: str, address: ItemAddress, softdatatype: int,
    *, is_1dim: bool = False,
) -> PlcTag | None:
    """Create a PlcTag instance for the given softdatatype.

    Args:
        name: Human-readable tag name.
        address: Item address for PLC access.
        softdatatype: Softdatatype constant.
        is_1dim: If ``True``, use the array write class where available.

    Returns:
        A :class:`PlcTag` instance, or ``None`` for unknown datatypes.
    """
    # Special types with custom encoding
    if softdatatype == Softdatatype.CHAR:
        return PlcTagChar(name, address, softdatatype)
    if softdatatype == Softdatatype.WCHAR:
        return PlcTagWChar(name, address, softdatatype)
    if softdatatype == Softdatatype.STRING:
        return PlcTagString(name, address, softdatatype)
    if softdatatype == Softdatatype.WSTRING:
        return PlcTagWString(name, address, softdatatype)
    if softdatatype == Softdatatype.DATE:
        return PlcTagDate(name, address, softdatatype)
    if softdatatype == Softdatatype.TIME_OF_DAY:
        return PlcTagTimeOfDay(name, address, softdatatype)
    if softdatatype == Softdatatype.TIME:
        return PlcTagTime(name, address, softdatatype)
    if softdatatype == Softdatatype.S5TIME:
        return PlcTagS5Time(name, address, softdatatype)
    if softdatatype == Softdatatype.DATE_AND_TIME:
        return PlcTagDateAndTime(name, address, softdatatype)
    if softdatatype == Softdatatype.LTIME:
        return PlcTagLTime(name, address, softdatatype)
    if softdatatype == Softdatatype.LTOD:
        return PlcTagLTOD(name, address, softdatatype)
    if softdatatype == Softdatatype.LDT:
        return PlcTagLDT(name, address, softdatatype)
    if softdatatype == Softdatatype.DTL:
        return PlcTagDTL(name, address, softdatatype)
    if softdatatype in (Softdatatype.POINTER,):
        return PlcTagRawBytes(name, address, softdatatype, size=6)
    if softdatatype in (Softdatatype.ANY, Softdatatype.REMOTE):
        return PlcTagRawBytes(name, address, softdatatype, size=10)

    # Simple types — use data-driven mapping
    entry = _SIMPLE_TAG_MAP.get(softdatatype)
    if entry is None:
        return None

    scalar_cls, array_cls = entry
    if is_1dim and array_cls is not None:
        return PlcTag(name, address, softdatatype, write_cls=array_cls)
    return PlcTag(name, address, softdatatype, write_cls=scalar_cls)


# ---------------------------------------------------------------------------
# Batch read/write
# ---------------------------------------------------------------------------

def read_tags(connection, tags: list[PlcTag]) -> int:
    """Read a batch of tags via the connection.

    Calls ``connection.read_values()`` with the tags' addresses, then
    dispatches the results to each tag's ``process_read_result``.

    Args:
        connection: Active :class:`S7CommPlusConnection`.
        tags: List of :class:`PlcTag` to read.

    Returns:
        Error code (``int``): 0 on success.
    """
    addresses = [tag.address for tag in tags]
    values, errors, result = connection.read_values(addresses)
    if result != 0:
        return result
    for i, tag in enumerate(tags):
        tag.process_read_result(values[i], errors[i])
    return 0


def write_tags(connection, tags: list[PlcTag]) -> int:
    """Write a batch of tags via the connection.

    Calls ``connection.write_values()`` with the tags' addresses and values,
    then dispatches the results to each tag's ``process_write_result``.

    Args:
        connection: Active :class:`S7CommPlusConnection`.
        tags: List of :class:`PlcTag` to write.

    Returns:
        Error code (``int``): 0 on success.
    """
    addresses = [tag.address for tag in tags]
    pvalues = [tag.get_write_value() for tag in tags]
    errors, result = connection.write_values(addresses, pvalues)
    if result != 0:
        return result
    for i, tag in enumerate(tags):
        tag.process_write_result(errors[i])
    return 0
