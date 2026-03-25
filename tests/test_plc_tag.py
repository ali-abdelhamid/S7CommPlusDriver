"""Tests for Phase E — PlcTag, tag_factory, read_tags, write_tags."""

from __future__ import annotations

from datetime import datetime, timedelta
from unittest.mock import MagicMock

import pytest

from s7commplus.protocol.constants import Softdatatype
from s7commplus.protocol.pobject import ItemAddress
from s7commplus.protocol.values import (
    ValueBool, ValueByte, ValueWord, ValueDWord, ValueLWord,
    ValueUSInt, ValueUInt, ValueUDInt, ValueULInt,
    ValueSInt, ValueInt, ValueDInt, ValueLInt,
    ValueReal, ValueLReal, ValueTimestamp, ValueTimespan,
    ValueStruct, ValueByteArray,
    ValueBoolArray, ValueUSIntArray, ValueUIntArray, ValueUDIntArray,
    ValueSIntArray, ValueIntArray, ValueDIntArray, ValueRealArray,
)
from s7commplus.client_api.plc_tag import (
    Quality, PlcTag, PlcTagChar, PlcTagWChar, PlcTagString, PlcTagWString,
    PlcTagDate, PlcTagTimeOfDay, PlcTagTime, PlcTagS5Time,
    PlcTagDateAndTime, PlcTagLTime, PlcTagLTOD, PlcTagLDT, PlcTagDTL,
    PlcTagRawBytes,
    tag_factory, read_tags, write_tags,
    _bcd_byte_to_int, _int_to_bcd_byte,
    _bcd_ushort_to_ushort, _ushort_to_bcd_ushort,
)


# ===================================================================
# Quality constants
# ===================================================================

class TestQuality:
    def test_quality_values(self):
        assert Quality.BAD == 0x00
        assert Quality.UNCERTAIN == 0x40
        assert Quality.GOOD == 0xC0
        assert Quality.WAITING_FOR_INITIAL_DATA == 0x20

    def test_mask(self):
        assert Quality.MASK == 0xC0
        assert Quality.STATUS_MASK == 0xFC


# ===================================================================
# BCD helpers
# ===================================================================

class TestBCDHelpers:
    def test_bcd_byte_to_int(self):
        assert _bcd_byte_to_int(0x23) == 23
        assert _bcd_byte_to_int(0x99) == 99
        assert _bcd_byte_to_int(0x00) == 0

    def test_int_to_bcd_byte(self):
        assert _int_to_bcd_byte(23) == 0x23
        assert _int_to_bcd_byte(99) == 0x99
        assert _int_to_bcd_byte(0) == 0x00

    def test_bcd_roundtrip(self):
        for val in (0, 1, 12, 50, 99):
            assert _bcd_byte_to_int(_int_to_bcd_byte(val)) == val

    def test_bcd_ushort_to_ushort(self):
        assert _bcd_ushort_to_ushort(0x0999) == 999
        assert _bcd_ushort_to_ushort(0x0100) == 100
        assert _bcd_ushort_to_ushort(0x0000) == 0

    def test_ushort_to_bcd_ushort(self):
        assert _ushort_to_bcd_ushort(999) == 0x0999
        assert _ushort_to_bcd_ushort(100) == 0x0100

    def test_ushort_bcd_roundtrip(self):
        for val in (0, 1, 42, 100, 500, 999):
            assert _bcd_ushort_to_ushort(_ushort_to_bcd_ushort(val)) == val


# ===================================================================
# PlcTag — base class
# ===================================================================

class TestPlcTagBase:
    def test_initial_state(self):
        addr = ItemAddress()
        tag = PlcTag("test", addr, Softdatatype.INT, write_cls=ValueInt)
        assert tag.name == "test"
        assert tag.quality == Quality.WAITING_FOR_INITIAL_DATA
        assert tag.value is None
        assert tag.last_read_error == 0
        assert tag.last_write_error == 0

    def test_process_read_result_success(self):
        addr = ItemAddress()
        tag = PlcTag("x", addr, Softdatatype.INT, write_cls=ValueInt)
        tag.process_read_result(ValueInt(42), 0)
        assert tag.value == 42
        assert tag.quality == Quality.GOOD
        assert tag.last_read_error == 0

    def test_process_read_result_error(self):
        addr = ItemAddress()
        tag = PlcTag("x", addr, Softdatatype.INT, write_cls=ValueInt)
        tag.process_read_result(ValueInt(42), 1)
        assert tag.quality == Quality.BAD
        assert tag.value is None  # not updated

    def test_get_write_value(self):
        addr = ItemAddress()
        tag = PlcTag("x", addr, Softdatatype.INT, write_cls=ValueInt)
        tag.value = 100
        pv = tag.get_write_value()
        assert isinstance(pv, ValueInt)
        assert pv.value == 100

    def test_get_write_value_no_cls_raises(self):
        addr = ItemAddress()
        tag = PlcTag("x", addr, 999)
        with pytest.raises(TypeError):
            tag.get_write_value()

    def test_process_write_result(self):
        addr = ItemAddress()
        tag = PlcTag("x", addr, Softdatatype.INT, write_cls=ValueInt)
        tag.process_write_result(5)
        assert tag.last_write_error == 5

    def test_repr(self):
        addr = ItemAddress()
        tag = PlcTag("myTag", addr, 5)
        r = repr(tag)
        assert "myTag" in r
        assert "sdt=5" in r


# ===================================================================
# PlcTagChar
# ===================================================================

class TestPlcTagChar:
    def test_read(self):
        tag = PlcTagChar("c", ItemAddress(), Softdatatype.CHAR)
        tag.process_read_result(ValueUSInt(65), 0)
        assert tag.value == "A"
        assert tag.quality == Quality.GOOD

    def test_write(self):
        tag = PlcTagChar("c", ItemAddress(), Softdatatype.CHAR)
        tag.value = "B"
        pv = tag.get_write_value()
        assert isinstance(pv, ValueUSInt)
        assert pv.value == 66

    def test_read_error(self):
        tag = PlcTagChar("c", ItemAddress(), Softdatatype.CHAR)
        tag.process_read_result(ValueUSInt(0), 1)
        assert tag.quality == Quality.BAD


# ===================================================================
# PlcTagWChar
# ===================================================================

class TestPlcTagWChar:
    def test_read(self):
        tag = PlcTagWChar("wc", ItemAddress(), Softdatatype.WCHAR)
        tag.process_read_result(ValueUInt(0x00E9), 0)
        assert tag.value == "\u00E9"  # é

    def test_write(self):
        tag = PlcTagWChar("wc", ItemAddress(), Softdatatype.WCHAR)
        tag.value = "\u00E9"
        pv = tag.get_write_value()
        assert isinstance(pv, ValueUInt)
        assert pv.value == 0x00E9


# ===================================================================
# PlcTagString
# ===================================================================

class TestPlcTagString:
    def test_read(self):
        tag = PlcTagString("s", ItemAddress(), Softdatatype.STRING, max_length=10)
        # Simulate USIntArray: [max_len=10, act_len=5, 'H','e','l','l','o', 0,0,0,0,0]
        data = [10, 5] + list(b"Hello") + [0] * 5
        tag.process_read_result(ValueUSIntArray(data), 0)
        assert tag.value == "Hello"
        assert tag.quality == Quality.GOOD

    def test_write(self):
        tag = PlcTagString("s", ItemAddress(), Softdatatype.STRING, max_length=10)
        tag.value = "Hi"
        pv = tag.get_write_value()
        assert isinstance(pv, ValueUSIntArray)
        arr = pv.value
        assert arr[0] == 10  # max_length
        assert arr[1] == 2   # actual length
        assert arr[2] == ord("H")
        assert arr[3] == ord("i")

    def test_empty_string(self):
        tag = PlcTagString("s", ItemAddress(), Softdatatype.STRING, max_length=254)
        data = [254, 0] + [0] * 254
        tag.process_read_result(ValueUSIntArray(data), 0)
        assert tag.value == ""


# ===================================================================
# PlcTagWString
# ===================================================================

class TestPlcTagWString:
    def test_read(self):
        tag = PlcTagWString("ws", ItemAddress(), Softdatatype.WSTRING, max_length=10)
        # UIntArray: [max_len=10, act_len=3, ord('A'), ord('B'), ord('C')]
        data = [10, 3, ord("A"), ord("B"), ord("C")]
        tag.process_read_result(ValueUIntArray(data), 0)
        assert tag.value == "ABC"

    def test_write(self):
        tag = PlcTagWString("ws", ItemAddress(), Softdatatype.WSTRING, max_length=10)
        tag.value = "XY"
        pv = tag.get_write_value()
        assert isinstance(pv, ValueUIntArray)
        arr = pv.value
        assert arr[0] == 10  # max_length
        assert arr[1] == 2
        assert arr[2] == ord("X")
        assert arr[3] == ord("Y")


# ===================================================================
# PlcTagDate
# ===================================================================

class TestPlcTagDate:
    def test_read(self):
        tag = PlcTagDate("d", ItemAddress(), Softdatatype.DATE)
        # 365 days after 1990-01-01 = 1991-01-01
        tag.process_read_result(ValueUInt(365), 0)
        assert tag.value == datetime(1991, 1, 1)

    def test_write(self):
        tag = PlcTagDate("d", ItemAddress(), Softdatatype.DATE)
        tag.value = datetime(1990, 1, 2)
        pv = tag.get_write_value()
        assert isinstance(pv, ValueUInt)
        assert pv.value == 1

    def test_epoch(self):
        tag = PlcTagDate("d", ItemAddress(), Softdatatype.DATE)
        tag.process_read_result(ValueUInt(0), 0)
        assert tag.value == datetime(1990, 1, 1)


# ===================================================================
# PlcTagTimeOfDay
# ===================================================================

class TestPlcTagTimeOfDay:
    def test_read_write(self):
        tag = PlcTagTimeOfDay("tod", ItemAddress(), Softdatatype.TIME_OF_DAY)
        # 01:02:03 = 3723000ms
        tag.process_read_result(ValueUDInt(3723000), 0)
        assert tag.value == 3723000
        pv = tag.get_write_value()
        assert isinstance(pv, ValueUDInt)
        assert pv.value == 3723000


# ===================================================================
# PlcTagTime
# ===================================================================

class TestPlcTagTime:
    def test_read_write(self):
        tag = PlcTagTime("t", ItemAddress(), Softdatatype.TIME)
        tag.process_read_result(ValueDInt(-5000), 0)
        assert tag.value == -5000
        pv = tag.get_write_value()
        assert isinstance(pv, ValueDInt)
        assert pv.value == -5000


# ===================================================================
# PlcTagS5Time
# ===================================================================

class TestPlcTagS5Time:
    def test_read(self):
        tag = PlcTagS5Time("s5", ItemAddress(), Softdatatype.S5TIME)
        # 2457 = 0x0999: timebase=0, BCD value=999
        tag.process_read_result(ValueWord(0x0999), 0)
        assert tag.time_value == 999
        assert tag.time_base == 0
        assert tag.milliseconds == 9990  # 999 * 10

    def test_read_with_base(self):
        tag = PlcTagS5Time("s5", ItemAddress(), Softdatatype.S5TIME)
        # timebase=2 (1s), BCD value=100
        raw = _ushort_to_bcd_ushort(100) | (2 << 12)
        tag.process_read_result(ValueWord(raw), 0)
        assert tag.time_value == 100
        assert tag.time_base == 2
        assert tag.milliseconds == 100000

    def test_write_roundtrip(self):
        tag = PlcTagS5Time("s5", ItemAddress(), Softdatatype.S5TIME)
        tag.time_value = 42
        tag.time_base = 1
        pv = tag.get_write_value()
        assert isinstance(pv, ValueWord)
        # Read it back
        tag2 = PlcTagS5Time("s5", ItemAddress(), Softdatatype.S5TIME)
        tag2.process_read_result(pv, 0)
        assert tag2.time_value == 42
        assert tag2.time_base == 1


# ===================================================================
# PlcTagDateAndTime
# ===================================================================

class TestPlcTagDateAndTime:
    def test_read(self):
        tag = PlcTagDateAndTime("dt", ItemAddress(), Softdatatype.DATE_AND_TIME)
        # 2023-06-15 10:30:45.123
        bcd = [
            _int_to_bcd_byte(23),  # year (2023)
            _int_to_bcd_byte(6),   # month
            _int_to_bcd_byte(15),  # day
            _int_to_bcd_byte(10),  # hour
            _int_to_bcd_byte(30),  # minute
            _int_to_bcd_byte(45),  # second
            _int_to_bcd_byte(12),  # ms high digits (120ms → 12)
            0x30,                   # ms low digit (3) << 4 + weekday
        ]
        tag.process_read_result(ValueUSIntArray(bcd), 0)
        assert tag.value.year == 2023
        assert tag.value.month == 6
        assert tag.value.day == 15
        assert tag.value.hour == 10
        assert tag.value.minute == 30
        assert tag.value.second == 45
        assert tag.quality == Quality.GOOD

    def test_write(self):
        tag = PlcTagDateAndTime("dt", ItemAddress(), Softdatatype.DATE_AND_TIME)
        tag.value = datetime(2023, 1, 15, 8, 30, 0)
        pv = tag.get_write_value()
        assert isinstance(pv, ValueUSIntArray)
        arr = pv.value
        assert _bcd_byte_to_int(arr[0]) == 23
        assert _bcd_byte_to_int(arr[1]) == 1
        assert _bcd_byte_to_int(arr[2]) == 15

    def test_1990s_year(self):
        tag = PlcTagDateAndTime("dt", ItemAddress(), Softdatatype.DATE_AND_TIME)
        bcd = [
            _int_to_bcd_byte(95),  # 1995
            _int_to_bcd_byte(12),
            _int_to_bcd_byte(25),
            _int_to_bcd_byte(0),
            _int_to_bcd_byte(0),
            _int_to_bcd_byte(0),
            _int_to_bcd_byte(0),
            0x00,
        ]
        tag.process_read_result(ValueUSIntArray(bcd), 0)
        assert tag.value.year == 1995


# ===================================================================
# PlcTagLTime / LTOD / LDT
# ===================================================================

class TestPlcTagLTimeLTODLDT:
    def test_ltime(self):
        tag = PlcTagLTime("lt", ItemAddress(), Softdatatype.LTIME)
        tag.process_read_result(ValueTimespan(1000000000), 0)
        assert tag.value == 1000000000
        pv = tag.get_write_value()
        assert isinstance(pv, ValueTimespan)
        assert pv.value == 1000000000

    def test_ltod(self):
        tag = PlcTagLTOD("ltod", ItemAddress(), Softdatatype.LTOD)
        tag.process_read_result(ValueULInt(86399999999999), 0)
        assert tag.value == 86399999999999

    def test_ldt(self):
        tag = PlcTagLDT("ldt", ItemAddress(), Softdatatype.LDT)
        tag.process_read_result(ValueTimestamp(12345678), 0)
        assert tag.value == 12345678
        pv = tag.get_write_value()
        assert isinstance(pv, ValueTimestamp)


# ===================================================================
# PlcTagDTL
# ===================================================================

class TestPlcTagDTL:
    DTL_ID = 0x02000043

    def _make_dtl_struct(self, year=2023, month=6, day=15,
                         hour=10, minute=30, second=45, nanosecond=0):
        """Create a ValueStruct matching DTL format."""
        struct_val = ValueStruct(self.DTL_ID)
        struct_val.packed_interface_timestamp = 0x10FF4AD6DFD5774C
        barr = bytearray(12)
        barr[0] = year >> 8
        barr[1] = year & 0xFF
        barr[2] = month
        barr[3] = day
        barr[4] = 0  # weekday
        barr[5] = hour
        barr[6] = minute
        barr[7] = second
        barr[8] = (nanosecond >> 24) & 0xFF
        barr[9] = (nanosecond >> 16) & 0xFF
        barr[10] = (nanosecond >> 8) & 0xFF
        barr[11] = nanosecond & 0xFF
        struct_val.add_element(self.DTL_ID, ValueByteArray(bytes(barr), flags=0))
        return struct_val

    def test_read(self):
        tag = PlcTagDTL("dtl", ItemAddress(), Softdatatype.DTL)
        sv = self._make_dtl_struct(2023, 6, 15, 10, 30, 45, 123456789)
        tag.process_read_result(sv, 0)
        assert tag.value.year == 2023
        assert tag.value.month == 6
        assert tag.value.day == 15
        assert tag.value.hour == 10
        assert tag.value.minute == 30
        assert tag.value.second == 45
        assert tag.nanosecond == 123456789
        assert tag.quality == Quality.GOOD

    def test_write_roundtrip(self):
        tag = PlcTagDTL("dtl", ItemAddress(), Softdatatype.DTL)
        tag.value = datetime(2024, 3, 25, 14, 0, 0)
        tag.nanosecond = 500000000
        pv = tag.get_write_value()
        assert isinstance(pv, ValueStruct)

        # Read it back
        tag2 = PlcTagDTL("dtl2", ItemAddress(), Softdatatype.DTL)
        tag2.process_read_result(pv, 0)
        assert tag2.value.year == 2024
        assert tag2.value.month == 3
        assert tag2.nanosecond == 500000000

    def test_read_bad_type(self):
        tag = PlcTagDTL("dtl", ItemAddress(), Softdatatype.DTL)
        tag.process_read_result(ValueInt(0), 0)
        assert tag.quality == Quality.BAD

    def test_read_missing_element(self):
        tag = PlcTagDTL("dtl", ItemAddress(), Softdatatype.DTL)
        sv = ValueStruct(self.DTL_ID)
        sv.packed_interface_timestamp = 0
        # No element added
        tag.process_read_result(sv, 0)
        assert tag.quality == Quality.BAD


# ===================================================================
# PlcTagRawBytes
# ===================================================================

class TestPlcTagRawBytes:
    def test_pointer(self):
        tag = PlcTagRawBytes("p", ItemAddress(), Softdatatype.POINTER, size=6)
        data = [0, 1, 0x84, 0, 0, 0x10]
        tag.process_read_result(ValueUSIntArray(data), 0)
        assert tag.value == data
        pv = tag.get_write_value()
        assert isinstance(pv, ValueUSIntArray)

    def test_any(self):
        tag = PlcTagRawBytes("a", ItemAddress(), Softdatatype.ANY, size=10)
        assert len(tag.value) == 10


# ===================================================================
# tag_factory
# ===================================================================

class TestTagFactory:
    def test_simple_bool(self):
        tag = tag_factory("b", ItemAddress(), Softdatatype.BOOL)
        assert tag is not None
        assert tag._write_cls is ValueBool

    def test_bool_array(self):
        tag = tag_factory("ba", ItemAddress(), Softdatatype.BOOL, is_1dim=True)
        assert tag is not None
        assert tag._write_cls is ValueBoolArray

    def test_int(self):
        tag = tag_factory("i", ItemAddress(), Softdatatype.INT)
        assert tag is not None
        assert tag._write_cls is ValueInt

    def test_int_array(self):
        tag = tag_factory("ia", ItemAddress(), Softdatatype.INT, is_1dim=True)
        assert tag._write_cls is ValueIntArray

    def test_real(self):
        tag = tag_factory("r", ItemAddress(), Softdatatype.REAL)
        assert tag._write_cls is ValueReal

    def test_real_array(self):
        tag = tag_factory("ra", ItemAddress(), Softdatatype.REAL, is_1dim=True)
        assert tag._write_cls is ValueRealArray

    def test_lreal(self):
        tag = tag_factory("lr", ItemAddress(), Softdatatype.LREAL)
        assert tag._write_cls is ValueLReal

    def test_lreal_no_array(self):
        # LREAL has no array variant in factory
        tag = tag_factory("lr", ItemAddress(), Softdatatype.LREAL, is_1dim=True)
        assert tag._write_cls is ValueLReal  # falls back to scalar

    def test_char(self):
        tag = tag_factory("c", ItemAddress(), Softdatatype.CHAR)
        assert isinstance(tag, PlcTagChar)

    def test_wchar(self):
        tag = tag_factory("wc", ItemAddress(), Softdatatype.WCHAR)
        assert isinstance(tag, PlcTagWChar)

    def test_string(self):
        tag = tag_factory("s", ItemAddress(), Softdatatype.STRING)
        assert isinstance(tag, PlcTagString)

    def test_wstring(self):
        tag = tag_factory("ws", ItemAddress(), Softdatatype.WSTRING)
        assert isinstance(tag, PlcTagWString)

    def test_date(self):
        tag = tag_factory("d", ItemAddress(), Softdatatype.DATE)
        assert isinstance(tag, PlcTagDate)

    def test_time_of_day(self):
        tag = tag_factory("tod", ItemAddress(), Softdatatype.TIME_OF_DAY)
        assert isinstance(tag, PlcTagTimeOfDay)

    def test_time(self):
        tag = tag_factory("t", ItemAddress(), Softdatatype.TIME)
        assert isinstance(tag, PlcTagTime)

    def test_s5time(self):
        tag = tag_factory("s5", ItemAddress(), Softdatatype.S5TIME)
        assert isinstance(tag, PlcTagS5Time)

    def test_date_and_time(self):
        tag = tag_factory("dt", ItemAddress(), Softdatatype.DATE_AND_TIME)
        assert isinstance(tag, PlcTagDateAndTime)

    def test_dtl(self):
        tag = tag_factory("dtl", ItemAddress(), Softdatatype.DTL)
        assert isinstance(tag, PlcTagDTL)

    def test_ltime(self):
        tag = tag_factory("lt", ItemAddress(), Softdatatype.LTIME)
        assert isinstance(tag, PlcTagLTime)

    def test_ltod(self):
        tag = tag_factory("ltod", ItemAddress(), Softdatatype.LTOD)
        assert isinstance(tag, PlcTagLTOD)

    def test_ldt(self):
        tag = tag_factory("ldt", ItemAddress(), Softdatatype.LDT)
        assert isinstance(tag, PlcTagLDT)

    def test_pointer(self):
        tag = tag_factory("p", ItemAddress(), Softdatatype.POINTER)
        assert isinstance(tag, PlcTagRawBytes)
        assert len(tag.value) == 6

    def test_any(self):
        tag = tag_factory("a", ItemAddress(), Softdatatype.ANY)
        assert isinstance(tag, PlcTagRawBytes)
        assert len(tag.value) == 10

    def test_remote(self):
        tag = tag_factory("r", ItemAddress(), Softdatatype.REMOTE)
        assert isinstance(tag, PlcTagRawBytes)

    def test_block_fb(self):
        tag = tag_factory("fb", ItemAddress(), Softdatatype.BLOCK_FB)
        assert tag._write_cls is ValueUInt

    def test_hw_any(self):
        tag = tag_factory("hw", ItemAddress(), Softdatatype.HW_ANY)
        assert tag._write_cls is ValueWord

    def test_ob_any(self):
        tag = tag_factory("ob", ItemAddress(), Softdatatype.OB_ANY)
        assert tag._write_cls is ValueInt

    def test_conn_r_id(self):
        tag = tag_factory("cr", ItemAddress(), Softdatatype.CONN_R_ID)
        assert tag._write_cls is ValueDWord

    def test_db_any(self):
        tag = tag_factory("db", ItemAddress(), Softdatatype.DB_ANY)
        assert tag._write_cls is ValueUInt

    def test_unknown_returns_none(self):
        tag = tag_factory("unk", ItemAddress(), 999)
        assert tag is None

    def test_bbool(self):
        tag = tag_factory("bb", ItemAddress(), Softdatatype.BBOOL)
        assert tag._write_cls is ValueBool

    def test_bbool_array(self):
        tag = tag_factory("bba", ItemAddress(), Softdatatype.BBOOL, is_1dim=True)
        assert tag._write_cls is ValueBoolArray

    def test_usint_array(self):
        tag = tag_factory("ua", ItemAddress(), Softdatatype.USINT, is_1dim=True)
        assert tag._write_cls is ValueUSIntArray

    def test_udint_array(self):
        tag = tag_factory("uda", ItemAddress(), Softdatatype.UDINT, is_1dim=True)
        assert tag._write_cls is ValueUDIntArray

    def test_sint_array(self):
        tag = tag_factory("sa", ItemAddress(), Softdatatype.SINT, is_1dim=True)
        assert tag._write_cls is ValueSIntArray


# ===================================================================
# read_tags / write_tags
# ===================================================================

class TestReadWriteTags:
    def test_read_tags_success(self):
        conn = MagicMock()
        conn.read_values.return_value = (
            [ValueInt(10), ValueReal(3.14)],
            [0, 0],
            0,
        )

        t1 = PlcTag("a", ItemAddress(), Softdatatype.INT, write_cls=ValueInt)
        t2 = PlcTag("b", ItemAddress(), Softdatatype.REAL, write_cls=ValueReal)

        result = read_tags(conn, [t1, t2])
        assert result == 0
        assert t1.value == 10
        assert t2.value == pytest.approx(3.14)
        assert t1.quality == Quality.GOOD
        assert t2.quality == Quality.GOOD

    def test_read_tags_connection_error(self):
        conn = MagicMock()
        conn.read_values.return_value = ([], [], -1)

        t1 = PlcTag("a", ItemAddress(), Softdatatype.INT, write_cls=ValueInt)
        result = read_tags(conn, [t1])
        assert result == -1
        assert t1.quality == Quality.WAITING_FOR_INITIAL_DATA  # unchanged

    def test_read_tags_per_tag_error(self):
        conn = MagicMock()
        conn.read_values.return_value = (
            [ValueInt(0), ValueInt(0)],
            [0, 99],
            0,
        )

        t1 = PlcTag("a", ItemAddress(), Softdatatype.INT, write_cls=ValueInt)
        t2 = PlcTag("b", ItemAddress(), Softdatatype.INT, write_cls=ValueInt)

        read_tags(conn, [t1, t2])
        assert t1.quality == Quality.GOOD
        assert t2.quality == Quality.BAD
        assert t2.last_read_error == 99

    def test_write_tags_success(self):
        conn = MagicMock()
        conn.write_values.return_value = ([0, 0], 0)

        t1 = PlcTag("a", ItemAddress(), Softdatatype.INT, write_cls=ValueInt)
        t1.value = 42
        t2 = PlcTag("b", ItemAddress(), Softdatatype.REAL, write_cls=ValueReal)
        t2.value = 1.5

        result = write_tags(conn, [t1, t2])
        assert result == 0
        assert t1.last_write_error == 0
        assert t2.last_write_error == 0

        # Verify connection was called with correct PValues
        args = conn.write_values.call_args
        addresses, values = args[0]
        assert isinstance(values[0], ValueInt)
        assert values[0].value == 42
        assert isinstance(values[1], ValueReal)

    def test_write_tags_connection_error(self):
        conn = MagicMock()
        conn.write_values.return_value = ([], -1)

        t1 = PlcTag("a", ItemAddress(), Softdatatype.INT, write_cls=ValueInt)
        t1.value = 0
        result = write_tags(conn, [t1])
        assert result == -1


# ===================================================================
# End-to-end: tag_factory → read → write roundtrip
# ===================================================================

class TestEndToEndRoundtrip:
    def test_int_roundtrip(self):
        tag = tag_factory("x", ItemAddress(), Softdatatype.INT)
        tag.process_read_result(ValueInt(-100), 0)
        assert tag.value == -100
        pv = tag.get_write_value()
        assert isinstance(pv, ValueInt)
        assert pv.value == -100

    def test_dint_roundtrip(self):
        tag = tag_factory("x", ItemAddress(), Softdatatype.DINT)
        tag.process_read_result(ValueDInt(2147483647), 0)
        pv = tag.get_write_value()
        assert pv.value == 2147483647

    def test_real_roundtrip(self):
        tag = tag_factory("x", ItemAddress(), Softdatatype.REAL)
        tag.process_read_result(ValueReal(3.14), 0)
        pv = tag.get_write_value()
        assert pv.value == pytest.approx(3.14)

    def test_bool_roundtrip(self):
        tag = tag_factory("x", ItemAddress(), Softdatatype.BOOL)
        tag.process_read_result(ValueBool(True), 0)
        assert tag.value is True
        pv = tag.get_write_value()
        assert pv.value is True

    def test_string_roundtrip(self):
        tag = tag_factory("x", ItemAddress(), Softdatatype.STRING)
        assert isinstance(tag, PlcTagString)
        data = [254, 5] + list(b"Hello") + [0] * 249
        tag.process_read_result(ValueUSIntArray(data), 0)
        assert tag.value == "Hello"
        pv = tag.get_write_value()
        assert isinstance(pv, ValueUSIntArray)
        assert pv.value[1] == 5

    def test_date_roundtrip(self):
        tag = tag_factory("x", ItemAddress(), Softdatatype.DATE)
        assert isinstance(tag, PlcTagDate)
        tag.process_read_result(ValueUInt(100), 0)
        dt = tag.value
        tag2 = tag_factory("y", ItemAddress(), Softdatatype.DATE)
        tag2.value = dt
        pv = tag2.get_write_value()
        assert pv.value == 100

    def test_byte_array_roundtrip(self):
        tag = tag_factory("x", ItemAddress(), Softdatatype.BYTE, is_1dim=True)
        tag.process_read_result(ValueByteArray(bytes([1, 2, 3])), 0)
        assert tag.value == bytes([1, 2, 3])
        pv = tag.get_write_value()
        assert isinstance(pv, ValueByteArray)
