"""
Unit tests for s7commplus.protocol — constants, errors, and utils.
"""

import pytest
from datetime import datetime, timezone

from s7commplus.protocol.constants import (
    ProtocolVersion, Opcode, FunctionCode, Datatype,
    ElementID, Ids, Softdatatype, SOFTDATATYPE_NAMES,
)
from s7commplus.protocol.errors import (
    S7CommPlusError, TCPError, ISOError, ClientError, OpenSSLError,
    error_text, check_error,
    ERR_TCP_CONNECTION_FAILED, ERR_ISO_CONNECT, ERR_CLI_JOB_TIMEOUT,
    ERR_OPENSSL,
)
from s7commplus.protocol.utils import (
    hex_dump, dt_from_value_timestamp,
    get_uint8, get_uint16, get_uint32, get_int16, get_int32,
    get_float, get_double, get_utf_string,
    get_uint16_le, get_uint32_le,
)


# ===================================================================
# Constants
# ===================================================================

class TestConstants:

    def test_protocol_versions(self):
        assert ProtocolVersion.V1 == 0x01
        assert ProtocolVersion.V2 == 0x02
        assert ProtocolVersion.V3 == 0x03

    def test_opcodes(self):
        assert Opcode.REQUEST == 0x31
        assert Opcode.RESPONSE == 0x32
        assert Opcode.NOTIFICATION == 0x33

    def test_function_codes(self):
        assert FunctionCode.EXPLORE == 0x04BB
        assert FunctionCode.SET_VARIABLE == 0x04F2
        assert FunctionCode.INIT_SSL == 0x05B3

    def test_datatypes(self):
        assert Datatype.BOOL == 0x01
        assert Datatype.UINT == 0x03
        assert Datatype.WSTRING == 0x15
        assert Datatype.STRUCT == 0x17

    def test_element_ids(self):
        assert ElementID.START_OF_OBJECT == 0xA1
        assert ElementID.TERMINATING_OBJECT == 0xA2
        assert ElementID.ATTRIBUTE == 0xA3

    def test_softdatatype_enum(self):
        assert Softdatatype.BOOL == 1
        assert Softdatatype.INT == 5
        assert Softdatatype.REAL == 8
        assert Softdatatype.LREAL == 48

    def test_softdatatype_names(self):
        assert SOFTDATATYPE_NAMES[1] == "BOOL"
        assert SOFTDATATYPE_NAMES[5] == "INT"
        assert SOFTDATATYPE_NAMES[62] == "WSTRING"


# ===================================================================
# Errors
# ===================================================================

class TestErrors:

    def test_error_text_known(self):
        assert "Connection Error" in error_text(ERR_TCP_CONNECTION_FAILED)
        assert "Connection Error" in error_text(ERR_ISO_CONNECT)

    def test_error_text_unknown(self):
        text = error_text(0xDEAD)
        assert "Unknown error" in text
        assert "0x0000dead" in text

    def test_error_text_ok(self):
        assert error_text(0) == "OK"

    def test_check_error_zero(self):
        check_error(0)  # should not raise

    def test_check_error_tcp(self):
        with pytest.raises(TCPError):
            check_error(ERR_TCP_CONNECTION_FAILED)

    def test_check_error_iso(self):
        with pytest.raises(ISOError):
            check_error(ERR_ISO_CONNECT)

    def test_check_error_client(self):
        with pytest.raises(ClientError):
            check_error(ERR_CLI_JOB_TIMEOUT)

    def test_check_error_openssl(self):
        with pytest.raises(OpenSSLError):
            check_error(ERR_OPENSSL)

    def test_exception_hierarchy(self):
        assert issubclass(TCPError, S7CommPlusError)
        assert issubclass(ISOError, S7CommPlusError)
        assert issubclass(ClientError, S7CommPlusError)
        assert issubclass(OpenSSLError, S7CommPlusError)

    def test_exception_attributes(self):
        try:
            check_error(ERR_TCP_CONNECTION_FAILED)
        except S7CommPlusError as e:
            assert e.code == ERR_TCP_CONNECTION_FAILED
            assert "Connection" in e.message


# ===================================================================
# Utils
# ===================================================================

class TestUtils:

    def test_hex_dump_empty(self):
        assert hex_dump(b"") == "<empty>"

    def test_hex_dump_basic(self):
        result = hex_dump(b"\x41\x42\x43")
        assert "41 42 43" in result
        assert "ABC" in result

    def test_hex_dump_non_printable(self):
        result = hex_dump(b"\x00\x01\x02")
        assert "00 01 02" in result
        assert "..." in result

    def test_dt_from_value_timestamp(self):
        # 1 billion nanoseconds = 1 second after epoch
        dt = dt_from_value_timestamp(1_000_000_000)
        assert dt.year == 1970
        assert dt.month == 1
        assert dt.day == 1
        assert dt.second == 1
        assert dt.tzinfo == timezone.utc

    def test_get_uint8(self):
        assert get_uint8(b"\xFF\x42", 1) == 0x42

    def test_get_uint16(self):
        assert get_uint16(b"\x01\x02", 0) == 0x0102

    def test_get_uint16_le(self):
        assert get_uint16_le(b"\x02\x01", 0) == 0x0102

    def test_get_uint32(self):
        assert get_uint32(b"\x01\x02\x03\x04", 0) == 0x01020304

    def test_get_uint32_le(self):
        assert get_uint32_le(b"\x04\x03\x02\x01", 0) == 0x01020304

    def test_get_int16(self):
        assert get_int16(b"\xFF\xFF", 0) == -1

    def test_get_int32(self):
        assert get_int32(b"\xFF\xFF\xFF\xFF", 0) == -1

    def test_get_float(self):
        import struct
        data = struct.pack(">f", 3.14)
        result = get_float(data, 0)
        assert abs(result - 3.14) < 1e-5

    def test_get_double(self):
        import struct
        data = struct.pack(">d", 3.141592653589793)
        result = get_double(data, 0)
        assert abs(result - 3.141592653589793) < 1e-12

    def test_get_utf_string(self):
        data = b"Hello, World!"
        assert get_utf_string(data, 0, 5) == "Hello"
        assert get_utf_string(data, 7, 5) == "World"
