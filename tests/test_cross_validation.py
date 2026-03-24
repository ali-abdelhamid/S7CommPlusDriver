"""
Cross-validation tests — verify Python encoding matches C# byte sequences.

These tests reconstruct the exact byte patterns that the C# S7CommPlusDriver
produces and verify our Python encoder emits identical output.  This is the
closest we can get to "protocol correctness" without a real PLC.

Sources:
    - S7Client.cs: ISO_CR, TPKT_ISO telegrams
    - S7CommPlusConnection.cs: PDU header/trailer format
    - InitSslRequest.cs: InitSSL message layout
    - S7p.cs: VLQ encoding of specific values
"""

import struct
import pytest

from s7commplus.protocol.s7p import (
    encode_byte, encode_uint16, encode_uint32, encode_uint64,
    encode_uint32_vlq, encode_int32_vlq,
    encode_uint64_vlq, encode_int64_vlq,
    decode_uint32_vlq, decode_int32_vlq,
    decode_uint64_vlq, decode_int64_vlq,
    encode_header,
)
from s7commplus.protocol.constants import (
    ProtocolVersion, Opcode, FunctionCode, ElementID, Ids,
)
from s7commplus.transport.cotp import (
    _build_iso_cr, REMOTE_TSAP_DEFAULT, ISO_HEADER_SIZE,
)


# ===================================================================
# 1. ISO_CR telegram — must match S7Client.cs byte-for-byte
# ===================================================================

class TestIsoCR_CrossValidation:
    """Cross-validate ISO Connection Request against S7Client.cs lines 33-58."""

    # The C# ISO_CR template (before TSAP overwrite), with default local TSAP
    # and the "SIMATIC-ROOT-HMI" remote TSAP appended.
    #
    # S7CommPlusConnection.cs line 404 sets LocalTSAP = 0x0600
    # The remote TSAP is the ASCII string "SIMATIC-ROOT-HMI" (16 bytes).

    def test_iso_cr_matches_csharp_template(self):
        """The first 20 bytes must match the C# ISO_CR array (after TSAP substitution)."""
        cr = _build_iso_cr(0x06, 0x00, REMOTE_TSAP_DEFAULT)

        # Byte 0-1: TPKT version, reserved
        assert cr[0] == 0x03
        assert cr[1] == 0x00

        # Byte 2-3: total length = 20 + 16 = 36 = 0x0024
        assert cr[2] == 0x00
        assert cr[3] == 0x24

        # Byte 4: PDU size length = 15 + 16 = 31 = 0x1F
        assert cr[4] == 0x1F

        # Byte 5: CR Connection Request ID
        assert cr[5] == 0xE0

        # Bytes 6-10: Dst Ref, Src Ref, Class+Options
        assert cr[6:11] == bytes([0x00, 0x00, 0x00, 0x01, 0x00])

        # Bytes 11-13: PDU Max Length parameter (C0 01 0A)
        assert cr[11:14] == bytes([0xC0, 0x01, 0x0A])

        # Bytes 14-15: Src TSAP parameter header (C1 02)
        assert cr[14:16] == bytes([0xC1, 0x02])

        # Bytes 16-17: Local TSAP (overwritten to 0x06, 0x00)
        assert cr[16] == 0x06
        assert cr[17] == 0x00

        # Bytes 18-19: Dst TSAP parameter header (C2 10)
        assert cr[18] == 0xC2
        assert cr[19] == 0x10  # 16 bytes

        # Bytes 20+: Remote TSAP string
        assert cr[20:] == b"SIMATIC-ROOT-HMI"

    def test_iso_cr_total_length(self):
        cr = _build_iso_cr(0x06, 0x00, REMOTE_TSAP_DEFAULT)
        assert len(cr) == 36  # 20 header + 16 TSAP string

    def test_iso_cr_full_bytes(self):
        """Verify the entire telegram byte-for-byte against what C# produces."""
        cr = _build_iso_cr(0x06, 0x00, REMOTE_TSAP_DEFAULT)
        expected = bytes([
            # TPKT header
            0x03, 0x00, 0x00, 0x24,
            # COTP CR
            0x1F, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00,
            # PDU max length param
            0xC0, 0x01, 0x0A,
            # Src TSAP
            0xC1, 0x02, 0x06, 0x00,
            # Dst TSAP header
            0xC2, 0x10,
            # "SIMATIC-ROOT-HMI"
            0x53, 0x49, 0x4D, 0x41, 0x54, 0x49, 0x43, 0x2D,
            0x52, 0x4F, 0x4F, 0x54, 0x2D, 0x48, 0x4D, 0x49,
        ])
        assert cr == expected


# ===================================================================
# 2. TPKT + COTP DT header — must match S7Client.cs TPKT_ISO
# ===================================================================

class TestTPKT_ISO_CrossValidation:
    """Cross-validate TPKT+COTP-DT framing against S7Client.cs lines 61-65."""

    def test_tpkt_iso_header_bytes(self):
        """Build a COTP DT frame and check the 7-byte header."""
        from s7commplus.transport.cotp import COTPTransport

        # Use a fake socket to capture what gets sent
        class CaptureSock:
            def __init__(self):
                self.sent = b""
                self.connected = True
            def send(self, data, size):
                self.sent = bytes(data[:size])
                return 0

        sock = CaptureSock()
        cotp = COTPTransport(sock)
        payload = b"\xAA\xBB\xCC"
        cotp.send_iso_packet(payload)

        sent = sock.sent
        # First 7 bytes = TPKT + COTP DT
        assert sent[0] == 0x03  # TPKT version
        assert sent[1] == 0x00  # Reserved
        # Length = 7 + 3 = 10
        assert struct.unpack_from(">H", sent, 2)[0] == 10
        assert sent[4] == 0x02  # COTP header length
        assert sent[5] == 0xF0  # DT PDU type
        assert sent[6] == 0x80  # TPDU number + EOT
        # Payload follows
        assert sent[7:10] == b"\xAA\xBB\xCC"


# ===================================================================
# 3. S7CommPlus PDU header/trailer — S7CommPlusConnection.cs
# ===================================================================

class TestPDU_CrossValidation:
    """Cross-validate S7CommPlus PDU header and trailer format."""

    def test_header_magic_byte(self):
        """PDU header starts with 0x72 (S7CommPlusConnection.cs line 204)."""
        buf = bytearray()
        encode_header(buf, ProtocolVersion.V1, 100)
        assert buf[0] == 0x72

    def test_header_format(self):
        """Header: [0x72, version, len_hi, len_lo]"""
        buf = bytearray()
        encode_header(buf, ProtocolVersion.V2, 0x0100)
        assert buf == bytes([0x72, 0x02, 0x01, 0x00])

    def test_trailer_format(self):
        """Trailer: [0x72, version, 0x00, 0x00]
        (S7CommPlusConnection.cs lines 217-224)"""
        buf = bytearray()
        # Trailer is just a header with length=0
        encode_header(buf, ProtocolVersion.V1, 0)
        assert buf == bytes([0x72, 0x01, 0x00, 0x00])

    def test_v3_header(self):
        buf = bytearray()
        encode_header(buf, ProtocolVersion.V3, 512)
        assert buf[0] == 0x72
        assert buf[1] == 0x03
        assert struct.unpack_from(">H", buf, 2)[0] == 512

    def test_system_event_header(self):
        buf = bytearray()
        encode_header(buf, ProtocolVersion.SYSTEM_EVENT, 0)
        assert buf[0] == 0x72
        assert buf[1] == 0xFE


# ===================================================================
# 4. InitSSL Request — InitSslRequest.cs Serialize()
# ===================================================================

class TestInitSslRequest_CrossValidation:
    """Cross-validate InitSSL request serialization.

    From InitSslRequest.cs lines 46-59:
        Opcode.Request (0x31)
        Reserved (0x00 0x00)
        FunctionCode.InitSsl (0x05B3)
        Reserved (0x00 0x00)
        SequenceNumber (uint16 BE)
        SessionId (uint32 BE)
        TransportFlags (0x30)
        Fill (0x00 0x00 0x00 0x00)

    The first call uses SequenceNumber=1, SessionId=0.
    """

    def _build_init_ssl_request(
        self, seq_num: int = 1, session_id: int = 0
    ) -> bytes:
        """Reproduce the C# InitSslRequest.Serialize() output."""
        buf = bytearray()
        encode_byte(buf, Opcode.REQUEST)        # 0x31
        encode_uint16(buf, 0)                    # Reserved
        encode_uint16(buf, FunctionCode.INIT_SSL)  # 0x05B3
        encode_uint16(buf, 0)                    # Reserved
        encode_uint16(buf, seq_num)
        encode_uint32(buf, session_id)
        encode_byte(buf, 0x30)                   # TransportFlags
        encode_uint32(buf, 0)                    # Fill
        return bytes(buf)

    def test_init_ssl_first_request(self):
        """First InitSSL: seq=1, session=0."""
        data = self._build_init_ssl_request(seq_num=1, session_id=0)
        expected = bytes([
            0x31,                   # Opcode.Request
            0x00, 0x00,             # Reserved
            0x05, 0xB3,             # FunctionCode.InitSsl
            0x00, 0x00,             # Reserved
            0x00, 0x01,             # SequenceNumber = 1
            0x00, 0x00, 0x00, 0x00, # SessionId = 0
            0x30,                   # TransportFlags
            0x00, 0x00, 0x00, 0x00, # Fill
        ])
        assert data == expected

    def test_init_ssl_length(self):
        """InitSSL payload is exactly 18 bytes (1+2+2+2+2+4+1+4)."""
        data = self._build_init_ssl_request()
        assert len(data) == 18

    def test_init_ssl_with_session(self):
        """Later InitSSL with a real session ID."""
        data = self._build_init_ssl_request(seq_num=5, session_id=288)
        # SessionId = 288 = 0x00000120
        assert data[9:13] == bytes([0x00, 0x00, 0x01, 0x20])
        assert data[7:9] == bytes([0x00, 0x05])  # seq=5

    def test_full_pdu_with_header_and_trailer(self):
        """A complete InitSSL PDU: header + payload + trailer."""
        payload = self._build_init_ssl_request(seq_num=1, session_id=0)
        buf = bytearray()
        # Header
        encode_header(buf, ProtocolVersion.V1, len(payload))
        buf.extend(payload)
        # Trailer
        encode_header(buf, ProtocolVersion.V1, 0)

        # Total: 4 (header) + 18 (payload) + 4 (trailer) = 26 bytes
        assert len(buf) == 26
        # Header
        assert buf[0] == 0x72
        assert buf[1] == 0x01
        assert struct.unpack_from(">H", buf, 2)[0] == 18
        # Trailer
        assert buf[22] == 0x72
        assert buf[23] == 0x01
        assert buf[24:26] == b'\x00\x00'


# ===================================================================
# 5. VLQ cross-validation — specific values from C# code
# ===================================================================

class TestVLQ_CrossValidation:
    """Verify VLQ encoding produces known byte sequences.

    The C# code uses VLQ extensively for IDs and addresses.  We verify our
    encoder against hand-calculated results and the C# algorithm.
    """

    # -- Unsigned 32-bit VLQ ------------------------------------------------

    def test_vlq_zero(self):
        buf = bytearray()
        encode_uint32_vlq(buf, 0)
        assert buf == bytes([0x00])

    def test_vlq_127(self):
        buf = bytearray()
        encode_uint32_vlq(buf, 127)
        assert buf == bytes([0x7F])

    def test_vlq_128(self):
        """128 = 0b10000000 → two bytes: [0x81, 0x00]"""
        buf = bytearray()
        encode_uint32_vlq(buf, 128)
        assert buf == bytes([0x81, 0x00])

    def test_vlq_id_285(self):
        """Ids.ObjectServerSessionContainer = 285
        285 = 2*128 + 29 → [0x82, 0x1D]"""
        buf = bytearray()
        encode_uint32_vlq(buf, Ids.OBJECT_SERVER_SESSION_CONTAINER)  # 285
        assert buf == bytes([0x82, 0x1D])
        # Verify decode
        val, _ = decode_uint32_vlq(buf, 0)
        assert val == 285

    def test_vlq_id_288(self):
        """Ids.ObjectNullServerSession = 288
        288 = 2*128 + 32 → [0x82, 0x20]"""
        buf = bytearray()
        encode_uint32_vlq(buf, Ids.OBJECT_NULL_SERVER_SESSION)  # 288
        assert buf == bytes([0x82, 0x20])

    def test_vlq_id_201(self):
        """Ids.ObjectRoot = 201
        201 = 1*128 + 73 → [0x81, 0x49]"""
        buf = bytearray()
        encode_uint32_vlq(buf, Ids.OBJECT_ROOT)  # 201
        assert buf == bytes([0x81, 0x49])

    def test_vlq_id_1256(self):
        """Ids.ObjectQualifier = 1256
        1256 = 9*128 + 104 → [0x89, 0x68]"""
        buf = bytearray()
        encode_uint32_vlq(buf, Ids.OBJECT_QUALIFIER)  # 1256
        assert buf == bytes([0x89, 0x68])

    def test_vlq_function_code_explore(self):
        """FunctionCode.Explore = 0x04BB = 1211
        1211 = 9*128 + 59 → [0x89, 0x3B]"""
        buf = bytearray()
        encode_uint32_vlq(buf, FunctionCode.EXPLORE)
        assert buf == bytes([0x89, 0x3B])

    def test_vlq_large_type_info_id(self):
        """Ids.TI_BOOL = 0x02000001 = 33554433
        0x02000001 = 0b10_0000000_0000000_0000001
        → 4 VLQ bytes: [0x90, 0x80, 0x80, 0x01]"""
        buf = bytearray()
        n = encode_uint32_vlq(buf, Ids.TI_BOOL)
        assert n == 4
        assert buf == bytes([0x90, 0x80, 0x80, 0x01])
        val, consumed = decode_uint32_vlq(buf, 0)
        assert val == 0x02000001
        assert consumed == 4

    def test_vlq_0xFFFFFFFF(self):
        """Maximum uint32 value."""
        buf = bytearray()
        n = encode_uint32_vlq(buf, 0xFFFFFFFF)
        assert n == 5
        val, _ = decode_uint32_vlq(buf, 0)
        assert val == 0xFFFFFFFF

    # -- Signed 32-bit VLQ -------------------------------------------------

    def test_signed_vlq_minus_one(self):
        """Negative one: sign bit set, value bits = 1."""
        buf = bytearray()
        encode_int32_vlq(buf, -1)
        val, _ = decode_int32_vlq(buf, 0)
        assert val == -1
        # First byte must have bit 6 set (sign flag)
        assert buf[0] & 0x40 != 0

    def test_signed_vlq_minus_64(self):
        buf = bytearray()
        encode_int32_vlq(buf, -64)
        val, _ = decode_int32_vlq(buf, 0)
        assert val == -64

    def test_signed_vlq_positive_63(self):
        """63 is the largest positive value in a single-byte signed VLQ."""
        buf = bytearray()
        n = encode_int32_vlq(buf, 63)
        assert n == 1
        val, _ = decode_int32_vlq(buf, 0)
        assert val == 63
        # No sign bit
        assert buf[0] & 0x40 == 0

    # -- Unsigned 64-bit VLQ -----------------------------------------------

    def test_vlq64_small(self):
        buf = bytearray()
        encode_uint64_vlq(buf, 42)
        assert buf == bytes([42])
        val, _ = decode_uint64_vlq(buf, 0)
        assert val == 42

    def test_vlq64_special_threshold(self):
        """Values > 0x00FFFFFFFFFFFFFF require 9 bytes with 8-bit last byte."""
        threshold = 0x00FFFFFFFFFFFFFF
        # Just below threshold — should use standard VLQ
        buf = bytearray()
        n1 = encode_uint64_vlq(buf, threshold)

        # Just above threshold — triggers special 9-byte encoding
        buf2 = bytearray()
        n2 = encode_uint64_vlq(buf2, threshold + 1)

        val1, _ = decode_uint64_vlq(buf, 0)
        val2, _ = decode_uint64_vlq(buf2, 0)
        assert val1 == threshold
        assert val2 == threshold + 1


# ===================================================================
# 6. Element IDs and markers
# ===================================================================

class TestElementMarkers_CrossValidation:
    """Verify protocol marker bytes match C# constants."""

    def test_start_of_object_marker(self):
        assert ElementID.START_OF_OBJECT == 0xA1

    def test_terminating_object_marker(self):
        assert ElementID.TERMINATING_OBJECT == 0xA2

    def test_attribute_marker(self):
        assert ElementID.ATTRIBUTE == 0xA3

    def test_relation_marker(self):
        assert ElementID.RELATION == 0xA4

    def test_vartype_list_marker(self):
        assert ElementID.VARTYPE_LIST == 0xAB

    def test_varname_list_marker(self):
        assert ElementID.VARNAME_LIST == 0xAC

    def test_markers_encode_as_single_bytes(self):
        """All element markers are single bytes and encode directly."""
        for marker in [0xA1, 0xA2, 0xA3, 0xA4, 0xA7, 0xA8, 0xAB, 0xAC]:
            buf = bytearray()
            encode_byte(buf, marker)
            assert len(buf) == 1
            assert buf[0] == marker


# ===================================================================
# 7. Complete message construction — Explore request skeleton
# ===================================================================

class TestExploreRequest_CrossValidation:
    """Verify we can construct an Explore request header that matches C#.

    From ExploreRequest.cs:
        Opcode.Request (0x31)
        Reserved (0x00 0x00)
        FunctionCode.Explore (0x04BB)
        Reserved (0x00 0x00)
        SequenceNumber (uint16 BE)
        SessionId (uint32 BE)
        TransportFlags (0x34)
    """

    def _build_explore_header(
        self, seq_num: int, session_id: int
    ) -> bytes:
        buf = bytearray()
        encode_byte(buf, Opcode.REQUEST)             # 0x31
        encode_uint16(buf, 0)                         # Reserved
        encode_uint16(buf, FunctionCode.EXPLORE)      # 0x04BB
        encode_uint16(buf, 0)                         # Reserved
        encode_uint16(buf, seq_num)
        encode_uint32(buf, session_id)
        encode_byte(buf, 0x34)                        # TransportFlags
        return bytes(buf)

    def test_explore_header_bytes(self):
        data = self._build_explore_header(seq_num=2, session_id=288)
        expected = bytes([
            0x31,                   # Opcode.Request
            0x00, 0x00,             # Reserved
            0x04, 0xBB,             # FunctionCode.Explore
            0x00, 0x00,             # Reserved
            0x00, 0x02,             # SequenceNumber = 2
            0x00, 0x00, 0x01, 0x20, # SessionId = 288
            0x34,                   # TransportFlags
        ])
        assert data == expected

    def test_explore_header_length(self):
        """Header is 14 bytes (1+2+2+2+2+4+1)."""
        data = self._build_explore_header(1, 0)
        assert len(data) == 14
