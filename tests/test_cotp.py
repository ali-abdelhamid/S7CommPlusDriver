"""
Unit tests for s7commplus.transport.cotp — TPKT/COTP framing.

Tests the ISO Connection Request telegram construction and the
send/receive framing logic using a mock socket.
"""

import struct
import pytest

from s7commplus.transport.cotp import (
    _build_iso_cr,
    COTPTransport,
    ISO_HEADER_SIZE,
    REMOTE_TSAP_DEFAULT,
)


class TestBuildIsoCR:
    """Test the ISO Connection Request telegram builder."""

    def test_default_tsap(self):
        cr = _build_iso_cr(0x01, 0x00, REMOTE_TSAP_DEFAULT)
        # TPKT version
        assert cr[0] == 0x03
        assert cr[1] == 0x00
        # Total length
        total_len = struct.unpack_from(">H", cr, 2)[0]
        assert total_len == 20 + len(REMOTE_TSAP_DEFAULT)
        assert total_len == len(cr)
        # CR PDU type
        assert cr[5] == 0xE0
        # Source TSAP
        assert cr[16] == 0x01
        assert cr[17] == 0x00
        # Destination TSAP length
        assert cr[19] == len(REMOTE_TSAP_DEFAULT)
        # Destination TSAP string
        assert cr[20:] == REMOTE_TSAP_DEFAULT

    def test_custom_tsap(self):
        cr = _build_iso_cr(0x42, 0x99, b"CUSTOM")
        assert cr[16] == 0x42
        assert cr[17] == 0x99
        assert cr[19] == 6
        assert cr[20:] == b"CUSTOM"
        total_len = struct.unpack_from(">H", cr, 2)[0]
        assert total_len == 20 + 6

    def test_pdu_size_length_field(self):
        """The PDU size length field (byte 4) should be 15 + tsap_len."""
        cr = _build_iso_cr(0x01, 0x00, b"TEST")
        assert cr[4] == 15 + 4  # 19


class FakeSocket:
    """Minimal mock of MsgSocket for testing COTPTransport framing.

    Feed it pre-built bytes via ``inject()`` and read back what was
    ``sent()`` through ``send()``.
    """

    def __init__(self):
        self._recv_buffer = bytearray()
        self._recv_pos = 0
        self._sent: list[bytes] = []
        self._connected = True

    def inject(self, data: bytes) -> None:
        """Append data that ``receive()`` will consume."""
        self._recv_buffer.extend(data)

    @property
    def sent_data(self) -> list[bytes]:
        return self._sent

    # MsgSocket interface

    @property
    def connected(self) -> bool:
        return self._connected

    def receive(self, buffer: bytearray, start: int, size: int) -> int:
        end = self._recv_pos + size
        if end > len(self._recv_buffer):
            return 0x00000005  # ERR_TCP_DATA_RECEIVE
        chunk = self._recv_buffer[self._recv_pos:end]
        buffer[start:start + size] = chunk
        self._recv_pos += size
        return 0

    def send(self, data: bytes | bytearray, size: int) -> int:
        self._sent.append(bytes(data[:size]))
        return 0


class TestCOTPTransport:

    def _make_iso_response(self) -> bytes:
        """Build a fake ISO CC (Connection Confirm) response of length 36."""
        # TPKT header: version=3, reserved=0, length=36
        # COTP: 0x02, 0xD0 (CC), 0x80
        # Then pad to total=36 bytes
        resp = bytearray(36)
        resp[0] = 0x03
        resp[1] = 0x00
        struct.pack_into(">H", resp, 2, 36)
        resp[4] = 0x02
        resp[5] = 0xD0  # CC PDU type
        resp[6] = 0x80
        return bytes(resp)

    def test_iso_connect_success(self):
        sock = FakeSocket()
        sock.inject(self._make_iso_response())
        cotp = COTPTransport(sock)
        err = cotp.iso_connect()
        assert err == 0
        # Should have sent a CR telegram
        assert len(sock.sent_data) == 1

    def test_iso_connect_wrong_pdu_type(self):
        """If the response PDU type is not CC (0xD0), return ISO connect error."""
        resp = bytearray(self._make_iso_response())
        resp[5] = 0xE0  # CR instead of CC
        sock = FakeSocket()
        sock.inject(bytes(resp))
        cotp = COTPTransport(sock)
        err = cotp.iso_connect()
        assert err != 0

    def test_iso_connect_wrong_size(self):
        """If the response size is not 36, return ISO invalid PDU error."""
        resp = bytearray(20)
        resp[0] = 0x03
        struct.pack_into(">H", resp, 2, 20)
        resp[4] = 0x02
        resp[5] = 0xD0
        resp[6] = 0x80
        sock = FakeSocket()
        sock.inject(bytes(resp))
        cotp = COTPTransport(sock)
        err = cotp.iso_connect()
        assert err != 0

    def test_send_iso_packet(self):
        sock = FakeSocket()
        cotp = COTPTransport(sock)
        payload = b'\x72\x01\x00\x10'
        err = cotp.send_iso_packet(payload)
        assert err == 0
        sent = sock.sent_data[0]
        # TPKT header
        assert sent[0] == 0x03
        assert sent[1] == 0x00
        total = struct.unpack_from(">H", sent, 2)[0]
        assert total == ISO_HEADER_SIZE + len(payload)
        # COTP DT header
        assert sent[4] == 0x02
        assert sent[5] == 0xF0
        assert sent[6] == 0x80
        # Payload
        assert sent[7:7 + len(payload)] == payload

    def test_recv_iso_packet(self):
        payload = b'\xDE\xAD\xBE\xEF'
        total = ISO_HEADER_SIZE + len(payload)
        frame = bytearray(total)
        frame[0] = 0x03
        frame[1] = 0x00
        struct.pack_into(">H", frame, 2, total)
        frame[4] = 0x02
        frame[5] = 0xF0
        frame[6] = 0x80
        frame[7:] = payload

        sock = FakeSocket()
        sock.inject(bytes(frame))
        cotp = COTPTransport(sock)
        data, err = cotp.recv_iso_packet()
        assert err == 0
        assert data == payload

    def test_recv_skips_keepalive(self):
        """Keep-alive packets (length==7) should be silently skipped."""
        # First: keep-alive (7-byte TPKT+COTP, no payload)
        keepalive = bytearray(7)
        keepalive[0] = 0x03
        struct.pack_into(">H", keepalive, 2, 7)
        keepalive[4] = 0x02
        keepalive[5] = 0xF0
        keepalive[6] = 0x80

        # Then: real packet
        payload = b'\x01\x02'
        total = ISO_HEADER_SIZE + len(payload)
        frame = bytearray(total)
        frame[0] = 0x03
        struct.pack_into(">H", frame, 2, total)
        frame[4] = 0x02
        frame[5] = 0xF0
        frame[6] = 0x80
        frame[7:] = payload

        sock = FakeSocket()
        sock.inject(bytes(keepalive) + bytes(frame))
        cotp = COTPTransport(sock)
        data, err = cotp.recv_iso_packet()
        assert err == 0
        assert data == payload
