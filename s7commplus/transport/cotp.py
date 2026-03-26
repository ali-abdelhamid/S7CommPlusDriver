"""
TPKT / COTP framing for ISO-on-TCP (RFC 1006 / ISO 8073).

Ported from the ISO_CR telegram and RecvIsoPacket / SendIsoPacket / ISOConnect
logic in S7Client.cs.

TPKT header (4 bytes):
    [0] 0x03  — RFC 1006 version
    [1] 0x00  — reserved
    [2..3]    — total packet length (big-endian uint16), includes TPKT header

COTP header for Data Transfer (DT) — 3 bytes:
    [4] 0x02  — header length (following bytes, not including this one)
    [5] 0xF0  — PDU type: DT (Data Transfer)
    [6] 0x80  — TPDU number + EOT flag

ISO header size = TPKT (4) + COTP-DT (3) = 7 bytes.
"""

from __future__ import annotations

import struct

from s7commplus.protocol.errors import (
    ERR_ISO_CONNECT,
    ERR_ISO_INVALID_PDU,
    ERR_TCP_NOT_CONNECTED,
)
from s7commplus.transport.tcp_socket import MsgSocket

# Default Remote TSAP string for Siemens S7-1200/1500 HMI access.
REMOTE_TSAP_DEFAULT = b"SIMATIC-ROOT-HMI"

# ISO header (TPKT + COTP-DT) size in bytes.
ISO_HEADER_SIZE = 7

# COTP Connection Confirm PDU type
_CC_PDU_TYPE = 0xD0

# Expected ISO Connect response size (TPKT total length field value).
_ISO_CONNECT_RESPONSE_SIZE = 36


def _build_iso_cr(
    local_tsap_hi: int,
    local_tsap_lo: int,
    remote_tsap: bytes,
) -> bytes:
    """Build an ISO Connection Request (CR) telegram.

    Layout (from S7Client.cs):
        TPKT header (4 bytes) + COTP CR header (16 bytes) + Remote TSAP.

    Total = 20 + len(remote_tsap).

    Args:
        local_tsap_hi: High byte of the local TSAP.
        local_tsap_lo: Low byte of the local TSAP.
        remote_tsap: Destination TSAP bytes.

    Returns:
        Complete CR telegram as ``bytes``.
    """
    tsap_len = len(remote_tsap)
    total_len = 20 + tsap_len
    pdu_size_len = 15 + tsap_len

    cr = bytearray([
        # TPKT
        0x03,               # RFC 1006 version
        0x00,               # reserved
        0x00, total_len,    # total length (will fix high byte below)
        # COTP CR
        pdu_size_len,       # PDU size length (rest of COTP)
        0xE0,               # CR — Connection Request
        0x00, 0x00,         # Destination reference
        0x00, 0x01,         # Source reference
        0x00,               # Class + options
        0xC0, 0x01, 0x0A,   # PDU max length parameter (0xC0, len=1, value=0x0A → 1024)
        0xC1, 0x02,         # Source TSAP parameter header
        local_tsap_hi,
        local_tsap_lo,
        0xC2, tsap_len,     # Destination TSAP parameter header
    ])
    # Total length may exceed 255 — encode properly.
    struct.pack_into(">H", cr, 2, total_len)
    cr.extend(remote_tsap)
    return bytes(cr)


class COTPTransport:
    """TPKT/COTP framing layer over a :class:`MsgSocket`.

    Provides ``iso_connect``, ``send_iso_packet``, and ``recv_iso_packet``
    which wrap raw TCP send/receive with TPKT+COTP framing.
    """

    def __init__(self, sock: MsgSocket) -> None:
        """Initialize the COTP framing layer.

        Args:
            sock: Underlying TCP socket to read/write through.
        """
        self._sock = sock
        self.last_error: int = 0
        self._last_pdu_type: int = 0
        self._pdu = bytearray(2048)

    # -- ISO Connect ---------------------------------------------------------

    def iso_connect(
        self,
        local_tsap_hi: int = 0x01,
        local_tsap_lo: int = 0x00,
        remote_tsap: bytes = REMOTE_TSAP_DEFAULT,
    ) -> int:
        """Perform the ISO (COTP) connection handshake.

        Sends a Connection Request (CR) and waits for a Connection Confirm (CC).

        Args:
            local_tsap_hi: High byte of the local TSAP.
            local_tsap_lo: Low byte of the local TSAP.
            remote_tsap: Destination TSAP bytes.

        Returns:
            Error code (``int``): 0 on success.
        """
        cr = _build_iso_cr(local_tsap_hi, local_tsap_lo, remote_tsap)
        self.last_error = self._send_packet(cr)
        if self.last_error != 0:
            return self.last_error

        size = self._recv_iso_packet()
        if self.last_error != 0:
            return self.last_error

        if size == _ISO_CONNECT_RESPONSE_SIZE:
            if self._last_pdu_type != _CC_PDU_TYPE:
                self.last_error = ERR_ISO_CONNECT
        else:
            self.last_error = ERR_ISO_INVALID_PDU

        return self.last_error

    # -- Send ----------------------------------------------------------------

    def send_iso_packet(self, payload: bytes | bytearray) -> int:
        """Wrap *payload* in a TPKT+COTP-DT header and send.

        Args:
            payload: Raw payload bytes to frame and send.

        Returns:
            Error code (``int``): 0 on success.
        """
        size = len(payload)
        total = size + ISO_HEADER_SIZE
        # Build TPKT + COTP-DT header
        self._pdu[0] = 0x03
        self._pdu[1] = 0x00
        struct.pack_into(">H", self._pdu, 2, total)
        self._pdu[4] = 0x02
        self._pdu[5] = 0xF0
        self._pdu[6] = 0x80
        self._pdu[ISO_HEADER_SIZE:ISO_HEADER_SIZE + size] = payload
        self.last_error = self._sock.send(self._pdu, total)
        return self.last_error

    # -- Receive -------------------------------------------------------------

    def recv_iso_packet(self) -> tuple[bytes, int]:
        """Receive one TPKT/COTP-DT framed packet.

        Returns:
            Tuple of ``(payload_bytes, error_code)``.  On error the
            payload is empty.
        """
        length = self._recv_iso_packet()
        if self.last_error != 0 or length <= ISO_HEADER_SIZE:
            return b"", self.last_error
        payload_size = length - ISO_HEADER_SIZE
        return bytes(self._pdu[ISO_HEADER_SIZE:ISO_HEADER_SIZE + payload_size]), 0

    def _recv_iso_packet(self) -> int:
        """Receive a full TPKT+COTP frame into ``self._pdu``.

        Mirrors RecvIsoPacket() in S7Client.cs — skips keep-alive packets
        (length == 7) automatically.

        Returns:
            Total TPKT length (``int``) including header; 0 on error.
        """
        done = False
        size = 0
        self.last_error = 0
        while self.last_error == 0 and not done:
            # Read 4-byte TPKT header
            self.last_error = self._sock.receive(self._pdu, 0, 4)
            if self.last_error != 0:
                break
            size = struct.unpack_from(">H", self._pdu, 2)[0]
            if size == ISO_HEADER_SIZE:
                # Keep-alive: read remaining 3 COTP bytes and loop
                self.last_error = self._sock.receive(self._pdu, 4, 3)
            else:
                done = True

        if self.last_error != 0:
            return 0

        # Read remaining 3 COTP bytes
        self.last_error = self._sock.receive(self._pdu, 4, 3)
        if self.last_error != 0:
            return 0
        self._last_pdu_type = self._pdu[5]

        # Read S7 payload
        payload_size = size - ISO_HEADER_SIZE
        if payload_size > 0:
            self.last_error = self._sock.receive(self._pdu, 7, payload_size)
        if self.last_error != 0:
            return 0
        return size

    # -- helpers -------------------------------------------------------------

    def _send_packet(self, data: bytes | bytearray) -> int:
        """Send a raw packet via the socket (no COTP framing).

        Args:
            data: Complete packet bytes to send.

        Returns:
            Error code (``int``): 0 on success.
        """
        if not self._sock.connected:
            return ERR_TCP_NOT_CONNECTED
        return self._sock.send(data, len(data))
