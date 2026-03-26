"""
TLS layer for S7CommPlus using Python's ssl.MemoryBIO.

Replaces the C# OpenSSLConnector + Native P/Invoke approach.  Python's
``ssl.MemoryBIO`` / ``ssl.SSLObject`` pair gives us the same memory-based
BIO pattern: TLS operates on in-memory buffers so it can sit transparently
on top of the COTP framing layer (which itself rides on TCP).

Data flow
---------
Sending plaintext to PLC:
    app → SSLObject.write(plain) → outgoing_bio → read encrypted → COTP send

Receiving encrypted from PLC:
    COTP recv → incoming_bio.write(cipher) → SSLObject.read() → plaintext to app

The ``TLSOverCOTP`` class exposes:
    - ``handshake()`` — drive the TLS 1.3 handshake over COTP frames
    - ``send(data)``  — encrypt and send via COTP
    - ``recv()``      — receive a COTP frame, decrypt, return plaintext
    - ``export_keying_material(label, length)`` — for OMS legitimation
"""

from __future__ import annotations

import os
import ssl
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from s7commplus.protocol.errors import ERR_OPENSSL

if TYPE_CHECKING:
    from s7commplus.transport.cotp import COTPTransport

# TLS 1.3 cipher suites required by S7CommPlus (GCM only — no padding,
# always +16 bytes overhead, which the protocol relies on for fragmentation).
# The C# driver sets: "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256"
# Python 3.12's ssl module doesn't expose set_ciphersuites() for TLS 1.3,
# so we rely on forcing TLS 1.3 (which auto-selects these ciphers) and the
# PLC will negotiate GCM.  If set_ciphersuites becomes available (Python 3.13+),
# we use it to exclude CHACHA20_POLY1305.
_CIPHERSUITES_TLS13 = "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256"


def _create_ssl_context(keylog_file: str | None = None) -> ssl.SSLContext:
    """Build an :class:`ssl.SSLContext` matching the C# SslActivate() config.

    Args:
        keylog_file: Optional path to a file where TLS key material will
            be logged in NSS Key Log format.  Compatible with Wireshark's
            "(Pre)-Master-Secret log filename" setting.  If ``None``, key
            logging is disabled unless the ``SSLKEYLOGFILE`` environment
            variable is set (standard OpenSSL/NSS convention).

    Returns:
        Configured :class:`ssl.SSLContext` for TLS 1.3 with GCM ciphers.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # Self-signed PLC certificates — disable verification.
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # Force TLS 1.3
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    # Restrict to GCM cipher suites if the API is available (Python 3.13+).
    # On older Python, TLS 1.3 ciphers are auto-selected; the PLC will
    # negotiate GCM regardless.
    if hasattr(ctx, "set_ciphersuites"):
        ctx.set_ciphersuites(_CIPHERSUITES_TLS13)  # type: ignore[attr-defined]
    # TLS key logging for Wireshark analysis.
    # Mirrors the C# SSL_CTX_keylog_cb in S7Client.cs.
    keylog_path = keylog_file or os.environ.get("SSLKEYLOGFILE")
    if keylog_path:
        ctx.keylog_filename = keylog_path
    return ctx


class TLSOverCOTP:
    """TLS encryption layer that sits on top of :class:`COTPTransport`.

    Uses :class:`ssl.MemoryBIO` pairs so that OpenSSL never touches a real
    socket — all I/O goes through the COTP framing layer.
    """

    def __init__(
        self,
        cotp: COTPTransport,
        keylog_file: str | None = None,
    ) -> None:
        """Initialize the TLS-over-COTP layer.

        Args:
            cotp: The COTP transport to send/receive encrypted frames.
            keylog_file: Optional path for TLS key log output.  If not
                provided, falls back to the ``SSLKEYLOGFILE`` environment
                variable.  The file is compatible with Wireshark and
                ``editcap --inject-secrets``.
        """
        self._cotp = cotp
        # Auto-generate a timestamped key log path matching the C# convention
        # (key_YYYYMMDD_HHmmss.log) if no explicit path is given and no env var.
        self._keylog_file = keylog_file
        if keylog_file is None and not os.environ.get("SSLKEYLOGFILE"):
            self._auto_keylog: str | None = None  # no auto-log unless opted in
        else:
            self._auto_keylog = None

        self._ctx = _create_ssl_context(keylog_file=keylog_file)
        self._incoming = ssl.MemoryBIO()   # encrypted from network
        self._outgoing = ssl.MemoryBIO()   # encrypted to network
        self._ssl: ssl.SSLObject = self._ctx.wrap_bio(
            self._incoming,
            self._outgoing,
            server_side=False,
            server_hostname=None,
        )
        self._active = False
        self.last_error: int = 0

    # -- public API ----------------------------------------------------------

    def handshake(self) -> int:
        """Drive the TLS 1.3 handshake over COTP frames.

        Returns:
            Error code (``int``): 0 on success, ``ERR_OPENSSL`` on failure.
        """
        self.last_error = 0
        try:
            while True:
                try:
                    self._ssl.do_handshake()
                    break  # handshake complete
                except ssl.SSLWantReadError:
                    # SSL needs to send data and/or receive data
                    self._flush_outgoing()
                    self._pump_incoming()
                except ssl.SSLWantWriteError:
                    self._flush_outgoing()
        except ssl.SSLError:
            self.last_error = ERR_OPENSSL
            return self.last_error

        # Flush any remaining handshake data
        self._flush_outgoing()
        self._active = True
        return 0

    def send(self, data: bytes | bytearray) -> int:
        """Encrypt *data* and send via COTP.

        Args:
            data: Plaintext payload to encrypt and send.

        Returns:
            Error code (``int``): 0 on success.
        """
        self.last_error = 0
        try:
            self._ssl.write(data)
            self._flush_outgoing()
        except ssl.SSLError:
            self.last_error = ERR_OPENSSL
        return self.last_error

    def recv(self) -> tuple[bytes, int]:
        """Receive one COTP frame, decrypt, and return plaintext.

        Returns:
            Tuple of ``(plaintext, error_code)``.  On error the plaintext
            is empty.
        """
        self.last_error = 0
        # Pump encrypted data from COTP into the incoming BIO, then attempt
        # to read decrypted plaintext.  If SSL needs more data (WantRead),
        # pump again — a single TLS record may span multiple COTP frames.
        while True:
            self._pump_incoming()
            if self.last_error != 0:
                return b"", self.last_error
            try:
                plaintext = self._ssl.read(65536)
                return plaintext, 0
            except ssl.SSLWantReadError:
                # The TLS record isn't complete yet — pump more COTP data.
                continue
            except ssl.SSLError:
                self.last_error = ERR_OPENSSL
                return b"", self.last_error

    def export_keying_material(
        self,
        label: str = "EXPERIMENTAL_OMS",
        length: int = 32,
    ) -> bytes:
        """Export keying material from the TLS session for OMS legitimation.

        Mirrors ``SSL_export_keying_material()`` used by
        ``OpenSSLConnector.getOMSExporterSecret()`` in C#.

        Args:
            label: TLS exporter label string.
            length: Number of bytes to export.

        Returns:
            Derived key material (``bytes``).

        Raises:
            NotImplementedError: If Python < 3.13 and no fallback available.
        """
        if hasattr(self._ssl, "export_keying_material"):
            return self._ssl.export_keying_material(label, length)  # type: ignore[attr-defined]
        # Fallback: not available in this Python version.
        raise NotImplementedError(
            "export_keying_material requires Python 3.13+ or a custom OpenSSL binding"
        )

    @property
    def active(self) -> bool:
        """Whether TLS is active (``bool``)."""
        return self._active

    def deactivate(self) -> None:
        """Mark TLS as inactive (cleartext mode resumes)."""
        self._active = False

    # -- internal I/O pumps --------------------------------------------------

    def _flush_outgoing(self) -> None:
        """Read all pending encrypted bytes from the outgoing BIO and send them as a COTP ISO packet."""
        data = self._outgoing.read()
        if data:
            err = self._cotp.send_iso_packet(data)
            if err != 0:
                self.last_error = err

    def _pump_incoming(self) -> None:
        """Receive one COTP ISO packet and feed the encrypted bytes into the incoming BIO for decryption."""
        payload, err = self._cotp.recv_iso_packet()
        if err != 0:
            self.last_error = err
            return
        if payload:
            self._incoming.write(payload)
