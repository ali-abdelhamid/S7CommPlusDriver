"""
S7CommPlus transport client — orchestrates TCP → COTP → TLS.

Ported from S7Client.cs.  This module ties together the three transport layers
and exposes a simple ``connect`` / ``disconnect`` / ``send`` / ``recv`` API
that the upper protocol layers consume.

Threading model
---------------
The C# driver uses a background ``RunThread`` that continuously reads COTP
packets and dispatches them (through TLS if active) via a callback delegate.
We preserve this pattern: ``connect()`` launches a daemon thread that calls
``recv_iso_packet`` in a loop and invokes a user-supplied callback with the
decrypted payload.  The thread exits cleanly on ``disconnect()``.
"""

from __future__ import annotations

import struct
import threading
import time
from typing import Callable

from s7commplus.protocol.errors import (
    ERR_OPENSSL,
    ERR_TCP_CONNECTION_FAILED,
    ERR_TCP_NOT_CONNECTED,
)
from s7commplus.transport.cotp import COTPTransport, REMOTE_TSAP_DEFAULT
from s7commplus.transport.tcp_socket import MsgSocket
from s7commplus.transport.tls import TLSOverCOTP

# Default port for ISO-on-TCP (TPKT/COTP)
ISOTCP_PORT = 102

# PDU size limits
MIN_PDU_SIZE = 240
MAX_PDU_SIZE = 960
DEFAULT_TIMEOUT = 2.0  # seconds

# Type alias for the data callback
DataCallback = Callable[[bytes, int], None]


class S7Client:
    """S7CommPlus transport client.

    Orchestrates the three-layer stack:

    1. **TCP** — raw socket via :class:`MsgSocket`
    2. **COTP** — TPKT/COTP framing via :class:`COTPTransport`
    3. **TLS** — optional TLS 1.3 via :class:`TLSOverCOTP`

    Usage::

        client = S7Client()
        client.set_connection_params("192.168.1.1", 0x0100, b"SIMATIC-ROOT-HMI")
        client.on_data_received = my_callback
        err = client.connect()
        # ... send/receive via callback ...
        client.disconnect()
    """

    def __init__(self) -> None:
        # Network stack
        self._socket = MsgSocket()
        self._cotp: COTPTransport | None = None
        self._tls: TLSOverCOTP | None = None

        # Connection parameters
        self._ip_address: str = ""
        self._local_tsap_hi: int = 0x01
        self._local_tsap_lo: int = 0x00
        self._remote_tsap: bytes = REMOTE_TSAP_DEFAULT
        self._plc_port: int = ISOTCP_PORT

        # Timeouts (seconds)
        self._recv_timeout: float = DEFAULT_TIMEOUT
        self._send_timeout: float = DEFAULT_TIMEOUT
        self._conn_timeout: float = DEFAULT_TIMEOUT

        # PDU
        self._pdu_length: int = 0
        self._pdu_size_requested: int = 480

        # Threading
        self._run_thread: threading.Thread | None = None
        self._stop_event = threading.Event()

        # State
        self._last_error: int = 0
        self._time_ms: int = 0
        self._ssl_active: bool = False

        # Callback for received data
        self.on_data_received: DataCallback | None = None

    # -- Connection setup ----------------------------------------------------

    def set_connection_params(
        self,
        address: str,
        local_tsap: int = 0x0100,
        remote_tsap: bytes = REMOTE_TSAP_DEFAULT,
    ) -> int:
        """Configure the connection parameters before calling :meth:`connect`.

        :param address: IP address of the PLC.
        :param local_tsap: 16-bit local TSAP (source).
        :param remote_tsap: Remote TSAP bytes (default: ``SIMATIC-ROOT-HMI``).
        """
        self._ip_address = address
        self._local_tsap_hi = (local_tsap >> 8) & 0xFF
        self._local_tsap_lo = local_tsap & 0xFF
        self._remote_tsap = bytes(remote_tsap)
        return 0

    # -- Connect / Disconnect ------------------------------------------------

    def connect(self) -> int:
        """Open the full TCP → COTP → background-reader stack.

        Returns 0 on success, or an error code.
        """
        self._last_error = 0
        self._time_ms = 0
        start = time.monotonic()

        if self.connected:
            return 0

        # Configure socket timeouts
        self._socket.connect_timeout = self._conn_timeout
        self._socket.read_timeout = self._recv_timeout
        self._socket.write_timeout = self._send_timeout

        # Stage 1: TCP
        self._last_error = self._socket.connect(self._ip_address, self._plc_port)
        if self._last_error != 0:
            self.disconnect()
            return self._last_error

        # Stage 2: COTP
        self._cotp = COTPTransport(self._socket)
        self._last_error = self._cotp.iso_connect(
            self._local_tsap_hi,
            self._local_tsap_lo,
            self._remote_tsap,
        )
        if self._last_error != 0:
            self.disconnect()
            return self._last_error

        # Stage 3: start background reader thread
        self._start_thread()
        self._time_ms = int((time.monotonic() - start) * 1000)
        return 0

    def ssl_activate(self, keylog_file: str | None = None) -> int:
        """Activate TLS 1.3 over the existing COTP connection.

        Must be called after :meth:`connect` succeeds.  Returns 0 on success.

        :param keylog_file: Optional path for TLS key log (Wireshark-compatible).
            If not given, falls back to ``SSLKEYLOGFILE`` env var.
        """
        if self._cotp is None:
            return ERR_TCP_NOT_CONNECTED
        try:
            self._tls = TLSOverCOTP(self._cotp, keylog_file=keylog_file)
            err = self._tls.handshake()
            if err != 0:
                self._tls = None
                return err
            self._ssl_active = True
            return 0
        except Exception:
            return ERR_OPENSSL

    def ssl_deactivate(self) -> None:
        """Deactivate TLS (payload sent in cleartext again)."""
        self._ssl_active = False
        if self._tls is not None:
            self._tls.deactivate()
            self._tls = None

    def disconnect(self) -> int:
        """Shut everything down cleanly."""
        self._stop_event.set()
        if self._run_thread is not None:
            self._run_thread.join(timeout=5.0)
            self._run_thread = None
        self._ssl_active = False
        self._tls = None
        self._cotp = None
        self._socket.close()
        return 0

    # -- Send / Receive ------------------------------------------------------

    def send(self, data: bytes | bytearray) -> int:
        """Send *data* through TLS (if active) or raw COTP.

        Returns 0 on success.
        """
        if self._ssl_active and self._tls is not None:
            return self._tls.send(data)
        if self._cotp is not None:
            return self._cotp.send_iso_packet(data)
        return ERR_TCP_NOT_CONNECTED

    def get_oms_exporter_secret(self) -> bytes | None:
        """Derive the 32-byte OMS exporter secret from the TLS session.

        Used for PLC legitimation.  Returns ``None`` if TLS is not active.
        """
        if self._tls is None:
            return None
        try:
            return self._tls.export_keying_material("EXPERIMENTAL_OMS", 32)
        except NotImplementedError:
            return None

    # -- Background reader thread --------------------------------------------

    def _start_thread(self) -> None:
        self._stop_event.clear()
        self._run_thread = threading.Thread(
            target=self._run_loop,
            name="S7Client-recv",
            daemon=True,
        )
        self._run_thread.start()

    def _run_loop(self) -> None:
        """Continuously read COTP packets and dispatch to callback."""
        while not self._stop_event.is_set():
            if self._cotp is None:
                break

            callback:DataCallback = self.on_data_received

            if self._ssl_active and self._tls is not None:
                # TLS path: receive encrypted COTP frame, decrypt
                plaintext, err = self._tls.recv()
                if err != 0:
                    self._last_error = err
                    break
                if plaintext and callback is not None:
                    callback(plaintext, len(plaintext))
            else:
                # Cleartext path: receive raw COTP payload
                payload, err = self._cotp.recv_iso_packet()
                if err != 0:
                    self._last_error = err
                    break
                if payload and self.on_data_received is not None:
                    self.on_data_received(payload, len(payload))

    # -- Properties ----------------------------------------------------------

    @property
    def connected(self) -> bool:
        return self._socket.connected

    @property
    def last_error(self) -> int:
        return self._last_error

    @property
    def plc_port(self) -> int:
        return self._plc_port

    @plc_port.setter
    def plc_port(self, value: int) -> None:
        self._plc_port = value

    @property
    def recv_timeout(self) -> float:
        return self._recv_timeout

    @recv_timeout.setter
    def recv_timeout(self, value: float) -> None:
        self._recv_timeout = value

    @property
    def send_timeout(self) -> float:
        return self._send_timeout

    @send_timeout.setter
    def send_timeout(self, value: float) -> None:
        self._send_timeout = value

    @property
    def conn_timeout(self) -> float:
        return self._conn_timeout

    @conn_timeout.setter
    def conn_timeout(self, value: float) -> None:
        self._conn_timeout = value

    @property
    def pdu_size_requested(self) -> int:
        return self._pdu_size_requested

    @pdu_size_requested.setter
    def pdu_size_requested(self, value: int) -> None:
        self._pdu_size_requested = max(MIN_PDU_SIZE, min(value, MAX_PDU_SIZE))

    @property
    def pdu_length(self) -> int:
        return self._pdu_length

    @property
    def execution_time(self) -> int:
        """Connection time in milliseconds."""
        return self._time_ms

    @property
    def ssl_active(self) -> bool:
        return self._ssl_active
