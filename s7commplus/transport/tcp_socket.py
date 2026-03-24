"""
Raw TCP socket wrapper for S7CommPlus communication.

Ported from MsgSocket.cs — provides blocking send/receive with configurable
timeouts over a TCP stream socket (Nagle disabled).
"""

import socket
import time

from s7commplus.protocol.errors import (
    ERR_TCP_CONNECTION_FAILED,
    ERR_TCP_DATA_RECEIVE,
    ERR_TCP_DATA_SEND,
    ERR_TCP_NOT_CONNECTED,
)


class MsgSocket:
    """Low-level TCP socket with timeout-based receive polling.

    This mirrors the C# MsgSocket class: a thin wrapper around a TCP stream
    socket that provides ``connect``, ``send``, and ``receive`` with explicit
    timeout handling.
    """

    def __init__(self) -> None:
        self._sock: socket.socket | None = None
        self.last_error: int = 0
        self._read_timeout: float = 2.0   # seconds
        self._write_timeout: float = 2.0
        self._connect_timeout: float = 1.0

    # -- lifecycle -----------------------------------------------------------

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self._sock.close()
            self._sock = None

    def _create_socket(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    # -- connect -------------------------------------------------------------

    def connect(self, host: str, port: int) -> int:
        self.last_error = 0
        if self.connected:
            return 0
        try:
            self._create_socket()
            assert self._sock is not None
            self._sock.settimeout(self._connect_timeout)
            self._sock.connect((host, port))
            # After connect, switch to blocking with no global timeout —
            # individual operations use their own timeouts.
            self._sock.settimeout(None)
        except (OSError, socket.timeout):
            self.last_error = ERR_TCP_CONNECTION_FAILED
            self.close()
        return self.last_error

    # -- data transfer -------------------------------------------------------

    def _wait_for_data(self, size: int, timeout: float) -> int:
        """Poll until *size* bytes are available or *timeout* expires."""
        self.last_error = 0
        if self._sock is None:
            self.last_error = ERR_TCP_NOT_CONNECTED
            return self.last_error

        deadline = time.monotonic() + timeout
        try:
            while True:
                available = self._bytes_available()
                if available >= size:
                    return 0
                if time.monotonic() >= deadline:
                    # Timeout — flush whatever is in the buffer
                    if available > 0:
                        try:
                            self._sock.recv(available)
                        except OSError:
                            pass
                    self.last_error = ERR_TCP_DATA_RECEIVE
                    return self.last_error
                time.sleep(0.002)  # 2 ms polling interval (matches C#)
        except OSError:
            self.last_error = ERR_TCP_DATA_RECEIVE
        return self.last_error

    def _bytes_available(self) -> int:
        """Return the number of bytes waiting in the receive buffer."""
        if self._sock is None:
            return 0
        # Use non-blocking peek to determine available bytes.
        try:
            self._sock.setblocking(False)
            data = self._sock.recv(65536, socket.MSG_PEEK)
            return len(data)
        except BlockingIOError:
            return 0
        except OSError:
            return 0
        finally:
            if self._sock is not None:
                self._sock.setblocking(True)

    def receive(self, buffer: bytearray, start: int, size: int) -> int:
        """Receive exactly *size* bytes into *buffer* at *start*.

        Blocks until all bytes arrive or the read timeout expires.
        Returns an error code (0 on success).
        """
        self.last_error = self._wait_for_data(size, self._read_timeout)
        if self.last_error != 0:
            return self.last_error
        try:
            assert self._sock is not None
            view = memoryview(buffer)
            total = 0
            while total < size:
                chunk = self._sock.recv(size - total)
                if not chunk:
                    # Connection closed by peer
                    self.last_error = ERR_TCP_DATA_RECEIVE
                    self.close()
                    return self.last_error
                view[start + total:start + total + len(chunk)] = chunk
                total += len(chunk)
        except OSError:
            self.last_error = ERR_TCP_DATA_RECEIVE
        return self.last_error

    def send(self, data: bytes | bytearray, size: int) -> int:
        """Send *size* bytes from *data*."""
        self.last_error = 0
        if self._sock is None:
            self.last_error = ERR_TCP_NOT_CONNECTED
            return self.last_error
        try:
            self._sock.settimeout(self._write_timeout)
            self._sock.sendall(data[:size])
            self._sock.settimeout(None)
        except (OSError, socket.timeout):
            self.last_error = ERR_TCP_DATA_SEND
            self.close()
        return self.last_error

    # -- properties ----------------------------------------------------------

    @property
    def connected(self) -> bool:
        if self._sock is None:
            return False
        # Quick liveness check — peek for 0 bytes
        try:
            self._sock.setblocking(False)
            data = self._sock.recv(1, socket.MSG_PEEK)
            # If recv returns b'', the peer closed the connection.
            if data == b'':
                self._sock.setblocking(True)
                return False
        except BlockingIOError:
            pass  # No data available — socket still alive
        except OSError:
            return False
        finally:
            if self._sock is not None:
                try:
                    self._sock.setblocking(True)
                except OSError:
                    pass
        return True

    @property
    def read_timeout(self) -> float:
        return self._read_timeout

    @read_timeout.setter
    def read_timeout(self, value: float) -> None:
        self._read_timeout = value

    @property
    def write_timeout(self) -> float:
        return self._write_timeout

    @write_timeout.setter
    def write_timeout(self, value: float) -> None:
        self._write_timeout = value

    @property
    def connect_timeout(self) -> float:
        return self._connect_timeout

    @connect_timeout.setter
    def connect_timeout(self, value: float) -> None:
        self._connect_timeout = value
