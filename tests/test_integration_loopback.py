"""
Loopback integration tests — full TCP → COTP → TLS stack with a local mock server.

These tests spin up a real TCP server on localhost, connect the Python client
to it, and verify that the COTP handshake and TLS encryption/decryption work
end-to-end.  No PLC required.

Test architecture:
    Client (our code)                Mock PLC Server (this test)
    ─────────────────                ─────────────────────────
    TCP connect ─────────────────→   accept()
    ISO CR (COTP) ───────────────→   recv CR, send CC
    TPKT/COTP DT ────────────────→   recv frame, unwrap, echo
    TLS ClientHello ─────────────→   recv, do TLS handshake
    encrypted data ──────────────→   decrypt, echo back encrypted
"""

import os
import socket
import ssl
import struct
import tempfile
import threading
import time
import pytest

from s7commplus.transport.tcp_socket import MsgSocket
from s7commplus.transport.cotp import COTPTransport, ISO_HEADER_SIZE
from s7commplus.transport.tls import TLSOverCOTP
from s7commplus.protocol.s7p import encode_header
from s7commplus.protocol.constants import ProtocolVersion


# ===================================================================
# Helpers — Mock PLC Server
# ===================================================================

def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """Receive exactly n bytes from a socket."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed")
        buf += chunk
    return buf


def _recv_tpkt_frame(sock: socket.socket) -> bytes:
    """Receive one complete TPKT frame and return the raw bytes."""
    header = _recv_exact(sock, 4)
    total_len = struct.unpack_from(">H", header, 2)[0]
    rest = _recv_exact(sock, total_len - 4)
    return header + rest


def _send_tpkt_frame(sock: socket.socket, payload: bytes) -> None:
    """Wrap payload in TPKT+COTP-DT and send."""
    total = ISO_HEADER_SIZE + len(payload)
    frame = bytearray(total)
    frame[0] = 0x03
    frame[1] = 0x00
    struct.pack_into(">H", frame, 2, total)
    frame[4] = 0x02
    frame[5] = 0xF0
    frame[6] = 0x80
    frame[7:] = payload
    sock.sendall(frame)


def _build_iso_cc() -> bytes:
    """Build a Connection Confirm (CC) response, total 36 bytes."""
    resp = bytearray(36)
    resp[0] = 0x03
    resp[1] = 0x00
    struct.pack_into(">H", resp, 2, 36)
    resp[4] = 0x02
    resp[5] = 0xD0  # CC
    resp[6] = 0x80
    return bytes(resp)


def _generate_self_signed_cert(cert_path: str, key_path: str) -> None:
    """Generate a self-signed certificate for the mock server.

    Uses Python's ssl module with OpenSSL to create a minimal cert.
    """
    # Use openssl CLI (available in most Linux environments)
    import subprocess
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", key_path, "-out", cert_path,
        "-days", "1", "-nodes",
        "-subj", "/CN=MockPLC",
    ], check=True, capture_output=True)


class MockPLCServer:
    """A minimal mock S7 PLC server for loopback testing.

    Supports:
    - COTP connection (CR → CC)
    - COTP data frame echo (unwrap, echo payload back in a COTP frame)
    - TLS handshake (server-side) and encrypted echo
    """

    def __init__(self, port: int = 0, enable_tls: bool = False):
        self._port = port
        self._enable_tls = enable_tls
        self._server_sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()
        self._stop = threading.Event()
        self._client_handler: threading.Thread | None = None
        self._cert_dir: tempfile.TemporaryDirectory | None = None
        self.actual_port: int = 0
        self.errors: list[str] = []
        self.received_payloads: list[bytes] = []

    def start(self) -> int:
        """Start the server.  Returns the port number."""
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind(("127.0.0.1", self._port))
        self._server_sock.listen(1)
        self._server_sock.settimeout(5.0)
        self.actual_port = self._server_sock.getsockname()[1]
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        self._ready.wait(timeout=5.0)
        return self.actual_port

    def stop(self) -> None:
        self._stop.set()
        if self._server_sock:
            self._server_sock.close()
        if self._thread:
            self._thread.join(timeout=5.0)
        if self._cert_dir:
            self._cert_dir.cleanup()

    def _accept_loop(self) -> None:
        self._ready.set()
        try:
            conn, _ = self._server_sock.accept()
            conn.settimeout(5.0)
            self._handle_client(conn)
            conn.close()
        except socket.timeout:
            pass
        except Exception as e:
            self.errors.append(f"accept: {e}")

    def _handle_client(self, conn: socket.socket) -> None:
        try:
            # Stage 1: COTP handshake
            cr_frame = _recv_tpkt_frame(conn)
            # Verify it's a CR (byte 5 should be 0xE0)
            if cr_frame[5] != 0xE0:
                self.errors.append(f"Expected CR (0xE0), got 0x{cr_frame[5]:02X}")
                return
            # Send CC response
            conn.sendall(_build_iso_cc())

            if self._enable_tls:
                self._handle_tls_client(conn)
            else:
                self._handle_cleartext_client(conn)
        except Exception as e:
            self.errors.append(f"handler: {e}")

    def _handle_cleartext_client(self, conn: socket.socket) -> None:
        """Echo loop for cleartext COTP frames."""
        for _ in range(10):  # max 10 exchanges
            if self._stop.is_set():
                break
            try:
                frame = _recv_tpkt_frame(conn)
                payload = frame[ISO_HEADER_SIZE:]
                self.received_payloads.append(payload)
                # Echo payload back in a COTP frame
                _send_tpkt_frame(conn, payload)
            except (socket.timeout, ConnectionError):
                break

    def _handle_tls_client(self, conn: socket.socket) -> None:
        """Handle TLS-over-COTP: unwrap COTP, do TLS handshake, echo encrypted."""
        # Generate self-signed cert
        self._cert_dir = tempfile.TemporaryDirectory()
        cert_path = os.path.join(self._cert_dir.name, "cert.pem")
        key_path = os.path.join(self._cert_dir.name, "key.pem")
        _generate_self_signed_cert(cert_path, key_path)

        # Create server-side SSL context
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_path, key_path)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3

        incoming_bio = ssl.MemoryBIO()
        outgoing_bio = ssl.MemoryBIO()
        ssl_obj = ctx.wrap_bio(incoming_bio, outgoing_bio, server_side=True)

        # TLS handshake over COTP frames
        handshake_done = False
        while not handshake_done and not self._stop.is_set():
            try:
                ssl_obj.do_handshake()
                handshake_done = True
            except ssl.SSLWantReadError:
                # Flush outgoing TLS data
                out_data = outgoing_bio.read()
                if out_data:
                    _send_tpkt_frame(conn, out_data)
                # Read incoming COTP frame with encrypted TLS data
                frame = _recv_tpkt_frame(conn)
                payload = frame[ISO_HEADER_SIZE:]
                incoming_bio.write(payload)

        # Flush any remaining handshake data
        out_data = outgoing_bio.read()
        if out_data:
            _send_tpkt_frame(conn, out_data)

        # Echo loop: read encrypted COTP, decrypt, re-encrypt, send back
        for _ in range(10):
            if self._stop.is_set():
                break
            try:
                frame = _recv_tpkt_frame(conn)
                payload = frame[ISO_HEADER_SIZE:]
                incoming_bio.write(payload)

                plaintext = ssl_obj.read(65536)
                self.received_payloads.append(plaintext)

                # Echo back encrypted
                ssl_obj.write(plaintext)
                out_data = outgoing_bio.read()
                if out_data:
                    _send_tpkt_frame(conn, out_data)
            except (socket.timeout, ConnectionError, ssl.SSLError):
                break


# ===================================================================
# Test: COTP-only loopback (no TLS)
# ===================================================================

class TestCOTPLoopback:
    """End-to-end test: TCP connect → COTP handshake → data echo."""

    def test_cotp_connect_and_echo(self):
        server = MockPLCServer()
        port = server.start()
        try:
            # Connect
            sock = MsgSocket()
            sock.connect_timeout = 2.0
            sock.read_timeout = 2.0
            err = sock.connect("127.0.0.1", port)
            assert err == 0, f"TCP connect failed: {err:#x}"

            # COTP handshake
            cotp = COTPTransport(sock)
            err = cotp.iso_connect(0x06, 0x00, b"SIMATIC-ROOT-HMI")
            assert err == 0, f"ISO connect failed: {err:#x}"

            # Send a test payload, receive echo
            test_payload = b"\x72\x01\x00\x04ABCD"
            err = cotp.send_iso_packet(test_payload)
            assert err == 0

            echo, err = cotp.recv_iso_packet()
            assert err == 0
            assert echo == test_payload

            sock.close()
        finally:
            server.stop()
        assert not server.errors, f"Server errors: {server.errors}"

    def test_cotp_multiple_exchanges(self):
        server = MockPLCServer()
        port = server.start()
        try:
            sock = MsgSocket()
            err = sock.connect("127.0.0.1", port)
            assert err == 0

            cotp = COTPTransport(sock)
            err = cotp.iso_connect()
            assert err == 0

            for i in range(5):
                payload = f"message-{i}".encode()
                cotp.send_iso_packet(payload)
                echo, err = cotp.recv_iso_packet()
                assert err == 0
                assert echo == payload

            sock.close()
        finally:
            server.stop()

    def test_cotp_s7commplus_pdu(self):
        """Send a realistic S7CommPlus PDU (header + InitSSL payload + trailer)."""
        server = MockPLCServer()
        port = server.start()
        try:
            sock = MsgSocket()
            err = sock.connect("127.0.0.1", port)
            assert err == 0

            cotp = COTPTransport(sock)
            err = cotp.iso_connect()
            assert err == 0

            # Build a realistic S7CommPlus PDU
            from s7commplus.protocol.s7p import (
                encode_byte, encode_uint16, encode_uint32,
            )
            from s7commplus.protocol.constants import Opcode, FunctionCode

            # InitSSL payload
            payload = bytearray()
            encode_byte(payload, Opcode.REQUEST)
            encode_uint16(payload, 0)
            encode_uint16(payload, FunctionCode.INIT_SSL)
            encode_uint16(payload, 0)
            encode_uint16(payload, 1)    # seq num
            encode_uint32(payload, 0)    # session id
            encode_byte(payload, 0x30)   # transport flags
            encode_uint32(payload, 0)    # fill

            # Wrap in S7CommPlus header + trailer
            pdu = bytearray()
            encode_header(pdu, ProtocolVersion.V1, len(payload))
            pdu.extend(payload)
            encode_header(pdu, ProtocolVersion.V1, 0)  # trailer

            err = cotp.send_iso_packet(bytes(pdu))
            assert err == 0

            echo, err = cotp.recv_iso_packet()
            assert err == 0
            assert echo == bytes(pdu)

            # Verify the server received it correctly
            assert len(server.received_payloads) == 1
            assert server.received_payloads[0] == bytes(pdu)

            sock.close()
        finally:
            server.stop()


# ===================================================================
# Test: TLS-over-COTP loopback
# ===================================================================

class TestTLSLoopback:
    """End-to-end test: TCP → COTP → TLS handshake → encrypted echo."""

    @pytest.fixture(autouse=True)
    def _check_openssl(self):
        """Skip if openssl CLI is not available."""
        import subprocess
        try:
            subprocess.run(
                ["openssl", "version"],
                capture_output=True, check=True,
            )
        except (FileNotFoundError, subprocess.CalledProcessError):
            pytest.skip("openssl CLI not available")

    def test_tls_handshake_and_echo(self):
        server = MockPLCServer(enable_tls=True)
        port = server.start()
        try:
            # TCP + COTP
            sock = MsgSocket()
            sock.read_timeout = 5.0
            err = sock.connect("127.0.0.1", port)
            assert err == 0

            cotp = COTPTransport(sock)
            err = cotp.iso_connect()
            assert err == 0

            # TLS handshake over COTP
            tls = TLSOverCOTP(cotp)
            err = tls.handshake()
            assert err == 0, f"TLS handshake failed: {err:#x}"
            assert tls.active

            # Send encrypted data, receive encrypted echo
            test_data = b"Hello from Python S7CommPlus client!"
            err = tls.send(test_data)
            assert err == 0

            plaintext, err = tls.recv()
            assert err == 0
            assert plaintext == test_data

            sock.close()
        finally:
            server.stop()
        assert not server.errors, f"Server errors: {server.errors}"

    def test_tls_multiple_messages(self):
        server = MockPLCServer(enable_tls=True)
        port = server.start()
        try:
            sock = MsgSocket()
            sock.read_timeout = 5.0
            err = sock.connect("127.0.0.1", port)
            assert err == 0

            cotp = COTPTransport(sock)
            err = cotp.iso_connect()
            assert err == 0

            tls = TLSOverCOTP(cotp)
            err = tls.handshake()
            assert err == 0

            for i in range(3):
                msg = f"encrypted-message-{i}".encode()
                tls.send(msg)
                echo, err = tls.recv()
                assert err == 0
                assert echo == msg

            sock.close()
        finally:
            server.stop()

    def test_tls_keylog(self):
        """Verify TLS key logging produces a Wireshark-compatible key log file."""
        server = MockPLCServer(enable_tls=True)
        port = server.start()

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".log", delete=False
        ) as f:
            keylog_path = f.name

        try:
            sock = MsgSocket()
            sock.read_timeout = 5.0
            err = sock.connect("127.0.0.1", port)
            assert err == 0

            cotp = COTPTransport(sock)
            err = cotp.iso_connect()
            assert err == 0

            # Pass keylog file to TLS layer
            tls = TLSOverCOTP(cotp, keylog_file=keylog_path)
            err = tls.handshake()
            assert err == 0

            # Send some data to generate key material
            tls.send(b"keylog test")
            tls.recv()

            sock.close()

            # Verify key log file was written
            with open(keylog_path) as f:
                content = f.read()

            # NSS Key Log format lines start with specific labels
            assert len(content) > 0, "Key log file is empty"
            lines = [l for l in content.strip().split("\n") if l and not l.startswith("#")]
            assert len(lines) > 0, "No key log entries found"
            # TLS 1.3 key log lines typically contain these labels
            valid_prefixes = (
                "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
                "SERVER_HANDSHAKE_TRAFFIC_SECRET",
                "CLIENT_TRAFFIC_SECRET_0",
                "SERVER_TRAFFIC_SECRET_0",
                "EXPORTER_SECRET",
            )
            for line in lines:
                assert any(
                    line.startswith(p) for p in valid_prefixes
                ), f"Unexpected key log line: {line}"

        finally:
            server.stop()
            os.unlink(keylog_path)

    def test_tls_s7commplus_pdu_encrypted(self):
        """Send a realistic S7CommPlus PDU through the TLS tunnel."""
        server = MockPLCServer(enable_tls=True)
        port = server.start()
        try:
            sock = MsgSocket()
            sock.read_timeout = 5.0
            err = sock.connect("127.0.0.1", port)
            assert err == 0

            cotp = COTPTransport(sock)
            cotp.iso_connect()

            tls = TLSOverCOTP(cotp)
            tls.handshake()

            # Build S7CommPlus InitSSL request PDU
            from s7commplus.protocol.s7p import encode_byte, encode_uint16, encode_uint32
            from s7commplus.protocol.constants import Opcode, FunctionCode

            payload = bytearray()
            encode_byte(payload, Opcode.REQUEST)
            encode_uint16(payload, 0)
            encode_uint16(payload, FunctionCode.INIT_SSL)
            encode_uint16(payload, 0)
            encode_uint16(payload, 1)
            encode_uint32(payload, 0)
            encode_byte(payload, 0x30)
            encode_uint32(payload, 0)

            pdu = bytearray()
            encode_header(pdu, ProtocolVersion.V1, len(payload))
            pdu.extend(payload)
            encode_header(pdu, ProtocolVersion.V1, 0)

            # Send through TLS
            err = tls.send(bytes(pdu))
            assert err == 0

            # Receive echo
            echo, err = tls.recv()
            assert err == 0
            assert echo == bytes(pdu)

            # Server should have received the decrypted PDU
            assert server.received_payloads[0] == bytes(pdu)

            sock.close()
        finally:
            server.stop()
