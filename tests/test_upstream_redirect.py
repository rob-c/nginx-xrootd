"""
Tests for upstream XRootD redirector support (kXR_redirect, kXR_wait,
kXR_waitresp).

nginx-xrootd can be configured with `xrootd_upstream host:port` so that
when a client requests a file that does not exist locally, nginx connects
to the upstream redirector, relays the request, and forwards the response
back to the client.

A lightweight Python mock redirector handles the upstream side of each
test scenario so no real XRootD installation is needed.
"""

import os
import socket
import struct
import threading
import time
import pytest

from settings import NGINX_BIN
import server_control

# ------------------------------------------------------------------ #
# XRootD wire constants                                                #
# ------------------------------------------------------------------ #

kXR_ok       = 0
kXR_error    = 4003
kXR_redirect = 4004
kXR_wait     = 4005
kXR_waitresp = 4006

kXR_protocol = 3006
kXR_login    = 3007
kXR_locate   = 3027

# ------------------------------------------------------------------ #
# Wire helpers                                                         #
# ------------------------------------------------------------------ #

def _build_resp_hdr(streamid: bytes, status: int, dlen: int) -> bytes:
    return struct.pack(">2sHI", streamid, status, dlen)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise RuntimeError(
                f"connection closed expecting {n} bytes, got {len(buf)}")
        buf += chunk
    return buf


def _read_response(sock: socket.socket):
    hdr    = _recv_exact(sock, 8)
    status = struct.unpack(">H", hdr[2:4])[0]
    dlen   = struct.unpack(">I", hdr[4:8])[0]
    body   = _recv_exact(sock, dlen) if dlen else b""
    return status, body


def _xrd_handshake_login(host: str, port: int) -> socket.socket:
    """Full XRootD bootstrap: handshake + kXR_protocol + kXR_login."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect((host, port))
    # Handshake
    sock.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))
    # kXR_protocol
    sock.sendall(struct.pack(">BB H I BB 10x I",
                             0, 1, kXR_protocol, 0x00000520, 0x02, 0x03, 0))
    _recv_exact(sock, 16)         # handshake response
    _read_response(sock)          # protocol response
    # kXR_login
    sock.sendall(struct.pack(">BB H I 8s BB B B I",
                             0, 1, kXR_login, 0,
                             b"test\x00\x00\x00\x00",
                             0, 0, 5, 0, 0))
    _read_response(sock)          # login response
    return sock


def _send_locate(sock: socket.socket, path: str):
    payload = path.encode() + b"\x00"
    hdr = struct.pack(">BB H H 14x I",
                      0, 1, kXR_locate, 0, len(payload))
    sock.sendall(hdr + payload)


def _make_redirect_body(host: str, port: int) -> bytes:
    return struct.pack(">I", port) + host.encode()


# ------------------------------------------------------------------ #
# Mock upstream redirector                                             #
# ------------------------------------------------------------------ #

class MockUpstream:
    """
    Listens on a random port, accepts one connection, completes the
    XRootD bootstrap, reads one client request, then runs ``handler``
    which returns a list of (status, body) tuples to send back.

    For multi-response scenarios (kXR_wait retry, kXR_waitresp), pass
    a ``handler`` that returns multiple tuples — they are all sent in
    sequence on the same connection.
    """

    def __init__(self, handler):
        self._handler  = handler
        self._sock     = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._port     = self._sock.getsockname()[1]
        self._errors   = []
        self._sock.listen(5)
        t = threading.Thread(target=self._serve, daemon=True)
        t.start()

    @property
    def port(self):
        return self._port

    def _bootstrap(self, conn):
        # Handshake (20 bytes)
        _recv_exact(conn, 20)
        conn.sendall(struct.pack(">2sHI", b"\x00\x00", kXR_ok, 8))
        conn.sendall(struct.pack(">II", 0x00000520, 1))
        # kXR_protocol (24 bytes)
        hdr = _recv_exact(conn, 24)
        sid = hdr[:2]
        conn.sendall(_build_resp_hdr(sid, kXR_ok, 8))
        conn.sendall(struct.pack(">II", 0x00000520, 1))
        # kXR_login (24 bytes + optional payload)
        hdr  = _recv_exact(conn, 24)
        sid  = hdr[:2]
        dlen = struct.unpack(">I", hdr[20:24])[0]
        if dlen:
            _recv_exact(conn, dlen)
        conn.sendall(_build_resp_hdr(sid, kXR_ok, 16))
        conn.sendall(b"\x01" * 16)

    def _read_one_request(self, conn):
        hdr    = _recv_exact(conn, 24)
        req_sid    = hdr[:2]
        req_opcode = struct.unpack(">H", hdr[2:4])[0]
        req_dlen   = struct.unpack(">I", hdr[20:24])[0]
        payload    = _recv_exact(conn, req_dlen) if req_dlen else b""
        path       = payload.rstrip(b"\x00").decode(errors="replace")
        return req_sid, req_opcode, path

    def _serve(self):
        try:
            conn, _ = self._sock.accept()
            conn.settimeout(5)
            self._bootstrap(conn)
            req_sid, opcode, path = self._read_one_request(conn)
            responses = self._handler(opcode, path)
            for status, body in responses:
                conn.sendall(_build_resp_hdr(req_sid, status, len(body)))
                if body:
                    conn.sendall(body)
            conn.close()
        except Exception as exc:
            self._errors.append(str(exc))
        finally:
            try:
                self._sock.close()
            except Exception:
                pass


# ------------------------------------------------------------------ #
# nginx config template used by all upstream tests                    #
# ------------------------------------------------------------------ #

UPSTREAM_CONF = """\
worker_processes 1;
error_log {LOG_DIR}/error.log info;
pid       {LOG_DIR}/nginx.pid;

events { worker_connections 128; }

stream {
    server {
        listen 127.0.0.1:{PORT};
        xrootd on;
        xrootd_root {DATA_DIR};
        xrootd_upstream 127.0.0.1:{UPSTREAM_PORT};
    }
}
"""


# ------------------------------------------------------------------ #
# Tests                                                                #
# ------------------------------------------------------------------ #

class TestUpstreamRedirect:

    def _start(self, upstream_port: int) -> dict:
        if not os.path.exists(NGINX_BIN):
            pytest.skip(f"nginx binary not found at {NGINX_BIN}")
        return server_control.start_nginx_instance(
            conf_text=UPSTREAM_CONF,
            template_kwargs={"UPSTREAM_PORT": upstream_port},
        )

    def test_locate_redirected(self):
        """Upstream returns kXR_redirect → client receives the redirect."""
        target_host = "storage.example.org"
        target_port = 1094

        mock = MockUpstream(
            lambda opcode, path: [
                (kXR_redirect, _make_redirect_body(target_host, target_port))
            ]
        )

        info = self._start(mock.port)
        try:
            sock = _xrd_handshake_login("127.0.0.1", info["port"])
            _send_locate(sock, "/data/file.root")
            status, body = _read_response(sock)
            sock.close()
        finally:
            info["stop"]()

        assert not mock._errors, f"mock upstream error: {mock._errors}"
        assert status == kXR_redirect, f"expected kXR_redirect, got {status}"
        assert len(body) >= 4
        got_port = struct.unpack(">I", body[:4])[0]
        got_host = body[4:].decode()
        assert got_port == target_port
        assert got_host == target_host

    def test_locate_wait_then_redirect(self):
        """Upstream returns kXR_wait(1), then kXR_redirect on retry."""
        target_host = "retry.example.org"
        target_port = 2094

        # Return wait on first request, redirect on second
        call_no = [0]

        def handler(opcode, path):
            call_no[0] += 1
            if call_no[0] == 1:
                return [(kXR_wait, struct.pack(">I", 1))]
            return [(kXR_redirect, _make_redirect_body(target_host, target_port))]

        # MockUpstream only handles one request per connection; for the retry,
        # build a mock that handles two requests on the same connection.
        class TwoRequestMock:
            def __init__(self):
                self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self._sock.bind(("127.0.0.1", 0))
                self._port = self._sock.getsockname()[1]
                self._sock.listen(5)
                self.errors = []
                t = threading.Thread(target=self._serve, daemon=True)
                t.start()

            @property
            def port(self):
                return self._port

            def _serve(self):
                try:
                    conn, _ = self._sock.accept()
                    conn.settimeout(10)
                    # bootstrap
                    _recv_exact(conn, 20)
                    conn.sendall(struct.pack(">2sHI", b"\x00\x00", kXR_ok, 8))
                    conn.sendall(struct.pack(">II", 0x00000520, 1))
                    hdr = _recv_exact(conn, 24)
                    sid = hdr[:2]
                    conn.sendall(_build_resp_hdr(sid, kXR_ok, 8))
                    conn.sendall(struct.pack(">II", 0x00000520, 1))
                    hdr = _recv_exact(conn, 24)
                    sid = hdr[:2]
                    dlen = struct.unpack(">I", hdr[20:24])[0]
                    if dlen:
                        _recv_exact(conn, dlen)
                    conn.sendall(_build_resp_hdr(sid, kXR_ok, 16))
                    conn.sendall(b"\x01" * 16)

                    # First request → kXR_wait(1 second)
                    hdr = _recv_exact(conn, 24)
                    req_sid = hdr[:2]
                    dlen = struct.unpack(">I", hdr[20:24])[0]
                    if dlen:
                        _recv_exact(conn, dlen)
                    conn.sendall(_build_resp_hdr(req_sid, kXR_wait, 4))
                    conn.sendall(struct.pack(">I", 1))

                    # Second request (after nginx waits 1 s) → redirect
                    hdr = _recv_exact(conn, 24)
                    req_sid = hdr[:2]
                    dlen = struct.unpack(">I", hdr[20:24])[0]
                    if dlen:
                        _recv_exact(conn, dlen)
                    body = _make_redirect_body(target_host, target_port)
                    conn.sendall(_build_resp_hdr(req_sid, kXR_redirect, len(body)))
                    conn.sendall(body)
                    conn.close()
                except Exception as exc:
                    self.errors.append(str(exc))
                finally:
                    try:
                        self._sock.close()
                    except Exception:
                        pass

        if not os.path.exists(NGINX_BIN):
            pytest.skip(f"nginx binary not found at {NGINX_BIN}")

        mock = TwoRequestMock()
        info = self._start(mock.port)
        try:
            sock = _xrd_handshake_login("127.0.0.1", info["port"])
            _send_locate(sock, "/data/file.root")
            sock.settimeout(10)   # nginx waits 1 s internally before retry
            status, body = _read_response(sock)
            sock.close()
        finally:
            info["stop"]()

        assert not mock.errors, f"mock upstream error: {mock.errors}"
        assert status == kXR_redirect, \
            f"expected kXR_redirect after kXR_wait, got {status}"
        got_port = struct.unpack(">I", body[:4])[0]
        got_host = body[4:].decode()
        assert got_port == target_port
        assert got_host == target_host

    def test_locate_waitresp_then_redirect(self):
        """Upstream returns kXR_waitresp then kXR_redirect → client gets both."""
        target_host = "async.example.org"
        target_port = 3094

        # Serve kXR_waitresp immediately, then a brief pause, then redirect
        class WaitRespMock:
            def __init__(self):
                self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self._sock.bind(("127.0.0.1", 0))
                self._port = self._sock.getsockname()[1]
                self._sock.listen(5)
                self.errors = []
                t = threading.Thread(target=self._serve, daemon=True)
                t.start()

            @property
            def port(self):
                return self._port

            def _serve(self):
                try:
                    conn, _ = self._sock.accept()
                    conn.settimeout(5)
                    # bootstrap
                    _recv_exact(conn, 20)
                    conn.sendall(struct.pack(">2sHI", b"\x00\x00", kXR_ok, 8))
                    conn.sendall(struct.pack(">II", 0x00000520, 1))
                    hdr = _recv_exact(conn, 24)
                    sid = hdr[:2]
                    conn.sendall(_build_resp_hdr(sid, kXR_ok, 8))
                    conn.sendall(struct.pack(">II", 0x00000520, 1))
                    hdr = _recv_exact(conn, 24)
                    sid = hdr[:2]
                    dlen = struct.unpack(">I", hdr[20:24])[0]
                    if dlen:
                        _recv_exact(conn, dlen)
                    conn.sendall(_build_resp_hdr(sid, kXR_ok, 16))
                    conn.sendall(b"\x01" * 16)
                    # Read request
                    hdr = _recv_exact(conn, 24)
                    req_sid = hdr[:2]
                    dlen = struct.unpack(">I", hdr[20:24])[0]
                    if dlen:
                        _recv_exact(conn, dlen)
                    # kXR_waitresp (dlen=0)
                    conn.sendall(_build_resp_hdr(req_sid, kXR_waitresp, 0))
                    # Brief async delay, then the actual redirect
                    time.sleep(0.1)
                    body = _make_redirect_body(target_host, target_port)
                    conn.sendall(_build_resp_hdr(req_sid, kXR_redirect, len(body)))
                    conn.sendall(body)
                    conn.close()
                except Exception as exc:
                    self.errors.append(str(exc))
                finally:
                    try:
                        self._sock.close()
                    except Exception:
                        pass

        if not os.path.exists(NGINX_BIN):
            pytest.skip(f"nginx binary not found at {NGINX_BIN}")

        mock = WaitRespMock()
        info = self._start(mock.port)
        try:
            sock = _xrd_handshake_login("127.0.0.1", info["port"])
            _send_locate(sock, "/data/file.root")
            sock.settimeout(5)
            status1, _body1 = _read_response(sock)
            status2, body2  = _read_response(sock)
            sock.close()
        finally:
            info["stop"]()

        assert not mock.errors, f"mock upstream error: {mock.errors}"
        assert status1 == kXR_waitresp, \
            f"expected kXR_waitresp first, got {status1}"
        assert status2 == kXR_redirect, \
            f"expected kXR_redirect second, got {status2}"
        got_port = struct.unpack(">I", body2[:4])[0]
        got_host = body2[4:].decode()
        assert got_port == target_port
        assert got_host == target_host

    def test_upstream_error_forwarded(self):
        """Upstream kXR_error is forwarded verbatim to the client."""
        err_code = 3011  # kXR_NotFound

        mock = MockUpstream(
            lambda opcode, path: [
                (kXR_error,
                 struct.pack(">I", err_code) + b"file not found\x00")
            ]
        )

        info = self._start(mock.port)
        try:
            sock = _xrd_handshake_login("127.0.0.1", info["port"])
            _send_locate(sock, "/data/missing.root")
            status, body = _read_response(sock)
            sock.close()
        finally:
            info["stop"]()

        assert not mock._errors, f"mock upstream error: {mock._errors}"
        assert status == kXR_error, f"expected kXR_error, got {status}"
        assert len(body) >= 4
        assert struct.unpack(">I", body[:4])[0] == err_code
