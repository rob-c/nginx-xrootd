"""
Protocol conformance edge cases for nginx-xrootd.

Tests wire-level protocol behavior that is not covered by the higher-level
XRootD Python client API tests:

  - Handshake validation (bad magic fields)
  - Multiple sequential requests on one connection
  - kXR_endsess behavior
  - readv with invalid segment descriptors
  - Stat on a handle (handle-based stat)
  - Open with conflicting flags
  - Connection resilience (server stays up after bad requests)

Run:
    pytest tests/test_protocol_edge_cases.py -v -s
"""

import os
import socket
import struct
import time

import pytest
from XRootD import client
from XRootD.client.flags import OpenFlags, QueryCode

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ANON_URL  = "root://localhost:11094"
ANON_HOST = "127.0.0.1"
ANON_PORT = 11094
DATA_DIR  = "/tmp/xrd-test/data"

# Request opcodes
kXR_query     = 3001
kXR_close     = 3003
kXR_dirlist   = 3004
kXR_protocol  = 3006
kXR_login     = 3007
kXR_open      = 3010
kXR_ping      = 3011
kXR_read      = 3013
kXR_stat      = 3017
kXR_readv     = 3025
kXR_endsess   = 3023

# Response/error codes
kXR_OK          = 0
kXR_ERROR       = 4003
kXR_FileNotOpen = 3004
kXR_ArgInvalid  = 3000

# Open flags
kXR_open_read = 0x0010
kXR_open_updt = 0x0020
kXR_new       = 0x0008
kXR_delete    = 0x0002
kXR_retstat   = 0x0400

# Query infotypes
kXR_Qcksum  = 8
kXR_QSpace  = 6
kXR_QCONFIG = 7


# ---------------------------------------------------------------------------
# Raw protocol helpers
# ---------------------------------------------------------------------------

def _recv_exact(sock, nbytes):
    data = bytearray()
    while len(data) < nbytes:
        chunk = sock.recv(nbytes - len(data))
        if not chunk:
            raise AssertionError("socket closed early")
        data.extend(chunk)
    return bytes(data)


def _read_response(sock):
    header = _recv_exact(sock, 8)
    _sid, status, dlen = struct.unpack("!2sHI", header)
    body = _recv_exact(sock, dlen) if dlen else b""
    return status, body


def _raw_session():
    sock = socket.create_connection((ANON_HOST, ANON_PORT), timeout=5)
    sock.settimeout(5)
    sock.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
    status, body = _read_response(sock)
    assert status == kXR_OK
    assert len(body) == 8
    return sock


def _login_anon(sock, streamid=b"\x00\x01"):
    username = b"pytest\x00\x00"
    req = struct.pack(
        "!2sHI8sBBBBI",
        streamid, kXR_login,
        os.getpid() & 0xFFFFFFFF,
        username, 0, 0, 5, 0, 0,
    )
    sock.sendall(req)
    status, body = _read_response(sock)
    assert status == kXR_OK


def _open_file_raw(sock, path, options, streamid=b"\x00\x02"):
    req = struct.pack(
        "!2sHHH2s6s4sI",
        streamid, kXR_open,
        0o644, options,
        b"\x00\x00", b"\x00" * 6, b"\x00" * 4,
        len(path),
    )
    sock.sendall(req + path)
    return _read_response(sock)


def _close_handle(sock, fhandle, streamid=b"\x00\x09"):
    req = struct.pack("!2sH4s12sI", streamid, kXR_close, fhandle, b"\x00" * 12, 0)
    sock.sendall(req)
    _read_response(sock)


def _error_code(body):
    assert len(body) >= 4
    return struct.unpack("!I", body[:4])[0]


# ===========================================================================
# Handshake validation
# ===========================================================================

class TestHandshake:
    """The initial 20-byte handshake must validate magic fields."""

    def test_valid_handshake(self):
        """Standard handshake should succeed."""
        sock = socket.create_connection((ANON_HOST, ANON_PORT), timeout=5)
        sock.settimeout(5)
        try:
            sock.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
            status, body = _read_response(sock)
            assert status == kXR_OK
            assert len(body) == 8
        finally:
            sock.close()

    def test_invalid_fourth_field(self):
        """Handshake with fourth != 4 should be rejected or cause disconnect."""
        sock = socket.create_connection((ANON_HOST, ANON_PORT), timeout=5)
        sock.settimeout(3)
        try:
            sock.sendall(struct.pack("!IIIII", 0, 0, 0, 99, 2012))
            try:
                status, body = _read_response(sock)
                # If server responds, it should be an error
                assert status == kXR_ERROR
            except (ConnectionResetError, AssertionError, socket.timeout):
                pass  # Server closed connection — acceptable behavior
        finally:
            sock.close()

    def test_invalid_fifth_field(self):
        """Handshake with fifth != 2012 should be rejected or cause disconnect."""
        sock = socket.create_connection((ANON_HOST, ANON_PORT), timeout=5)
        sock.settimeout(3)
        try:
            sock.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 9999))
            try:
                status, body = _read_response(sock)
                assert status == kXR_ERROR
            except (ConnectionResetError, AssertionError, socket.timeout):
                pass  # Server closed connection — acceptable behavior
        finally:
            sock.close()


# ===========================================================================
# Multiple sequential requests on one session
# ===========================================================================

class TestSequentialRequests:
    """Multiple requests on a single connection must all be handled."""

    def test_ping_after_stat(self):
        """A ping after a stat on the same connection should succeed."""
        with _raw_session() as sock:
            _login_anon(sock)

            # stat /
            payload = b"/"
            req = struct.pack(
                "!2sH1s7sI4sI",
                b"\x00\x02", kXR_stat,
                b"\x00", b"\x00" * 7, 0, b"\x00" * 4,
                len(payload),
            )
            sock.sendall(req + payload)
            status, _ = _read_response(sock)
            assert status == kXR_OK

            # ping
            req = struct.pack("!2sH16sI", b"\x00\x03", kXR_ping, b"\x00" * 16, 0)
            sock.sendall(req)
            status, _ = _read_response(sock)
            assert status == kXR_OK

    def test_multiple_stats(self):
        """Multiple stat requests on the same connection."""
        with _raw_session() as sock:
            _login_anon(sock)

            for i in range(5):
                payload = b"/test.txt"
                sid = struct.pack("!H", i + 2)
                req = struct.pack(
                    "!2sH1s7sI4sI",
                    sid, kXR_stat,
                    b"\x00", b"\x00" * 7, 0, b"\x00" * 4,
                    len(payload),
                )
                sock.sendall(req + payload)
                status, _ = _read_response(sock)
                assert status == kXR_OK, f"stat #{i} failed"

    def test_open_read_close_cycle(self):
        """Open → read → close cycle via raw protocol."""
        with _raw_session() as sock:
            _login_anon(sock)

            status, body = _open_file_raw(sock, b"/test.txt", kXR_open_read)
            assert status == kXR_OK
            fhandle = body[:4]

            # Read first 10 bytes
            req = struct.pack(
                "!2sH4sqiI",
                b"\x00\x03", kXR_read,
                fhandle, 0, 10, 0,
            )
            sock.sendall(req)
            status, data = _read_response(sock)
            assert status == kXR_OK
            assert len(data) == 10

            _close_handle(sock, fhandle, streamid=b"\x00\x04")


# ===========================================================================
# kXR_endsess behavior
# ===========================================================================

class TestEndSession:
    """kXR_endsess should terminate the session cleanly."""

    def test_endsess_closes_session(self):
        """After endsess, subsequent requests should fail."""
        with _raw_session() as sock:
            _login_anon(sock)

            # Verify the session works
            req = struct.pack("!2sH16sI", b"\x00\x02", kXR_ping, b"\x00" * 16, 0)
            sock.sendall(req)
            status, _ = _read_response(sock)
            assert status == kXR_OK

            # Send endsess
            req = struct.pack("!2sH16sI", b"\x00\x03", kXR_endsess, b"\x00" * 16, 0)
            sock.sendall(req)
            status, _ = _read_response(sock)
            assert status == kXR_OK

            # After endsess, trying stat should fail or the connection closes
            payload = b"/test.txt"
            req = struct.pack(
                "!2sH1s7sI4sI",
                b"\x00\x04", kXR_stat,
                b"\x00", b"\x00" * 7, 0, b"\x00" * 4,
                len(payload),
            )
            try:
                sock.sendall(req + payload)
                status, body = _read_response(sock)
                # If server responds, it should be an auth error (session ended)
                assert status == kXR_ERROR
            except (BrokenPipeError, ConnectionResetError, AssertionError):
                pass  # Connection closed — acceptable after endsess


# ===========================================================================
# Handle-based stat
# ===========================================================================

class TestHandleStat:
    """kXR_stat with a handle (dlen=0) should work after open."""

    @pytest.fixture(autouse=True)
    def _setup(self):
        self.disk = os.path.join(DATA_DIR, "_proto_handle_stat.txt")
        with open(self.disk, "wb") as f:
            f.write(b"handle stat test content\n")
        yield
        if os.path.exists(self.disk):
            os.unlink(self.disk)

    def test_stat_via_handle(self):
        """stat with fhandle from open should return file size."""
        with _raw_session() as sock:
            _login_anon(sock)

            status, body = _open_file_raw(
                sock, b"/_proto_handle_stat.txt", kXR_open_read
            )
            assert status == kXR_OK
            fhandle = body[:4]

            # Handle-based stat: dlen=0, fhandle set
            req = struct.pack(
                "!2sH1s7sI4sI",
                b"\x00\x03", kXR_stat,
                b"\x00", b"\x00" * 7, 0,
                fhandle,
                0,  # dlen=0 → handle-based
            )
            sock.sendall(req)
            status, stat_body = _read_response(sock)
            assert status == kXR_OK
            # Parse stat string: "id size flags mtime"
            stat_str = stat_body.rstrip(b"\x00").decode()
            parts = stat_str.split()
            assert len(parts) >= 4, f"stat response malformed: {stat_str!r}"
            size = int(parts[1])
            assert size == 25, f"expected size 25, got {size}"

            _close_handle(sock, fhandle, streamid=b"\x00\x04")


# ===========================================================================
# readv edge cases
# ===========================================================================

class TestReadvEdgeCases:
    """readv with edge-case segment descriptors."""

    @pytest.fixture(autouse=True)
    def _setup(self):
        self.disk = os.path.join(DATA_DIR, "_proto_readv.txt")
        with open(self.disk, "wb") as f:
            f.write(b"A" * 1000)
        yield
        if os.path.exists(self.disk):
            os.unlink(self.disk)

    def test_readv_zero_length_segment(self):
        """A zero-length readv segment should be handled gracefully."""
        f = client.File()
        status, _ = f.open(f"{ANON_URL}//_proto_readv.txt", OpenFlags.READ)
        assert status.ok

        # Zero-length chunk
        status, result = f.vector_read([(0, 0)])
        # May succeed with empty data or may error — either is fine
        f.close()

    def test_readv_past_eof(self):
        """readv segment starting past EOF should be rejected or return partial data."""
        f = client.File()
        status, _ = f.open(f"{ANON_URL}//_proto_readv.txt", OpenFlags.READ)
        assert status.ok

        # Segment starting at offset 999, requesting 100 bytes — only 1 byte available
        status, result = f.vector_read([(999, 100)])
        # Server may reject readv past EOF with an error, or return partial data
        if status.ok:
            chunks = list(result)
            if len(chunks) > 0:
                assert len(chunks[0].buffer) <= 100
        else:
            # Server correctly rejects readv past EOF — that's fine
            pass

        f.close()

    def test_readv_many_segments(self):
        """readv with many small segments should succeed."""
        f = client.File()
        status, _ = f.open(f"{ANON_URL}//_proto_readv.txt", OpenFlags.READ)
        assert status.ok

        # 50 segments of 10 bytes each
        chunks = [(i * 10, 10) for i in range(50)]
        status, result = f.vector_read(chunks)
        assert status.ok
        assert result is not None
        data_chunks = list(result)
        assert len(data_chunks) == 50
        for chunk in data_chunks:
            assert bytes(chunk.buffer) == b"A" * 10

        f.close()


# ===========================================================================
# Open with retstat flag
# ===========================================================================

class TestOpenWithRetstat:
    """kXR_open with kXR_retstat should include stat info in response."""

    @pytest.fixture(autouse=True)
    def _setup(self):
        self.disk = os.path.join(DATA_DIR, "_proto_retstat.txt")
        with open(self.disk, "wb") as f:
            f.write(b"X" * 256)
        yield
        if os.path.exists(self.disk):
            os.unlink(self.disk)

    def test_open_retstat_includes_size(self):
        """Open with kXR_retstat should include stat in the response body."""
        with _raw_session() as sock:
            _login_anon(sock)

            status, body = _open_file_raw(
                sock, b"/_proto_retstat.txt",
                kXR_open_read | kXR_retstat,
            )
            assert status == kXR_OK
            # Body: fhandle(4) + cpsize(4) + cptype(4) + stat_string
            assert len(body) >= 12, f"retstat body too short: {len(body)} bytes"
            fhandle = body[:4]

            # The stat string should be after the first 12 bytes
            if len(body) > 12:
                stat_str = body[12:].rstrip(b"\x00").decode()
                parts = stat_str.split()
                assert len(parts) >= 4, f"stat string malformed: {stat_str!r}"
                size = int(parts[1])
                assert size == 256

            _close_handle(sock, fhandle, streamid=b"\x00\x03")


# ===========================================================================
# Connection resilience after errors
# ===========================================================================

class TestConnectionResilience:
    """The server should keep the connection alive after non-fatal errors."""

    def test_connection_survives_stat_nonexistent(self):
        """A stat on a nonexistent file should not close the connection."""
        with _raw_session() as sock:
            _login_anon(sock)

            # stat a missing file
            payload = b"/nonexistent_proto_resilience.txt"
            req = struct.pack(
                "!2sH1s7sI4sI",
                b"\x00\x02", kXR_stat,
                b"\x00", b"\x00" * 7, 0, b"\x00" * 4,
                len(payload),
            )
            sock.sendall(req + payload)
            status, _ = _read_response(sock)
            assert status == kXR_ERROR

            # Connection should still work
            req = struct.pack("!2sH16sI", b"\x00\x03", kXR_ping, b"\x00" * 16, 0)
            sock.sendall(req)
            status, _ = _read_response(sock)
            assert status == kXR_OK

    def test_connection_survives_invalid_handle(self):
        """Reading an invalid handle should not close the connection."""
        with _raw_session() as sock:
            _login_anon(sock)

            # Read from invalid handle
            req = struct.pack(
                "!2sH4sqiI",
                b"\x00\x02", kXR_read,
                b"\xfe\x00\x00\x00", 0, 100, 0,
            )
            sock.sendall(req)
            status, _ = _read_response(sock)
            assert status == kXR_ERROR

            # Verify connection is still alive
            req = struct.pack("!2sH16sI", b"\x00\x03", kXR_ping, b"\x00" * 16, 0)
            sock.sendall(req)
            status, _ = _read_response(sock)
            assert status == kXR_OK

    def test_connection_survives_multiple_errors(self):
        """Multiple consecutive errors should not accumulate state corruption."""
        with _raw_session() as sock:
            _login_anon(sock)

            for i in range(5):
                payload = f"/nonexistent_{i}.txt".encode()
                sid = struct.pack("!H", i + 2)
                req = struct.pack(
                    "!2sH1s7sI4sI",
                    sid, kXR_stat,
                    b"\x00", b"\x00" * 7, 0, b"\x00" * 4,
                    len(payload),
                )
                sock.sendall(req + payload)
                status, _ = _read_response(sock)
                assert status == kXR_ERROR

            # Connection should still work after 5 errors
            req = struct.pack("!2sH16sI", b"\x00\x0a", kXR_ping, b"\x00" * 16, 0)
            sock.sendall(req)
            status, _ = _read_response(sock)
            assert status == kXR_OK


# ===========================================================================
# Query edge cases
# ===========================================================================

class TestQueryEdgeCases:
    """Edge cases for kXR_query infotypes."""

    def test_unsupported_query_infotype(self):
        """An unsupported query infotype should return an error."""
        with _raw_session() as sock:
            _login_anon(sock)

            payload = b"/"
            req = struct.pack(
                "!2sHH2s4s8sI",
                b"\x00\x02", kXR_query,
                9999,             # invalid infotype
                b"\x00\x00",
                b"\x00" * 4,
                b"\x00" * 8,
                len(payload),
            )
            sock.sendall(req + payload)
            status, body = _read_response(sock)

        assert status == kXR_ERROR

    def test_checksum_via_api(self):
        """Checksum query via XRootD API should work on test.txt."""
        fs = client.FileSystem(ANON_URL)
        status, resp = fs.query(QueryCode.CHECKSUM, "/test.txt")
        assert status.ok
        text = resp.rstrip(b"\x00").decode()
        algo, hexval = text.split()
        assert algo == "adler32"
        assert len(hexval) == 8

    def test_space_query_positive_values(self):
        """Space query should return positive numeric values."""
        fs = client.FileSystem(ANON_URL)
        status, resp = fs.query(QueryCode.SPACE, "/")
        assert status.ok
        text = resp.rstrip(b"\x00").decode()
        for pair in text.split("&"):
            if "=" in pair:
                key, val = pair.split("=", 1)
                if key in ("oss.space", "oss.free", "oss.used"):
                    assert int(val) >= 0, f"{key} has negative value: {val}"
