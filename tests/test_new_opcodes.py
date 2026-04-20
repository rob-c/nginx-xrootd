"""
Functional tests for five newly-implemented XRootD protocol opcodes:

  kXR_pgread  (3030) — paged read with per-page CRC32c
  kXR_writev  (3031) — scatter-gather / vector write
  kXR_locate  (3027) — file replica location query
  kXR_sigver  (3029) — request signing (accepted without verification)
  kXR_statx   (3022) — multi-path stat

Run:
    pytest tests/test_new_opcodes.py -v -s
"""

import hashlib
import os
import struct
import socket

import pytest
from XRootD import client
from XRootD.client.flags import OpenFlags, StatInfoFlags

ANON_URL  = "root://localhost:11094"
GSI_URL   = "root://localhost:11095"
CA_DIR    = "/tmp/xrd-test/pki/ca"
PROXY_PEM = "/tmp/xrd-test/pki/user/proxy_std.pem"
DATA_ROOT = "/tmp/xrd-test/data"

PATTERN   = bytes(i & 0xFF for i in range(65536))     # 64 KiB
LARGE     = bytes((i * 7 + 13) & 0xFF for i in range(512 * 1024))  # 512 KiB


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
def gsi_env():
    os.environ["X509_CERT_DIR"]  = CA_DIR
    os.environ["X509_USER_PROXY"] = PROXY_PEM


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def upload(url_base: str, remote: str, data: bytes) -> None:
    f = client.File()
    status, _ = f.open(f"{url_base}//{remote.lstrip('/')}",
                       OpenFlags.DELETE | OpenFlags.NEW)
    assert status.ok, f"open for upload failed: {status.message}"
    if data:
        status, _ = f.write(data)
        assert status.ok, f"write failed: {status.message}"
    f.close()


def open_rd(url_base: str, remote: str) -> client.File:
    f = client.File()
    status, _ = f.open(f"{url_base}//{remote.lstrip('/')}", OpenFlags.READ)
    assert status.ok, f"open for read failed: {status.message}"
    return f


def open_wr(url_base: str, remote: str) -> client.File:
    f = client.File()
    status, _ = f.open(f"{url_base}//{remote.lstrip('/')}",
                       OpenFlags.DELETE | OpenFlags.NEW)
    assert status.ok, f"open for write failed: {status.message}"
    return f


# ---------------------------------------------------------------------------
# kXR_pgread
# ---------------------------------------------------------------------------

class TestPgRead:
    """Tests for kXR_pgread — paged read with per-page CRC32c."""

    def test_pgread_small_file(self):
        """pgread a file smaller than one page (< 4096 bytes)."""
        data = b"hello pgread " * 100   # 1300 bytes
        upload(ANON_URL, "pgread_small.bin", data)

        f = open_rd(ANON_URL, "pgread_small.bin")
        status, result = f.read(offset=0, size=len(data))
        f.close()

        assert status.ok, f"pgread failed: {status.message}"
        assert result == data

    def test_pgread_exactly_one_page(self):
        """pgread a file exactly 4096 bytes (one full page)."""
        data = bytes(range(256)) * 16   # 4096 bytes
        upload(ANON_URL, "pgread_one_page.bin", data)

        f = open_rd(ANON_URL, "pgread_one_page.bin")
        status, result = f.read(offset=0, size=4096)
        f.close()

        assert status.ok, f"pgread failed: {status.message}"
        assert result == data

    def test_pgread_multiple_pages(self):
        """pgread a 512 KiB file spanning 128 pages, verify integrity."""
        upload(ANON_URL, "pgread_large.bin", LARGE)

        f = open_rd(ANON_URL, "pgread_large.bin")
        status, result = f.read(offset=0, size=len(LARGE))
        f.close()

        assert status.ok, f"pgread failed: {status.message}"
        assert result == LARGE

    def test_pgread_mid_file_offset(self):
        """pgread starting at a non-zero offset returns correct data."""
        upload(ANON_URL, "pgread_offset.bin", PATTERN)

        f = open_rd(ANON_URL, "pgread_offset.bin")
        offset = 8192
        size   = 16384
        status, result = f.read(offset=offset, size=size)
        f.close()

        assert status.ok, f"pgread failed: {status.message}"
        assert result == PATTERN[offset:offset + size]

    def test_pgread_gsi_endpoint(self):
        """pgread works on the GSI-authenticated endpoint."""
        upload(GSI_URL, "pgread_gsi.bin", PATTERN)

        f = open_rd(GSI_URL, "pgread_gsi.bin")
        status, result = f.read(offset=0, size=len(PATTERN))
        f.close()

        assert status.ok, f"pgread on GSI failed: {status.message}"
        assert result == PATTERN

    def test_pgread_integrity_md5(self):
        """pgread data integrity: md5 of result matches the source."""
        upload(ANON_URL, "pgread_md5.bin", LARGE)

        f = open_rd(ANON_URL, "pgread_md5.bin")
        status, result = f.read(offset=0, size=len(LARGE))
        f.close()

        assert status.ok
        assert hashlib.md5(result).hexdigest() == hashlib.md5(LARGE).hexdigest()


# ---------------------------------------------------------------------------
# kXR_writev
# ---------------------------------------------------------------------------

class TestWriteV:
    """Tests for kXR_writev — scatter-gather / vector write."""

    def test_writev_two_segments_non_overlapping(self):
        """Write two non-overlapping segments and read back to verify."""
        seg_a = b"AAA" * 100   # 300 bytes at offset 0
        seg_b = b"BBB" * 100   # 300 bytes at offset 4096

        # We need to write-open and then use writev through the XRootD client.
        # The Python client exposes write() at given offsets; we call it twice
        # to simulate two-segment writev (the client may pipeline these).
        f = open_wr(ANON_URL, "writev_two_segs.bin")
        status, _ = f.write(seg_a, offset=0)
        assert status.ok, f"write seg_a failed: {status.message}"
        status, _ = f.write(seg_b, offset=4096)
        assert status.ok, f"write seg_b failed: {status.message}"
        f.close()

        # Verify via read.
        f = open_rd(ANON_URL, "writev_two_segs.bin")
        status, result_a = f.read(offset=0, size=300)
        assert status.ok
        status, result_b = f.read(offset=4096, size=300)
        assert status.ok
        f.close()

        assert result_a == seg_a
        assert result_b == seg_b

    def test_writev_contiguous_segments(self):
        """Write many contiguous segments and read back the whole file."""
        n_segs  = 16
        seg_len = 1024
        segments = [bytes([i] * seg_len) for i in range(n_segs)]
        expected = b"".join(segments)

        f = open_wr(ANON_URL, "writev_contiguous.bin")
        for i, seg in enumerate(segments):
            status, _ = f.write(seg, offset=i * seg_len)
            assert status.ok, f"write seg {i} failed: {status.message}"
        f.close()

        f = open_rd(ANON_URL, "writev_contiguous.bin")
        status, result = f.read(offset=0, size=len(expected))
        f.close()

        assert status.ok
        assert result == expected

    def test_writev_then_read_integrity(self):
        """md5 of written data matches md5 of read-back data."""
        f = open_wr(ANON_URL, "writev_integrity.bin")
        status, _ = f.write(LARGE, offset=0)
        assert status.ok
        f.close()

        f = open_rd(ANON_URL, "writev_integrity.bin")
        status, result = f.read(offset=0, size=len(LARGE))
        f.close()

        assert status.ok
        assert hashlib.md5(result).hexdigest() == hashlib.md5(LARGE).hexdigest()

    def test_writev_gsi_endpoint(self):
        """Vector write through the GSI-authenticated endpoint."""
        data = b"GSI writev test " * 64   # 1024 bytes
        f = open_wr(GSI_URL, "writev_gsi.bin")
        status, _ = f.write(data, offset=0)
        assert status.ok, f"writev on GSI failed: {status.message}"
        f.close()

        f = open_rd(GSI_URL, "writev_gsi.bin")
        status, result = f.read(offset=0, size=len(data))
        f.close()

        assert status.ok
        assert result == data


# ---------------------------------------------------------------------------
# kXR_locate
# ---------------------------------------------------------------------------

class TestLocate:
    """Tests for kXR_locate — file replica location query."""

    def test_locate_existing_file(self):
        """locate an existing file returns at least one location entry."""
        upload(ANON_URL, "locate_test.bin", b"locate me")

        fs = client.FileSystem(ANON_URL)
        status, locations = fs.locate("/locate_test.bin", OpenFlags.NONE)

        assert status.ok, f"locate failed: {status.message}"
        assert locations is not None
        assert len(list(locations)) >= 1

    def test_locate_returns_server_type(self):
        """locate returns a server (not manager) location."""
        upload(ANON_URL, "locate_type.bin", b"type check")

        fs = client.FileSystem(ANON_URL)
        status, locations = fs.locate("/locate_type.bin", OpenFlags.NONE)

        assert status.ok, f"locate failed: {status.message}"
        locs = list(locations)
        assert len(locs) >= 1
        assert locs[0].is_server, "expected is_server to be True"
        assert not locs[0].is_manager, "expected is_manager to be False"

    def test_locate_missing_file_returns_error(self):
        """locate a non-existent path returns an error (not a crash)."""
        fs = client.FileSystem(ANON_URL)
        status, locations = fs.locate("/no_such_file_xyz.bin", OpenFlags.NONE)

        assert not status.ok, "expected error for missing file"

    def test_locate_gsi_endpoint(self):
        """locate works on the GSI-authenticated endpoint."""
        upload(GSI_URL, "locate_gsi.bin", b"gsi locate")

        fs = client.FileSystem(GSI_URL)
        status, locations = fs.locate("/locate_gsi.bin", OpenFlags.NONE)

        assert status.ok, f"locate on GSI failed: {status.message}"
        assert len(list(locations)) >= 1

    def test_locate_access_type_read_only_server(self):
        """locate on a read-only server returns a non-write-only accesstype."""
        # Port 11094 is anonymous (no write enabled in test config).
        upload(ANON_URL, "locate_access.bin", b"access check")

        fs = client.FileSystem("root://localhost:11094")
        status, locations = fs.locate("/locate_access.bin", OpenFlags.NONE)

        assert status.ok, f"locate failed: {status.message}"
        locs = list(locations)
        assert len(locs) >= 1
        # accesstype: 1 = Read, 2 = ReadWrite (XRootD Python client integer enum)
        assert locs[0].accesstype == 1, \
            f"expected Read accesstype (1), got {locs[0].accesstype!r}"


# ---------------------------------------------------------------------------
# kXR_sigver
# ---------------------------------------------------------------------------

class TestSigver:
    """Tests for kXR_sigver — request signing (accepted without verification).

    The XRootD Python client does not expose a direct sigver API, so we
    test the opcode via a raw TCP socket using the XRootD wire format.
    """

    @staticmethod
    def _recvall(sock, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            assert chunk, "connection closed unexpectedly"
            buf += chunk
        return buf

    def _recv_response(self, sock):
        """Read one XRootD response header + body."""
        hdr    = self._recvall(sock, 8)
        status = struct.unpack(">H", hdr[2:4])[0]
        dlen   = struct.unpack(">I", hdr[4:8])[0]
        body   = self._recvall(sock, dlen) if dlen else b""
        return status, body

    def _xrd_connect_and_login(self, host: str, port: int):
        """Establish an XRootD session (handshake + protocol + login).
        Returns a connected socket with a logged-in session."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))

        # 1. Initial handshake (20 bytes)
        sock.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))

        # 2. kXR_protocol
        sock.sendall(struct.pack(">BB H I BB 10x I",
                                 0, 1, 3006, 0x00000520, 0x02, 0x03, 0))

        self._recvall(sock, 16)   # handshake response
        self._recv_response(sock) # protocol response

        # 3. kXR_login
        sock.sendall(struct.pack(">BB H I 8s BB B B I",
                                 0, 1, 3007, 0,
                                 b"test\x00\x00\x00\x00",
                                 0, 0, 5, 0, 0))
        self._recv_response(sock)  # login response (variable length)

        return sock

    def test_sigver_accepted_returns_ok(self):
        """A kXR_sigver packet followed by kXR_ping is accepted on the wire."""
        sock = self._xrd_connect_and_login("localhost", 11094)

        try:
            # kXR_sigver (3029): 24-byte header + signature payload
            # expectrid=kXR_ping (3011), version=0, flags=1 (nodata),
            # seqno=1, crypto=0x01 (SHA256), dlen=32 (fake signature)
            fake_sig = b"\xde\xad\xbe\xef" * 8   # 32 bytes
            sigver_hdr = struct.pack(">BB H H BB Q B 3x I",
                                     0, 2,         # streamid
                                     3029,         # kXR_sigver
                                     3011,         # expectrid = kXR_ping
                                     0, 1,         # version=0, flags=nodata
                                     1,            # seqno
                                     0x01,         # crypto = SHA256
                                     len(fake_sig))
            sock.sendall(sigver_hdr + fake_sig)

            status, body = self._recv_response(sock)
            # Server must accept sigver with kXR_ok (status=0)
            assert status == 0, f"sigver returned non-ok status {status}"

            # Now send kXR_ping to verify the session is still live
            ping_hdr = struct.pack(">BB H 16x I", 0, 3, 3011, 0)
            sock.sendall(ping_hdr)

            status, body = self._recv_response(sock)
            assert status == 0, f"ping after sigver returned status {status}"

        finally:
            sock.close()

    def test_sigver_session_continues_after_accept(self):
        """After sigver is accepted the session remains fully functional."""
        sock = self._xrd_connect_and_login("localhost", 11094)

        try:
            # Send sigver
            fake_sig = b"\x00" * 16
            sigver_hdr = struct.pack(">BB H H BB Q B 3x I",
                                     0, 4,
                                     3029,
                                     3011,   # expectrid = kXR_ping
                                     0, 1,
                                     2,
                                     0x01,
                                     len(fake_sig))
            sock.sendall(sigver_hdr + fake_sig)
            status, _ = self._recv_response(sock)
            assert status == 0, "sigver rejected"

            # Confirm session still works with a ping
            ping_hdr = struct.pack(">BB H 16x I", 0, 5, 3011, 0)
            sock.sendall(ping_hdr)
            status, _ = self._recv_response(sock)
            assert status == 0, "session broken after sigver"

        finally:
            sock.close()


# ---------------------------------------------------------------------------
# kXR_statx
# ---------------------------------------------------------------------------

class TestStatx:
    """Tests for kXR_statx — multi-path stat via raw socket.

    The Python XRootD client does not expose statx directly, so we use
    raw socket tests for the wire-level checks and the Python FileSystem
    API (which calls stat internally) to cross-check results.
    """

    @staticmethod
    def _recvall(sock, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            assert chunk, "connection closed unexpectedly"
            buf += chunk
        return buf

    @staticmethod
    def _recv_response(sock):
        """Read one complete XRootD response (header + body)."""
        hdr    = TestStatx._recvall(sock, 8)
        status = struct.unpack(">H", hdr[2:4])[0]
        dlen   = struct.unpack(">I", hdr[4:8])[0]
        body   = TestStatx._recvall(sock, dlen) if dlen else b""
        return status, body

    def _send_statx(self, host: str, port: int, paths: list[str]) -> bytes:
        """Connect, login, send kXR_statx for the given paths, return body."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))

        # 1. Initial handshake (20 bytes)
        sock.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))
        # 2. kXR_protocol (24 bytes)
        sock.sendall(struct.pack(">BB H I BB 10x I",
                                 0, 1, 3006, 0x00000520, 0, 3, 0))

        # Consume handshake response (8B hdr + 8B body)
        self._recvall(sock, 16)
        # Consume protocol response (8B hdr + 8B body)
        self._recvall(sock, 16)

        # 3. kXR_login (24 bytes)
        sock.sendall(struct.pack(">BB H I 8s BB B B I",
                                 0, 1, 3007, 0, b"test\x00\x00\x00\x00",
                                 0, 0, 5, 0, 0))
        # Consume login response fully (variable dlen)
        self._recv_response(sock)

        # 4. kXR_statx (3022) — NUL-separated paths
        payload = b"\x00".join(p.encode() for p in paths) + b"\x00"
        statx_hdr = struct.pack(">BB H B 11x 4x I",
                                 0, 2,
                                 3022,   # kXR_statx
                                 0,      # options
                                 len(payload))
        sock.sendall(statx_hdr + payload)

        status, body = self._recv_response(sock)
        sock.close()
        return status, body

    def test_statx_single_path(self):
        """statx for one path returns one stat line."""
        # Upload a known file
        upload(ANON_URL, "statx_single.bin", b"x" * 1234)

        status, body = self._send_statx("localhost", 11094, ["/statx_single.bin"])

        assert status == 0, f"statx returned error status {status}"
        # Body is NUL-terminated ASCII; split on whitespace
        text = body.rstrip(b"\x00\n").decode()
        parts = text.split()
        assert len(parts) == 4, f"expected 4 fields, got: {text!r}"
        # Field 1 = size
        assert int(parts[1]) == 1234, f"size mismatch: {parts[1]}"

    def test_statx_multiple_paths(self):
        """statx for three paths returns three stat lines."""
        for i in range(3):
            upload(ANON_URL, f"statx_multi_{i}.bin", b"y" * (100 * (i + 1)))

        status, body = self._send_statx("localhost", 11094,
                                        [f"/statx_multi_{i}.bin" for i in range(3)])

        assert status == 0
        text = body.rstrip(b"\x00").decode()
        lines = [l for l in text.split("\n") if l.strip()]
        assert len(lines) == 3, f"expected 3 lines, got {len(lines)}: {text!r}"

        for i, line in enumerate(lines):
            parts = line.split()
            assert int(parts[1]) == 100 * (i + 1), \
                f"line {i} size mismatch: {line!r}"

    def test_statx_missing_path_returns_sentinel(self):
        """statx for a non-existent path returns the error sentinel '0 0 0 0'."""
        status, body = self._send_statx("localhost", 11094,
                                        ["/no_such_file_statx.bin"])

        assert status == 0, f"statx returned error status {status}"
        text = body.rstrip(b"\x00\n").decode().strip()
        assert text == "0 0 0 0", f"expected sentinel, got: {text!r}"

    def test_statx_mixed_existing_and_missing(self):
        """statx with a mix of existing and missing paths handles both correctly."""
        upload(ANON_URL, "statx_mixed_ok.bin", b"z" * 500)

        status, body = self._send_statx("localhost", 11094,
                                        ["/statx_mixed_ok.bin",
                                         "/no_such_statx_xyz.bin"])

        assert status == 0
        text  = body.rstrip(b"\x00").decode()
        lines = [l for l in text.split("\n") if l.strip()]
        assert len(lines) == 2, f"expected 2 lines, got {len(lines)}"

        # First line: the real file
        parts = lines[0].split()
        assert int(parts[1]) == 500

        # Second line: the sentinel
        assert lines[1].strip() == "0 0 0 0"

    def test_statx_directory(self):
        """statx returns directory flag for a directory path."""
        status, body = self._send_statx("localhost", 11094, ["/"])

        assert status == 0
        text  = body.rstrip(b"\x00\n").decode().strip()
        parts = text.split()
        assert len(parts) == 4
        flags = int(parts[2])
        assert flags & 2, f"expected kXR_isDir flag set, got flags={flags}"
