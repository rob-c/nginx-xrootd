"""
Security hardening regressions for nginx-xrootd.

These tests focus on hostile or malformed user input that the normal XRootD
client APIs do not generate:
  - symlink escapes under write-side path resolution
  - mutating requests sent before login/authentication
  - embedded-NUL bytes in path payloads
"""

import os
import socket
import stat
import struct
import tempfile
import time

from XRootD import client
from XRootD.client.flags import DirListFlags, MkDirFlags


ANON_URL = "root://localhost:11094"
ANON_HOST = "127.0.0.1"
ANON_PORT = 11094
DATA_DIR = "/tmp/xrd-test/data"
LOG_DIR = "/tmp/xrd-test/logs"
ANON_ACCESS_LOG = os.path.join(LOG_DIR, "xrootd_access_anon.log")
ERROR_LOG = os.path.join(LOG_DIR, "error.log")

kXR_OK = 0
kXR_ERROR = 4003

kXR_CHMOD = 3002
kXR_QUERY = 3001
kXR_LOGIN = 3007
kXR_MV = 3009
kXR_RM = 3014
kXR_RMDIR = 3015

kXR_ARG_INVALID = 3000
kXR_NOT_AUTHORIZED = 3010
kXR_QCONFIG = 7


def _recv_exact(sock: socket.socket, nbytes: int) -> bytes:
    """Read exactly *nbytes* or fail loudly if the server closes early."""
    data = bytearray()
    while len(data) < nbytes:
        chunk = sock.recv(nbytes - len(data))
        if not chunk:
            raise AssertionError("socket closed before full response arrived")
        data.extend(chunk)
    return bytes(data)


def _read_response(sock: socket.socket) -> tuple[int, bytes]:
    """Read one standard XRootD response frame: 8-byte header + body."""
    header = _recv_exact(sock, 8)
    _streamid, status, dlen = struct.unpack("!2sHI", header)
    body = _recv_exact(sock, dlen) if dlen else b""
    return status, body


def _raw_session() -> socket.socket:
    """Open a raw socket and complete only the initial 20-byte handshake."""
    sock = socket.create_connection((ANON_HOST, ANON_PORT), timeout=5)
    sock.settimeout(5)
    sock.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
    status, body = _read_response(sock)
    assert status == kXR_OK, f"handshake failed: status={status} body={body!r}"
    assert len(body) == 8, f"unexpected handshake body: {body!r}"
    return sock


def _login_anon(sock: socket.socket, streamid: bytes = b"\x00\x01") -> None:
    """Send a minimal anonymous kXR_login so later requests are post-auth."""
    username = b"pytest\x00\x00"
    req = struct.pack(
        "!2sHI8sBBBBI",
        streamid,
        kXR_LOGIN,
        os.getpid() & 0xFFFFFFFF,
        username,
        0,
        0,
        5,
        0,
        0,
    )
    sock.sendall(req)
    status, body = _read_response(sock)
    assert status == kXR_OK, f"login failed: status={status} body={body!r}"
    assert len(body) >= 16, f"unexpected login body: {body!r}"


def _error_code(body: bytes) -> int:
    """Extract the kXR_error numeric code from the response body."""
    assert len(body) >= 4, f"error response too short: {body!r}"
    return struct.unpack("!I", body[:4])[0]


def _unlink_if_exists(path: str) -> None:
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


def _log_size(path: str) -> int:
    try:
        return os.path.getsize(path)
    except FileNotFoundError:
        return 0


def _read_log_delta(path: str, offset: int, timeout: float = 1.0) -> bytes:
    deadline = time.time() + timeout

    while time.time() < deadline:
        if _log_size(path) > offset:
            break
        time.sleep(0.05)

    with open(path, "rb") as fh:
        fh.seek(offset)
        return fh.read()


def test_mkdir_with_mkpath_rejects_symlink_escape():
    """Recursive mkdir must not follow a symlinked prefix outside the export root."""
    fs = client.FileSystem(ANON_URL)
    link_name = "_harden_symlink_escape"
    link_path = os.path.join(DATA_DIR, link_name)

    _unlink_if_exists(link_path)

    with tempfile.TemporaryDirectory(prefix="xrd_escape_target_") as outside:
        escaped = os.path.join(outside, "nested")
        # The link itself lives under DATA_DIR, but it points outside the export.
        os.symlink(outside, link_path)
        try:
            status, _ = fs.mkdir(f"/{link_name}/nested", MkDirFlags.MAKEPATH)
            assert not status.ok, "mkpath should reject symlink escape outside root"
            assert not os.path.exists(escaped), "server created a directory outside xrootd_root"
        finally:
            _unlink_if_exists(link_path)


def test_preauth_rmdir_rejected():
    """A client that never sends kXR_login must not be able to remove paths."""
    victim = os.path.join(DATA_DIR, "_harden_preauth_rmdir")
    os.makedirs(victim, exist_ok=True)

    try:
        with _raw_session() as sock:
            payload = b"/_harden_preauth_rmdir"
            # Reserved bytes are zero; only streamid/requestid/dlen matter here.
            req = struct.pack("!2sH16sI", b"\x00\x02", kXR_RMDIR, b"\x00" * 16, len(payload))
            sock.sendall(req + payload)
            status, body = _read_response(sock)

        assert status == kXR_ERROR, f"expected error response, got {status}"
        assert _error_code(body) == kXR_NOT_AUTHORIZED, body
        assert os.path.isdir(victim), "pre-auth rmdir unexpectedly succeeded"
    finally:
        if os.path.isdir(victim):
            os.rmdir(victim)


def test_preauth_mv_rejected():
    """Raw kXR_mv frames must be rejected before auth, even if well-formed."""
    src = os.path.join(DATA_DIR, "_harden_preauth_mv_src.txt")
    dst = os.path.join(DATA_DIR, "_harden_preauth_mv_dst.txt")
    with open(src, "w", encoding="utf-8") as fh:
        fh.write("preauth move\n")
    _unlink_if_exists(dst)

    try:
        with _raw_session() as sock:
            src_wire = b"/_harden_preauth_mv_src.txt"
            dst_wire = b"/_harden_preauth_mv_dst.txt"
            # kXR_mv encodes src + single space + dst, with arg1len=src length.
            payload = src_wire + b" " + dst_wire
            req = struct.pack(
                "!2sH14shI",
                b"\x00\x03",
                kXR_MV,
                b"\x00" * 14,
                len(src_wire),
                len(payload),
            )
            sock.sendall(req + payload)
            status, body = _read_response(sock)

        assert status == kXR_ERROR, f"expected error response, got {status}"
        assert _error_code(body) == kXR_NOT_AUTHORIZED, body
        assert os.path.exists(src), "pre-auth mv unexpectedly removed the source"
        assert not os.path.exists(dst), "pre-auth mv unexpectedly created the destination"
    finally:
        _unlink_if_exists(src)
        _unlink_if_exists(dst)


def test_preauth_chmod_rejected():
    """Permission changes must be denied until the session is authenticated."""
    victim = os.path.join(DATA_DIR, "_harden_preauth_chmod.txt")
    with open(victim, "w", encoding="utf-8") as fh:
        fh.write("preauth chmod\n")
    os.chmod(victim, 0o644)

    try:
        with _raw_session() as sock:
            payload = b"/_harden_preauth_chmod.txt"
            req = struct.pack(
                "!2sH14sHI",
                b"\x00\x04",
                kXR_CHMOD,
                b"\x00" * 14,
                0o444,
                len(payload),
            )
            sock.sendall(req + payload)
            status, body = _read_response(sock)

        assert status == kXR_ERROR, f"expected error response, got {status}"
        assert _error_code(body) == kXR_NOT_AUTHORIZED, body
        assert stat.S_IMODE(os.stat(victim).st_mode) == 0o644, (
            "pre-auth chmod unexpectedly changed permissions"
        )
    finally:
        _unlink_if_exists(victim)


def test_rm_rejects_embedded_nul_path_payload():
    """A trailing terminator is fine; an in-band NUL must invalidate the path."""
    victim = os.path.join(DATA_DIR, "_harden_nul_rm.txt")
    with open(victim, "w", encoding="utf-8") as fh:
        fh.write("nul payload target\n")

    try:
        with _raw_session() as sock:
            # Authenticate first so the failure is attributed to path parsing.
            _login_anon(sock)
            payload = b"/_harden_nul_rm.txt\x00../../outside"
            req = struct.pack("!2sH16sI", b"\x00\x05", kXR_RM, b"\x00" * 16, len(payload))
            sock.sendall(req + payload)
            status, body = _read_response(sock)

        assert status == kXR_ERROR, f"expected error response, got {status}"
        assert _error_code(body) == kXR_ARG_INVALID, body
        assert os.path.exists(victim), "embedded-NUL rm unexpectedly touched the target"
    finally:
        _unlink_if_exists(victim)


def test_login_username_is_escaped_in_access_log():
    """Control bytes in usernames must stay inside one sanitized access-log line."""
    before = _log_size(ANON_ACCESS_LOG)

    with _raw_session() as sock:
        username = b'ev\n" \\\x1bA'
        req = struct.pack(
            "!2sHI8sBBBBI",
            b"\x00\x06",
            kXR_LOGIN,
            os.getpid() & 0xFFFFFFFF,
            username,
            0,
            0,
            5,
            0,
            0,
        )
        sock.sendall(req)
        status, body = _read_response(sock)

    assert status == kXR_OK, f"login failed: status={status} body={body!r}"

    delta = _read_log_delta(ANON_ACCESS_LOG, before)
    assert b"LOGIN - ev\\x0A\\x22\\x20\\x5C\\x1BA" in delta
    assert username not in delta
    assert sum(1 for line in delta.splitlines() if b"LOGIN" in line) == 1


def test_malicious_path_is_escaped_in_access_and_error_logs():
    """Path-related warnings must escape client control bytes before logging."""
    access_before = _log_size(ANON_ACCESS_LOG)
    error_before = _log_size(ERROR_LOG)

    with _raw_session() as sock:
        _login_anon(sock, streamid=b"\x00\x07")
        payload = b"/../log\nrm"
        req = struct.pack("!2sH16sI", b"\x00\x08", kXR_RM, b"\x00" * 16, len(payload))
        sock.sendall(req + payload)
        status, body = _read_response(sock)

    assert status == kXR_ERROR, f"expected error response, got {status}"
    assert body, "expected an error body for rejected path traversal"

    access_delta = _read_log_delta(ANON_ACCESS_LOG, access_before)
    error_delta = _read_log_delta(ERROR_LOG, error_before)

    assert b"/../log\\x0Arm" in access_delta
    assert payload not in access_delta
    assert b"path traversal attempt: /../log\\x0Arm" in error_delta
    assert payload not in error_delta


def test_qconfig_long_payload_is_truncated_without_stack_leak():
    """Long Qconfig queries must stop at the fixed buffer boundary cleanly."""
    key = b"A" * 120
    payload = b"\n".join([key] * 20)
    expected = (key + b"=0\n") * 4

    with _raw_session() as sock:
        _login_anon(sock, streamid=b"\x00\x09")
        req = struct.pack(
            "!2sHH2s4s8sI",
            b"\x00\x0a",
            kXR_QUERY,
            kXR_QCONFIG,
            b"\x00\x00",
            b"\x00" * 4,
            b"\x00" * 8,
            len(payload),
        )
        sock.sendall(req + payload)
        status, body = _read_response(sock)

    assert status == kXR_OK, f"expected OK response, got {status}"
    assert body == expected, body


def test_dirlist_stat_skips_control_byte_names():
    """Directory listings must not let newline-bearing names forge extra entries."""
    fs = client.FileSystem(ANON_URL)
    dirname = "_harden_dirlist_ctrl"
    dirpath = os.path.join(DATA_DIR, dirname)
    safe_name = "safe.txt"
    bad_name = "evil_dirlist\nshadow.txt"

    os.makedirs(dirpath, exist_ok=True)
    with open(os.path.join(dirpath, safe_name), "w", encoding="utf-8") as fh:
        fh.write("safe\n")
    with open(os.path.join(dirpath, bad_name), "w", encoding="utf-8") as fh:
        fh.write("unsafe\n")

    try:
        status, listing = fs.dirlist(f"/{dirname}", DirListFlags.STAT)
        assert status.ok, f"dirlist failed: {status.message}"
        names = {entry.name for entry in listing}
        assert safe_name in names
        assert bad_name not in names
        assert "evil_dirlist" not in names
        assert "shadow.txt" not in names
    finally:
        for name in (safe_name, bad_name):
            try:
                os.unlink(os.path.join(dirpath, name))
            except FileNotFoundError:
                pass
        try:
            os.rmdir(dirpath)
        except FileNotFoundError:
            pass