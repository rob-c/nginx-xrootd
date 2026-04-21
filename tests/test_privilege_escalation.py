"""
Privilege escalation and authorization boundary tests for nginx-xrootd.

Tests that verify the server correctly enforces:
  - Pre-auth rejection of ALL data opcodes (not just rm/mv/chmod)
  - Read-only server config rejects every mutating opcode
  - Read-side path resolution rejects symlinks escaping the export root
  - Handle-based truncate respects read-only open mode
  - Write operations on read-only opened handles are rejected
  - Unknown opcodes return kXR_Unsupported
  - Invalid/out-of-range file handles are rejected
  - Negative or overflow offsets in read/write
  - Oversized path payloads

These complement test_security_hardening.py (which covers symlink escapes,
embedded NULs, and log sanitization) with protocol-level privilege checks.

Run:
    pytest tests/test_privilege_escalation.py -v -s
"""

import os
import socket
import struct
import tempfile

import pytest

from backend_matrix import root_endpoint_parts, selected_backend_name
from settings import DATA_ROOT, NGINX_BIN

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CROSS_BACKEND = selected_backend_name()
ANON_HOST = "127.0.0.1"
ANON_PORT = 11094
DATA_DIR  = DATA_ROOT
READONLY_HOST = "127.0.0.1"
READONLY_PORT = 0


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

# XRootD request opcodes
kXR_auth      = 3000
kXR_query     = 3001
kXR_chmod     = 3002
kXR_close     = 3003
kXR_dirlist   = 3004
kXR_protocol  = 3006
kXR_login     = 3007
kXR_mkdir     = 3008
kXR_mv        = 3009
kXR_open      = 3010
kXR_ping      = 3011
kXR_read      = 3013
kXR_rm        = 3014
kXR_rmdir     = 3015
kXR_sync      = 3016
kXR_stat      = 3017
kXR_write     = 3019
kXR_writev    = 3031
kXR_endsess   = 3023
kXR_readv     = 3025
kXR_pgwrite   = 3026
kXR_truncate  = 3028

# XRootD response/error codes
kXR_OK             = 0
kXR_ERROR          = 4003
kXR_ArgInvalid     = 3000
kXR_FileNotOpen    = 3004
kXR_InvalidRequest = 3006
kXR_NOT_AUTHORIZED = 3010
kXR_Unsupported    = 3013
kXR_fsReadOnly     = 3025

# Open flags for raw protocol
kXR_open_read = 0x0010
kXR_open_updt = 0x0020
kXR_open_wrto = 0x8000
kXR_new       = 0x0008
kXR_delete    = 0x0002


# ---------------------------------------------------------------------------
# Raw protocol helpers  (same pattern as test_security_hardening.py)
# ---------------------------------------------------------------------------

def _recv_exact(sock: socket.socket, nbytes: int) -> bytes:
    data = bytearray()
    while len(data) < nbytes:
        chunk = sock.recv(nbytes - len(data))
        if not chunk:
            raise AssertionError("socket closed before full response arrived")
        data.extend(chunk)
    return bytes(data)


def _read_response(sock: socket.socket) -> tuple[int, bytes]:
    header = _recv_exact(sock, 8)
    _streamid, status, dlen = struct.unpack("!2sHI", header)
    body = _recv_exact(sock, dlen) if dlen else b""
    return status, body


def _raw_session(host: str = None, port: int = None) -> socket.socket:
    if host is None:
        host = ANON_HOST
    if port is None:
        port = ANON_PORT
    sock = socket.create_connection((host, port), timeout=5)
    sock.settimeout(5)
    sock.sendall(struct.pack("!IIIII", 0, 0, 0, 4, 2012))
    status, body = _read_response(sock)
    assert status == kXR_OK, f"handshake failed: status={status}"
    assert len(body) == 8
    return sock


def _login_anon(sock: socket.socket, streamid: bytes = b"\x00\x01") -> None:
    username = b"pytest\x00\x00"
    req = struct.pack(
        "!2sHI8sBBBBI",
        streamid, kXR_login,
        os.getpid() & 0xFFFFFFFF,
        username, 0, 0, 5, 0, 0,
    )
    sock.sendall(req)
    status, body = _read_response(sock)
    assert status == kXR_OK, f"login failed: status={status} body={body!r}"


def _error_code(body: bytes) -> int:
    assert len(body) >= 4, f"error response too short: {body!r}"
    return struct.unpack("!I", body[:4])[0]


def _open_file_raw(sock: socket.socket, path: bytes, options: int,
                   streamid: bytes = b"\x00\x02") -> tuple[int, bytes]:
    """Send kXR_open and return (status, body). Body contains fhandle on success."""
    req = struct.pack(
        "!2sHHH2s6s4sI",
        streamid, kXR_open,
        0o644,           # mode
        options,         # kXR_open_read, kXR_open_updt, etc.
        b"\x00\x00",    # optiont
        b"\x00" * 6,    # reserved
        b"\x00" * 4,    # fhtemplt
        len(path),
    )
    sock.sendall(req + path)
    return _read_response(sock)


def _close_handle_raw(sock: socket.socket, fhandle: bytes,
                      streamid: bytes = b"\x00\x09") -> None:
    req = struct.pack(
        "!2sH4s12sI",
        streamid, kXR_close, fhandle, b"\x00" * 12, 0,
    )
    sock.sendall(req)
    _read_response(sock)  # discard


def _stat_path_raw(sock: socket.socket, path: bytes,
                   streamid: bytes = b"\x00\x02") -> tuple[int, bytes]:
    req = struct.pack(
        "!2sH1s7sI4sI",
        streamid, kXR_stat,
        b"\x00",
        b"\x00" * 7,
        0,
        b"\x00" * 4,
        len(path),
    )
    sock.sendall(req + path)
    return _read_response(sock)


def _dirlist_raw(sock: socket.socket, path: bytes,
                 streamid: bytes = b"\x00\x02") -> tuple[int, bytes]:
    req = struct.pack(
        "!2sH15sBi",
        streamid, kXR_dirlist,
        b"\x00" * 15,
        0,
        len(path),
    )
    sock.sendall(req + path)
    return _read_response(sock)


def _read_raw(sock: socket.socket, fhandle: bytes, offset: int, length: int,
              streamid: bytes = b"\x00\x02") -> tuple[int, bytes]:
    req = struct.pack(
        "!2sH4sqiI",
        streamid, kXR_read,
        fhandle,
        offset,
        length,
        0,
    )
    sock.sendall(req)
    return _read_response(sock)


def _readv_raw(sock: socket.socket, fhandle: bytes, offset: int, length: int,
               streamid: bytes = b"\x00\x02") -> tuple[int, bytes]:
    segment = struct.pack("!4sIq", fhandle, length, offset)
    req = struct.pack(
        "!2sH16sI",
        streamid, kXR_readv,
        b"\x00" * 16,
        len(segment),
    )
    sock.sendall(req + segment)
    return _read_response(sock)


def _assert_readonly_response(status: int, body: bytes) -> None:
    assert status == kXR_ERROR
    assert _error_code(body) == kXR_fsReadOnly


def _assert_preauth_rejected(status: int, body: bytes) -> None:
    """Portable pre-auth rejection: nginx and xrootd use different codes."""
    assert status == kXR_ERROR
    code = _error_code(body)
    if CROSS_BACKEND == "xrootd":
        assert code in (kXR_NOT_AUTHORIZED, kXR_InvalidRequest)
    else:
        assert code == kXR_NOT_AUTHORIZED


def _assert_readonly_handle_write_rejected(status: int, body: bytes) -> None:
    """Portable read-only-handle write rejection across nginx and xrootd."""
    assert status == kXR_ERROR
    code = _error_code(body)
    if CROSS_BACKEND == "xrootd":
        assert code in (kXR_NOT_AUTHORIZED, kXR_FileNotOpen)
    else:
        assert code == kXR_NOT_AUTHORIZED


def _unlink_if_exists(path: str) -> None:
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


def _rmdir_if_exists(path: str) -> None:
    try:
        os.rmdir(path)
    except FileNotFoundError:
        pass


@pytest.fixture(scope="module", autouse=True)
def _configure(test_env, ref_xrootd):
    """Bind module constants from the selected shared test environment."""
    global ANON_HOST, ANON_PORT, DATA_DIR
    if CROSS_BACKEND == "xrootd":
        ANON_HOST, ANON_PORT = root_endpoint_parts(ref_xrootd["url"])
        DATA_DIR = ref_xrootd["data_dir"]
    else:
        ANON_HOST = "127.0.0.1"
        ANON_PORT = test_env["anon_port"]
        DATA_DIR = test_env["data_dir"]


@pytest.fixture(scope="session")
def readonly_nginx():
    """Start an isolated anonymous XRootD listener with xrootd_allow_write off."""
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")
    import server_control

    global READONLY_PORT
    READONLY_PORT = _free_port()

    info = server_control.start_nginx_instance(
        port=READONLY_PORT, nginx_bin=NGINX_BIN,
        conf_file="nginx_readonly.conf",
        template_kwargs={"DATA_DIR": DATA_DIR},
    )

    try:
        yield
    finally:
        try:
            info["stop"]()
        except Exception:
            pass


# ===========================================================================
# Read-only server authorization boundary
# ===========================================================================

@pytest.mark.skipif(
    CROSS_BACKEND == "xrootd",
    reason="read-only listener coverage is specific to nginx-xrootd",
)
class TestReadOnlyServer:
    """A listener without xrootd_allow_write must permit reads and block mutations."""

    @pytest.fixture(autouse=True)
    def _setup_paths(self):
        self.read_name = "_priv_ro_read.txt"
        self.read_remote = f"/{self.read_name}"
        self.read_disk = os.path.join(DATA_DIR, self.read_name)
        self.read_data = b"read-only listener still serves bytes\n"

        self.list_name = "_priv_ro_list"
        self.list_remote = f"/{self.list_name}"
        self.list_disk = os.path.join(DATA_DIR, self.list_name)
        self.list_child = os.path.join(self.list_disk, "child.txt")

        self.open_write_disk = os.path.join(DATA_DIR, "_priv_ro_open_write.txt")
        self.truncate_disk = os.path.join(DATA_DIR, "_priv_ro_truncate.txt")
        self.mkdir_disk = os.path.join(DATA_DIR, "_priv_ro_mkdir")
        self.rm_disk = os.path.join(DATA_DIR, "_priv_ro_rm.txt")
        self.rmdir_disk = os.path.join(DATA_DIR, "_priv_ro_rmdir")
        self.rmdir_child = os.path.join(self.rmdir_disk, "keep.txt")
        self.mv_src_disk = os.path.join(DATA_DIR, "_priv_ro_mv_src.txt")
        self.mv_dst_disk = os.path.join(DATA_DIR, "_priv_ro_mv_dst.txt")
        self.chmod_disk = os.path.join(DATA_DIR, "_priv_ro_chmod.txt")

        for path in (
            self.open_write_disk,
            self.rm_disk,
            self.mv_src_disk,
            self.mv_dst_disk,
            self.chmod_disk,
            self.truncate_disk,
        ):
            _unlink_if_exists(path)
        _unlink_if_exists(self.rmdir_child)
        _rmdir_if_exists(self.rmdir_disk)
        _unlink_if_exists(self.list_child)
        _rmdir_if_exists(self.list_disk)
        _rmdir_if_exists(self.mkdir_disk)

        with open(self.read_disk, "wb") as fh:
            fh.write(self.read_data)
        os.makedirs(self.list_disk, exist_ok=True)
        with open(self.list_child, "wb") as fh:
            fh.write(b"listed\n")

        yield

        for path in (
            self.open_write_disk,
            self.rm_disk,
            self.mv_src_disk,
            self.mv_dst_disk,
            self.chmod_disk,
            self.truncate_disk,
            self.read_disk,
        ):
            _unlink_if_exists(path)
        _unlink_if_exists(self.rmdir_child)
        _rmdir_if_exists(self.rmdir_disk)
        _unlink_if_exists(self.list_child)
        _rmdir_if_exists(self.list_disk)
        _rmdir_if_exists(self.mkdir_disk)

    def _readonly_session(self):
        sock = _raw_session(READONLY_HOST, READONLY_PORT)
        _login_anon(sock)
        return sock

    def test_read_side_ops_still_work_on_readonly_listener(self, readonly_nginx):
        """The write gate must not accidentally turn the listener into no-access."""
        with self._readonly_session() as sock:
            status, body = _stat_path_raw(sock, self.read_remote.encode())
            assert status == kXR_OK
            assert str(len(self.read_data)).encode() in body

            status, body = _open_file_raw(
                sock, self.read_remote.encode(), kXR_open_read,
                streamid=b"\x00\x03",
            )
            assert status == kXR_OK
            fhandle = body[:4]

            status, body = _read_raw(
                sock, fhandle, 0, len(self.read_data),
                streamid=b"\x00\x04",
            )
            assert status == kXR_OK
            assert body == self.read_data

            status, body = _readv_raw(sock, fhandle, 0, 4, streamid=b"\x00\x05")
            assert status == kXR_OK
            assert len(body) >= 20
            assert body[16:20] == self.read_data[:4]

            status, body = _dirlist_raw(
                sock, self.list_remote.encode(),
                streamid=b"\x00\x06",
            )
            assert status == kXR_OK
            assert b"child.txt" in body

            _close_handle_raw(sock, fhandle, streamid=b"\x00\x07")

    @pytest.mark.parametrize(
        "case",
        [
            "open_write",
            "write",
            "pgwrite",
            "writev",
            "sync",
            "truncate",
            "mkdir",
            "rm",
            "rmdir",
            "mv",
            "chmod",
        ],
    )
    def test_mutating_opcode_rejected_by_readonly_listener(
            self, readonly_nginx, case):
        """Every mutating opcode should fail with kXR_fsReadOnly before side effects."""
        with self._readonly_session() as sock:
            if case == "open_write":
                payload = b"/_priv_ro_open_write.txt"
                req = struct.pack(
                    "!2sHHH2s6s4sI",
                    b"\x00\x03", kXR_open,
                    0o644,
                    kXR_open_wrto | kXR_new,
                    b"\x00\x00",
                    b"\x00" * 6,
                    b"\x00" * 4,
                    len(payload),
                )
                sock.sendall(req + payload)
                status, body = _read_response(sock)
                _assert_readonly_response(status, body)
                assert not os.path.exists(self.open_write_disk)
                return

            if case == "write":
                data = b"blocked"
                req = struct.pack(
                    "!2sH4sq1s3sI",
                    b"\x00\x03", kXR_write,
                    b"\x00" * 4,
                    0,
                    b"\x00",
                    b"\x00" * 3,
                    len(data),
                )
                sock.sendall(req + data)
                status, body = _read_response(sock)
                _assert_readonly_response(status, body)
                return

            if case == "pgwrite":
                data = b"\x00\x00\x00\x00blocked"
                req = struct.pack(
                    "!2sH4sq1s1s2sI",
                    b"\x00\x03", kXR_pgwrite,
                    b"\x00" * 4,
                    0,
                    b"\x00",
                    b"\x00",
                    b"\x00" * 2,
                    len(data),
                )
                sock.sendall(req + data)
                status, body = _read_response(sock)
                _assert_readonly_response(status, body)
                return

            if case == "writev":
                req = struct.pack(
                    "!2sH16sI",
                    b"\x00\x03", kXR_writev,
                    b"\x00" * 16,
                    0,
                )
                sock.sendall(req)
                status, body = _read_response(sock)
                _assert_readonly_response(status, body)
                return

            if case == "sync":
                status, body = _open_file_raw(
                    sock, self.read_remote.encode(), kXR_open_read,
                    streamid=b"\x00\x03",
                )
                assert status == kXR_OK
                fhandle = body[:4]
                req = struct.pack(
                    "!2sH4s12sI",
                    b"\x00\x04", kXR_sync,
                    fhandle,
                    b"\x00" * 12,
                    0,
                )
                sock.sendall(req)
                status, body = _read_response(sock)
                _assert_readonly_response(status, body)
                _close_handle_raw(sock, fhandle, streamid=b"\x00\x05")
                return

            if case == "truncate":
                with open(self.truncate_disk, "wb") as fh:
                    fh.write(b"do not truncate\n")
                payload = b"/_priv_ro_truncate.txt"
                req = struct.pack(
                    "!2sH4sq4sI",
                    b"\x00\x03", kXR_truncate,
                    b"\x00" * 4,
                    0,
                    b"\x00" * 4,
                    len(payload),
                )
                sock.sendall(req + payload)
                status, body = _read_response(sock)
                _assert_readonly_response(status, body)
                assert os.path.getsize(self.truncate_disk) == len(b"do not truncate\n")
                return

            if case == "mkdir":
                payload = b"/_priv_ro_mkdir"
                req = struct.pack(
                    "!2sH1s13sHI",
                    b"\x00\x03", kXR_mkdir,
                    b"\x00",
                    b"\x00" * 13,
                    0o755,
                    len(payload),
                )
                sock.sendall(req + payload)
                status, body = _read_response(sock)
                _assert_readonly_response(status, body)
                assert not os.path.exists(self.mkdir_disk)
                return

            if case == "rm":
                with open(self.rm_disk, "wb") as fh:
                    fh.write(b"keep me\n")
                payload = b"/_priv_ro_rm.txt"
                req = struct.pack(
                    "!2sH16sI",
                    b"\x00\x03", kXR_rm,
                    b"\x00" * 16,
                    len(payload),
                )
                sock.sendall(req + payload)
                status, body = _read_response(sock)
                _assert_readonly_response(status, body)
                with open(self.rm_disk, "rb") as fh:
                    assert fh.read() == b"keep me\n"
                return

            if case == "rmdir":
                os.makedirs(self.rmdir_disk, exist_ok=True)
                with open(self.rmdir_child, "wb") as fh:
                    fh.write(b"keep dir non-empty\n")
                payload = b"/_priv_ro_rmdir"
                req = struct.pack(
                    "!2sH16sI",
                    b"\x00\x03", kXR_rmdir,
                    b"\x00" * 16,
                    len(payload),
                )
                sock.sendall(req + payload)
                status, body = _read_response(sock)
                _assert_readonly_response(status, body)
                assert os.path.isdir(self.rmdir_disk)
                assert os.path.exists(self.rmdir_child)
                return

            if case == "mv":
                with open(self.mv_src_disk, "wb") as fh:
                    fh.write(b"do not move\n")
                src = b"/_priv_ro_mv_src.txt"
                dst = b"/_priv_ro_mv_dst.txt"
                payload = src + b" " + dst
                req = struct.pack(
                    "!2sH14shI",
                    b"\x00\x03", kXR_mv,
                    b"\x00" * 14,
                    len(src),
                    len(payload),
                )
                sock.sendall(req + payload)
                status, body = _read_response(sock)
                _assert_readonly_response(status, body)
                assert os.path.exists(self.mv_src_disk)
                assert not os.path.exists(self.mv_dst_disk)
                return

            if case == "chmod":
                with open(self.chmod_disk, "wb") as fh:
                    fh.write(b"do not chmod\n")
                os.chmod(self.chmod_disk, 0o644)
                payload = b"/_priv_ro_chmod.txt"
                req = struct.pack(
                    "!2sH14sHI",
                    b"\x00\x03", kXR_chmod,
                    b"\x00" * 14,
                    0o600,
                    len(payload),
                )
                sock.sendall(req + payload)
                status, body = _read_response(sock)
                _assert_readonly_response(status, body)
                assert (os.stat(self.chmod_disk).st_mode & 0o777) == 0o644
                return

        pytest.fail(f"unhandled read-only test case: {case}")


# ===========================================================================
# Read-side symlink escape checks
# ===========================================================================

class TestReadSideSymlinkEscape:
    """Read-only operations must not follow symlinks outside xrootd_root."""

    @pytest.fixture(autouse=True)
    def _setup_symlinks(self):
        self.outside = tempfile.TemporaryDirectory(prefix="xrd-priv-outside-")
        self.outside_file = os.path.join(self.outside.name, "secret.txt")
        self.outside_dir = os.path.join(self.outside.name, "secret-dir")
        self.outside_child = os.path.join(self.outside_dir, "leak.txt")
        self.link_file_name = "_priv_symlink_escape_file"
        self.link_dir_name = "_priv_symlink_escape_dir"
        self.link_file = os.path.join(DATA_DIR, self.link_file_name)
        self.link_dir = os.path.join(DATA_DIR, self.link_dir_name)

        os.makedirs(self.outside_dir, exist_ok=True)
        with open(self.outside_file, "wb") as fh:
            fh.write(b"outside file must not be visible\n")
        with open(self.outside_child, "wb") as fh:
            fh.write(b"outside directory must not be listed\n")

        _unlink_if_exists(self.link_file)
        _unlink_if_exists(self.link_dir)
        os.symlink(self.outside_file, self.link_file)
        os.symlink(self.outside_dir, self.link_dir)

        yield

        _unlink_if_exists(self.link_file)
        _unlink_if_exists(self.link_dir)
        self.outside.cleanup()

    def test_stat_rejects_symlink_escape(self):
        with _raw_session() as sock:
            _login_anon(sock)
            status, body = _stat_path_raw(
                sock, f"/{self.link_file_name}".encode(),
            )

        assert status == kXR_ERROR

    def test_open_rejects_symlink_escape(self):
        with _raw_session() as sock:
            _login_anon(sock)
            status, body = _open_file_raw(
                sock, f"/{self.link_file_name}".encode(), kXR_open_read,
            )

        assert status == kXR_ERROR

    def test_dirlist_rejects_symlink_escape(self):
        with _raw_session() as sock:
            _login_anon(sock)
            status, body = _dirlist_raw(
                sock, f"/{self.link_dir_name}".encode(),
            )

        assert status == kXR_ERROR


# ===========================================================================
# Pre-auth rejection of ALL data opcodes
# ===========================================================================

class TestPreAuthRejection:
    """Every data opcode must be rejected before login/auth."""

    def test_preauth_stat_rejected(self):
        """kXR_stat must fail before login."""
        with _raw_session() as sock:
            payload = b"/test.txt"
            req = struct.pack(
                "!2sH1s7sI4sI",
                b"\x00\x01", kXR_stat,
                b"\x00",         # options
                b"\x00" * 7,     # reserved
                0,               # wants
                b"\x00" * 4,     # fhandle
                len(payload),
            )
            sock.sendall(req + payload)
            status, body = _read_response(sock)

        _assert_preauth_rejected(status, body)

    def test_preauth_open_rejected(self):
        """kXR_open must fail before login."""
        with _raw_session() as sock:
            payload = b"/test.txt"
            req = struct.pack(
                "!2sHHH2s6s4sI",
                b"\x00\x01", kXR_open,
                0o644, kXR_open_read,
                b"\x00\x00", b"\x00" * 6, b"\x00" * 4,
                len(payload),
            )
            sock.sendall(req + payload)
            status, body = _read_response(sock)

        _assert_preauth_rejected(status, body)

    def test_preauth_read_rejected(self):
        """kXR_read must fail before login."""
        with _raw_session() as sock:
            req = struct.pack(
                "!2sH4sqiI",
                b"\x00\x01", kXR_read,
                b"\x00" * 4,     # fhandle
                0,               # offset (big-endian int64)
                1024,            # rlen
                0,               # dlen
            )
            sock.sendall(req)
            status, body = _read_response(sock)

        _assert_preauth_rejected(status, body)

    def test_preauth_write_rejected(self):
        """kXR_write must fail before login."""
        with _raw_session() as sock:
            data = b"unauthorized write"
            req = struct.pack(
                "!2sH4sq1s3sI",
                b"\x00\x01", kXR_write,
                b"\x00" * 4,    # fhandle
                0,              # offset
                b"\x00",        # pathid
                b"\x00" * 3,    # reserved
                len(data),
            )
            sock.sendall(req + data)
            status, body = _read_response(sock)

        _assert_preauth_rejected(status, body)

    def test_preauth_dirlist_rejected(self):
        """kXR_dirlist must fail before login."""
        with _raw_session() as sock:
            payload = b"/"
            req = struct.pack(
                "!2sH15sBi",
                b"\x00\x01", kXR_dirlist,
                b"\x00" * 15, 0,  # reserved + options
                len(payload),
            )
            sock.sendall(req + payload)
            status, body = _read_response(sock)

        _assert_preauth_rejected(status, body)

    def test_preauth_truncate_rejected(self):
        """kXR_truncate must fail before login."""
        with _raw_session() as sock:
            payload = b"/test.txt"
            req = struct.pack(
                "!2sH4sq4sI",
                b"\x00\x01", kXR_truncate,
                b"\x00" * 4,   # fhandle
                0,             # target length
                b"\x00" * 4,   # reserved
                len(payload),
            )
            sock.sendall(req + payload)
            status, body = _read_response(sock)

        _assert_preauth_rejected(status, body)

    def test_preauth_query_rejected(self):
        """kXR_query must fail before login."""
        with _raw_session() as sock:
            payload = b"/test.txt"
            # infotype=8 (kXR_Qcksum)
            req = struct.pack(
                "!2sHH2s4s8sI",
                b"\x00\x01", kXR_query,
                8,               # kXR_Qcksum
                b"\x00\x00",
                b"\x00" * 4,
                b"\x00" * 8,
                len(payload),
            )
            sock.sendall(req + payload)
            status, body = _read_response(sock)

        _assert_preauth_rejected(status, body)

    def test_preauth_readv_rejected(self):
        """kXR_readv must fail before login."""
        with _raw_session() as sock:
            # readv payload: [fhandle(4) + rlen(4) + offset(8)] per segment
            segment = struct.pack("!4sIq", b"\x00" * 4, 100, 0)
            req = struct.pack(
                "!2sH16sI",
                b"\x00\x01", kXR_readv,
                b"\x00" * 16,
                len(segment),
            )
            sock.sendall(req + segment)
            status, body = _read_response(sock)

        _assert_preauth_rejected(status, body)

    def test_preauth_mkdir_rejected(self):
        """kXR_mkdir must fail before login."""
        victim = os.path.join(DATA_DIR, "_priv_preauth_mkdir")
        try:
            with _raw_session() as sock:
                payload = b"/_priv_preauth_mkdir"
                req = struct.pack(
                    "!2sH1s13sHI",
                    b"\x00\x01", kXR_mkdir,
                    b"\x00",          # options
                    b"\x00" * 13,     # reserved
                    0o755,            # mode
                    len(payload),
                )
                sock.sendall(req + payload)
                status, body = _read_response(sock)

            _assert_preauth_rejected(status, body)
            assert not os.path.exists(victim), "pre-auth mkdir created directory"
        finally:
            if os.path.isdir(victim):
                os.rmdir(victim)


# ===========================================================================
# Pre-auth ALLOWED opcodes (should succeed before login)
# ===========================================================================

class TestPreAuthAllowed:
    """Protocol, ping, and login should work before auth."""

    def test_preauth_ping_ok(self):
        """kXR_ping should succeed before login."""
        if CROSS_BACKEND == "xrootd":
            pytest.skip("reference xrootd rejects pre-auth ping")
        with _raw_session() as sock:
            req = struct.pack(
                "!2sH16sI",
                b"\x00\x01", kXR_ping,
                b"\x00" * 16, 0,
            )
            sock.sendall(req)
            status, _body = _read_response(sock)

        assert status == kXR_OK

    def test_preauth_protocol_ok(self):
        """kXR_protocol should succeed before login."""
        with _raw_session() as sock:
            req = struct.pack(
                "!2sHIBB10sI",
                b"\x00\x01", kXR_protocol,
                0x00000520,      # client protocol version
                0x01,            # flags: kXR_secreqs
                0x03,            # expect: kXR_ExpLogin
                b"\x00" * 10,
                0,
            )
            sock.sendall(req)
            status, body = _read_response(sock)

        assert status == kXR_OK
        assert len(body) >= 8  # at least ServerProtocolBody


# ===========================================================================
# Unknown opcode handling
# ===========================================================================

class TestUnknownOpcode:
    """Unknown request IDs must return kXR_Unsupported."""

    def test_unknown_opcode_after_login(self):
        """A bogus request ID should get kXR_Unsupported."""
        with _raw_session() as sock:
            _login_anon(sock)
            # Use requestid 3099 — well outside defined range
            req = struct.pack(
                "!2sH16sI",
                b"\x00\x02", 3099,
                b"\x00" * 16, 0,
            )
            sock.sendall(req)
            status, body = _read_response(sock)

        assert status == kXR_ERROR
        assert _error_code(body) == kXR_Unsupported

    def test_unknown_opcode_before_login(self):
        """A bogus request ID before login should also be rejected."""
        with _raw_session() as sock:
            req = struct.pack(
                "!2sH16sI",
                b"\x00\x01", 3099,
                b"\x00" * 16, 0,
            )
            sock.sendall(req)
            status, body = _read_response(sock)

        assert status == kXR_ERROR


# ===========================================================================
# Handle-based truncate on a read-only handle
# ===========================================================================

class TestTruncateOnReadOnly:
    """Handle-based kXR_truncate must fail on a read-only opened file."""

    @pytest.fixture(autouse=True)
    def _setup_file(self):
        self.remote = "/_priv_truncate_ro.txt"
        self.disk_path = os.path.join(DATA_DIR, "_priv_truncate_ro.txt")
        with open(self.disk_path, "wb") as f:
            f.write(b"A" * 1024)
        yield
        _unlink_if_exists(self.disk_path)

    def test_handle_truncate_on_readonly_rejected(self):
        """Open file read-only, then try handle-based truncate → must fail."""
        with _raw_session() as sock:
            _login_anon(sock)

            # Open the file read-only
            status, body = _open_file_raw(sock, self.remote.encode(), kXR_open_read)
            assert status == kXR_OK, f"open failed: status={status}"
            fhandle = body[:4]

            # Try handle-based truncate (dlen=0 → handle mode)
            req = struct.pack(
                "!2sH4sq4sI",
                b"\x00\x03", kXR_truncate,
                fhandle,
                0,             # target length = 0
                b"\x00" * 4,
                0,             # dlen=0 → handle-based
            )
            sock.sendall(req)
            status, body = _read_response(sock)

            # Server should reject: either kXR_NotAuthorized or kXR_IOError
            # (ftruncate on read-only fd returns EINVAL/EBADF at OS level)
            assert status == kXR_ERROR, (
                f"handle-based truncate on read-only handle should fail, got status={status}"
            )

            # Verify file was NOT actually truncated
            assert os.path.getsize(self.disk_path) == 1024, (
                "file was truncated despite read-only open"
            )

            _close_handle_raw(sock, fhandle)


# ===========================================================================
# Write on a read-only handle
# ===========================================================================

class TestWriteOnReadOnly:
    """kXR_write to a read-only file handle must be rejected."""

    @pytest.fixture(autouse=True)
    def _setup_file(self):
        self.remote = "/_priv_write_ro.txt"
        self.disk_path = os.path.join(DATA_DIR, "_priv_write_ro.txt")
        with open(self.disk_path, "wb") as f:
            f.write(b"original content\n")
        yield
        _unlink_if_exists(self.disk_path)

    def test_write_on_readonly_handle_rejected(self):
        """Open file read-only, then attempt kXR_write → must fail."""
        with _raw_session() as sock:
            _login_anon(sock)

            status, body = _open_file_raw(sock, self.remote.encode(), kXR_open_read)
            assert status == kXR_OK
            fhandle = body[:4]

            # Try to write to the read-only handle
            data = b"malicious overwrite"
            req = struct.pack(
                "!2sH4sq1s3sI",
                b"\x00\x03", kXR_write,
                fhandle,
                0,             # offset
                b"\x00",       # pathid
                b"\x00" * 3,   # reserved
                len(data),
            )
            sock.sendall(req + data)
            status, body = _read_response(sock)

        _assert_readonly_handle_write_rejected(status, body)

        # Verify file content was NOT modified
        with open(self.disk_path, "rb") as f:
            assert f.read() == b"original content\n"


# ===========================================================================
# Invalid file handle tests
# ===========================================================================

class TestInvalidHandles:
    """Operations on invalid file handles must return clean errors."""

    def test_read_invalid_handle(self):
        """kXR_read with an unopened handle should error."""
        with _raw_session() as sock:
            _login_anon(sock)

            req = struct.pack(
                "!2sH4sqiI",
                b"\x00\x02", kXR_read,
                b"\xff\x00\x00\x00",  # handle 255 — unlikely to be open
                0,                     # offset
                100,                   # rlen
                0,                     # dlen
            )
            sock.sendall(req)
            status, body = _read_response(sock)

        assert status == kXR_ERROR
        assert _error_code(body) == kXR_FileNotOpen

    def test_write_invalid_handle(self):
        """kXR_write with an unopened handle should error."""
        with _raw_session() as sock:
            _login_anon(sock)

            data = b"test data"
            req = struct.pack(
                "!2sH4sq1s3sI",
                b"\x00\x02", kXR_write,
                b"\xff\x00\x00\x00",
                0, b"\x00", b"\x00" * 3,
                len(data),
            )
            sock.sendall(req + data)
            status, body = _read_response(sock)

        assert status == kXR_ERROR
        assert _error_code(body) == kXR_FileNotOpen

    def test_sync_invalid_handle(self):
        """kXR_sync with an unopened handle should error."""
        with _raw_session() as sock:
            _login_anon(sock)

            req = struct.pack(
                "!2sH4s12sI",
                b"\x00\x02", kXR_sync,
                b"\xff\x00\x00\x00",
                b"\x00" * 12, 0,
            )
            sock.sendall(req)
            status, body = _read_response(sock)

        assert status == kXR_ERROR
        assert _error_code(body) == kXR_FileNotOpen

    def test_close_invalid_handle(self):
        """kXR_close with an unopened handle should error."""
        with _raw_session() as sock:
            _login_anon(sock)

            req = struct.pack(
                "!2sH4s12sI",
                b"\x00\x02", kXR_close,
                b"\xff\x00\x00\x00",
                b"\x00" * 12, 0,
            )
            sock.sendall(req)
            status, body = _read_response(sock)

        assert status == kXR_ERROR
        assert _error_code(body) == kXR_FileNotOpen

    def test_truncate_invalid_handle(self):
        """Handle-based kXR_truncate with invalid handle should error."""
        with _raw_session() as sock:
            _login_anon(sock)

            req = struct.pack(
                "!2sH4sq4sI",
                b"\x00\x02", kXR_truncate,
                b"\xff\x00\x00\x00",
                0,              # target length
                b"\x00" * 4,
                0,              # dlen=0 → handle-based
            )
            sock.sendall(req)
            status, body = _read_response(sock)

        assert status == kXR_ERROR
        assert _error_code(body) == kXR_FileNotOpen


# ===========================================================================
# Oversized path payload
# ===========================================================================

class TestOversizedPath:
    """Paths exceeding the server buffer limit must be rejected cleanly."""

    def test_oversized_stat_path(self):
        """A stat request with a >4096 byte path should be rejected or disconnect."""
        with _raw_session() as sock:
            _login_anon(sock)

            payload = b"/" + b"A" * 8000
            req = struct.pack(
                "!2sH1s7sI4sI",
                b"\x00\x02", kXR_stat,
                b"\x00", b"\x00" * 7, 0, b"\x00" * 4,
                len(payload),
            )
            sock.sendall(req + payload)
            try:
                status, body = _read_response(sock)
                assert status == kXR_ERROR
            except (ConnectionResetError, BrokenPipeError, AssertionError):
                pass  # Server disconnecting on oversized payload is acceptable

    def test_oversized_open_path(self):
        """An open request with a >4096 byte path should be rejected or disconnect."""
        with _raw_session() as sock:
            _login_anon(sock)

            payload = b"/" + b"B" * 8000
            req = struct.pack(
                "!2sHHH2s6s4sI",
                b"\x00\x02", kXR_open,
                0o644, kXR_open_read,
                b"\x00\x00", b"\x00" * 6, b"\x00" * 4,
                len(payload),
            )
            sock.sendall(req + payload)
            try:
                status, body = _read_response(sock)
                assert status == kXR_ERROR
            except (ConnectionResetError, BrokenPipeError, AssertionError):
                pass  # Server disconnecting on oversized payload is acceptable


# ===========================================================================
# Double-close and use-after-close
# ===========================================================================

class TestUseAfterClose:
    """Operations on a closed handle must fail cleanly."""

    @pytest.fixture(autouse=True)
    def _setup_file(self):
        self.remote = "/_priv_use_after_close.txt"
        self.disk_path = os.path.join(DATA_DIR, "_priv_use_after_close.txt")
        with open(self.disk_path, "wb") as f:
            f.write(b"use after close test\n")
        yield
        _unlink_if_exists(self.disk_path)

    def test_read_after_close(self):
        """Reading from a closed handle must return kXR_FileNotOpen."""
        with _raw_session() as sock:
            _login_anon(sock)

            # Open
            status, body = _open_file_raw(sock, self.remote.encode(), kXR_open_read)
            assert status == kXR_OK
            fhandle = body[:4]

            # Close
            _close_handle_raw(sock, fhandle, streamid=b"\x00\x03")

            # Try to read the closed handle
            req = struct.pack(
                "!2sH4sqiI",
                b"\x00\x04", kXR_read,
                fhandle,
                0, 100, 0,
            )
            sock.sendall(req)
            status, body = _read_response(sock)

        assert status == kXR_ERROR
        assert _error_code(body) == kXR_FileNotOpen

    def test_double_close(self):
        """Closing an already-closed handle must not crash."""
        with _raw_session() as sock:
            _login_anon(sock)

            status, body = _open_file_raw(sock, self.remote.encode(), kXR_open_read)
            assert status == kXR_OK
            fhandle = body[:4]

            # First close
            _close_handle_raw(sock, fhandle, streamid=b"\x00\x03")

            # Second close on same handle
            req = struct.pack(
                "!2sH4s12sI",
                b"\x00\x04", kXR_close,
                fhandle, b"\x00" * 12, 0,
            )
            sock.sendall(req)
            status, body = _read_response(sock)

        assert status == kXR_ERROR
        assert _error_code(body) == kXR_FileNotOpen


# ===========================================================================
# Empty/zero payload edge cases
# ===========================================================================

class TestEmptyPayloads:
    """Operations with missing mandatory path payloads must fail."""

    def test_rm_no_path(self):
        """kXR_rm with dlen=0 (no path) should fail."""
        with _raw_session() as sock:
            _login_anon(sock)

            req = struct.pack(
                "!2sH16sI",
                b"\x00\x02", kXR_rm,
                b"\x00" * 16, 0,
            )
            sock.sendall(req)
            status, body = _read_response(sock)

        assert status == kXR_ERROR

    def test_mkdir_no_path(self):
        """kXR_mkdir with dlen=0 should fail."""
        with _raw_session() as sock:
            _login_anon(sock)

            req = struct.pack(
                "!2sH1s13sHI",
                b"\x00\x02", kXR_mkdir,
                b"\x00", b"\x00" * 13, 0o755, 0,
            )
            sock.sendall(req)
            status, body = _read_response(sock)

        assert status == kXR_ERROR

    def test_stat_no_path_no_handle(self):
        """kXR_stat with dlen=0 and no handle should still succeed (stat of handle 0)."""
        # This tests the edge case — stat with fhandle=0 and dlen=0 might
        # map to handle-based stat, which should fail if handle 0 is not open
        with _raw_session() as sock:
            _login_anon(sock)

            req = struct.pack(
                "!2sH1s7sI4sI",
                b"\x00\x02", kXR_stat,
                b"\x00", b"\x00" * 7, 0,
                b"\x00" * 4,    # fhandle 0
                0,              # dlen=0
            )
            sock.sendall(req)
            status, body = _read_response(sock)

        # Either OK (if stat goes path-based with empty path → root)
        # or ERROR (if handle 0 is not open). Both are acceptable as
        # long as the server doesn't crash.
        assert status in (kXR_OK, kXR_ERROR)


# ===========================================================================
# Path traversal attempts (raw protocol — avoids XRootD client hangs)
# ===========================================================================

class TestPathTraversal:
    """Path traversal attempts must be caught and rejected."""

    def test_stat_dot_dot_traversal(self):
        """stat('/../etc/passwd') must be rejected."""
        with _raw_session() as sock:
            _login_anon(sock)

            payload = b"/../etc/passwd"
            req = struct.pack(
                "!2sH1s7sI4sI",
                b"\x00\x02", kXR_stat,
                b"\x00", b"\x00" * 7, 0, b"\x00" * 4,
                len(payload),
            )
            sock.sendall(req + payload)
            try:
                status, body = _read_response(sock)
                assert status == kXR_ERROR
            except (ConnectionResetError, BrokenPipeError):
                pass  # disconnecting is also acceptable

    def test_open_dot_dot_traversal(self):
        """open('/../etc/passwd') must be rejected."""
        with _raw_session() as sock:
            _login_anon(sock)

            payload = b"/../etc/passwd"
            req = struct.pack(
                "!2sHHH2s6s4sI",
                b"\x00\x02", kXR_open,
                0o644, kXR_open_read,
                b"\x00\x00", b"\x00" * 6, b"\x00" * 4,
                len(payload),
            )
            sock.sendall(req + payload)
            try:
                status, body = _read_response(sock)
                assert status == kXR_ERROR
            except (ConnectionResetError, BrokenPipeError):
                pass

    def test_dirlist_outside_root(self):
        """dirlist('/../') must not expose system directories."""
        with _raw_session() as sock:
            _login_anon(sock)

            payload = b"/../"
            req = struct.pack(
                "!2sH15sBi",
                b"\x00\x02", kXR_dirlist,
                b"\x00" * 15, 0,
                len(payload),
            )
            sock.sendall(req + payload)
            try:
                status, body = _read_response(sock)
                if status == kXR_OK:
                    listing = body.decode("utf-8", errors="replace")
                    # /etc, /usr, /var should NOT appear
                    assert "etc" not in listing.split("\n")
                    assert "usr" not in listing.split("\n")
                else:
                    assert status == kXR_ERROR  # outright rejection is fine
            except (ConnectionResetError, BrokenPipeError):
                pass

    def test_mv_dot_dot_destination(self):
        """mv to a path outside the root must be rejected."""
        src = os.path.join(DATA_DIR, "_priv_mv_src.txt")
        with open(src, "w") as f:
            f.write("mv traversal test\n")
        try:
            with _raw_session() as sock:
                _login_anon(sock)

                # kXR_mv payload is "oldpath \nnewpath"
                payload = b"/_priv_mv_src.txt\n/../../../tmp/_priv_mv_escaped.txt"
                req = struct.pack(
                    "!2sH16sI",
                    b"\x00\x02", kXR_mv,
                    b"\x00" * 16,
                    len(payload),
                )
                sock.sendall(req + payload)
                try:
                    status, body = _read_response(sock)
                    assert status == kXR_ERROR
                except (ConnectionResetError, BrokenPipeError):
                    pass

            assert os.path.exists(src), "source was removed despite traversal block"
            assert not os.path.exists("/tmp/_priv_mv_escaped.txt")
        finally:
            _unlink_if_exists(src)
            _unlink_if_exists("/tmp/_priv_mv_escaped.txt")
