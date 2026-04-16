"""
tests/test_server_robustness.py

Adversarial / robustness tests against a running XRootD server.

Uses raw TCP sockets with hand-crafted XRootD protocol messages to probe for:

  • Lockups   — server stops answering legitimate clients after malformed input
  • Crashes   — server process disappears
  • Auth-bypass — operations succeed without authentication
  • DoS vectors — a single client can exhaust connections or file descriptors
  • Protocol fuzzing — garbage opcodes, wrong dlen, bad magic, embedded nulls

The target is the nginx-xrootd anonymous endpoint on ANON_PORT.  Every
attack ends with a health check confirming the server still responds to
legitimate traffic.

Run with:
    pytest tests/test_server_robustness.py -v

Prerequisites:
    • nginx-xrootd running with anonymous auth on ANON_PORT  (default 1094)
    • A file at /tmp/xrd-test/data/ for read tests

Protocol wire layout (from xrootd_protocol.h + XProtocol.hh):

  ClientInitHandShake (20 bytes):
    first[4]=0  second[4]=0  third[4]=0  fourth[4]=htonl(4)  fifth[4]=htonl(2012)

  ClientRequestHdr (24 bytes):
    streamid[2]  requestid[2]  body[16]  dlen[4]
    ↑ All fields big-endian.  dlen = bytes of payload that follow.

  ClientOpenRequest body[16]:
    mode[2]  options[2]  optiont[2]  reserved[6]  fhtemplt[4]

  ClientReadRequest body[16]:
    fhandle[4]  offset[8]  rlen[4]
    ↑ No separate payload; dlen = 0.

  ClientCloseRequest body[16]:
    fhandle[4]  reserved[12]
    ↑ No payload; dlen = 0.

  ServerResponseHdr (8 bytes):
    streamid[2]  status[2]  dlen[4]
"""

import os
import socket
import struct
import threading
import time

import pytest

# ---------------------------------------------------------------------------
# Target
# ---------------------------------------------------------------------------

ANON_HOST = "localhost"
ANON_PORT = 11094         # nginx-xrootd anonymous endpoint

# ---------------------------------------------------------------------------
# XRootD protocol constants
# ---------------------------------------------------------------------------

# Request opcodes
kXR_auth     = 3000
kXR_close    = 3003
kXR_dirlist  = 3004
kXR_protocol = 3006
kXR_login    = 3007
kXR_mkdir    = 3008
kXR_open     = 3010
kXR_ping     = 3011
kXR_read     = 3013
kXR_rm       = 3014
kXR_stat     = 3017
kXR_write    = 3019
kXR_pgwrite  = 3026

# Response status codes
kXR_ok        = 0
kXR_error     = 4003

# Error codes (first 4 bytes of kXR_error body)
kXR_NotAuthorized = 3010
kXR_Unsupported   = 3013
kXR_FileNotOpen   = 3004

# Protocol version 5.2.0
PROTOVER = 0x00000520

# Handshake magic values
ROOTD_PQ = 2012

# ---------------------------------------------------------------------------
# Protocol builders
# All integers big-endian; all body arguments must be exactly 16 bytes.
# ---------------------------------------------------------------------------

HANDSHAKE              = struct.pack(">iiiii", 0, 0, 0, 4, ROOTD_PQ)
HANDSHAKE_BAD_FOURTH   = struct.pack(">iiiii", 0, 0, 0, 0, ROOTD_PQ)  # fourth must be 4
HANDSHAKE_BAD_FIFTH    = struct.pack(">iiiii", 0, 0, 0, 4, 9999)       # fifth must be 2012


def _body16(data: bytes) -> bytes:
    """Pad or truncate data to exactly 16 bytes."""
    return data[:16].ljust(16, b'\x00')


def make_request(streamid: bytes, reqid: int,
                 body: bytes = b'\x00' * 16,
                 payload: bytes = b'') -> bytes:
    """
    Build one complete XRootD request:
      ClientRequestHdr (24 bytes) + optional payload.
    streamid must be 2 bytes; body must be 16 bytes.
    """
    return (streamid
            + struct.pack(">H", reqid)
            + _body16(body)
            + struct.pack(">i", len(payload))
            + payload)


def make_protocol_req(streamid: bytes = b'\x00\x01',
                      flags: int = 0x01) -> bytes:
    """kXR_protocol — capability negotiation."""
    body = struct.pack(">I", PROTOVER)  # clientpv (4 bytes)
    body += bytes([flags])              # flags: 0x01 = kXR_secreqs
    body += b'\x00' * 11               # reserved
    return make_request(streamid, kXR_protocol, body)


def make_login_req(streamid: bytes = b'\x00\x02',
                   username: bytes = b'test\x00\x00\x00\x00') -> bytes:
    """kXR_login — anonymous login.
    ClientLoginRequest body[16]: pid[4] username[8] ability2[1] ability[1] capver[1] reserved[1]
    """
    body  = struct.pack(">I", os.getpid() & 0xFFFFFFFF)  # pid
    body += username[:8].ljust(8, b'\x00')                # username
    body += b'\x00'                                         # ability2
    body += b'\x00'                                         # ability
    body += b'\x05'                                         # capver (v5)
    body += b'\x00'                                         # reserved
    return make_request(streamid, kXR_login, body)


def make_ping_req(streamid: bytes = b'\x00\x03') -> bytes:
    """kXR_ping — liveness check (no body, no payload)."""
    return make_request(streamid, kXR_ping)


def make_stat_req(path: bytes, streamid: bytes = b'\x00\x04') -> bytes:
    """kXR_stat — stat a path.
    ClientStatRequest body[16]: options[1] reserved[7] wants[4] fhandle[4]
    Path (null-terminated) is the payload.
    """
    return make_request(streamid, kXR_stat,
                        body=b'\x00' * 16,
                        payload=path + b'\x00')


def make_open_req(path: bytes, options: int = 0x0010,
                  streamid: bytes = b'\x00\x05') -> bytes:
    """kXR_open — open a file.
    ClientOpenRequest body[16]: mode[2] options[2] optiont[2] reserved[6] fhtemplt[4]
    Path (null-terminated) is the payload.
    """
    body  = struct.pack(">H", 0)        # mode (POSIX bits; 0 = default)
    body += struct.pack(">H", options)  # options: 0x0010 = kXR_open_read
    body += b'\x00' * 12               # optiont + reserved + fhtemplt
    return make_request(streamid, kXR_open, body, path + b'\x00')


def make_read_req(handle: bytes, offset: int, rlen: int,
                  streamid: bytes = b'\x00\x06') -> bytes:
    """kXR_read — read from an open file.
    ClientReadRequest body[16]: fhandle[4] offset[8] rlen[4]
    No payload; dlen = 0.
    """
    body = handle[:4] + struct.pack(">qi", offset, rlen)
    return make_request(streamid, kXR_read, body)


def make_close_req(handle: bytes,
                   streamid: bytes = b'\x00\x07') -> bytes:
    """kXR_close — close an open file handle.
    ClientCloseRequest body[16]: fhandle[4] reserved[12]
    """
    body = handle[:4] + b'\x00' * 12
    return make_request(streamid, kXR_close, body)


# ---------------------------------------------------------------------------
# Low-level socket helpers
# ---------------------------------------------------------------------------

RECV_TIMEOUT = 5.0
CONN_TIMEOUT = 3.0


def _connect(host: str = ANON_HOST, port: int = ANON_PORT) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(CONN_TIMEOUT)
    s.connect((host, port))
    s.settimeout(RECV_TIMEOUT)
    return s


def _recvall(s: socket.socket, n: int) -> bytes:
    buf = b''
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise ConnectionError(f"Server closed after {len(buf)}/{n} bytes")
        buf += chunk
    return buf


def _recv_response(s: socket.socket) -> tuple[int, bytes]:
    """Read one complete ServerResponseHdr + body. Returns (status, body)."""
    hdr    = _recvall(s, 8)
    status = struct.unpack(">H", hdr[2:4])[0]
    dlen   = struct.unpack(">i", hdr[4:8])[0]
    body   = _recvall(s, dlen) if dlen > 0 else b''
    return status, body


def _handshake_and_protocol(s: socket.socket) -> tuple[int, int]:
    """Send handshake + kXR_protocol; return (hs_status, proto_status)."""
    s.sendall(HANDSHAKE + make_protocol_req())
    hs_st, _  = _recv_response(s)
    pr_st, _  = _recv_response(s)
    return hs_st, pr_st


def _full_anon_login(s: socket.socket) -> tuple[int, int, int]:
    """Handshake + protocol + anonymous login. Returns (hs, proto, login) statuses."""
    hs_st, pr_st = _handshake_and_protocol(s)
    s.sendall(make_login_req())
    lg_st, _ = _recv_response(s)
    return hs_st, pr_st, lg_st


def _errcode(body: bytes) -> int:
    """Extract the 4-byte error code from a kXR_error response body."""
    return struct.unpack(">I", body[:4])[0] if len(body) >= 4 else 0


# ---------------------------------------------------------------------------
# Health check — confirm server still serves legitimate requests
# ---------------------------------------------------------------------------

def server_healthy(host: str = ANON_HOST, port: int = ANON_PORT) -> bool:
    """
    Connect, complete handshake + login + ping.
    Returns True if every step returns kXR_ok within short timeouts.
    """
    try:
        s = _connect(host, port)
        s.settimeout(4.0)
        hs_st, pr_st = _handshake_and_protocol(s)
        if hs_st != kXR_ok or pr_st != kXR_ok:
            s.close()
            return False
        s.sendall(make_login_req())
        lg_st, _ = _recv_response(s)
        if lg_st != kXR_ok:
            s.close()
            return False
        s.sendall(make_ping_req())
        ping_st, _ = _recv_response(s)
        s.close()
        return ping_st == kXR_ok
    except Exception:
        return False


def assert_healthy(host: str = ANON_HOST, port: int = ANON_PORT, retries: int = 3):
    """Verify the server is healthy, retrying briefly to allow recovery."""
    for _ in range(retries):
        if server_healthy(host, port):
            return
        time.sleep(0.5)
    pytest.fail(
        f"Server at {host}:{port} failed health check after {retries} attempts — "
        "it may have crashed or locked up."
    )


# ---------------------------------------------------------------------------
# Module fixture — skip if server is not reachable
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
def require_server():
    """Skip the entire module if the target server is not reachable."""
    if not server_healthy():
        pytest.skip(
            f"No XRootD server reachable at {ANON_HOST}:{ANON_PORT}. "
            "Start nginx-xrootd before running robustness tests."
        )


# ============================================================================
# 1. Lockup probes
#    Malformed or truncated input must never cause the server to hang.
# ============================================================================

class TestLockup:

    def test_partial_handshake_10_bytes(self):
        """Send 10 of 20 handshake bytes then nothing."""
        s = _connect()
        s.sendall(HANDSHAKE[:10])
        try:
            s.settimeout(3.0)
            s.recv(1024)
        except (socket.timeout, ConnectionError, OSError):
            pass
        finally:
            s.close()
        assert_healthy()

    def test_partial_handshake_19_bytes(self):
        """One byte short of a valid handshake."""
        s = _connect()
        s.sendall(HANDSHAKE[:19])
        try:
            s.settimeout(3.0)
            s.recv(1024)
        except (socket.timeout, ConnectionError, OSError):
            pass
        finally:
            s.close()
        assert_healthy()

    def test_handshake_then_silence(self):
        """Valid handshake then no kXR_protocol — other clients must not be blocked."""
        s = _connect()
        s.sendall(HANDSHAKE)
        time.sleep(1.0)
        s.close()
        assert_healthy()

    def test_huge_dlen_no_body_after_login(self):
        """
        After login, send a ping header claiming a 1 MB payload but provide
        no bytes at all.  Server must not freeze waiting for data.
        """
        s = _connect()
        _full_anon_login(s)
        # kXR_ping header with dlen=1_000_000 (no payload follows)
        bad = b'\x00\x10' + struct.pack(">H", kXR_ping) + b'\x00' * 16 + struct.pack(">i", 1_000_000)
        s.sendall(bad)
        try:
            s.settimeout(3.0)
            s.recv(1024)
        except (socket.timeout, ConnectionError, OSError):
            pass
        finally:
            s.close()
        assert_healthy()

    def test_dlen_max_uint32_after_login(self):
        """dlen = 0xFFFFFFFF — server must not wait for 4 GB of body."""
        s = _connect()
        _full_anon_login(s)
        bad = b'\x00\x11' + struct.pack(">H", kXR_stat) + b'\x00' * 16 + struct.pack(">I", 0xFFFFFFFF)
        s.sendall(bad)
        try:
            s.settimeout(3.0)
            s.recv(1024)
        except (socket.timeout, ConnectionError, OSError):
            pass
        finally:
            s.close()
        assert_healthy()

    def test_connect_and_send_nothing(self):
        """Open TCP, send nothing, leave it open for a second."""
        s = _connect()
        time.sleep(1.5)
        s.close()
        assert_healthy()

    def test_50_silent_connections_do_not_block_legitimate_traffic(self):
        """
        50 connections that stall after the handshake.
        A fresh connection must still complete successfully.
        """
        stale = []
        for _ in range(50):
            try:
                s = _connect()
                s.sendall(HANDSHAKE)
                stale.append(s)
            except OSError:
                break   # kernel queue limit; acceptable
        assert_healthy()   # must respond while stale sockets are still open
        for s in stale:
            try:
                s.close()
            except OSError:
                pass

    def test_truncated_request_header(self):
        """Send 15 of the 24 header bytes after login, then stop."""
        s = _connect()
        _full_anon_login(s)
        s.sendall(b'\x00\x50' + struct.pack(">H", kXR_ping) + b'\x00' * 11)
        try:
            s.settimeout(3.0)
            s.recv(1024)
        except (socket.timeout, ConnectionError, OSError):
            pass
        finally:
            s.close()
        assert_healthy()


# ============================================================================
# 2. Authentication bypass
#    Operations requiring a session must always fail before login.
# ============================================================================

class TestAuthBypass:

    def _proto_only(self) -> socket.socket:
        """Connect and negotiate protocol, but do NOT login."""
        s = _connect()
        _handshake_and_protocol(s)
        return s

    def test_stat_before_login(self):
        s = self._proto_only()
        s.sendall(make_stat_req(b'/'))
        status, body = _recv_response(s)
        s.close()
        assert status == kXR_error, f"Pre-login stat must fail, got {status}"
        assert _errcode(body) == kXR_NotAuthorized, \
            f"Expected NotAuthorized(3010), got {_errcode(body)}"
        assert_healthy()

    def test_open_before_login(self):
        s = self._proto_only()
        s.sendall(make_open_req(b'/'))
        status, body = _recv_response(s)
        s.close()
        assert status == kXR_error, f"Pre-login open must fail, got {status}"
        assert _errcode(body) == kXR_NotAuthorized
        assert_healthy()

    def test_read_with_fake_handle_before_login(self):
        s = self._proto_only()
        s.sendall(make_read_req(b'\xDE\xAD\xBE\xEF', 0, 4096,
                                streamid=b'\x00\x20'))
        status, body = _recv_response(s)
        s.close()
        assert status == kXR_error, f"Pre-login read must fail, got {status}"
        assert_healthy()

    def test_dirlist_before_login(self):
        s = self._proto_only()
        s.sendall(make_request(b'\x00\x21', kXR_dirlist,
                               payload=b'/\x00'))
        status, _ = _recv_response(s)
        s.close()
        assert status == kXR_error
        assert_healthy()

    def test_mkdir_before_login(self):
        s = self._proto_only()
        s.sendall(make_request(b'\x00\x22', kXR_mkdir,
                               payload=b'/probe_mkdir\x00'))
        status, _ = _recv_response(s)
        s.close()
        assert status == kXR_error
        assert_healthy()

    def test_rm_before_login(self):
        s = self._proto_only()
        s.sendall(make_request(b'\x00\x23', kXR_rm,
                               payload=b'/probe_rm\x00'))
        status, _ = _recv_response(s)
        s.close()
        assert status == kXR_error
        assert_healthy()

    def test_write_before_login(self):
        """kXR_write with invented handle before login must fail."""
        s = self._proto_only()
        body = b'\xDE\xAD\xBE\xEF' + b'\x00' * 12   # fhandle + reserved
        s.sendall(make_request(b'\x00\x24', kXR_write, body,
                               payload=b'malicious data'))
        status, _ = _recv_response(s)
        s.close()
        assert status == kXR_error
        assert_healthy()

    def test_auth_before_login(self):
        """kXR_auth before kXR_login must not succeed."""
        s = self._proto_only()
        s.sendall(make_request(b'\x00\x25', kXR_auth,
                               payload=b'garbage_auth_data'))
        status, _ = _recv_response(s)
        s.close()
        # kXR_authmore (4002) would indicate the server is treating this as a valid
        # auth exchange — that is a bug. ok (0) is also a bug.
        assert status not in (kXR_ok, 4002), \
            f"kXR_auth before login should be rejected, got status={status}"
        assert_healthy()

    def test_double_login_does_not_crash(self):
        """A second kXR_login on an already-logged-in connection must not crash."""
        s = _connect()
        _full_anon_login(s)
        s.sendall(make_login_req(streamid=b'\x00\x30',
                                 username=b'hacker\x00\x00'))
        try:
            _recv_response(s)
        except (socket.timeout, ConnectionError):
            pass
        s.close()
        assert_healthy()


# ============================================================================
# 3. Protocol fuzzing
#    Unknown opcodes, boundary paths, extreme values, garbage bytes.
# ============================================================================

class TestProtocolFuzzing:

    def _logged_in(self) -> socket.socket:
        s = _connect()
        _full_anon_login(s)
        return s

    def test_unknown_opcode_zero(self):
        """Opcode 0 is not defined — must return error, never kXR_ok."""
        s = self._logged_in()
        s.sendall(make_request(b'\x00\x40', 0))
        try:
            status, _ = _recv_response(s)
        except (socket.timeout, ConnectionError):
            status = kXR_error
        s.close()
        assert status != kXR_ok, "Unknown opcode 0 returned kXR_ok"
        assert_healthy()

    def test_unknown_opcode_0xffff(self):
        """Opcode 0xFFFF — extreme garbage."""
        s = self._logged_in()
        s.sendall(make_request(b'\x00\x41', 0xFFFF))
        try:
            status, _ = _recv_response(s)
        except (socket.timeout, ConnectionError):
            status = kXR_error
        s.close()
        assert status != kXR_ok
        assert_healthy()

    def test_unknown_opcode_9999(self):
        """Opcode 9999 — not currently assigned."""
        s = self._logged_in()
        s.sendall(make_request(b'\x00\x42', 9999))
        try:
            status, _ = _recv_response(s)
        except (socket.timeout, ConnectionError):
            status = kXR_error
        s.close()
        assert status != kXR_ok
        assert_healthy()

    def test_path_with_embedded_null(self):
        """Path containing a null byte (/\\x00etc/passwd) must not escape or crash."""
        s = self._logged_in()
        req = make_request(b'\x00\x43', kXR_stat,
                           body=b'\x00' * 16,
                           payload=b'/\x00etc/passwd\x00')
        s.sendall(req)
        try:
            status, body = _recv_response(s)
        except (socket.timeout, ConnectionError):
            status = kXR_error
            body = b''
        s.close()
        # If the server responds ok, it must be for "/" (empty path after null),
        # never for /etc/passwd. In practice most implementations reject empty paths.
        # What we strictly forbid is any response that includes /etc/passwd content.
        if status == kXR_ok and body:
            assert b'/etc/passwd' not in body, \
                "Null-byte injection may have exposed /etc/passwd"
        assert_healthy()

    def test_path_at_maximum_length_4096(self):
        """Stat a path exactly 4096 bytes long — limit boundary."""
        s = self._logged_in()
        path = b'/' + b'a' * 4094
        req  = make_request(b'\x00\x44', kXR_stat,
                            body=b'\x00' * 16,
                            payload=path + b'\x00')
        s.sendall(req)
        try:
            _recv_response(s)   # ok or error — either is fine; no crash
        except (socket.timeout, ConnectionError):
            pass
        s.close()
        assert_healthy()

    def test_path_one_over_maximum(self):
        """Path 1 byte over the 4096-byte limit must be rejected."""
        s = self._logged_in()
        path = b'/' + b'a' * 4095
        req  = make_request(b'\x00\x45', kXR_stat,
                            body=b'\x00' * 16,
                            payload=path + b'\x00')
        s.sendall(req)
        try:
            status, _ = _recv_response(s)
        except (socket.timeout, ConnectionError):
            status = kXR_error
        s.close()
        assert status != kXR_ok, "Over-length path must be rejected"
        assert_healthy()

    def test_null_only_path(self):
        """Path that is just a null byte must not crash."""
        s = self._logged_in()
        req = make_request(b'\x00\x46', kXR_stat,
                           body=b'\x00' * 16,
                           payload=b'\x00')
        s.sendall(req)
        try:
            _recv_response(s)
        except (socket.timeout, ConnectionError):
            pass
        s.close()
        assert_healthy()

    def test_stream_id_all_ones(self):
        """Stream ID 0xFFFF is uncommon but legal."""
        s = self._logged_in()
        s.sendall(make_ping_req(streamid=b'\xFF\xFF'))
        try:
            _recv_response(s)
        except (socket.timeout, ConnectionError):
            pass
        s.close()
        assert_healthy()

    def test_all_zero_24_byte_request(self):
        """24 zero bytes after login — opcode 0, dlen 0."""
        s = self._logged_in()
        s.sendall(b'\x00' * 24)
        try:
            _recv_response(s)
        except (socket.timeout, ConnectionError):
            pass
        s.close()
        assert_healthy()

    def test_all_ff_24_byte_request(self):
        """24 0xFF bytes — extreme garbage. Server must not crash."""
        s = self._logged_in()
        s.sendall(b'\xff' * 24)
        try:
            s.settimeout(3.0)
            s.recv(1024)   # accept close or error
        except (socket.timeout, ConnectionError, OSError):
            pass
        s.close()
        assert_healthy()

    def test_bad_handshake_fourth_field(self):
        """fourth field must be 4; wrong value must be rejected cleanly."""
        try:
            s = _connect()
            s.sendall(HANDSHAKE_BAD_FOURTH)
            s.settimeout(3.0)
            s.recv(1024)
            s.close()
        except (socket.timeout, ConnectionError, OSError):
            pass
        assert_healthy()

    def test_bad_handshake_fifth_field(self):
        """fifth field must be 2012; wrong value must be rejected cleanly."""
        try:
            s = _connect()
            s.sendall(HANDSHAKE_BAD_FIFTH)
            s.settimeout(3.0)
            s.recv(1024)
            s.close()
        except (socket.timeout, ConnectionError, OSError):
            pass
        assert_healthy()

    def test_200_repeated_kxr_protocol_requests(self):
        """
        200 kXR_protocol requests on one connection.
        Server must respond to each, never exhaust per-session state.
        """
        s = _connect()
        _handshake_and_protocol(s)
        for i in range(200):
            sid = struct.pack(">H", (i % 0xFFFE) + 1)
            s.sendall(make_protocol_req(streamid=sid))
        ok_count = 0
        for _ in range(200):
            try:
                status, _ = _recv_response(s)
                if status == kXR_ok:
                    ok_count += 1
            except (socket.timeout, ConnectionError):
                break
        s.close()
        assert ok_count > 0, "No kXR_protocol responses received at all"
        assert_healthy()

    def test_wrong_login_body_zero_username(self):
        """kXR_login with an all-zero username — must not crash."""
        s = _connect()
        _handshake_and_protocol(s)
        body  = struct.pack(">I", os.getpid() & 0xFFFFFFFF)
        body += b'\x00' * 8   # all-zero username
        body += b'\x00\x00\x05\x00'
        s.sendall(make_request(b'\x00\x50', kXR_login, body))
        try:
            _recv_response(s)
        except (socket.timeout, ConnectionError):
            pass
        s.close()
        assert_healthy()


# ============================================================================
# 4. Resource exhaustion
#    Single clients must not exhaust server-side resources.
# ============================================================================

class TestResourceExhaustion:

    def test_connection_storm_50(self):
        """
        50 connections opened simultaneously.  Each performs the handshake +
        protocol negotiation, then is closed.  The server must survive and
        remain responsive; some connection resets under load are tolerated.
        """
        assert_healthy()   # ensure we start from a clean state
        sockets = []
        failures = 0
        for _ in range(50):
            try:
                s = _connect()
                hs_st, pr_st = _handshake_and_protocol(s)
                if hs_st == kXR_ok and pr_st == kXR_ok:
                    sockets.append(s)
                else:
                    s.close()
                    failures += 1
            except OSError:
                failures += 1
        # Close all before asserting health so the server can drain its backlog.
        for s in sockets:
            try:
                s.close()
            except OSError:
                pass
        # Under load some resets are expected (nginx event loop, WSL2 limits).
        # What matters is that the server recovers fully afterwards.
        assert failures <= 25, f"Too many failures ({failures}/50) in connection storm"
        assert_healthy(retries=6)

    def test_rapid_connect_disconnect_50(self):
        """50 rapid connect-then-immediately-close cycles."""
        assert_healthy(retries=6)   # wait for any prior storm to drain
        for _ in range(50):
            try:
                s = _connect()
                s.close()
            except OSError:
                pass
        assert_healthy(retries=6)

    def test_ping_flood_1000(self):
        """
        1000 pings on one authenticated connection.
        Every ping must return kXR_ok (99% success threshold).
        """
        assert_healthy(retries=6)   # wait for any prior storm to drain
        s = _connect()
        _full_anon_login(s)
        n = 1000
        for i in range(n):
            sid = struct.pack(">H", (i % 0xFFFE) + 1)
            s.sendall(make_ping_req(streamid=sid))
        ok_count = 0
        for _ in range(n):
            try:
                s.settimeout(10.0)
                status, _ = _recv_response(s)
                if status == kXR_ok:
                    ok_count += 1
            except (socket.timeout, ConnectionError):
                break
        s.close()
        assert ok_count >= int(n * 0.99), \
            f"Ping flood: only {ok_count}/{n} pings returned kXR_ok"
        assert_healthy()

    def test_open_16_handles_and_close_cleanly(self):
        """Open 16 file handles and close each one in sequence."""
        assert_healthy(retries=6)
        test_path = "/tmp/xrd-test/data/robustness_handles.bin"
        with open(test_path, "wb") as f:
            f.write(b'x' * 1024)
        s = _connect()
        _full_anon_login(s)

        handles = []
        for i in range(16):
            sid = struct.pack(">H", 0x0100 + i)
            s.sendall(make_open_req(b'/robustness_handles.bin', streamid=sid))
            try:
                status, body = _recv_response(s)
                if status == kXR_ok and len(body) >= 4:
                    handles.append(body[:4])
            except (socket.timeout, ConnectionError):
                break

        assert len(handles) >= 8, \
            f"Expected to open at least 8 handles, got {len(handles)}"

        for i, handle in enumerate(handles):
            sid = struct.pack(">H", 0x0180 + i)
            s.sendall(make_close_req(handle, streamid=sid))
            try:
                _recv_response(s)
            except (socket.timeout, ConnectionError):
                break

        s.close()
        os.unlink(test_path)
        assert_healthy()

    def test_open_beyond_handle_limit_returns_error(self):
        """Opening more than 16 files must return an error, not crash."""
        assert_healthy(retries=6)
        test_path = "/tmp/xrd-test/data/robustness_overlimit.bin"
        with open(test_path, "wb") as f:
            f.write(b'y' * 1024)
        s = _connect()
        _full_anon_login(s)

        open_count   = 0
        first_err_at = None
        for i in range(20):
            sid = struct.pack(">H", 0x0200 + i)
            s.sendall(make_open_req(b'/robustness_overlimit.bin', streamid=sid))
            try:
                status, _ = _recv_response(s)
                if status == kXR_ok:
                    open_count += 1
                elif first_err_at is None:
                    first_err_at = i
            except (socket.timeout, ConnectionError):
                break

        s.close()
        os.unlink(test_path)

        assert open_count <= 16, \
            f"Server allowed {open_count} simultaneous handles (limit is 16)"
        assert first_err_at is not None, \
            "Server never returned an error after exceeding handle limit"
        assert_healthy()


# ============================================================================
# 5. State machine attacks
#    Protocol must be enforced regardless of operation ordering.
# ============================================================================

class TestStateMachineAttacks:

    def test_read_from_closed_handle(self):
        """
        Open a file, read from it, close it, then re-read with the same handle.
        The second read must fail.
        """
        test_path = "/tmp/xrd-test/data/robustness_reuse.bin"
        with open(test_path, "wb") as f:
            f.write(b"REUSE TEST DATA " * 64)   # 1024 bytes

        s = _connect()
        _full_anon_login(s)

        # Open
        s.sendall(make_open_req(b'/robustness_reuse.bin', streamid=b'\x00\x70'))
        open_st, open_body = _recv_response(s)
        assert open_st == kXR_ok, "Could not open test file"
        handle = open_body[:4]

        # Read once — must succeed
        s.sendall(make_read_req(handle, 0, 256, streamid=b'\x00\x71'))
        read_st, _ = _recv_response(s)
        assert read_st == kXR_ok, f"First read failed with {read_st}"

        # Close
        s.sendall(make_close_req(handle, streamid=b'\x00\x72'))
        _recv_response(s)

        # Read again with the same handle — must fail
        s.sendall(make_read_req(handle, 0, 256, streamid=b'\x00\x73'))
        try:
            stale_st, _ = _recv_response(s)
        except (socket.timeout, ConnectionError):
            stale_st = kXR_error

        s.close()
        os.unlink(test_path)

        assert stale_st != kXR_ok, \
            f"Read from closed handle returned kXR_ok — use-after-close!"
        assert_healthy()

    def test_endsess_closes_open_file_handles(self):
        """
        After kXR_endsess, any file handles that were open must be invalidated.
        The XRootD spec says kXR_endsess releases all session resources; a read
        using a handle opened before endsess must therefore fail.

        Note: the protocol does not require the server to invalidate the TCP
        session itself — the client is expected to close the connection.  So
        path-based ops (stat, dirlist) may still work on the same socket; that
        is implementation-defined behaviour, not a bug.
        """
        test_path = "/tmp/xrd-test/data/robustness_endsess.bin"
        with open(test_path, "wb") as f:
            f.write(b'ENDSESS DATA ' * 80)

        s = _connect()
        _full_anon_login(s)

        # Open a file — must succeed
        s.sendall(make_open_req(b'/robustness_endsess.bin', streamid=b'\x00\x60'))
        open_st, open_body = _recv_response(s)
        assert open_st == kXR_ok, "Could not open test file"
        handle = open_body[:4]

        # Verify it is readable
        s.sendall(make_read_req(handle, 0, 64, streamid=b'\x00\x61'))
        read_st, _ = _recv_response(s)
        assert read_st == kXR_ok, "Pre-endsess read must succeed"

        # End session
        s.sendall(make_request(b'\x00\x62', 3023))  # kXR_endsess
        try:
            _recv_response(s)
        except (socket.timeout, ConnectionError):
            pass

        # Read with the same handle — must fail (handle was released by endsess)
        s.sendall(make_read_req(handle, 0, 64, streamid=b'\x00\x63'))
        try:
            s.settimeout(2.0)
            post_st, _ = _recv_response(s)
        except (socket.timeout, ConnectionError, OSError):
            post_st = kXR_error  # connection closed is also correct

        s.close()
        os.unlink(test_path)

        assert post_st != kXR_ok, \
            "Read using handle from before kXR_endsess must fail after endsess"
        assert_healthy()

    def test_auth_after_anonymous_login(self):
        """Send kXR_auth after a successful anonymous login — must not crash."""
        s = _connect()
        _full_anon_login(s)
        s.sendall(make_request(b'\x00\x80', kXR_auth, payload=b'garbage'))
        try:
            _recv_response(s)
        except (socket.timeout, ConnectionError):
            pass
        s.close()
        assert_healthy()

    def test_read_without_prior_open(self):
        """kXR_read with an invented handle (no prior open) must return an error."""
        s = _connect()
        _full_anon_login(s)
        s.sendall(make_read_req(b'\xDE\xAD\xBE\xEF', 0, 4096,
                                streamid=b'\x00\x90'))
        try:
            status, body = _recv_response(s)
        except (socket.timeout, ConnectionError):
            status = kXR_error
            body = b''
        s.close()
        assert status == kXR_error, \
            f"Read with invented handle must fail, got {status}"
        assert_healthy()


# ============================================================================
# 6. Path traversal
#    Every escape attempt must be rejected cleanly.
# ============================================================================

class TestPathTraversal:

    TRAVERSAL_PATHS = [
        b"/../etc/passwd",
        b"/../../etc/shadow",
        b"/../../../root/.ssh/authorized_keys",
        b"/..",
        b"/../",
        b"/a/b/../../../../../../etc/passwd",
        b"/a/./b/./../../../../../../etc/passwd",
    ]

    def test_all_traversal_paths_rejected(self):
        """
        Every path-traversal attempt must return kXR_error, never kXR_ok.
        If the server closes the connection mid-test, we reconnect.
        """
        s = _connect()
        _full_anon_login(s)

        for path in self.TRAVERSAL_PATHS:
            req = make_request(b'\x00\xA0', kXR_stat,
                               body=b'\x00' * 16,
                               payload=path + b'\x00')
            s.sendall(req)
            try:
                status, body = _recv_response(s)
                assert status != kXR_ok, \
                    f"Traversal '{path!r}' returned kXR_ok — path escape!"
                # Extra check: body must not contain /etc content
                if body:
                    assert b'root:' not in body and b'/bin/bash' not in body, \
                        f"Traversal '{path!r}' returned /etc content!"
            except (socket.timeout, ConnectionError):
                # Connection dropped — server rejected it hard. Reconnect.
                s = _connect()
                _full_anon_login(s)

        s.close()
        assert_healthy()


# ============================================================================
# 7. Concurrency safety
#    Multiple threads must not corrupt each other's responses.
# ============================================================================

class TestConcurrencySafety:

    def _ping_worker(self, n: int, results: list, idx: int):
        ok = 0
        err = None
        try:
            s = _connect()
            _full_anon_login(s)
            for i in range(n):
                sid = struct.pack(">H", (idx * n + i) % 0xFFFE + 1)
                s.sendall(make_ping_req(streamid=sid))
                status, _ = _recv_response(s)
                if status == kXR_ok:
                    ok += 1
            s.close()
        except Exception as e:
            err = str(e)
        results.append((idx, ok, err))

    def test_16_concurrent_ping_sessions(self):
        """16 threads each send 50 pings on independent connections."""
        results = []
        threads = [
            threading.Thread(target=self._ping_worker, args=(50, results, i))
            for i in range(16)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        errors    = [r for r in results if r[2] is not None]
        total_ok  = sum(r[1] for r in results)

        assert errors == [], f"Thread errors: {errors}"
        assert total_ok == 16 * 50, \
            f"Expected {16*50} pings ok, got {total_ok}"
        assert_healthy()

    def test_concurrent_stat_and_ping(self):
        """
        8 ping threads + 8 stat threads simultaneously.
        No cross-connection response corruption should occur.
        """
        test_path = "/tmp/xrd-test/data/robustness_concurrent.bin"
        with open(test_path, "wb") as f:
            f.write(b'z' * 512)

        errors = []

        def ping_worker():
            try:
                s = _connect()
                _full_anon_login(s)
                for i in range(20):
                    sid = struct.pack(">H", i + 1)
                    s.sendall(make_ping_req(streamid=sid))
                    st, _ = _recv_response(s)
                    assert st == kXR_ok
                s.close()
            except Exception as e:
                errors.append(f"ping: {e}")

        def stat_worker():
            try:
                s = _connect()
                _full_anon_login(s)
                for i in range(20):
                    sid = struct.pack(">H", i + 1)
                    s.sendall(make_stat_req(b'/robustness_concurrent.bin',
                                           streamid=sid))
                    st, _ = _recv_response(s)
                    assert st == kXR_ok, f"stat returned {st}"
                s.close()
            except Exception as e:
                errors.append(f"stat: {e}")

        threads = (
            [threading.Thread(target=ping_worker) for _ in range(8)]
            + [threading.Thread(target=stat_worker) for _ in range(8)]
        )
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        os.unlink(test_path)
        assert errors == [], f"Concurrent errors: {errors}"
        assert_healthy()
