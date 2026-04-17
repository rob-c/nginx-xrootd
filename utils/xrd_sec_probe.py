"""
xrd_sec_probe.py — Adversarial security probe for XRootD protocol servers.

Tests lockup, resource-exhaustion, authentication-bypass, path-traversal,
and protocol-safety behaviours. After every probe, a health check confirms
the server still responds to a legitimate handshake+login+ping sequence.

Usage:
    python3 utils/xrd_sec_probe.py [HOST:PORT]

    HOST:PORT defaults to localhost:11094 (the anonymous test endpoint).

Outcomes:
  PASS    — server handled the input gracefully and is still healthy
  FINDING — server behaved in a security-relevant way (see detail)
  HANG    — server stopped responding after this input
  CRASH   — server process disappeared
  ERROR   — unexpected exception in the probe itself
"""

import os, socket, struct, threading, time, sys, textwrap, traceback

# ── target ─────────────────────────────────────────────────────────────────
_target = sys.argv[1] if len(sys.argv) > 1 else "localhost:11094"
if ":" in _target:
    HOST, _port = _target.rsplit(":", 1)
    PORT = int(_port)
else:
    HOST = _target
    PORT = 11094
XROOTD_VERSION  = "nginx-xrootd"

# ── protocol constants ──────────────────────────────────────────────────────
kXR_auth     = 3000; kXR_close  = 3003; kXR_dirlist  = 3004
kXR_protocol = 3006; kXR_login  = 3007; kXR_mkdir    = 3008
kXR_open     = 3010; kXR_ping   = 3011; kXR_read     = 3013
kXR_rm       = 3014; kXR_stat   = 3017; kXR_write    = 3019
kXR_endsess  = 3023; kXR_pgwrite= 3026

kXR_ok       = 0;    kXR_error  = 4003; kXR_authmore = 4002
kXR_NotAuthorized = 3010

PROTOVER = 0x00000520
ROOTD_PQ = 2012

HANDSHAKE     = struct.pack(">iiiii", 0, 0, 0, 4, ROOTD_PQ)
HS_BAD_FOURTH = struct.pack(">iiiii", 0, 0, 0, 0, ROOTD_PQ)
HS_BAD_FIFTH  = struct.pack(">iiiii", 0, 0, 0, 4, 9999)
HS_12_BYTE    = struct.pack(">III", 8, PROTOVER, 1)   # old ServerInitHandShake format

# ── wire builders ───────────────────────────────────────────────────────────

def _b16(b): return b[:16].ljust(16, b'\x00')

def req(sid, rid, body=b'', payload=b''):
    return sid + struct.pack(">H", rid) + _b16(body) + struct.pack(">i", len(payload)) + payload

def proto_req(sid=b'\x00\x01', flags=0x01):
    return req(sid, kXR_protocol, struct.pack(">I", PROTOVER) + bytes([flags]) + b'\x00'*11)

def login_req(sid=b'\x00\x02', user=b'probe\x00\x00\x00'):
    body = struct.pack(">I", os.getpid()&0xFFFFFFFF) + user[:8].ljust(8,b'\x00') + b'\x00\x00\x05\x00'
    return req(sid, kXR_login, body)

def ping_req(sid=b'\x00\x03'):
    return req(sid, kXR_ping)

def stat_req(path, sid=b'\x00\x04'):
    return req(sid, kXR_stat, payload=path+b'\x00')

def open_req(path, opts=0x0010, sid=b'\x00\x05'):
    body = struct.pack(">HH", 0, opts) + b'\x00'*12
    return req(sid, kXR_open, body, path+b'\x00')

def read_req(handle, offset, rlen, sid=b'\x00\x06'):
    return req(sid, kXR_read, handle[:4] + struct.pack(">qi", offset, rlen))

def close_req(handle, sid=b'\x00\x07'):
    return req(sid, kXR_close, handle[:4] + b'\x00'*12)

# ── socket helpers ──────────────────────────────────────────────────────────

def connect(timeout=4.0):
    s = socket.socket()
    s.settimeout(timeout)
    s.connect((HOST, PORT))
    return s

def recvall(s, n):
    buf = b''
    while len(buf) < n:
        c = s.recv(n - len(buf))
        if not c: raise ConnectionError(f"closed after {len(buf)}/{n}")
        buf += c
    return buf

def recv_resp(s):
    h  = recvall(s, 8)
    st = struct.unpack(">H", h[2:4])[0]
    dl = struct.unpack(">i", h[4:8])[0]
    return st, (recvall(s, dl) if dl > 0 else b'')

def do_hs_proto(s):
    s.sendall(HANDSHAKE + proto_req())
    hs, _ = recv_resp(s); pr, _ = recv_resp(s)
    return hs, pr

def do_login(s):
    hs, pr = do_hs_proto(s)
    s.sendall(login_req()); lg, _ = recv_resp(s)
    return hs, pr, lg

def safe_close(s):
    try: s.close()
    except: pass

# ── health check ────────────────────────────────────────────────────────────

def server_alive():
    """Returns 'ok', 'hang', or 'crash'."""
    try:
        s = connect(6); s.settimeout(6)
        do_login(s)
        s.sendall(ping_req()); st, _ = recv_resp(s)
        safe_close(s)
        return "ok" if st == kXR_ok else f"bad-ping:{st}"
    except ConnectionRefusedError: return "crash"
    except (socket.timeout, TimeoutError): return "hang"
    except Exception as e: return f"error:{e}"

# ── result tracking ─────────────────────────────────────────────────────────

PROBES  = []   # (name, fn) in registration order
RESULTS = []   # (name, outcome, detail, repro)
ICONS   = {"PASS":"✓","FINDING":"★","HANG":"⚠","CRASH":"✗","ERROR":"?"}

def probe(name):
    """Register a probe function. The function returns None (pass) or
    (outcome, detail, repro) to signal a finding."""
    def decorator(fn):
        PROBES.append((name, fn))
        return fn
    return decorator

def run_all():
    for name, fn in PROBES:
        print(f"\n── {name}")
        try:
            result = fn()
            if result is None:
                health = server_alive()
                if   health == "ok":    outcome, detail, repro = "PASS",  "", ""
                elif health == "hang":  outcome, detail, repro = "HANG",  "Server stopped responding to legitimate clients.", name
                elif health == "crash": outcome, detail, repro = "CRASH", "Server process disappeared.", name
                else:                   outcome, detail, repro = "ERROR", health, ""
            else:
                outcome, detail, repro = result
                health = server_alive()
                if health == "hang":
                    outcome, detail = "HANG",  f"Server locked up. {detail}"
                elif health == "crash":
                    outcome, detail = "CRASH", f"Server crashed. {detail}"
        except Exception:
            tb = traceback.format_exc().strip().splitlines()[-1]
            health = server_alive()
            outcome = health if health != "ok" else "ERROR"
            detail, repro = tb, ""

        icon = ICONS.get(outcome, "·")
        print(f"  [{icon}] {outcome:8s}  {name}")
        if detail:
            for line in textwrap.wrap(detail, 72):
                print(f"           {line}")
        RESULTS.append((name, outcome, detail, repro))

# ══════════════════════════════════════════════════════════════════════════
# PROBES
# ══════════════════════════════════════════════════════════════════════════

# ─── Lockup probes ─────────────────────────────────────────────────────────

@probe("LK-01  partial handshake 10/20 bytes then nothing")
def _():
    s = connect()
    s.sendall(HANDSHAKE[:10])
    try: s.settimeout(3); s.recv(256)
    except: pass
    safe_close(s)

@probe("LK-02  partial handshake 19/20 bytes then nothing")
def _():
    s = connect()
    s.sendall(HANDSHAKE[:19])
    try: s.settimeout(3); s.recv(256)
    except: pass
    safe_close(s)

@probe("LK-03  12-byte handshake (old ServerInitHandShake layout)")
def _():
    """protocol-notes.md §1: this format causes v5 clients to hang.
    Testing whether the server itself crashes or hangs on receipt."""
    s = connect()
    s.sendall(HS_12_BYTE)
    try: s.settimeout(3); s.recv(256)
    except: pass
    safe_close(s)

@probe("LK-04  TCP connect + silence for 2 s")
def _():
    s = connect()
    time.sleep(2)
    safe_close(s)

@probe("LK-05  handshake only + silence for 2 s")
def _():
    s = connect()
    s.sendall(HANDSHAKE)
    time.sleep(2)
    safe_close(s)

@probe("LK-06  dlen=0xFFFFFFFF with no body after login")
def _():
    s = connect(); do_login(s)
    bad = b'\x00\x10' + struct.pack(">H", kXR_ping) + b'\x00'*16 + struct.pack(">I", 0xFFFFFFFF)
    s.sendall(bad)
    try: s.settimeout(3); s.recv(256)
    except: pass
    safe_close(s)

@probe("LK-07  dlen=2^31-1 with no body after login")
def _():
    s = connect(); do_login(s)
    bad = b'\x00\x11' + struct.pack(">H", kXR_stat) + b'\x00'*16 + struct.pack(">i", 2**31-1)
    s.sendall(bad)
    try: s.settimeout(3); s.recv(256)
    except: pass
    safe_close(s)

@probe("LK-08  50 stalled connections then fresh request")
def _():
    stale = []
    for _ in range(50):
        try:
            sx = connect(2); sx.sendall(HANDSHAKE); stale.append(sx)
        except OSError: break
    alive = server_alive()
    for sx in stale:
        safe_close(sx)
    if alive != "ok":
        return ("FINDING",
                f"Server became unhealthy ({alive}) while 50 stalled connections held open.",
                "Open 50 TCP connections that send handshake but never kXR_protocol; "
                "then attempt fresh login+ping on a 51st connection.")

@probe("LK-09  truncated request header 15/24 bytes after login")
def _():
    s = connect(); do_login(s)
    s.sendall(b'\x00\x20' + struct.pack(">H", kXR_ping) + b'\x00'*11)
    try: s.settimeout(3); s.recv(256)
    except: pass
    safe_close(s)

# ─── Authentication enforcement ─────────────────────────────────────────────

def _pre_auth(name, pkt):
    """Send pkt before kXR_login; return finding if kXR_ok."""
    s = connect(); do_hs_proto(s)
    s.sendall(pkt)
    try:
        st, body = recv_resp(s); safe_close(s)
        if st == kXR_ok:
            return ("FINDING",
                    f"Pre-login {name} returned kXR_ok — authentication bypass.",
                    f"Connect → handshake+protocol → {name} without kXR_login")
    except: safe_close(s)

@probe("AE-01  kXR_stat before kXR_login")
def _(): return _pre_auth("kXR_stat", stat_req(b'/'))

@probe("AE-02  kXR_open before kXR_login")
def _(): return _pre_auth("kXR_open", open_req(b'/test.bin'))

@probe("AE-03  kXR_read (invented handle) before kXR_login")
def _(): return _pre_auth("kXR_read", read_req(b'\xDE\xAD\xBE\xEF', 0, 4096))

@probe("AE-04  kXR_dirlist before kXR_login")
def _(): return _pre_auth("kXR_dirlist", req(b'\x00\x21', kXR_dirlist, payload=b'/\x00'))

@probe("AE-05  kXR_mkdir before kXR_login")
def _(): return _pre_auth("kXR_mkdir", req(b'\x00\x22', kXR_mkdir, payload=b'/evil\x00'))

@probe("AE-06  kXR_rm before kXR_login")
def _(): return _pre_auth("kXR_rm", req(b'\x00\x23', kXR_rm, payload=b'/test.bin\x00'))

@probe("AE-07  kXR_write (invented handle) before kXR_login")
def _():
    return _pre_auth("kXR_write",
        req(b'\x00\x24', kXR_write, b'\xDE\xAD\xBE\xEF' + b'\x00'*12, b'evil payload'))

@probe("AE-08  kXR_auth before kXR_login (must not trigger authmore)")
def _():
    s = connect(); do_hs_proto(s)
    s.sendall(req(b'\x00\x25', kXR_auth, payload=b'garbage_auth_data'))
    try:
        st, _ = recv_resp(s); safe_close(s)
        if st in (kXR_ok, kXR_authmore):
            return ("FINDING",
                    f"kXR_auth before kXR_login returned {st} "
                    f"({'kXR_ok' if st==kXR_ok else 'kXR_authmore'}) — "
                    "server entered auth state machine without a preceding login.",
                    "Connect → handshake → kXR_auth(garbage) — got authmore/ok")
    except: safe_close(s)

# ─── Handshake magic field fuzzing ───────────────────────────────────────────

@probe("HF-01  wrong fourth field (0, must be 4)")
def _():
    s = connect()
    s.sendall(HS_BAD_FOURTH + proto_req())
    try: s.settimeout(3); recv_resp(s); recv_resp(s)
    except: pass
    safe_close(s)

@probe("HF-02  wrong fifth field (9999, must be 2012)")
def _():
    s = connect()
    s.sendall(HS_BAD_FIFTH + proto_req())
    try: s.settimeout(3); s.recv(256)
    except: pass
    safe_close(s)

@probe("HF-03  all-zero 20-byte handshake")
def _():
    s = connect()
    s.sendall(b'\x00'*20 + proto_req())
    try: s.settimeout(3); s.recv(256)
    except: pass
    safe_close(s)

@probe("HF-04  all-0xFF 20-byte handshake")
def _():
    s = connect()
    s.sendall(b'\xff'*20)
    try: s.settimeout(3); s.recv(256)
    except: pass
    safe_close(s)

# ─── Unknown / extreme opcodes ────────────────────────────────────────────────

def _opcode(rid, label):
    s = connect(); do_login(s)
    s.sendall(req(b'\x00\x40', rid))
    try:
        st, _ = recv_resp(s); safe_close(s)
        if st == kXR_ok:
            return ("FINDING",
                    f"Unknown opcode {label} returned kXR_ok after login.",
                    f"Login → request with requestid={rid}")
    except: safe_close(s)

@probe("OF-01  opcode 0 after login")
def _(): return _opcode(0,  "0")

@probe("OF-02  opcode 9999 after login")
def _(): return _opcode(9999,   "9999")

@probe("OF-03  opcode 0xFFFF after login")
def _(): return _opcode(0xFFFF, "0xFFFF")

@probe("OF-04  all-zero 24-byte request after login")
def _():
    s = connect(); do_login(s)
    s.sendall(b'\x00'*24)
    try: recv_resp(s)
    except: pass
    safe_close(s)

@probe("OF-05  all-0xFF 24-byte request after login")
def _():
    s = connect(); do_login(s)
    s.sendall(b'\xff'*24)
    try: s.settimeout(3); s.recv(256)
    except: pass
    safe_close(s)

# ─── Path fuzzing ─────────────────────────────────────────────────────────────

TRAVERSAL = [
    b"/../etc/passwd",
    b"/../../etc/shadow",
    b"/../../../root/.ssh/authorized_keys",
    b"/..",
    b"/../",
    b"/a/b/../../../../../../etc/passwd",
    b"/a/./b/./../../../../../../etc/passwd",
]

@probe("PF-01  path traversal attempts (7 patterns)")
def _():
    s = connect(); do_login(s)
    for path in TRAVERSAL:
        s.sendall(stat_req(path, sid=b'\x00\xA0'))
        try:
            st, body = recv_resp(s)
            if st == kXR_ok:
                return ("FINDING",
                        f"Traversal path '{path.decode()}' returned kXR_ok.",
                        f"Login → kXR_stat path={path!r}")
            if body and (b'root:' in body or b'/bin/' in body):
                return ("FINDING",
                        f"Response to '{path.decode()}' contains /etc-like content.",
                        f"Login → kXR_stat path={path!r}")
        except (socket.timeout, ConnectionError):
            s = connect(); do_login(s)
    safe_close(s)

@probe("PF-02  null-byte injection /\\x00etc/passwd")
def _():
    s = connect(); do_login(s)
    s.sendall(req(b'\x00\xA1', kXR_stat, payload=b'/\x00etc/passwd\x00'))
    try:
        st, body = recv_resp(s); safe_close(s)
        if st == kXR_ok and body and b'root:' in body:
            return ("FINDING",
                    "Null-byte injection returned /etc/passwd content.",
                    "Login → kXR_stat payload=b'/\\x00etc/passwd\\x00'")
    except: safe_close(s)

@probe("PF-03  path 8193 bytes long (well over 4096 limit)")
def _():
    s = connect(); do_login(s)
    long_path = b'/' + b'a'*8192 + b'\x00'
    s.sendall(req(b'\x00\xA2', kXR_stat, payload=long_path))
    try:
        st, _ = recv_resp(s); safe_close(s)
        if st == kXR_ok:
            return ("FINDING",
                    "8193-byte path returned kXR_ok — no path length limit enforced.",
                    "Login → kXR_stat with 8193-byte path payload")
    except: safe_close(s)

@probe("PF-04  null-only path (single 0x00 byte)")
def _():
    s = connect(); do_login(s)
    s.sendall(req(b'\x00\xA3', kXR_stat, payload=b'\x00'))
    try: recv_resp(s)
    except: pass
    safe_close(s)

# ─── Resource exhaustion ──────────────────────────────────────────────────────

@probe("RE-01  50-connection storm")
def _():
    stale = []; fails = 0
    for _ in range(50):
        try:
            sx = connect(2); do_hs_proto(sx); stale.append(sx)
        except OSError: fails += 1
    for sx in stale: safe_close(sx)
    time.sleep(0.5)
    health = server_alive()
    if health != "ok":
        return (("CRASH" if health=="crash" else "FINDING"),
                f"Server state after 50-connection storm: {health} (connect failures: {fails})",
                "Open 50 TCP connections each sending handshake+protocol, then close all.")

@probe("RE-02  1000-ping flood on one connection")
def _():
    s = connect(); do_login(s)
    n = 1000
    for i in range(n):
        s.sendall(ping_req(struct.pack(">H", (i%0xFFFE)+1)))
    ok = 0
    for _ in range(n):
        try:
            s.settimeout(10); st, _ = recv_resp(s)
            if st == kXR_ok: ok += 1
        except: break
    safe_close(s)
    if ok < int(n*0.99):
        return ("FINDING",
                f"Only {ok}/{n} pings returned kXR_ok under flood — possible queue overflow.",
                "Login → send 1000 kXR_ping back-to-back → read all responses")

@probe("RE-03  open 20 file handles (typical limit is 16-256)")
def _():
    s = connect(); do_login(s)
    opened = 0; first_err = None
    for i in range(20):
        sid = struct.pack(">H", 0x200+i)
        s.sendall(open_req(b'/test.bin', sid=sid))
        try:
            st, _ = recv_resp(s)
            if st == kXR_ok: opened += 1
            elif first_err is None: first_err = i
        except: break
    safe_close(s)
    # Note: official xrootd may allow many more handles than nginx-xrootd's 16.
    # We report the count; only flag if server crashed/hung.
    print(f"           opened {opened}/20 handles before first error at position {first_err}")

@probe("RE-04  rapid connect-disconnect 100 cycles")
def _():
    for _ in range(100):
        try: sx = connect(1); safe_close(sx)
        except: pass
    time.sleep(0.5)

# ─── State machine ────────────────────────────────────────────────────────────

@probe("SM-01  read from closed file handle (use-after-close)")
def _():
    s = connect(); do_login(s)
    s.sendall(open_req(b'/test.bin', sid=b'\x00\x70'))
    try:
        st, body = recv_resp(s)
        if st != kXR_ok: safe_close(s); return
        handle = body[:4]
    except: safe_close(s); return
    s.sendall(close_req(handle, sid=b'\x00\x71'))
    try: recv_resp(s)
    except: pass
    s.sendall(read_req(handle, 0, 64, sid=b'\x00\x72'))
    try:
        st2, body2 = recv_resp(s); safe_close(s)
        if st2 == kXR_ok and body2:
            return ("FINDING",
                    "Read from closed handle returned kXR_ok with data — use-after-close.",
                    "Open /test.bin → kXR_close → kXR_read same handle → got data")
    except: safe_close(s)

@probe("SM-02  kXR_read after kXR_endsess (open handle must be released)")
def _():
    s = connect(); do_login(s)
    s.sendall(open_req(b'/test.bin', sid=b'\x00\x80'))
    try:
        st, body = recv_resp(s)
        if st != kXR_ok: safe_close(s); return
        handle = body[:4]
    except: safe_close(s); return
    s.sendall(req(b'\x00\x81', kXR_endsess))
    try: recv_resp(s)
    except: pass
    s.sendall(read_req(handle, 0, 64, sid=b'\x00\x82'))
    try:
        st2, body2 = recv_resp(s); safe_close(s)
        if st2 == kXR_ok and body2:
            return ("FINDING",
                    "kXR_read after kXR_endsess returned kXR_ok with data — "
                    "file handle not released by endsess.",
                    "Open /test.bin → kXR_endsess → kXR_read same handle → got data")
    except: safe_close(s)

@probe("SM-03  double kXR_login on same connection")
def _():
    s = connect(); do_login(s)
    s.sendall(login_req(sid=b'\x00\x90', user=b'hacker\x00\x00'))
    try: recv_resp(s)
    except: pass
    safe_close(s)

@probe("SM-04  200 repeated kXR_protocol on one connection")
def _():
    s = connect(); do_hs_proto(s)
    for i in range(200):
        s.sendall(proto_req(sid=struct.pack(">H", i+1)))
    ok = 0
    for _ in range(200):
        try:
            st, _ = recv_resp(s)
            if st == kXR_ok: ok += 1
        except: break
    safe_close(s)
    if ok == 0:
        return ("FINDING",
                "No kXR_protocol responses received after 200 consecutive requests.",
                "Connect → handshake → 200 × kXR_protocol")

# ─── Protocol version edge cases ──────────────────────────────────────────────

@probe("PV-01  kXR_protocol with clientpv=0")
def _():
    s = connect(); s.sendall(HANDSHAKE)
    body = struct.pack(">I", 0) + b'\x00'*12
    s.sendall(req(b'\x00\x01', kXR_protocol, body))
    try: recv_resp(s); recv_resp(s)
    except: pass
    safe_close(s)

@probe("PV-02  kXR_protocol with clientpv=0xFFFFFFFF")
def _():
    s = connect(); s.sendall(HANDSHAKE)
    body = struct.pack(">I", 0xFFFFFFFF) + b'\x01' + b'\x00'*11
    s.sendall(req(b'\x00\x01', kXR_protocol, body))
    try: recv_resp(s); recv_resp(s)
    except: pass
    safe_close(s)

@probe("PV-03  kXR_login with all-zero username")
def _():
    s = connect(); do_hs_proto(s)
    body = struct.pack(">I", os.getpid()&0xFFFFFFFF) + b'\x00'*8 + b'\x00\x00\x05\x00'
    s.sendall(req(b'\x00\x02', kXR_login, body))
    try: recv_resp(s)
    except: pass
    safe_close(s)

@probe("PV-04  kXR_login username='root' pid=0 (privilege escalation probe)")
def _():
    """Anonymous server: username='root' should work but not grant extra privilege."""
    s = connect(); do_hs_proto(s)
    body = struct.pack(">I", 0) + b'root\x00\x00\x00\x00' + b'\x00\x00\x05\x00'
    s.sendall(req(b'\x00\x02', kXR_login, body))
    try:
        st, body_r = recv_resp(s); safe_close(s)
        # Then try to read /etc/passwd by path traversal if login succeeded
    except: safe_close(s)

# ─── Concurrency ──────────────────────────────────────────────────────────────

@probe("CC-01  16 threads × 50 pings simultaneously")
def _():
    errors = []
    def worker(idx):
        try:
            s = connect(); do_login(s)
            for i in range(50):
                s.sendall(ping_req(struct.pack(">H", (idx*50+i)%0xFFFE+1)))
            ok = 0
            for _ in range(50):
                try:
                    st, _ = recv_resp(s)
                    if st == kXR_ok: ok += 1
                except: break
            safe_close(s)
            if ok < 50: errors.append(f"thread {idx}: {ok}/50 pings ok")
        except Exception as e: errors.append(f"thread {idx}: {e}")
    ts = [threading.Thread(target=worker, args=(i,)) for i in range(16)]
    for t in ts: t.start()
    for t in ts: t.join(30)
    if errors:
        return ("FINDING", "Concurrent ping errors: " + "; ".join(errors[:3]),
                "16 simultaneous connections each sending 50 pings")

@probe("CC-02  8 ping threads + 8 stat threads concurrently")
def _():
    errors = []
    def ping_w():
        try:
            s = connect(); do_login(s)
            for i in range(20):
                s.sendall(ping_req(struct.pack(">H", i+1)))
                st, _ = recv_resp(s)
                if st != kXR_ok: errors.append(f"ping {i}→{st}")
            safe_close(s)
        except Exception as e: errors.append(f"ping: {e}")
    def stat_w():
        try:
            s = connect(); do_login(s)
            for i in range(20):
                s.sendall(stat_req(b'/test.bin', sid=struct.pack(">H", i+1)))
                st, _ = recv_resp(s)
                if st != kXR_ok: errors.append(f"stat {i}→{st}")
            safe_close(s)
        except Exception as e: errors.append(f"stat: {e}")
    ts = ([threading.Thread(target=ping_w) for _ in range(8)]
        + [threading.Thread(target=stat_w) for _ in range(8)])
    for t in ts: t.start()
    for t in ts: t.join(30)
    if errors:
        return ("FINDING", "; ".join(errors[:4]),
                "8 ping threads + 8 stat threads simultaneously")

# ══════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print(f"""
╔══════════════════════════════════════════════════════════════════╗
║   XRootD Security Probe  —  {XROOTD_VERSION:<36}║
║   Target : {HOST}:{PORT}                                     ║
╚══════════════════════════════════════════════════════════════════╝
""")

    initial = server_alive()
    if initial != "ok":
        print(f"ERROR: server not reachable at {HOST}:{PORT} (status={initial})")
        sys.exit(1)
    print(f"  Server confirmed reachable. Running {len(PROBES)} probes...\n")

    run_all()

    findings = [(n,o,d,r) for n,o,d,r in RESULTS if o in ("FINDING","HANG","CRASH")]
    passes   = [(n,o,d,r) for n,o,d,r in RESULTS if o == "PASS"]
    errors   = [(n,o,d,r) for n,o,d,r in RESULTS if o == "ERROR"]

    import textwrap
    print(f"\n\n{'═'*70}")
    print("FINDINGS REPORT")
    print(f"{'═'*70}")
    print(f"Target  : xrootd {XROOTD_VERSION}  {HOST}:{PORT}")
    print(f"Date    : {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}")
    print(f"Probes  : {len(RESULTS)}   Passed: {len(passes)}   "
          f"Findings: {len(findings)}   Errors: {len(errors)}")

    if findings:
        print(f"\n{'─'*70}")
        print("POTENTIAL SECURITY ISSUES")
        print(f"{'─'*70}")
        for i, (n,o,d,r) in enumerate(findings, 1):
            print(f"\n[{i}] {o}: {n}")
            if d:
                for line in textwrap.wrap(d, 68):
                    print(f"    {line}")
            if r:
                print(f"    Repro: {r}")
    else:
        print("\n  No findings — all probes passed or were rejected gracefully.")

    if errors:
        print(f"\n{'─'*70}")
        print("PROBE ERRORS (investigate manually)")
        print(f"{'─'*70}")
        for n,o,d,r in errors:
            print(f"  {n}: {d}")

    print(f"\n{'═'*70}")
    print(f"Check the target server's error log for details.")
    print(f"{'═'*70}\n")
