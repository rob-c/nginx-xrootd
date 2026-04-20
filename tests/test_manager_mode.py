"""
Tests for manager-mode static path -> backend mapping that returns
an XRootD kXR_redirect (port + host) for matching locate requests.

These tests use a raw socket to perform the handshake/login then send
an explicit kXR_locate request so we can assert the wire-level
redirect response contents.
"""

import os
import shutil
import socket
import struct
import subprocess
import time

import pytest

NGINX_BIN = "/tmp/nginx-1.28.3/objs/nginx"
WORKDIR = "/tmp/xrd-manager-mode-test"


def _free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _wait_for_port(host, port, proc, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return False
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.1)
    return False


@pytest.fixture(scope="module")
def manager_nginx():
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")

    # Prepare workspace
    shutil.rmtree(WORKDIR, ignore_errors=True)
    conf_dir = os.path.join(WORKDIR, "conf")
    log_dir = os.path.join(WORKDIR, "logs")
    os.makedirs(conf_dir, exist_ok=True)
    os.makedirs(log_dir, exist_ok=True)

    port = _free_port()

    # Two mappings to exercise longest-prefix matching
    map_a_host = "backend.example.org"
    map_a_port = 54321
    map_b_host = "backend2.example.org"
    map_b_port = 12345

    conf_path = os.path.join(conf_dir, "nginx.conf")
    with open(conf_path, "w", encoding="utf-8") as fh:
        fh.write(f"""\
daemon off;
worker_processes 1;
error_log {log_dir}/error.log info;
pid       {log_dir}/nginx.pid;

events {{ worker_connections 128; }}

stream {{
    server {{
        listen 127.0.0.1:{port};
        xrootd on;
        xrootd_manager_map /maps {map_a_host}:{map_a_port};
        xrootd_manager_map /maps/prefix {map_b_host}:{map_b_port};
    }}
}}
""")

    stderr_path = os.path.join(log_dir, "stderr.log")
    stderr_fh = open(stderr_path, "w")
    proc = subprocess.Popen(
        [NGINX_BIN, "-c", conf_path],
        stdout=subprocess.DEVNULL,
        stderr=stderr_fh,
    )
    stderr_fh.close()

    if not _wait_for_port("127.0.0.1", port, proc):
        proc.terminate()
        proc.wait(timeout=5)
        with open(stderr_path, encoding="utf-8", errors="replace") as fh:
            stderr = fh.read()
        pytest.fail(f"manager-mode nginx did not start\nstderr:\n{stderr}")

    yield {
        "proc": proc,
        "port": port,
        "map_a": (map_a_host, map_a_port),
        "map_b": (map_b_host, map_b_port),
    }

    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def _xrd_handshake_and_login(host: str, port: int):
    """Establish an XRootD session: handshake, protocol, login.

    Returns a connected socket ready to send requests.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect((host, port))

    # 1. Initial handshake (20 bytes)
    sock.sendall(struct.pack(">IIIII", 0, 0, 0, 4, 2012))

    # 2. kXR_protocol
    sock.sendall(struct.pack(">BB H I BB 10x I",
                             0, 1, 3006, 0x00000520, 0x02, 0x03, 0))

    # Read handshake response (8 + 8 per server code path)
    # The server replies with an 8-byte ServerResponseHdr then 8-byte body
    _ = sock.recv(16)

    # Next protocol response (ServerResponseHdr + body)
    hdr = sock.recv(8)
    if len(hdr) < 8:
        raise RuntimeError("short protocol response header")
    dlen = struct.unpack(">I", hdr[4:8])[0]
    if dlen:
        _ = sock.recv(dlen)

    # 3. kXR_login — send a minimal login (username "test")
    sock.sendall(struct.pack(">BB H I 8s BB B B I",
                             0, 1, 3007, 0,
                             b"test\x00\x00\x00\x00",
                             0, 0, 5, 0, 0))

    # read login response
    hdr = sock.recv(8)
    if len(hdr) < 8:
        raise RuntimeError("short login response header")
    dlen = struct.unpack(">I", hdr[4:8])[0]
    if dlen:
        _ = sock.recv(dlen)

    return sock


def _send_locate_and_recv(sock: socket.socket, path: str):
    # Build ClientLocateRequest header: streamid[2]=0,1; requestid=3027; options=0; reserved=14 zeros; dlen=payload length
    payload = path.encode("utf-8") + b"\x00"
    hdr = struct.pack(">BBHH14sI", 0, 1, 3027, 0, b"\x00" * 14, len(payload))
    sock.sendall(hdr + payload)

    # Read response header (8 bytes) then body
    resp_hdr = sock.recv(8)
    if len(resp_hdr) < 8:
        raise RuntimeError("short response header")
    status = struct.unpack(">H", resp_hdr[2:4])[0]
    dlen = struct.unpack(">I", resp_hdr[4:8])[0]
    body = b""
    while len(body) < dlen:
        chunk = sock.recv(dlen - len(body))
        if not chunk:
            raise RuntimeError("connection closed while reading body")
        body += chunk

    return status, body


def test_locate_redirect_basic(manager_nginx):
    info = manager_nginx
    host = "127.0.0.1"
    port = info["port"]

    sock = _xrd_handshake_and_login(host, port)

    try:
        status, body = _send_locate_and_recv(sock, "/maps/somefile.bin")
        # Expect kXR_redirect (4004)
        assert status == 4004, f"expected redirect status, got {status}"

        # Body = 4-byte BE port followed by host bytes
        assert len(body) >= 4
        port_be = struct.unpack(">I", body[:4])[0]
        host_str = body[4:].decode("utf-8")

        assert port_be == info["map_a"][1]
        assert host_str == info["map_a"][0]

        # Now test longest-prefix: /maps/prefix should match map_b
        status2, body2 = _send_locate_and_recv(sock, "/maps/prefix/xyz")
        assert status2 == 4004
        pb = struct.unpack(">I", body2[:4])[0]
        hb = body2[4:].decode("utf-8")
        assert pb == info["map_b"][1]
        assert hb == info["map_b"][0]

    finally:
        sock.close()
