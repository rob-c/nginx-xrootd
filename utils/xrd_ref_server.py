#!/usr/bin/env python3
"""
Minimal reference XRootD data server — used to calibrate xrdcp/xrdfs
behaviour against a known-correct implementation.

Implements just enough of the XRootD protocol to serve files:
    handshake, kXR_protocol, kXR_login, kXR_ping, kXR_stat,
    kXR_open, kXR_read, kXR_close, kXR_dirlist, kXR_endsess

Usage:
    python3 utils/xrd_ref_server.py [PORT] [ROOT_DIR]

    PORT      defaults to 19942
    ROOT_DIR  defaults to /tmp/xrd-test/data

Example:
    python3 utils/xrd_ref_server.py 19942 /tmp/xrd-test/data &
    xrdfs root://localhost:19942 ls /
    xrdcp root://localhost:19942//test.txt /tmp/out.txt
"""
import os
import socket
import stat
import struct
import sys
import threading

HOST = "127.0.0.1"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 19942
ROOT = sys.argv[2] if len(sys.argv) > 2 else "/tmp/xrd-test/data"

HANDSHAKE_LEN = 20
ROOTD_PQ      = 2012
PROTO_VER     = 0x00000520

kXR_protocol  = 3006
kXR_login     = 3007
kXR_ping      = 3011
kXR_stat      = 3017
kXR_open      = 3010
kXR_read      = 3013
kXR_close     = 3003
kXR_dirlist   = 3004
kXR_endsess   = 3023

kXR_ok        = 0
kXR_error     = 4003
kXR_NotFound  = 3011
kXR_IOError   = 3007
kXR_isDir     = 3016
kXR_readable  = 16
kXR_isDirectory = 2

SESSION_ID = os.urandom(16)


def recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise EOFError
        buf += chunk
    return buf


def send_hsk(s):
    pkt = struct.pack(">III", 8, PROTO_VER, 1)  # msglen=8, protover, DataServer
    s.sendall(pkt)
    print(f"  sent handshake ({len(pkt)}B)", flush=True)


def send_resp(s, streamid, status, body=b""):
    hdr = struct.pack(">HHI", streamid, status, len(body))
    s.sendall(hdr + body)
    print(f"  sent resp sid={streamid} status={status} dlen={len(body)}", flush=True)


def handle(conn):
    conn.settimeout(15)

    # Handshake
    raw = recv_exact(conn, HANDSHAKE_LEN)
    _, _, _, fourth, fifth = struct.unpack(">iiiii", raw)
    print(f"handshake: fourth={fourth} fifth={fifth}", flush=True)
    if fourth != 4 or fifth != ROOTD_PQ:
        print("bad handshake", flush=True)
        return
    send_hsk(conn)

    open_files = {}

    while True:
        hdr = recv_exact(conn, 24)
        sid_raw = hdr[0:2]
        sid     = struct.unpack(">H", sid_raw)[0]
        reqid   = struct.unpack(">H", hdr[2:4])[0]
        body    = hdr[4:20]
        dlen    = struct.unpack(">I", hdr[20:24])[0]
        payload = recv_exact(conn, dlen) if dlen else b""
        print(f"req sid={sid} reqid={reqid} dlen={dlen} payload={payload!r}", flush=True)

        if reqid == kXR_protocol:
            pkt = struct.pack(">II", PROTO_VER, 1)  # pval, kXR_isServer
            send_resp(conn, sid, kXR_ok, pkt)

        elif reqid == kXR_login:
            send_resp(conn, sid, kXR_ok, SESSION_ID)

        elif reqid == kXR_ping:
            send_resp(conn, sid, kXR_ok)

        elif reqid == kXR_endsess:
            send_resp(conn, sid, kXR_ok)
            break

        elif reqid == kXR_stat:
            path = payload.rstrip(b"\x00").decode()
            full = os.path.join(ROOT, path.lstrip("/"))
            full = os.path.realpath(full)
            if not full.startswith(os.path.realpath(ROOT)):
                send_resp(conn, sid, kXR_error,
                          struct.pack(">I", kXR_NotFound) + b"not found\0")
                continue
            try:
                st = os.stat(full)
                flags = kXR_readable
                if stat.S_ISDIR(st.st_mode):
                    flags |= kXR_isDirectory
                body_s = f"{st.st_ino} {flags} {st.st_size} {int(st.st_mtime)}\0".encode()
                send_resp(conn, sid, kXR_ok, body_s)
            except FileNotFoundError:
                send_resp(conn, sid, kXR_error,
                          struct.pack(">I", kXR_NotFound) + b"not found\0")

        elif reqid == kXR_open:
            path  = payload.rstrip(b"\x00").decode()
            full  = os.path.join(ROOT, path.lstrip("/"))
            full  = os.path.realpath(full)
            if not full.startswith(os.path.realpath(ROOT)):
                send_resp(conn, sid, kXR_error,
                          struct.pack(">I", kXR_NotFound) + b"not found\0")
                continue
            try:
                fd = os.open(full, os.O_RDONLY)
                idx = len(open_files)
                open_files[idx] = fd
                fhandle = struct.pack(">I", idx)
                resp_body = fhandle + struct.pack(">I", 0) + b"\x00" * 4
                send_resp(conn, sid, kXR_ok, resp_body)
            except FileNotFoundError:
                send_resp(conn, sid, kXR_error,
                          struct.pack(">I", kXR_NotFound) + b"not found\0")

        elif reqid == kXR_read:
            fh, offset, rlen = struct.unpack(">4sqI", body[:16])
            idx = struct.unpack(">I", fh)[0]
            if idx not in open_files:
                send_resp(conn, sid, kXR_error,
                          struct.pack(">I", kXR_IOError) + b"bad handle\0")
                continue
            os.lseek(open_files[idx], offset, os.SEEK_SET)
            data = os.read(open_files[idx], min(rlen, 4 * 1024 * 1024))
            send_resp(conn, sid, kXR_ok, data)

        elif reqid == kXR_close:
            idx = struct.unpack(">I", body[:4])[0]
            if idx in open_files:
                os.close(open_files.pop(idx))
            send_resp(conn, sid, kXR_ok)

        else:
            send_resp(conn, sid, kXR_error,
                      struct.pack(">I", 3013) + b"unsupported\0")


srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind((HOST, PORT))
srv.listen(5)
srv.settimeout(30)
print(f"reference server on {PORT}, root={ROOT}", flush=True)
while True:
    try:
        conn, addr = srv.accept()
        print(f"connect from {addr}", flush=True)
        threading.Thread(target=handle, args=(conn,), daemon=True).start()
    except socket.timeout:
        break
