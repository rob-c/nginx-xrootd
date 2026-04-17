#!/usr/bin/env python3
"""
TCP relay/hex-dump proxy for debugging XRootD protocol traffic.

Sits between a client and the nginx-xrootd server, printing every byte
exchanged to stdout in hex format with direction labels.

Usage:
    python3 utils/xrd_proxy.py [LISTEN_PORT] [BACKEND_PORT]

    LISTEN_PORT   defaults to 19941
    BACKEND_PORT  defaults to 11094

Connect your xrdfs/xrdcp client to localhost:LISTEN_PORT and watch the
protocol exchanges scroll past.

Example:
    python3 utils/xrd_proxy.py &
    xrdfs root://localhost:19941 ls /
"""
import socket
import sys
import threading

LISTEN_PORT  = int(sys.argv[1]) if len(sys.argv) > 1 else 19941
BACKEND_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 11094


def relay(src, dst, label):
    try:
        while True:
            data = src.recv(4096)
            if not data:
                break
            print(f"[{label}] {len(data)}B: {data.hex()}", flush=True)
            dst.sendall(data)
    except Exception as e:
        print(f"[{label}] end: {e}", flush=True)


srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", LISTEN_PORT))
srv.listen(1)
srv.settimeout(12)
print(f"proxy ready on {LISTEN_PORT} → 127.0.0.1:{BACKEND_PORT}", flush=True)
conn, _ = srv.accept()
backend = socket.create_connection(("127.0.0.1", BACKEND_PORT))
backend.settimeout(10)
print("connected to nginx", flush=True)
t1 = threading.Thread(target=relay, args=(conn, backend, "C>S"), daemon=True)
t2 = threading.Thread(target=relay, args=(backend, conn, "S>C"), daemon=True)
t1.start()
t2.start()
t1.join(timeout=10)
t2.join(timeout=1)
