#!/usr/bin/env python3
"""
load_test.py — Concurrent transfer load test for nginx-xrootd vs xrootd.

Measures peak throughput and latency distribution under 200+ simultaneous
connections across three auth modes:
  • XRootD root:// + GSI
  • WebDAV davs:// + GSI
  • WebDAV davs:// + Bearer token

Runs against nginx-xrootd and optionally an official xrootd server,
then prints a side-by-side comparison table.

Usage
-----
    # Start servers first (see docs/load-testing.md or run_load_test.sh)

    # Test nginx-xrootd only
    python3 tests/load_test.py --target nginx

    # Test official xrootd only
    python3 tests/load_test.py --target xrootd

    # Full comparison (requires both servers running)
    python3 tests/load_test.py --target both

    # Custom concurrency and file size
    python3 tests/load_test.py --target nginx --concurrency 50,100,200 --file load_1g.bin

    # Save JSON results
    python3 tests/load_test.py --target both --json results.json

    # Direct nginx-xrootd vs xrootd-native root:// comparison
    python3 tests/load_test.py --target both --suite root-gsi --concurrency 128

    # High-concurrency read test without 500+ GiB of client temp files
    python3 tests/load_test.py --target both --suite root-gsi --concurrency 500 --read-sink devnull

    # Read-only tests (no writes)
    python3 tests/load_test.py --target nginx --mode read

    # Write tests only
    python3 tests/load_test.py --target nginx --mode write

File sizes
----------
    load_100m.bin  100 MiB — fast sweep, tests connection handling
    load_1g.bin    1 GiB   — stress test, tests sustained throughput (default)
    large200.bin   200 MiB — existing file from test suite

Servers
-------
    nginx-xrootd:
        XRootD+GSI    root://localhost:11095
        WebDAV+GSI    davs://localhost:8443
        WebDAV+token  davs://localhost:8443  (Bearer token in env)

    xrootd native:
        XRootD+GSI    root://localhost:12094
        (HTTP plugin is optional; token auth requires xrootd-http)
"""

import argparse
import hashlib
import json
import math
import multiprocessing
import os
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field, asdict
from typing import Optional

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DATA_DIR   = "/tmp/xrd-test/data"
CA_DIR     = "/tmp/xrd-test/pki/ca"
PROXY_PEM  = "/tmp/xrd-test/pki/user/proxy_std.pem"
TOKEN_DIR  = "/tmp/xrd-test/tokens"
SERVER_CERT = "/tmp/xrd-test/pki/server/hostcert.pem"

NGINX_XRD_GSI_URL       = "root://localhost:11095"
NGINX_XRD_TLS_URL       = "roots://localhost:11096"  # stream-level TLS, auth none
NGINX_XRD_GSI_TLS_URL   = "roots://localhost:11097"  # stream-level TLS, auth gsi
NGINX_XRD_ANON_URL      = "root://localhost:11093"   # perf config anon port
NGINX_DAV_URL           = "davs://localhost:8443"
NGINX_DAV_HTTP_URL      = "https://localhost:8443"   # for curl

XROOTD_GSI_URL      = "root://localhost:12094"   # official xrootd GSI instance
XROOTD_ANON_URL     = "root://localhost:12093"   # official xrootd anon instance
XROOTD_DAV_HTTP_URL = "https://localhost:12443"  # not available in this config

DEFAULT_FILE    = "load_1g.bin"
DEFAULT_WORKERS = [1, 8, 32, 64, 128, 200]


def _apply_xrootd_gsi_env(env: dict, proxy: Optional[str],
                          ca_dir: str) -> None:
    """Configure xrdcp for the local test GSI proxy.

    Also sets X509_CERT_DIR unconditionally so that roots:// (stream-level TLS)
    connections can verify the server certificate against the test CA.
    """
    # Always needed: server-cert verification for roots:// TLS connections.
    env["X509_CERT_DIR"] = ca_dir

    if not proxy:
        return

    env["X509_USER_PROXY"] = proxy
    env["XrdSecPROTOCOL"]  = "gsi"
    env["XRD_SECPROTOCOL"] = "gsi"
    env["XrdSecGSISRVNAMES"] = "*"
    env.pop("X509_USER_CERT", None)
    env.pop("X509_USER_KEY", None)

    # A 128-way 1 GiB localhost benchmark can queue briefly behind disk and
    # thread-pool work. Keep xrdcp's own request timer above the subprocess
    # wall timeout so slower workers report transfer time, not client timeout.
    env.setdefault("XRD_REQUESTTIMEOUT", "600")
    env.setdefault("XRD_STREAMTIMEOUT", "120")

# ---------------------------------------------------------------------------
# Worker functions (must be module-level for multiprocessing pickling)
# ---------------------------------------------------------------------------

def _xrootd_read_worker(args: dict) -> dict:
    """Single-process xrdcp read. One file download."""
    worker_id  = args["id"]
    url        = args["url"]         # full URL incl. path
    proxy      = args["proxy"]
    ca_dir     = args["ca_dir"]
    sink       = args.get("sink", "tempfile")
    expected_bytes = args.get("expected_bytes", 0)
    tls_nosecureverify = args.get("tls_nosecureverify", False)
    result = {"id": worker_id, "ok": False, "error": None,
              "bytes": 0, "elapsed": 0.0}

    env = os.environ.copy()
    _apply_xrootd_gsi_env(env, proxy, ca_dir)
    if tls_nosecureverify:
        # Skip hostname verification for roots:// with the test PKI whose cert
        # CN may not match "localhost".  CA trust is still enforced via X509_CERT_DIR.
        env["XRD_NOSECUREVERIFY"] = "1"

    if sink == "devnull":
        t0 = time.perf_counter()
        proc = subprocess.run(
            ["xrdcp", "-f", url, "/dev/null"],
            env=env, capture_output=True, timeout=600,
        )
        elapsed = time.perf_counter() - t0

        if proc.returncode != 0:
            result["error"] = proc.stderr.decode(errors="replace").strip()[:200]
            return result

        result.update(ok=True, bytes=expected_bytes, elapsed=elapsed)
        return result

    with tempfile.NamedTemporaryFile(delete=True) as dst:
        t0 = time.perf_counter()
        proc = subprocess.run(
            ["xrdcp", "-f", url, dst.name],
            env=env, capture_output=True, timeout=600,
        )
        elapsed = time.perf_counter() - t0

        if proc.returncode != 0:
            result["error"] = proc.stderr.decode(errors="replace").strip()[:200]
            return result

        nbytes = os.path.getsize(dst.name)
        result.update(ok=True, bytes=nbytes, elapsed=elapsed)
    return result


def _xrootd_write_worker(args: dict) -> dict:
    """Single-process xrdcp write. Uploads a local file to the server."""
    worker_id  = args["id"]
    src        = args["src"]         # local file path
    url        = args["url"]         # destination URL incl. path
    proxy      = args["proxy"]
    ca_dir     = args["ca_dir"]
    result = {"id": worker_id, "ok": False, "error": None,
              "bytes": 0, "elapsed": 0.0}

    env = os.environ.copy()
    _apply_xrootd_gsi_env(env, proxy, ca_dir)

    t0 = time.perf_counter()
    proc = subprocess.run(
        ["xrdcp", "-f", src, url],
        env=env, capture_output=True, timeout=600,
    )
    elapsed = time.perf_counter() - t0

    if proc.returncode != 0:
        result["error"] = proc.stderr.decode(errors="replace").strip()[:200]
        return result

    result.update(ok=True, bytes=os.path.getsize(src), elapsed=elapsed)
    return result


def _webdav_read_worker(args: dict) -> dict:
    """curl-based WebDAV GET. Supports GSI (client cert) and bearer token.
    Uses HTTP/2 when the server advertises it via ALPN (--http2).
    """
    worker_id  = args["id"]
    url        = args["url"]
    proxy      = args.get("proxy")
    ca_dir     = args.get("ca_dir")
    token      = args.get("token")
    server_cert = args.get("server_cert")
    result = {"id": worker_id, "ok": False, "error": None,
              "bytes": 0, "elapsed": 0.0}

    cmd = ["curl", "-s", "-S", "-o", "/dev/null", "-w", "%{size_download}",
           "--insecure",   # test PKI; remove for production
           "--http2"]      # negotiate HTTP/2 via ALPN when server supports it
    if proxy:
        cmd += ["--cert", proxy, "--key", proxy]
    if token:
        cmd += ["-H", f"Authorization: Bearer {token}"]
    cmd.append(url)

    t0 = time.perf_counter()
    proc = subprocess.run(cmd, capture_output=True, timeout=300)
    elapsed = time.perf_counter() - t0

    if proc.returncode != 0:
        result["error"] = proc.stderr.decode(errors="replace").strip()[:200]
        return result

    try:
        nbytes = int(proc.stdout.decode().strip())
    except ValueError:
        result["error"] = "could not parse curl output"
        return result

    result.update(ok=True, bytes=nbytes, elapsed=elapsed)
    return result


def _webdav_write_worker(args: dict) -> dict:
    """curl-based WebDAV PUT."""
    worker_id   = args["id"]
    src         = args["src"]
    url         = args["url"]
    proxy       = args.get("proxy")
    token       = args.get("token")
    result = {"id": worker_id, "ok": False, "error": None,
              "bytes": 0, "elapsed": 0.0}

    file_size = os.path.getsize(src)
    cmd = ["curl", "-s", "-S", "-X", "PUT",
           "--insecure",
           "--upload-file", src,
           "-w", "%{http_code}",
           "-o", "/dev/null"]
    if proxy:
        cmd += ["--cert", proxy, "--key", proxy]
    if token:
        cmd += ["-H", f"Authorization: Bearer {token}"]
    cmd.append(url)

    t0 = time.perf_counter()
    proc = subprocess.run(cmd, capture_output=True, timeout=300)
    elapsed = time.perf_counter() - t0

    if proc.returncode != 0:
        result["error"] = proc.stderr.decode(errors="replace").strip()[:200]
        return result

    code = proc.stdout.decode().strip()
    if code not in ("200", "201", "204"):
        result["error"] = f"HTTP {code}"
        return result

    result.update(ok=True, bytes=file_size, elapsed=elapsed)
    return result


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@dataclass
class RunStats:
    label:       str = ""
    n_workers:   int = 0
    n_ok:        int = 0
    n_err:       int = 0
    total_bytes: int = 0
    wall_s:      float = 0.0
    elapsed_list: list = field(default_factory=list)
    errors:      list = field(default_factory=list)

    @property
    def ok_rate(self) -> float:
        return self.n_ok / self.n_workers if self.n_workers else 0.0

    @property
    def agg_mib_s(self) -> float:
        return (self.total_bytes / (1024**2)) / self.wall_s if self.wall_s else 0.0

    @property
    def agg_gib_s(self) -> float:
        return self.agg_mib_s / 1024.0

    @property
    def p50(self) -> float:
        return self._percentile(50)

    @property
    def p95(self) -> float:
        return self._percentile(95)

    @property
    def p99(self) -> float:
        return self._percentile(99)

    @property
    def mean_mib_s(self) -> float:
        if not self.elapsed_list or self.n_ok == 0:
            return 0.0
        per = [self.total_bytes / self.n_ok / (1024**2) / e
               for e in self.elapsed_list if e > 0]
        return sum(per) / len(per) if per else 0.0

    def _percentile(self, pct: int) -> float:
        s = sorted(self.elapsed_list)
        if not s:
            return 0.0
        idx = max(0, int(math.ceil(len(s) * pct / 100)) - 1)
        return s[idx]

    def summary_line(self) -> str:
        return (
            f"  n={self.n_workers:<4}  ok={self.n_ok}/{self.n_workers}"
            f"  agg={self.agg_mib_s:>7.0f} MiB/s"
            f"  ({self.agg_gib_s:.2f} GiB/s)"
            f"  p50={self.p50:.1f}s  p95={self.p95:.1f}s  p99={self.p99:.1f}s"
            f"  per-conn={self.mean_mib_s:.0f} MiB/s"
        )


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_concurrent(worker_fn, arg_list: list[dict], n_workers: int,
                   label: str) -> RunStats:
    """
    Launch n_workers parallel processes using the given worker function.
    Returns a RunStats with aggregate metrics.
    """
    stats = RunStats(label=label, n_workers=n_workers)

    t_wall_start = time.perf_counter()
    with multiprocessing.Pool(processes=n_workers) as pool:
        results = pool.map(worker_fn, arg_list)
    stats.wall_s = time.perf_counter() - t_wall_start

    for r in results:
        if r["ok"]:
            stats.n_ok        += 1
            stats.total_bytes += r["bytes"]
            stats.elapsed_list.append(r["elapsed"])
        else:
            stats.n_err += 1
            if r.get("error"):
                stats.errors.append(r["error"])

    return stats


# ---------------------------------------------------------------------------
# Token generation
# ---------------------------------------------------------------------------

def _make_bearer_token() -> Optional[str]:
    """Generate a short-lived read token using make_token.py."""
    script = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "utils", "make_token.py"
    )
    if not os.path.exists(script):
        return None
    proc = subprocess.run(
        [sys.executable, script, "gen",
         "--scope", "storage.read:/",
         TOKEN_DIR],
        capture_output=True, timeout=10,
    )
    if proc.returncode != 0:
        return None
    # make_token.py prints the JWT on stdout
    return proc.stdout.decode().strip()


# ---------------------------------------------------------------------------
# Test suites
# ---------------------------------------------------------------------------

def _read_args_xrd(base_url: str, filename: str, n: int,
                   proxy: Optional[str] = None,
                   sink: str = "tempfile",
                   expected_bytes: int = 0,
                   tls_nosecureverify: bool = False) -> list[dict]:
    return [{"id": i, "url": f"{base_url}//{filename}",
             "proxy": proxy, "ca_dir": CA_DIR, "sink": sink,
             "expected_bytes": expected_bytes,
             "tls_nosecureverify": tls_nosecureverify} for i in range(n)]


def _read_args_dav(base_url: str, filename: str, n: int,
                   proxy: Optional[str] = None,
                   token: Optional[str] = None) -> list[dict]:
    return [{"id": i, "url": f"{base_url}/{filename}",
             "proxy": proxy, "ca_dir": CA_DIR, "token": token,
             "server_cert": SERVER_CERT} for i in range(n)]


def _write_args_xrd(base_url: str, src: str, n: int,
                    proxy: Optional[str] = None) -> list[dict]:
    basename = os.path.basename(src)
    return [{"id": i, "url": f"{base_url}//load_write_{i}_{basename}",
             "src": src, "proxy": proxy, "ca_dir": CA_DIR} for i in range(n)]


def _write_args_dav(base_url: str, src: str, n: int,
                    proxy: Optional[str] = None,
                    token: Optional[str] = None) -> list[dict]:
    basename = os.path.basename(src)
    return [{"id": i, "url": f"{base_url}/load_write_{i}_{basename}",
             "src": src, "proxy": proxy, "ca_dir": CA_DIR, "token": token} for i in range(n)]


class Suite:
    """One named collection of runs at various concurrency levels."""

    def __init__(self, label: str, worker_fn, arg_fn, concurrency: list[int]):
        self.label      = label
        self.worker_fn  = worker_fn
        self.arg_fn     = arg_fn        # callable(n) → list[dict]
        self.concurrency = concurrency
        self.runs: list[RunStats] = []

    def run(self) -> list[RunStats]:
        print(f"\n{'='*60}")
        print(f"  {self.label}")
        print(f"{'='*60}")
        for n in self.concurrency:
            args = self.arg_fn(n)
            print(f"  launching {n} workers ...", flush=True)
            stats = run_concurrent(self.worker_fn, args, n,
                                   label=f"{self.label} n={n}")
            self.runs.append(stats)
            print(stats.summary_line())
            if stats.errors:
                sample = stats.errors[:3]
                print(f"    errors (sample): {sample}")
        return self.runs


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def print_comparison(nginx_suites: list[Suite], xrd_suites: list[Suite]):
    print("\n" + "="*80)
    print("  COMPARISON REPORT: nginx-xrootd  vs  xrootd native")
    print("="*80)

    headers = ["Protocol/Auth", "n", "nginx agg MiB/s", "xrootd agg MiB/s",
               "nginx p95 s", "xrootd p95 s", "nginx ok%", "xrootd ok%"]
    row_fmt = "  {:<28} {:>4}  {:>14}  {:>16}  {:>10}  {:>11}  {:>8}  {:>9}"

    print(row_fmt.format(*headers))
    print("  " + "-"*78)

    # Pair up suites by index
    for ns, xs in zip(nginx_suites, xrd_suites):
        assert len(ns.runs) == len(xs.runs)
        for nr, xr in zip(ns.runs, xs.runs):
            label = ns.label[:28]
            print(row_fmt.format(
                label, nr.n_workers,
                f"{nr.agg_mib_s:.0f}",
                f"{xr.agg_mib_s:.0f}",
                f"{nr.p95:.1f}",
                f"{xr.p95:.1f}",
                f"{nr.ok_rate*100:.0f}%",
                f"{xr.ok_rate*100:.0f}%",
            ))


def save_json(suites: list[Suite], path: str, target: str):
    data = {"target": target, "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "suites": []}
    for s in suites:
        suite_data = {"label": s.label, "runs": []}
        for r in s.runs:
            d = asdict(r)
            d["agg_mib_s"]  = r.agg_mib_s
            d["agg_gib_s"]  = r.agg_gib_s
            d["mean_mib_s"] = r.mean_mib_s
            d["p50"]        = r.p50
            d["p95"]        = r.p95
            d["p99"]        = r.p99
            d["ok_rate"]    = r.ok_rate
            d.pop("elapsed_list", None)   # can be very long
            suite_data["runs"].append(d)
        data["suites"].append(suite_data)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"\n  Results saved to {path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def build_suites(target: str, filename: str, concurrency: list[int],
                 mode: str, suite_filter: str, read_sink: str) -> list[Suite]:
    src_file = os.path.join(DATA_DIR, filename)
    if not os.path.exists(src_file):
        sys.exit(f"Source file not found: {src_file}")
    src_size = os.path.getsize(src_file)

    token = _make_bearer_token()
    if token is None:
        print("  WARNING: could not generate bearer token — WebDAV+token tests skipped")

    if target == "nginx":
        xrd_gsi_url      = NGINX_XRD_GSI_URL
        xrd_tls_url      = NGINX_XRD_TLS_URL
        xrd_gsi_tls_url  = NGINX_XRD_GSI_TLS_URL
        xrd_anon_url     = NGINX_XRD_ANON_URL
        dav_url          = NGINX_DAV_HTTP_URL
    else:
        xrd_gsi_url      = XROOTD_GSI_URL
        xrd_tls_url      = None   # xrootd native has no stream-TLS endpoint
        xrd_gsi_tls_url  = None
        xrd_anon_url     = XROOTD_ANON_URL
        dav_url          = XROOTD_DAV_HTTP_URL

    suites = []

    def want(name: str) -> bool:
        return suite_filter == "all" or suite_filter == name

    if mode in ("read", "both"):
        # -- XRootD anonymous
        if want("root-anon"):
            suites.append(Suite(
                label="XRootD root:// anon (read)",
                worker_fn=_xrootd_read_worker,
                arg_fn=lambda n: _read_args_xrd(xrd_anon_url, filename, n,
                                                sink=read_sink,
                                                expected_bytes=src_size),
                concurrency=concurrency,
            ))
        # -- XRootD + GSI
        if want("root-gsi"):
            suites.append(Suite(
                label="XRootD root:// + GSI (read)",
                worker_fn=_xrootd_read_worker,
                arg_fn=lambda n: _read_args_xrd(xrd_gsi_url, filename, n,
                                                 proxy=PROXY_PEM,
                                                 sink=read_sink,
                                                 expected_bytes=src_size),
                concurrency=concurrency,
            ))
        # -- XRootD + TLS (stream-level, nginx only; roots:// scheme)
        if want("root-tls") and xrd_tls_url is not None:
            suites.append(Suite(
                label="XRootD roots:// + TLS (read)",
                worker_fn=_xrootd_read_worker,
                arg_fn=lambda n: _read_args_xrd(xrd_tls_url, filename, n,
                                                sink=read_sink,
                                                expected_bytes=src_size,
                                                tls_nosecureverify=True),
                concurrency=concurrency,
            ))
        # -- XRootD + GSI + stream TLS (nginx only; roots:// + GSI auth)
        if want("root-gsi-tls") and xrd_gsi_tls_url is not None:
            suites.append(Suite(
                label="XRootD roots:// + GSI + TLS (read)",
                worker_fn=_xrootd_read_worker,
                arg_fn=lambda n: _read_args_xrd(xrd_gsi_tls_url, filename, n,
                                                proxy=PROXY_PEM,
                                                sink=read_sink,
                                                expected_bytes=src_size,
                                                tls_nosecureverify=True),
                concurrency=concurrency,
            ))
        # -- WebDAV + GSI
        if want("webdav-gsi"):
            suites.append(Suite(
                label="WebDAV davs:// + GSI (read)",
                worker_fn=_webdav_read_worker,
                arg_fn=lambda n: _read_args_dav(dav_url, filename, n,
                                                 proxy=PROXY_PEM),
                concurrency=concurrency,
            ))
        # -- WebDAV + Bearer token
        if token and want("webdav-token"):
            suites.append(Suite(
                label="WebDAV davs:// + token (read)",
                worker_fn=_webdav_read_worker,
                arg_fn=lambda n, t=token: _read_args_dav(dav_url, filename, n,
                                                          token=t),
                concurrency=concurrency,
            ))

    if mode in ("write", "both"):
        # -- XRootD + GSI write
        if want("root-gsi"):
            suites.append(Suite(
                label="XRootD root:// + GSI (write)",
                worker_fn=_xrootd_write_worker,
                arg_fn=lambda n: _write_args_xrd(xrd_gsi_url, src_file, n,
                                                  proxy=PROXY_PEM),
                concurrency=concurrency,
            ))
        # -- WebDAV + GSI write
        if want("webdav-gsi"):
            suites.append(Suite(
                label="WebDAV davs:// + GSI (write)",
                worker_fn=_webdav_write_worker,
                arg_fn=lambda n: _write_args_dav(dav_url, src_file, n,
                                                  proxy=PROXY_PEM),
                concurrency=concurrency,
            ))
        # -- WebDAV + token write
        if token and want("webdav-token"):
            suites.append(Suite(
                label="WebDAV davs:// + token (write)",
                worker_fn=_webdav_write_worker,
                arg_fn=lambda n, t=token: _write_args_dav(
                    dav_url, src_file, n, token=t),
                concurrency=concurrency,
            ))

    if not suites:
        sys.exit(f"No suites selected for mode={mode!r}, suite={suite_filter!r}")

    return suites


def main():
    ap = argparse.ArgumentParser(
        description="Load test nginx-xrootd vs xrootd native",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("--target", choices=["nginx", "xrootd", "both"],
                    default="nginx")
    ap.add_argument("--file", default=DEFAULT_FILE,
                    help=f"filename under {DATA_DIR} (default: {DEFAULT_FILE})")
    ap.add_argument("--concurrency",
                    default=",".join(str(c) for c in DEFAULT_WORKERS),
                    help="comma-separated list of worker counts")
    ap.add_argument("--mode", choices=["read", "write", "both"], default="read")
    ap.add_argument("--suite",
                    choices=["all", "root-anon", "root-gsi", "root-tls",
                             "root-gsi-tls", "webdav-gsi", "webdav-token"],
                    default="all",
                    help="limit run to one protocol/auth suite")
    ap.add_argument("--read-sink", choices=["tempfile", "devnull"],
                    default="tempfile",
                    help="where root:// read workers write downloaded bytes")
    ap.add_argument("--json", metavar="FILE",
                    help="save results to JSON file")
    args = ap.parse_args()

    concurrency = [int(c) for c in args.concurrency.split(",")]

    print(f"\n  nginx-xrootd / xrootd load test")
    print(f"  target={args.target}  file={args.file}"
          f"  concurrency={concurrency}  mode={args.mode}"
          f"  suite={args.suite}  read_sink={args.read_sink}")

    all_results: dict[str, list[Suite]] = {}

    if args.target in ("nginx", "both"):
        suites = build_suites("nginx", args.file, concurrency, args.mode,
                              args.suite, args.read_sink)
        for s in suites:
            s.run()
        all_results["nginx"] = suites
        if args.json:
            save_json(suites, args.json.replace(".json", "_nginx.json"), "nginx")

    if args.target in ("xrootd", "both"):
        suites = build_suites("xrootd", args.file, concurrency, args.mode,
                              args.suite, args.read_sink)
        for s in suites:
            s.run()
        all_results["xrootd"] = suites
        if args.json:
            save_json(suites, args.json.replace(".json", "_xrootd.json"), "xrootd")

    if args.target == "both":
        # Pair up by position — assumes same suite ordering
        print_comparison(all_results["nginx"], all_results["xrootd"])

    print("\n  Done.\n")


if __name__ == "__main__":
    # Required for multiprocessing on Linux (fork is default, but be explicit)
    multiprocessing.set_start_method("fork", force=True)
    main()
