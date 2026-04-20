"""
Concurrent transfer tests for nginx-xrootd.

Runs N simultaneous 200 MB transfers from the same single-worker nginx
instance and measures per-connection throughput, aggregate throughput, and
data integrity.

Run:
    pytest tests/test_concurrent.py -v -s
"""

import hashlib
import os
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import pytest
from XRootD import client

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

ANON_URL    = "root://localhost:11094"
GSI_URL     = "root://localhost:11095"
GSI_TLS_URL = "roots://localhost:11096"

CA_DIR    = "/tmp/xrd-test/pki/ca"
PROXY_PEM = "/tmp/xrd-test/pki/user/proxy_std.pem"

LARGE_FILE      = "large200.bin"
LARGE_FILE_SIZE = 200 * 1024 * 1024
LARGE_FILE_MD5  = "e974166996ffd73416120d15574672d6"

READ_CHUNK = 4 * 1024 * 1024   # 4 MiB — matches XROOTD_READ_MAX in module


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
def gsi_env():
    os.environ["X509_CERT_DIR"]  = CA_DIR
    os.environ["X509_USER_PROXY"] = PROXY_PEM


# ---------------------------------------------------------------------------
# Per-worker transfer function (called from threads)
# ---------------------------------------------------------------------------

def _transfer_worker(worker_id: int, base_url: str) -> dict:
    """
    Open and read LARGE_FILE entirely in READ_CHUNK-sized requests.
    Returns a result dict with timing and integrity information.
    Called from a thread; each thread owns its own XRootD File object.
    """
    url = f"{base_url}//{LARGE_FILE}"
    result = {"id": worker_id, "url": base_url, "ok": False, "error": None}

    try:
        f = client.File()
        t_open = time.perf_counter()

        status, _ = f.open(url)
        if not status.ok:
            result["error"] = f"open failed: {status.message}"
            return result

        status, st = f.stat()
        if not status.ok:
            result["error"] = f"stat failed: {status.message}"
            return result
        total = st.size

        t_start = time.perf_counter()
        md5 = hashlib.md5()
        received = 0

        while received < total:
            want = min(READ_CHUNK, total - received)
            status, data = f.read(offset=received, size=want)
            if not status.ok:
                result["error"] = f"read at {received} failed: {status.message}"
                return result
            if len(data) != want:
                result["error"] = (
                    f"short read at {received}: got {len(data)}, want {want}"
                )
                return result
            md5.update(data)
            received += len(data)

        f.close()
        t_end = time.perf_counter()

        result.update(
            ok=True,
            bytes=received,
            md5=md5.hexdigest(),
            t_open=t_open,
            t_start=t_start,
            t_end=t_end,
            elapsed_total=t_end - t_open,
            elapsed_data=t_end - t_start,
            mib_s=(received / (1024**2)) / (t_end - t_start),
        )
    except Exception as exc:
        result["error"] = str(exc)

    return result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run_concurrent(n_workers: int, base_url: str) -> tuple[list[dict], float]:
    """
    Launch n_workers threads simultaneously, each transferring LARGE_FILE.
    Returns (results_list, wall_clock_elapsed).
    """
    t_wall_start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=n_workers) as pool:
        futures = [
            pool.submit(_transfer_worker, i, base_url)
            for i in range(n_workers)
        ]
        results = [f.result() for f in as_completed(futures)]
    t_wall_end = time.perf_counter()
    return results, t_wall_end - t_wall_start


def _assert_and_report(results: list[dict], n: int, wall: float, label: str):
    total_bytes = 0
    for r in results:
        assert r["ok"], f"worker {r['id']} failed: {r['error']}"
        assert r["bytes"] == LARGE_FILE_SIZE, (
            f"worker {r['id']}: size {r['bytes']} != {LARGE_FILE_SIZE}"
        )
        assert r["md5"] == LARGE_FILE_MD5, (
            f"worker {r['id']}: md5 mismatch {r['md5']}"
        )
        total_bytes += r["bytes"]

    total_mib   = total_bytes / (1024**2)
    agg_mib_s   = total_mib / wall
    per_rates   = [r["mib_s"] for r in results]
    min_rate    = min(per_rates)
    max_rate    = max(per_rates)
    mean_rate   = sum(per_rates) / len(per_rates)

    # Time from first open to last close — measures true overlap
    t_first = min(r["t_open"]  for r in results)
    t_last  = max(r["t_end"]   for r in results)
    overlap = t_last - t_first

    print(
        f"\n  [{label}] {n} concurrent × 200 MiB = {total_mib:.0f} MiB total"
        f"\n    wall clock      : {wall:.2f}s"
        f"\n    open→close span : {overlap:.2f}s"
        f"\n    aggregate rate  : {agg_mib_s:.0f} MiB/s"
        f"\n    per-connection  : min={min_rate:.0f}  mean={mean_rate:.0f}"
        f"  max={max_rate:.0f} MiB/s"
    )
    return agg_mib_s, per_rates


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestConcurrent:

    # ---- single-connection baseline (reuse in later assertions) -----------

    def test_baseline_single_anon(self):
        """Single transfer baseline for anonymous endpoint."""
        results, wall = _run_concurrent(1, ANON_URL)
        _assert_and_report(results, 1, wall, "anon n=1 baseline")

    def test_baseline_single_gsi(self):
        """Single transfer baseline for GSI endpoint."""
        results, wall = _run_concurrent(1, GSI_URL)
        _assert_and_report(results, 1, wall, "gsi  n=1 baseline")

    # ---- concurrent anonymous --------------------------------------------

    def test_concurrent_2_anon(self):
        """2 simultaneous anonymous transfers — all must complete correctly."""
        results, wall = _run_concurrent(2, ANON_URL)
        _assert_and_report(results, 2, wall, "anon n=2")

    def test_concurrent_4_anon(self):
        """4 simultaneous anonymous transfers."""
        results, wall = _run_concurrent(4, ANON_URL)
        _assert_and_report(results, 4, wall, "anon n=4")

    def test_concurrent_8_anon(self):
        """8 simultaneous anonymous transfers."""
        results, wall = _run_concurrent(8, ANON_URL)
        _assert_and_report(results, 8, wall, "anon n=8")

    # ---- concurrent GSI --------------------------------------------------

    def test_concurrent_2_gsi(self):
        """2 simultaneous GSI-authenticated transfers."""
        results, wall = _run_concurrent(2, GSI_URL)
        _assert_and_report(results, 2, wall, "gsi  n=2")

    def test_concurrent_4_gsi(self):
        """4 simultaneous GSI-authenticated transfers."""
        results, wall = _run_concurrent(4, GSI_URL)
        _assert_and_report(results, 4, wall, "gsi  n=4")

    def test_concurrent_8_gsi(self):
        """8 simultaneous GSI-authenticated transfers."""
        results, wall = _run_concurrent(8, GSI_URL)
        _assert_and_report(results, 8, wall, "gsi  n=8")

    # ---- mixed anon + GSI ------------------------------------------------

    def test_concurrent_mixed_anon_and_gsi(self):
        """
        4 anonymous + 4 GSI transfers simultaneously from the same server.
        Verifies the server correctly multiplexes authenticated and
        unauthenticated connections in one event loop.
        """
        with ThreadPoolExecutor(max_workers=8) as pool:
            t0 = time.perf_counter()
            futures = (
                [pool.submit(_transfer_worker, i,   ANON_URL) for i in range(4)]
              + [pool.submit(_transfer_worker, i+4, GSI_URL)  for i in range(4)]
            )
            results = [f.result() for f in as_completed(futures)]
        wall = time.perf_counter() - t0

        anon_results = [r for r in results if ANON_URL in r["url"]]
        gsi_results  = [r for r in results if GSI_URL  in r["url"]]

        _assert_and_report(anon_results, 4, wall, "mixed → anon side")
        _assert_and_report(gsi_results,  4, wall, "mixed → gsi  side")

    # ---- scalability assertion -------------------------------------------

    @pytest.mark.timeout(240)
    def test_aggregate_throughput_scales_with_connections(self):
        """
        Aggregate throughput with 4 connections should be at least 1.5× that
        of 1 connection — i.e. the server actually parallelises I/O rather
        than serialising requests.
        """
        # Warm connections first so we measure data transfer not handshake
        _run_concurrent(1, ANON_URL)
        _run_concurrent(4, ANON_URL)

        # Best-of-2 to reduce single-sample noise
        wall1 = min(_run_concurrent(1, ANON_URL)[1], _run_concurrent(1, ANON_URL)[1])
        wall4 = min(_run_concurrent(4, ANON_URL)[1], _run_concurrent(4, ANON_URL)[1])

        agg1 = LARGE_FILE_SIZE / wall1
        agg4 = (4 * LARGE_FILE_SIZE) / wall4
        ratio = agg4 / agg1

        print(
            f"\n  n=1 aggregate: {agg1/1e6:.0f} MB/s  wall={wall1:.2f}s"
            f"\n  n=4 aggregate: {agg4/1e6:.0f} MB/s  wall={wall4:.2f}s"
            f"\n  scale-up ratio: {ratio:.2f}x"
        )

        assert ratio >= 1.5, (
            f"Expected ≥1.5× aggregate throughput at n=4 vs n=1, got {ratio:.2f}×. "
            f"n=1={agg1/1e6:.0f} MB/s  n=4={agg4/1e6:.0f} MB/s"
        )


class TestConcurrentTLS:
    """
    Same concurrency matrix as TestConcurrent but against the roots:// endpoint
    (GSI auth + kXR_ableTLS in-protocol TLS upgrade).
    """

    def test_baseline_single_gsi_tls(self):
        """Single transfer baseline for GSI+TLS endpoint."""
        results, wall = _run_concurrent(1, GSI_TLS_URL)
        _assert_and_report(results, 1, wall, "gsi+tls n=1 baseline")

    def test_concurrent_2_gsi_tls(self):
        """2 simultaneous GSI+TLS transfers."""
        results, wall = _run_concurrent(2, GSI_TLS_URL)
        _assert_and_report(results, 2, wall, "gsi+tls n=2")

    def test_concurrent_4_gsi_tls(self):
        """4 simultaneous GSI+TLS transfers."""
        results, wall = _run_concurrent(4, GSI_TLS_URL)
        _assert_and_report(results, 4, wall, "gsi+tls n=4")

    def test_concurrent_8_gsi_tls(self):
        """8 simultaneous GSI+TLS transfers."""
        results, wall = _run_concurrent(8, GSI_TLS_URL)
        _assert_and_report(results, 8, wall, "gsi+tls n=8")

    def test_concurrent_mixed_gsi_and_gsi_tls(self):
        """
        4 plain-GSI + 4 GSI+TLS transfers simultaneously.
        Verifies the server correctly multiplexes TLS-upgraded and plain
        connections within one event loop.
        """
        with ThreadPoolExecutor(max_workers=8) as pool:
            t0 = time.perf_counter()
            futures = (
                [pool.submit(_transfer_worker, i,   GSI_URL)     for i in range(4)]
              + [pool.submit(_transfer_worker, i+4, GSI_TLS_URL) for i in range(4)]
            )
            results = [f.result() for f in as_completed(futures)]
        wall = time.perf_counter() - t0

        gsi_results     = [r for r in results if GSI_URL     in r["url"] and GSI_TLS_URL not in r["url"]]
        gsi_tls_results = [r for r in results if GSI_TLS_URL in r["url"]]

        _assert_and_report(gsi_results,     4, wall, "mixed → gsi      side")
        _assert_and_report(gsi_tls_results, 4, wall, "mixed → gsi+tls  side")

    @pytest.mark.timeout(240)
    def test_aggregate_throughput_scales_gsi_tls(self):
        """
        Aggregate throughput with 4 GSI+TLS connections should be at least
        1.5× that of 1 connection — TLS overhead should not serialise I/O.
        """
        _run_concurrent(1, GSI_TLS_URL)
        _run_concurrent(4, GSI_TLS_URL)

        wall1 = min(_run_concurrent(1, GSI_TLS_URL)[1], _run_concurrent(1, GSI_TLS_URL)[1])
        wall4 = min(_run_concurrent(4, GSI_TLS_URL)[1], _run_concurrent(4, GSI_TLS_URL)[1])

        agg1 = LARGE_FILE_SIZE / wall1
        agg4 = (4 * LARGE_FILE_SIZE) / wall4
        ratio = agg4 / agg1

        print(
            f"\n  gsi+tls n=1 aggregate: {agg1/1e6:.0f} MB/s  wall={wall1:.2f}s"
            f"\n  gsi+tls n=4 aggregate: {agg4/1e6:.0f} MB/s  wall={wall4:.2f}s"
            f"\n  scale-up ratio: {ratio:.2f}x"
        )

        assert ratio >= 1.5, (
            f"Expected ≥1.5× aggregate throughput at n=4 vs n=1, got {ratio:.2f}×. "
            f"n=1={agg1/1e6:.0f} MB/s  n=4={agg4/1e6:.0f} MB/s"
        )
