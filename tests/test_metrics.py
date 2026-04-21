"""
Prometheus metrics endpoint tests for nginx-xrootd.

Verifies that:
  - GET /metrics returns 200 with correct Content-Type
  - Counter names and TYPE/HELP headers are present
  - Counters increment correctly after connections, reads, writes
  - Per-server labels (port, auth) are correct
  - Both anon (11094) and GSI (11095) servers appear after activity

Run:
    pytest tests/test_metrics.py -v -s
"""

import os
import re
import subprocess
import tempfile
import time

import pytest
import urllib.request
from settings import CA_DIR as DEFAULT_CA_DIR, PROXY_STD

METRICS_URL = ""
ANON_PORT   = ""
GSI_PORT    = ""
CA_DIR      = DEFAULT_CA_DIR
PROXY_PEM   = PROXY_STD


@pytest.fixture(scope="module", autouse=True)
def _configure(test_env):
    """Bind module constants from the shared test environment."""
    global METRICS_URL, ANON_PORT, GSI_PORT, CA_DIR, PROXY_PEM
    METRICS_URL = test_env["metrics_url"]
    ANON_PORT   = str(test_env["anon_port"])
    GSI_PORT    = str(test_env["gsi_port"])
    CA_DIR      = test_env["ca_dir"]
    PROXY_PEM   = test_env["proxy_pem"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def fetch_metrics() -> str:
    with urllib.request.urlopen(METRICS_URL, timeout=5) as resp:
        return resp.read().decode()


def parse_metric(text: str, name: str, labels: dict) -> int:
    """Return the integer value of a metric line matching name and all labels.

    Label order in the output is not assumed — each required label is checked
    as a substring within the { } block.
    """
    for line in text.splitlines():
        if not line.startswith(name + "{"):
            continue
        # Extract the label block
        m = re.match(r'^' + re.escape(name) + r'\{([^}]*)\}\s+(\d+)', line)
        if not m:
            continue
        label_block, value = m.group(1), m.group(2)
        # Verify every required label appears in the block
        if all(f'{k}="{v}"' in label_block for k, v in labels.items()):
            return int(value)
    return -1  # not found


def xrdcp_put(local_path: str, remote_url: str, env: dict | None = None) -> int:
    cmd = ["xrdcp", "-f", local_path, remote_url]
    result = subprocess.run(cmd, capture_output=True, env={**os.environ, **(env or {})})
    return result.returncode


def xrdcp_get(remote_url: str, local_path: str, env: dict | None = None) -> int:
    cmd = ["xrdcp", "-f", remote_url, local_path]
    result = subprocess.run(cmd, capture_output=True, env={**os.environ, **(env or {})})
    return result.returncode


# ---------------------------------------------------------------------------
# Basic endpoint tests
# ---------------------------------------------------------------------------

class TestMetricsEndpoint:
    def test_returns_200(self):
        with urllib.request.urlopen(METRICS_URL, timeout=5) as resp:
            assert resp.status == 200

    def test_content_type(self):
        with urllib.request.urlopen(METRICS_URL, timeout=5) as resp:
            ct = resp.headers.get("Content-Type", "")
        assert "text/plain" in ct

    def test_help_and_type_headers_present(self):
        text = fetch_metrics()
        expected = [
            "# HELP xrootd_connections_total",
            "# TYPE xrootd_connections_total counter",
            "# HELP xrootd_connections_active",
            "# TYPE xrootd_connections_active gauge",
            "# HELP xrootd_bytes_rx_total",
            "# TYPE xrootd_bytes_rx_total counter",
            "# HELP xrootd_bytes_tx_total",
            "# TYPE xrootd_bytes_tx_total counter",
            "# HELP xrootd_requests_total",
            "# TYPE xrootd_requests_total counter",
        ]
        for line in expected:
            assert line in text, f"Missing: {line!r}"

    def test_all_op_names_present(self):
        text = fetch_metrics()
        ops = [
            "login", "auth", "stat", "open_rd", "open_wr",
            "read", "write", "sync", "close", "dirlist",
            "mkdir", "rmdir", "rm", "mv", "chmod", "truncate", "ping",
        ]
        for op in ops:
            assert f'op="{op}"' in text, f"Missing op label: {op!r}"


# ---------------------------------------------------------------------------
# Anon server counter tests
# ---------------------------------------------------------------------------

class TestAnonCounters:
    """Write then read a file via the anonymous server; verify counter deltas."""

    @pytest.fixture(autouse=True)
    def _baseline(self):
        self.before = fetch_metrics()
        yield
        # (after is fetched per-test)

    def _delta(self, name: str, labels: dict) -> int:
        after = fetch_metrics()
        v_before = parse_metric(self.before, name, labels)
        v_after  = parse_metric(after,       name, labels)
        if v_before == -1:
            v_before = 0
        assert v_after != -1, f"Metric {name}{labels} not found after activity"
        return v_after - v_before

    def test_write_increments_connections(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            f.write(b"metrics test data")
            f.flush()
            rc = xrdcp_put(f.name, f"root://localhost:{ANON_PORT}//metrics_write_test.txt")
        assert rc == 0
        delta = self._delta("xrootd_connections_total", {"port": ANON_PORT, "auth": "anon"})
        assert delta >= 1

    def test_write_increments_bytes_rx(self):
        payload = b"x" * 1024
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(payload)
            f.flush()
            rc = xrdcp_put(f.name, f"root://localhost:{ANON_PORT}//metrics_bytes_rx.bin")
        assert rc == 0
        delta = self._delta("xrootd_bytes_rx_total", {"port": ANON_PORT, "auth": "anon"})
        assert delta >= len(payload)

    def test_read_increments_bytes_tx(self):
        payload = b"y" * 2048
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(payload)
            f.flush()
            rc = xrdcp_put(f.name, f"root://localhost:{ANON_PORT}//metrics_bytes_tx.bin")
        assert rc == 0
        self.before = fetch_metrics()  # reset baseline after write
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as out:
            rc = xrdcp_get(f"root://localhost:{ANON_PORT}//metrics_bytes_tx.bin", out.name)
        assert rc == 0
        delta = self._delta("xrootd_bytes_tx_total", {"port": ANON_PORT, "auth": "anon"})
        assert delta >= len(payload)

    def test_open_wr_counter(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"open_wr test")
            f.flush()
            rc = xrdcp_put(f.name, f"root://localhost:{ANON_PORT}//metrics_open_wr.txt")
        assert rc == 0
        delta = self._delta(
            "xrootd_requests_total",
            {"port": ANON_PORT, "auth": "anon", "op": "open_wr", "status": "ok"},
        )
        assert delta >= 1

    def test_open_rd_counter(self):
        # Ensure file exists first
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"open_rd test")
            f.flush()
            xrdcp_put(f.name, f"root://localhost:{ANON_PORT}//metrics_open_rd.txt")
        self.before = fetch_metrics()
        with tempfile.NamedTemporaryFile(delete=False) as out:
            rc = xrdcp_get(f"root://localhost:{ANON_PORT}//metrics_open_rd.txt", out.name)
        assert rc == 0
        delta = self._delta(
            "xrootd_requests_total",
            {"port": ANON_PORT, "auth": "anon", "op": "open_rd", "status": "ok"},
        )
        assert delta >= 1

    def test_login_counter_per_connection(self):
        # Two separate xrdcp commands → two logins
        before_text = fetch_metrics()
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"login counter test 1")
            f.flush()
            xrdcp_put(f.name, f"root://localhost:{ANON_PORT}//metrics_login1.txt")
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"login counter test 2")
            f.flush()
            xrdcp_put(f.name, f"root://localhost:{ANON_PORT}//metrics_login2.txt")
        after_text = fetch_metrics()
        v_before = parse_metric(before_text, "xrootd_requests_total",
                                {"port": ANON_PORT, "auth": "anon", "op": "login", "status": "ok"})
        v_after  = parse_metric(after_text,  "xrootd_requests_total",
                                {"port": ANON_PORT, "auth": "anon", "op": "login", "status": "ok"})
        if v_before == -1:
            v_before = 0
        assert v_after - v_before >= 2

    def test_connections_active_does_not_leak(self):
        # connections_active must not be higher after our xrdcp than before it,
        # proving that the gauge is correctly decremented on disconnect.
        # (Other tests may leave connections open, so we cannot assert == 0.)
        before_text = fetch_metrics()
        before = parse_metric(before_text, "xrootd_connections_active",
                              {"port": ANON_PORT, "auth": "anon"})
        if before == -1:
            before = 0
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"active connections test")
            f.flush()
            rc = xrdcp_put(f.name, f"root://localhost:{ANON_PORT}//metrics_active.txt")
        assert rc == 0
        time.sleep(0.2)   # let the connection fully close
        after_text = fetch_metrics()
        after = parse_metric(after_text, "xrootd_connections_active",
                             {"port": ANON_PORT, "auth": "anon"})
        assert after != -1, "xrootd_connections_active metric missing after activity"
        assert after <= before, (
            f"connections_active rose from {before} to {after} after xrdcp closed — gauge is leaking"
        )


# ---------------------------------------------------------------------------
# GSI server counter tests
# ---------------------------------------------------------------------------

class TestGSICounters:
    """Basic GSI metrics — verify the gsi server slot appears after a transfer."""

    @property
    def GSI_ENV(self):
        return {
            "X509_CERT_DIR":   CA_DIR,
            "X509_USER_PROXY": PROXY_PEM,
        }

    def test_gsi_server_appears_in_metrics(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"gsi metrics test")
            f.flush()
            rc = xrdcp_put(
                f.name,
                f"root://localhost:{GSI_PORT}//metrics_gsi_test.txt",
                env=self.GSI_ENV,
            )
        assert rc == 0
        text = fetch_metrics()
        assert f'port="{GSI_PORT}"' in text
        assert 'auth="gsi"' in text

    def test_gsi_connections_total_increments(self):
        before = fetch_metrics()
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"gsi connections")
            f.flush()
            rc = xrdcp_put(
                f.name,
                f"root://localhost:{GSI_PORT}//metrics_gsi_conn.txt",
                env=self.GSI_ENV,
            )
        assert rc == 0
        after = fetch_metrics()
        v_before = parse_metric(before, "xrootd_connections_total",
                                {"port": GSI_PORT, "auth": "gsi"})
        v_after  = parse_metric(after,  "xrootd_connections_total",
                                {"port": GSI_PORT, "auth": "gsi"})
        if v_before == -1:
            v_before = 0
        assert v_after - v_before >= 1

    def test_gsi_login_counter(self):
        before = fetch_metrics()
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"gsi login counter")
            f.flush()
            rc = xrdcp_put(
                f.name,
                f"root://localhost:{GSI_PORT}//metrics_gsi_login.txt",
                env=self.GSI_ENV,
            )
        assert rc == 0
        after = fetch_metrics()
        v_before = parse_metric(before, "xrootd_requests_total",
                                {"port": GSI_PORT, "auth": "gsi", "op": "login", "status": "ok"})
        v_after  = parse_metric(after,  "xrootd_requests_total",
                                {"port": GSI_PORT, "auth": "gsi", "op": "login", "status": "ok"})
        if v_before == -1:
            v_before = 0
        assert v_after - v_before >= 1
