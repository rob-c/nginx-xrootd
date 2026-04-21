"""Shared session-scoped fixtures for the nginx-xrootd test suite.

Provides a ``test_env`` fixture that starts a single nginx instance with the
full server configuration (anonymous, GSI, GSI+TLS, token-auth, metrics,
and WebDAV endpoints) on dynamically allocated ports.  Tests that previously
assumed pre-running servers on hardcoded ports now request ``test_env`` and
read ports / paths from the returned dict.

Also provides:
  - ``ref_xrootd`` — a session-scoped anonymous xrootd reference server
    sharing the same data directory, for protocol conformance comparisons.
  - ``ref_xrootd_gsi`` — a session-scoped GSI-authenticated xrootd reference
    server with its own data directory, for GSI bridge / cross-server tests.
"""

import os
import subprocess
import time
from pathlib import Path

import pytest
from settings import CA_CERT, CA_DIR, DATA_ROOT, PROXY_STD, SERVER_CERT, SERVER_KEY, TOKENS_DIR

from server_control import (
    start_nginx_instance,
    start_xrootd_instance,
    _free_port,
    _wait_for_port,
)


def _wait_for_gsi_ref(url: str, ca_dir: str, proxy_pem: str) -> bool:
    """Probe a GSI-authenticated reference server until it responds."""
    gsi_env = os.environ.copy()
    gsi_env["X509_CERT_DIR"] = ca_dir
    gsi_env["X509_USER_PROXY"] = proxy_pem
    gsi_env["XrdSecPROTOCOL"] = "gsi"

    for _ in range(30):
        try:
            result = subprocess.run(
                ["xrdfs", url, "ls", "/"],
                env=gsi_env,
                capture_output=True,
                timeout=5,
            )
        except subprocess.TimeoutExpired:
            time.sleep(0.5)
            continue
        if result.returncode == 0:
            return True
        time.sleep(0.5)
    return False


def _start_or_attach_ref_xrootd_gsi(test_env, ref_base: Path, data_dir: str) -> dict:
    """Return a ready GSI-authenticated reference xrootd instance."""
    os.makedirs(data_dir, exist_ok=True)

    ext = os.environ.get("TEST_REF_GSI_URL")
    if ext:
        if not _wait_for_gsi_ref(ext, test_env["ca_dir"], test_env["proxy_pem"]):
            pytest.fail(f"External ref xrootd GSI not reachable at {ext}")
        return {"url": ext, "port": 0, "data_dir": data_dir, "stop": lambda: None}

    port = _free_port()
    url = f"root://localhost:{port}"

    authdb_path = str(ref_base / "authdb")
    with open(authdb_path, "w") as f:
        f.write("u * / lr\n")

    ref = start_xrootd_instance(
        port=port,
        ref_dir=str(ref_base),
        data_dir=data_dir,
        conf_file="xrootd_ref_gsi.conf",
        template_kwargs={
            "SECLIB": "/usr/lib64/libXrdSec-5.so",
            "CA_DIR": test_env["ca_dir"],
            "SERVER_CERT": SERVER_CERT,
            "SERVER_KEY": SERVER_KEY,
            "AUTHDB_PATH": authdb_path,
        },
    )

    if not _wait_for_gsi_ref(url, test_env["ca_dir"], test_env["proxy_pem"]):
        ref["stop"]()
        log_path = ref_base / "conformance.log"
        log_text = ""
        try:
            log_text = log_path.read_text()[-3000:]
        except Exception:
            pass
        pytest.fail(
            f"Reference xrootd GSI did not start on port {port}.\n"
            f"Log:\n{log_text}"
        )

    return {"url": url, "port": port, "data_dir": data_dir, "stop": ref["stop"]}


@pytest.fixture(scope="session")
def test_env():
    """Start the shared nginx test environment on dynamic ports.

    Yields a dict with keys:

        Ports:   anon_port, gsi_port, gsi_tls_port, token_port,
                 metrics_port, webdav_port
        URLs:    anon_url, gsi_url, gsi_tls_url, token_url,
                 metrics_url, webdav_url
        Paths:   data_dir, ca_dir, ca_pem, proxy_pem, token_dir, log_dir
    """
    data_dir = DATA_ROOT
    ca_dir = CA_DIR
    ca_pem = CA_CERT
    proxy_pem = PROXY_STD
    token_dir = TOKENS_DIR

    ports = {
        "anon_port": _free_port(),
        "gsi_port": _free_port(),
        "gsi_tls_port": _free_port(),
        "token_port": _free_port(),
        "metrics_port": _free_port(),
        "webdav_port": _free_port(),
    }

    info = start_nginx_instance(
        port=ports["anon_port"],
        conf_file="nginx_shared.conf",
        template_kwargs={
            "DATA_DIR": data_dir,
            "ANON_PORT": ports["anon_port"],
            "GSI_PORT": ports["gsi_port"],
            "GSI_TLS_PORT": ports["gsi_tls_port"],
            "TOKEN_PORT": ports["token_port"],
            "METRICS_PORT": ports["metrics_port"],
            "WEBDAV_PORT": ports["webdav_port"],
            "CA_DIR": ca_dir,
            "TOKEN_DIR": token_dir,
        },
    )

    # start_nginx_instance only waits for the primary port; wait for the rest.
    for name, p in ports.items():
        if name == "anon_port":
            continue
        if not _wait_for_port("127.0.0.1", p, timeout=15):
            info["stop"]()
            raise RuntimeError(f"nginx port {p} ({name}) did not become ready")

    log_dir = str(Path(info["prefix"]) / "logs")

    env = {
        **ports,
        "anon_url": f"root://localhost:{ports['anon_port']}",
        "gsi_url": f"root://localhost:{ports['gsi_port']}",
        "gsi_tls_url": f"roots://localhost:{ports['gsi_tls_port']}",
        "token_url": f"root://localhost:{ports['token_port']}",
        "metrics_url": f"http://localhost:{ports['metrics_port']}/metrics",
        "webdav_url": f"https://localhost:{ports['webdav_port']}",
        "data_dir": data_dir,
        "ca_dir": ca_dir,
        "ca_pem": ca_pem,
        "proxy_pem": proxy_pem,
        "token_dir": token_dir,
        "log_dir": log_dir,
    }

    yield env

    info["stop"]()


# ---------------------------------------------------------------------------
# Session-scoped anonymous reference xrootd
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def ref_xrootd(test_env):
    """Start a session-scoped anonymous xrootd serving the same data directory.

    Yields a dict with keys: ``url``, ``port``, ``ref_dir``, ``data_dir``,
    ``stop()``.
    Used by conformance and comparison tests.
    """
    ref = start_xrootd_instance(port=None, data_dir=test_env["data_dir"])
    ref["data_dir"] = test_env["data_dir"]
    yield ref
    ref["stop"]()


# ---------------------------------------------------------------------------
# Session-scoped GSI-authenticated reference xrootd
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def ref_xrootd_gsi(test_env, tmp_path_factory):
    """Start a session-scoped GSI-authenticated xrootd with its own data dir.

    Yields a dict with keys: ``url``, ``port``, ``data_dir``.
    The data directory is separate from the main nginx data so cross-server
    transfer tests can distinguish which server a file came from.
    """
    ref_base = tmp_path_factory.mktemp("xrd-gsi-bridge")
    bridge_data = str(ref_base / "data")
    ref = _start_or_attach_ref_xrootd_gsi(test_env, ref_base, bridge_data)
    yield ref
    ref["stop"]()


@pytest.fixture(scope="session")
def ref_xrootd_gsi_shared(test_env, tmp_path_factory):
    """Start a GSI-authenticated reference xrootd sharing the anon data dir."""
    ref_base = tmp_path_factory.mktemp("xrd-gsi-shared")
    ref = _start_or_attach_ref_xrootd_gsi(test_env, ref_base, test_env["data_dir"])
    yield ref
    ref["stop"]()
