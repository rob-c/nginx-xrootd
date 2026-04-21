"""
tests/test_crl.py

Certificate Revocation List (CRL) tests.

Verifies that when xrootd_crl is configured, revoked user certificates
are rejected by both the XRootD stream (GSI) and WebDAV (HTTPS) auth
paths.

Test infrastructure:
  - Generates a CRL signed by the test CA that revokes the test user cert
  - Starts a dedicated nginx listener with CRL checking enabled
  - Verifies that the revoked proxy is rejected while a non-revoked cert
    would succeed (baseline sanity via the existing non-CRL listener)

Run:
    pytest tests/test_crl.py -v
"""

import datetime
import os
import socket
import subprocess
import time

import pytest
import urllib3
import requests

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import (
    CertificateRevocationListBuilder,
    RevokedCertificateBuilder,
)
from settings import CA_CERT, CA_KEY, DATA_ROOT, NGINX_BIN, PKI_DIR, PROXY_STD, USER_CERT

# Suppress InsecureRequestWarning — test certs have no SAN
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

PROXY_PEM  = PROXY_STD

CRL_DIR    = "/tmp/xrd-crl-test"
CRL_PEM    = os.path.join(CRL_DIR, "crl.pem")

CRL_PORT   = _free_port()
CRL_HOST   = "127.0.0.1"

WEBDAV_CRL_PORT = _free_port()

# Directory-mode test paths
CRL_DIR_TEST      = "/tmp/xrd-crl-dir-test"
CRL_DIR_CRLS      = os.path.join(CRL_DIR_TEST, "crls")   # directory of CRLs
CRL_DIR_PORT      = _free_port()
WEBDAV_DIR_PORT   = _free_port()

# Reload-mode test paths
CRL_RELOAD_DIR    = "/tmp/xrd-crl-reload-test"
CRL_RELOAD_CRLS   = os.path.join(CRL_RELOAD_DIR, "crls")
CRL_RELOAD_PORT   = _free_port()
RELOAD_INTERVAL   = 2  # seconds — keep short for testing

# ---------------------------------------------------------------------------
# CRL generation
# ---------------------------------------------------------------------------

def generate_crl(ca_cert_path, ca_key_path, revoked_cert_path, crl_path):
    """Generate a CRL that revokes the given certificate."""
    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    with open(ca_key_path, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(revoked_cert_path, "rb") as f:
        revoked_cert = x509.load_pem_x509_certificate(f.read())

    now = datetime.datetime.now(datetime.timezone.utc)

    revoked = (
        RevokedCertificateBuilder()
        .serial_number(revoked_cert.serial_number)
        .revocation_date(now - datetime.timedelta(hours=1))
        .build()
    )

    crl = (
        CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now - datetime.timedelta(hours=1))
        .next_update(now + datetime.timedelta(days=30))
        .add_revoked_certificate(revoked)
        .sign(ca_key, hashes.SHA256())
    )

    os.makedirs(os.path.dirname(crl_path), exist_ok=True)
    with open(crl_path, "wb") as f:
        f.write(crl.public_bytes(serialization.Encoding.PEM))


# ---------------------------------------------------------------------------
# Wait for port
# ---------------------------------------------------------------------------

def _wait_for_port(host, port, proc, timeout=5):
    """Block until a TCP port accepts connections or the process dies."""
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


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def crl_file():
    """Generate a CRL revoking the test user certificate."""
    generate_crl(CA_CERT, CA_KEY, USER_CERT, CRL_PEM)
    return CRL_PEM


@pytest.fixture(scope="session", autouse=True)
def crl_nginx(crl_file):
    """Start an nginx with CRL checking enabled on a dedicated port."""
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")
    import server_control

    info = server_control.start_nginx_instance(
        port=CRL_PORT, nginx_bin=NGINX_BIN,
        conf_file="nginx_crl.conf",
        template_kwargs={
            "DATA_DIR": DATA_ROOT,
            "CRL_PATH": crl_file,
            "WEBDAV_PORT": WEBDAV_CRL_PORT,
        },
    )

    # Wait for the HTTPS port to become available as well
    ok_https = False
    for _ in range(30):
        try:
            with socket.create_connection(("127.0.0.1", WEBDAV_CRL_PORT), timeout=0.5):
                ok_https = True
                break
        except Exception:
            time.sleep(0.1)

    if not ok_https:
        try:
            info["stop"]()
        except Exception:
            pass
        pytest.fail("CRL nginx did not start (HTTPS port not reachable)")

    yield info

    try:
        info["stop"]()
    except Exception:
        pass


@pytest.fixture(scope="session", autouse=True)
def crl_dir_nginx(crl_file):
    """Start nginx with xrootd_crl pointing at a *directory* of CRL files."""
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")

    # Put the CRL in a directory
    os.makedirs(CRL_RELOAD_CRLS, exist_ok=True)
    os.makedirs(CRL_DIR_CRLS, exist_ok=True)
    import shutil
    shutil.copy2(crl_file, os.path.join(CRL_DIR_CRLS, "ca.r0"))

    import server_control
    info = server_control.start_nginx_instance(
        port=CRL_DIR_PORT, nginx_bin=NGINX_BIN,
        conf_file="nginx_crl.conf",
        template_kwargs={
            "DATA_DIR": DATA_ROOT,
            "CRL_PATH": CRL_DIR_CRLS,
            "WEBDAV_PORT": WEBDAV_DIR_PORT,
        },
    )

    # Wait for both stream and HTTPS to be reachable
    ok_stream = False
    ok_https = False
    for _ in range(30):
        try:
            with socket.create_connection(("127.0.0.1", CRL_DIR_PORT), timeout=0.5):
                ok_stream = True
        except Exception:
            ok_stream = False
        try:
            with socket.create_connection(("127.0.0.1", WEBDAV_DIR_PORT), timeout=0.5):
                ok_https = True
        except Exception:
            ok_https = False
        if ok_stream and ok_https:
            break
        time.sleep(0.1)

    if not ok_stream or not ok_https:
        try:
            info["stop"]()
        except Exception:
            pass
        pytest.fail(f"CRL dir nginx did not start. stream={ok_stream} https={ok_https}")

    yield info

    try:
        info["stop"]()
    except Exception:
        pass


@pytest.fixture(scope="session", autouse=True)
def crl_reload_nginx(crl_file):
    """Start nginx with CRL reload enabled, initially with NO CRL in the dir.

    The test will copy the CRL into the directory after nginx starts,
    wait for the reload timer to fire, then verify rejection.
    """
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")

    # Start with an empty CRL directory
    os.makedirs(CRL_RELOAD_CRLS, exist_ok=True)
    # Remove any leftover CRL files from previous runs
    for f in os.listdir(CRL_RELOAD_CRLS):
        os.remove(os.path.join(CRL_RELOAD_CRLS, f))

    import server_control
    info = server_control.start_nginx_instance(
        port=CRL_RELOAD_PORT, nginx_bin=NGINX_BIN,
        conf_file="nginx_crl_reload.conf",
        template_kwargs={
            "DATA_DIR": DATA_ROOT,
            "CRL_PATH": CRL_RELOAD_CRLS,
            "CRL_RELOAD_INTERVAL": RELOAD_INTERVAL,
            "HTTP_STUB_PORT": 18999,
        },
    )

    ok = False
    for _ in range(30):
        try:
            with socket.create_connection((CRL_HOST, CRL_RELOAD_PORT), timeout=0.5):
                ok = True
                break
        except Exception:
            time.sleep(0.1)

    if not ok:
        try:
            info["stop"]()
        except Exception:
            pass
        pytest.fail("CRL reload nginx did not start.")

    yield {"proc": None, "crl_src": crl_file, "log_dir": info["prefix"] + "/logs"}
    try:
        info["stop"]()
    except Exception:
        pass
    try:
        info["stop"]()
    except Exception:
        pass


# =========================================================================
# Tests
# =========================================================================


class TestCRLGeneration:
    """Validate the generated CRL."""

    def test_crl_file_exists(self, crl_file):
        assert os.path.exists(crl_file)

    def test_crl_contains_revoked_serial(self, crl_file):
        """CRL should list the user cert serial number."""
        with open(crl_file, "rb") as f:
            crl = x509.load_pem_x509_crl(f.read())
        with open(USER_CERT, "rb") as f:
            user_cert = x509.load_pem_x509_certificate(f.read())

        revoked = crl.get_revoked_certificate_by_serial_number(
            user_cert.serial_number
        )
        assert revoked is not None, "user cert should be in the CRL"


class TestCRLStreamRejection:
    """XRootD GSI auth should reject a revoked user certificate."""

    def test_baseline_non_crl_server_accepts(self):
        """Sanity check: the normal GSI listener (no CRL) still accepts."""
        env = os.environ.copy()
        env["X509_CERT_DIR"]     = os.path.join(PKI_DIR, "ca")
        env["X509_USER_PROXY"]   = PROXY_PEM
        env["XrdSecPROTOCOL"]    = "gsi"
        env["XrdSecGSISRVNAMES"] = "*"

        result = subprocess.run(
            ["xrdfs", "root://localhost:11095", "stat", "/test.txt"],
            capture_output=True, text=True, timeout=10, env=env,
        )
        assert result.returncode == 0, (
            f"baseline GSI stat failed: {result.stderr}"
        )

    def test_revoked_cert_rejected_by_crl_server(self, crl_nginx):
        """The CRL-enabled listener should reject the revoked proxy."""
        env = os.environ.copy()
        env["X509_CERT_DIR"]     = os.path.join(PKI_DIR, "ca")
        env["X509_USER_PROXY"]   = PROXY_PEM
        env["XrdSecPROTOCOL"]    = "gsi"
        env["XrdSecGSISRVNAMES"] = "*"

        result = subprocess.run(
            ["xrdfs", f"root://localhost:{CRL_PORT}", "stat", "/test.txt"],
            capture_output=True, text=True, timeout=10, env=env,
        )
        assert result.returncode != 0, (
            f"revoked cert should be rejected but stat succeeded"
        )


class TestCRLWebDAVRejection:
    """WebDAV/HTTPS should reject a revoked client certificate."""

    def test_revoked_cert_rejected_by_webdav(self, crl_nginx):
        """HTTPS request with revoked client cert should fail auth."""
        # We need to present the client cert for mutual TLS.
        # requests uses cert= for client certs.
        # The proxy_std.pem has cert+key+chain in one file.
        resp = requests.get(
            f"https://localhost:{WEBDAV_CRL_PORT}/test.txt",
            cert=PROXY_PEM,
            verify=False,
        )
        # Should be 403 (forbidden) because the cert is revoked
        assert resp.status_code == 403, (
            f"expected 403, got {resp.status_code}: {resp.text}"
        )


class TestCRLConfigDirectives:
    """Verify CRL configuration directives are accepted."""

    def test_nginx_config_test_passes(self, crl_file):
        """nginx -t should validate config with xrootd_crl."""
        conf_path = os.path.join(CRL_DIR, "conf", "nginx.conf")
        if not os.path.exists(conf_path):
            pytest.skip("CRL config not written")

        result = subprocess.run(
            [NGINX_BIN, "-t", "-c", conf_path],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, (
            f"nginx -t failed: {result.stderr}"
        )

    def test_crl_loaded_in_logs(self, crl_file):
        """Postconfiguration should log that the CRL was loaded."""
        conf_path = os.path.join(CRL_DIR, "conf", "nginx.conf")
        if not os.path.exists(conf_path):
            pytest.skip("CRL config not written")

        # ngx_conf_log_error() during postconfiguration writes to stderr,
        # not to the error_log file.  Use `nginx -t` to capture it.
        result = subprocess.run(
            [NGINX_BIN, "-t", "-c", conf_path],
            capture_output=True,
            text=True,
        )
        combined = result.stdout + result.stderr
        assert "loaded" in combined and "CRL" in combined, (
            f"expected CRL loaded message in nginx -t output:\n{combined}"
        )


class TestCRLDirectoryMode:
    """Verify xrootd_crl with a directory of CRL files."""

    def test_revoked_cert_rejected_stream(self, crl_dir_nginx):
        """Stream: revoked cert should fail via directory-loaded CRL."""
        env = os.environ.copy()
        env["X509_CERT_DIR"]     = os.path.join(PKI_DIR, "ca")
        env["X509_USER_PROXY"]   = PROXY_PEM
        env["XrdSecPROTOCOL"]    = "gsi"
        env["XrdSecGSISRVNAMES"] = "*"

        result = subprocess.run(
            ["xrdfs", f"root://localhost:{CRL_DIR_PORT}", "stat", "/test.txt"],
            capture_output=True, text=True, timeout=10, env=env,
        )
        assert result.returncode != 0, (
            "revoked cert should be rejected via directory CRL"
        )

    def test_revoked_cert_rejected_webdav(self, crl_dir_nginx):
        """WebDAV: revoked cert should fail via directory-loaded CRL."""
        resp = requests.get(
            f"https://localhost:{WEBDAV_DIR_PORT}/test.txt",
            cert=PROXY_PEM,
            verify=False,
        )
        assert resp.status_code == 403, (
            f"expected 403, got {resp.status_code}: {resp.text}"
        )

    def test_directory_crl_config_test(self, crl_file):
        """nginx -t should accept a directory path for xrootd_crl."""
        conf_path = os.path.join(CRL_DIR_TEST, "conf", "nginx.conf")
        if not os.path.exists(conf_path):
            pytest.skip("dir-mode config not written")

        result = subprocess.run(
            [NGINX_BIN, "-t", "-c", conf_path],
            capture_output=True, text=True,
        )
        assert result.returncode == 0, (
            f"nginx -t failed for directory CRL: {result.stderr}"
        )

    def test_directory_crl_loaded_in_logs(self, crl_file):
        """Postconfiguration should log CRL count for directory mode."""
        conf_path = os.path.join(CRL_DIR_TEST, "conf", "nginx.conf")
        if not os.path.exists(conf_path):
            pytest.skip("dir-mode config not written")

        result = subprocess.run(
            [NGINX_BIN, "-t", "-c", conf_path],
            capture_output=True, text=True,
        )
        combined = result.stdout + result.stderr
        assert "CRL" in combined and "loaded" in combined, (
            f"expected CRL loaded message in nginx -t output:\n{combined}"
        )


class TestCRLReload:
    """Verify xrootd_crl_reload picks up new CRLs without restart."""

    def test_initially_accepts_revoked_cert(self, crl_reload_nginx):
        """Before CRL is placed, revoked cert should be accepted."""
        env = os.environ.copy()
        env["X509_CERT_DIR"]     = os.path.join(PKI_DIR, "ca")
        env["X509_USER_PROXY"]   = PROXY_PEM
        env["XrdSecPROTOCOL"]    = "gsi"
        env["XrdSecGSISRVNAMES"] = "*"

        result = subprocess.run(
            ["xrdfs", f"root://localhost:{CRL_RELOAD_PORT}", "stat",
             "/test.txt"],
            capture_output=True, text=True, timeout=10, env=env,
        )
        assert result.returncode == 0, (
            f"should accept before CRL is loaded: {result.stderr}"
        )

    def test_rejects_after_crl_reload(self, crl_reload_nginx):
        """After CRL is copied into directory and timer fires, cert rejected."""
        import shutil

        info = crl_reload_nginx
        # Copy CRL into the reload directory
        shutil.copy2(info["crl_src"],
                     os.path.join(CRL_RELOAD_CRLS, "ca.r0"))

        # Wait for the reload interval + margin
        time.sleep(RELOAD_INTERVAL + 2)

        env = os.environ.copy()
        env["X509_CERT_DIR"]     = os.path.join(PKI_DIR, "ca")
        env["X509_USER_PROXY"]   = PROXY_PEM
        env["XrdSecPROTOCOL"]    = "gsi"
        env["XrdSecGSISRVNAMES"] = "*"

        result = subprocess.run(
            ["xrdfs", f"root://localhost:{CRL_RELOAD_PORT}", "stat",
             "/test.txt"],
            capture_output=True, text=True, timeout=10, env=env,
        )
        assert result.returncode != 0, (
            "revoked cert should be rejected after CRL reload"
        )

    def test_reload_timer_log_message(self, crl_reload_nginx):
        """The error log should contain the CRL reload timer message."""
        info = crl_reload_nginx
        log_path = os.path.join(info["log_dir"], "error.log")

        if not os.path.exists(log_path):
            pytest.skip("error.log not found")

        with open(log_path) as f:
            log_content = f.read()

        assert "CRL reload timer fired" in log_content, (
            "expected 'CRL reload timer fired' in error.log"
        )
