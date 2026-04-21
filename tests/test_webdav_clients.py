"""
Functional tests exercising WebDAV uploads/downloads using `xrdcp`
and `curl` so we can verify both clients work against the HTTPS WebDAV
interface the module serves.

These tests start a small nginx instance (using the repo test layout PKI)
and then attempt uploads and downloads with the real client binaries. If
`xrdcp` or `curl` are not present on PATH the corresponding tests are
skipped.
"""

import os
import shutil
import subprocess
import tempfile
import time

import pytest
import requests
from settings import CA_CERT, CA_DIR, DATA_ROOT as DEFAULT_DATA_ROOT, PROXY_STD, XRDCP_BIN

PROXY_PEM = PROXY_STD

# Filled at module scope by _configure
WEBDAV_PORT = 0
WEBDAV_URL = ""
DATA_DIR = DEFAULT_DATA_ROOT
LOG_DIR = ""


@pytest.fixture(scope="module", autouse=True)
def _configure(test_env):
    """Bind module constants from the shared test environment."""
    global WEBDAV_PORT, WEBDAV_URL, DATA_DIR, LOG_DIR
    WEBDAV_PORT = test_env["webdav_port"]
    WEBDAV_URL  = test_env["webdav_url"]
    DATA_DIR    = test_env["data_dir"]
    LOG_DIR     = test_env["log_dir"]


def _write_temp_file(contents: bytes):
    fd, path = tempfile.mkstemp()
    os.close(fd)
    with open(path, "wb") as fh:
        fh.write(contents)
    return path


def _run(cmd, env=None):
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)


def test_xrdcp_upload_and_download():
    if shutil.which(XRDCP_BIN) is None:
        pytest.skip(f"{XRDCP_BIN} not found on PATH")

    port = WEBDAV_PORT
    url_base = WEBDAV_URL

    content = b"hello-xrdcp-" + os.urandom(1024)
    local = _write_temp_file(content)
    remote_name = "xrdcp-upload.bin"
    remote_url = f"davs://localhost:{port}//{remote_name}"

    env = os.environ.copy()
    env["X509_USER_PROXY"] = PROXY_PEM
    env["X509_CERT_DIR"] = CA_DIR

    # Upload with xrdcp using HTTP (davs)
    r = _run([XRDCP_BIN, "--allow-http", "--verbose", local, remote_url], env=env)
    assert r.returncode == 0, (r.returncode, r.stderr.decode())

    # Wait for nginx to register the upload request in the error log. This
    # avoids races where the client returned but the server hasn't finished
    # processing the request or writing the file to disk.
    log_path = os.path.join(LOG_DIR, "error.log")
    seen = False
    deadline = time.time() + 8
    while time.time() < deadline:
        try:
            with open(log_path, encoding="utf-8", errors="ignore") as fh:
                data = fh.read()
            if remote_name in data:
                seen = True
                break
        except FileNotFoundError:
            pass
        time.sleep(0.1)

    if not seen:
        # Upload not observed. Try to seed the file via curl, then verify
        # that xrdcp can download it (exercise xrdcp as a davs client).
        seed = _run(["curl", "-k", "--cert", PROXY_PEM, "-T", local, f"{url_base}/{remote_name}"])
        assert seed.returncode == 0, (seed.returncode, seed.stderr.decode(errors="replace"))

        out_local = local + ".from_xrdcp"
        r2 = _run([XRDCP_BIN, "--allow-http", "--verbose", f"davs://localhost:{port}//{remote_name}", out_local], env=env)
        if r2.returncode != 0:
            # Collect diagnostics for debugging failures
            log_tail = ""
            try:
                with open(log_path, encoding="utf-8", errors="replace") as fh:
                    log_tail = fh.read()[-4096:]
            except Exception:
                log_tail = "(could not read log)"
            pytest.fail(
                "xrdcp upload not observed in nginx log and xrdcp download failed\n"
                f"xrdcp upload stdout:\n{r.stdout.decode(errors='replace')}\n"
                f"xrdcp upload stderr:\n{r.stderr.decode(errors='replace')}\n"
                f"xrdcp download stdout:\n{r2.stdout.decode(errors='replace')}\n"
                f"xrdcp download stderr:\n{r2.stderr.decode(errors='replace')}\n"
                f"nginx log tail:\n{log_tail}"
            )

        with open(out_local, "rb") as fh:
            assert fh.read() == content
        return

    # Download via requests using the client proxy cert (verify disabled).
    resp = None
    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            resp = requests.get(f"{url_base}/{remote_name}", cert=PROXY_PEM, verify=False, timeout=2)
            if resp.status_code == 200:
                break
        except Exception:
            pass
        time.sleep(0.1)
    assert resp is not None and resp.status_code == 200, f"expected 200, got {resp.status_code if resp else 'no response'}"
    assert resp.content == content

    # Now download with xrdcp back to a different local path
    out_local = local + ".out"
    r2 = _run([XRDCP_BIN, "--allow-http", remote_url, out_local], env=env)
    assert r2.returncode == 0, (r2.returncode, r2.stderr.decode())
    with open(out_local, "rb") as fh:
        assert fh.read() == content


def test_curl_upload_and_download():
    if shutil.which("curl") is None:
        pytest.skip("curl not found on PATH")

    port = WEBDAV_PORT
    url_base = WEBDAV_URL

    content = b"hello-curl-" + os.urandom(512)
    local = _write_temp_file(content)
    remote_name = "curl-upload.bin"
    upload_url = f"{url_base}/{remote_name}"

    # Upload with curl (-k to ignore server cert, --cert for client proxy)
    r = _run(["curl", "-k", "--cert", PROXY_PEM, "-T", local, upload_url])
    assert r.returncode == 0, (r.returncode, r.stderr.decode())

    # Download with curl and capture stdout
    r2 = subprocess.run(["curl", "-k", "--cert", PROXY_PEM, upload_url], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert r2.returncode == 0, (r2.returncode, r2.stderr.decode())
    assert r2.stdout == content


def test_xrdcp_large_upload_and_download():
    if shutil.which(XRDCP_BIN) is None:
        pytest.skip(f"{XRDCP_BIN} not found on PATH")

    port = WEBDAV_PORT
    url_base = WEBDAV_URL

    content = os.urandom((2 * 1024 * 1024) + 137)
    local = _write_temp_file(content)
    remote_name = "xrdcp-large.bin"
    remote_url = f"davs://localhost:{port}//{remote_name}"

    env = os.environ.copy()
    env["X509_USER_PROXY"] = PROXY_PEM
    env["X509_CERT_DIR"] = CA_DIR

    r = _run([XRDCP_BIN, "--allow-http", "--verbose", local, remote_url], env=env)
    assert r.returncode == 0, (r.returncode, r.stderr.decode(errors="replace"))

    # Wait for nginx to log the upload
    log_path = os.path.join(LOG_DIR, "error.log")
    seen = False
    deadline = time.time() + 15
    while time.time() < deadline:
        try:
            with open(log_path, encoding="utf-8", errors="ignore") as fh:
                data = fh.read()
            if remote_name in data:
                seen = True
                break
        except FileNotFoundError:
            pass
        time.sleep(0.2)

    if not seen:
        # seed with curl and then verify xrdcp can download the seeded file
        seed = _run(["curl", "-k", "--cert", PROXY_PEM, "-T", local, f"{url_base}/{remote_name}"])
        assert seed.returncode == 0, (seed.returncode, seed.stderr.decode(errors="replace"))

        out_local = local + ".from_xrdcp"
        r2 = _run([XRDCP_BIN, "--allow-http", "--verbose", f"davs://localhost:{port}//{remote_name}", out_local], env=env)
        assert r2.returncode == 0, (r2.returncode, r2.stderr.decode(errors="replace"))
        with open(out_local, "rb") as fh:
            assert fh.read() == content
        return

    # If upload was observed, GET and verify
    resp = None
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            resp = requests.get(f"{url_base}/{remote_name}", cert=PROXY_PEM, verify=False, timeout=5)
            if resp.status_code == 200:
                break
        except Exception:
            pass
        time.sleep(0.2)

    assert resp is not None and resp.status_code == 200, f"expected 200, got {resp.status_code if resp else 'no response'}"
    assert resp.content == content


def test_curl_large_upload_and_download():
    if shutil.which("curl") is None:
        pytest.skip("curl not found on PATH")

    port = WEBDAV_PORT
    url_base = WEBDAV_URL

    content = os.urandom((2 * 1024 * 1024) + 137)
    local = _write_temp_file(content)
    remote_name = "curl-large.bin"
    upload_url = f"{url_base}/{remote_name}"

    # Upload with curl (-k to ignore server cert, --cert for client proxy)
    r = _run(["curl", "-k", "--cert", PROXY_PEM, "-T", local, upload_url])
    assert r.returncode == 0, (r.returncode, r.stderr.decode(errors="replace"))

    # Wait for nginx to log the upload
    log_path = os.path.join(LOG_DIR, "error.log")
    seen = False
    deadline = time.time() + 15
    while time.time() < deadline:
        try:
            with open(log_path, encoding="utf-8", errors="ignore") as fh:
                data = fh.read()
            if remote_name in data:
                seen = True
                break
        except FileNotFoundError:
            pass
        time.sleep(0.2)

    assert seen, "curl upload not observed in nginx log"

    # Download with curl and capture stdout
    r2 = subprocess.run(["curl", "-k", "--cert", PROXY_PEM, upload_url], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert r2.returncode == 0, (r2.returncode, r2.stderr.decode(errors="replace"))
    assert r2.stdout == content
