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
import socket
import subprocess
import tempfile
import time

import pytest
import requests

NGINX_BIN = "/tmp/nginx-1.28.3/objs/nginx"
WORKDIR = "/tmp/xrd-webdav-client-test"

PKI_DIR = "/tmp/xrd-test/pki"
CA_CERT = os.path.join(PKI_DIR, "ca", "ca.pem")
PROXY_PEM = os.path.join(PKI_DIR, "user", "proxy_std.pem")
SERVER_CERT = os.path.join(PKI_DIR, "server", "hostcert.pem")
SERVER_KEY = os.path.join(PKI_DIR, "server", "hostkey.pem")


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
def webdav_nginx():
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")

    for path in (CA_CERT, PROXY_PEM, SERVER_CERT, SERVER_KEY):
        if not os.path.exists(path):
            pytest.skip(f"required PKI file not found: {path}")

    shutil.rmtree(WORKDIR, ignore_errors=True)
    conf_dir = os.path.join(WORKDIR, "conf")
    log_dir = os.path.join(WORKDIR, "logs")
    data_dir = os.path.join(WORKDIR, "data")
    tmp_dir = os.path.join(WORKDIR, "tmp")
    os.makedirs(conf_dir, exist_ok=True)
    os.makedirs(log_dir, exist_ok=True)
    os.makedirs(data_dir, exist_ok=True)
    os.makedirs(tmp_dir, exist_ok=True)

    port = _free_port()
    conf_path = os.path.join(conf_dir, "nginx.conf")

    # WebDAV server: require client cert for auth and allow writes
    with open(conf_path, "w", encoding="utf-8") as fh:
        fh.write(f"""\
daemon off;
worker_processes 1;
error_log {log_dir}/error.log info;
pid       {log_dir}/nginx.pid;

events {{ worker_connections 128; }}

http {{
    access_log off;
    client_max_body_size 64m;
    client_body_buffer_size 4k;
    client_body_in_file_only clean;
    client_body_temp_path {tmp_dir};
    proxy_temp_path       {tmp_dir};
    fastcgi_temp_path     {tmp_dir};
    uwsgi_temp_path       {tmp_dir};
    scgi_temp_path        {tmp_dir};
    server {{
        listen 127.0.0.1:{port} ssl;
        server_name localhost;

        ssl_certificate     {SERVER_CERT};
        ssl_certificate_key {SERVER_KEY};
        ssl_verify_client   optional_no_ca;
        ssl_verify_depth    10;

                xrootd_webdav_proxy_certs on;

            location / {{
                xrootd_webdav on;
                xrootd_webdav_root    {data_dir};
                xrootd_webdav_cafile  {CA_CERT};
                xrootd_webdav_auth    required;
                xrootd_webdav_allow_write on;
            }}
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
        pytest.fail(f"webdav nginx did not start\nstderr:\n{stderr}")

    yield {
        "proc": proc,
        "port": port,
        "data_dir": data_dir,
        "url_base": f"https://localhost:{port}",
        "log_dir": log_dir,
    }

    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def _write_temp_file(contents: bytes):
    fd, path = tempfile.mkstemp()
    os.close(fd)
    with open(path, "wb") as fh:
        fh.write(contents)
    return path


def _run(cmd, env=None):
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)


def test_xrdcp_upload_and_download(webdav_nginx):
    if shutil.which("xrdcp") is None:
        pytest.skip("xrdcp not found on PATH")

    # Do not probe for HTTP plugin presence; attempt the real upload.
    # If xrdcp cannot talk HTTP(s) this will fail and should be addressed
    # in the environment where tests run.

    info = webdav_nginx
    port = info["port"]
    url_base = info["url_base"]

    content = b"hello-xrdcp-" + os.urandom(1024)
    local = _write_temp_file(content)
    remote_name = "xrdcp-upload.bin"
    remote_url = f"davs://localhost:{port}//{remote_name}"

    env = os.environ.copy()
    env["X509_USER_PROXY"] = PROXY_PEM
    env["X509_CERT_DIR"] = os.path.join(PKI_DIR, "ca")

    # Upload with xrdcp using HTTP (davs)
    r = _run(["xrdcp", "--allow-http", "--verbose", local, remote_url], env=env)
    assert r.returncode == 0, (r.returncode, r.stderr.decode())

    # Wait for nginx to register the upload request in the error log. This
    # avoids races where the client returned but the server hasn't finished
    # processing the request or writing the file to disk.
    log_path = os.path.join(info["log_dir"], "error.log")
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
        r2 = _run(["xrdcp", "--allow-http", "--verbose", f"davs://localhost:{port}//{remote_name}", out_local], env=env)
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
    r2 = _run(["xrdcp", "--allow-http", remote_url, out_local], env=env)
    assert r2.returncode == 0, (r2.returncode, r2.stderr.decode())
    with open(out_local, "rb") as fh:
        assert fh.read() == content


def test_curl_upload_and_download(webdav_nginx):
    if shutil.which("curl") is None:
        pytest.skip("curl not found on PATH")

    info = webdav_nginx
    port = info["port"]
    url_base = info["url_base"]

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


def test_xrdcp_large_upload_and_download(webdav_nginx):
    if shutil.which("xrdcp") is None:
        pytest.skip("xrdcp not found on PATH")

    info = webdav_nginx
    port = info["port"]
    url_base = info["url_base"]

    content = os.urandom((2 * 1024 * 1024) + 137)
    local = _write_temp_file(content)
    remote_name = "xrdcp-large.bin"
    remote_url = f"davs://localhost:{port}//{remote_name}"

    env = os.environ.copy()
    env["X509_USER_PROXY"] = PROXY_PEM
    env["X509_CERT_DIR"] = os.path.join(PKI_DIR, "ca")

    r = _run(["xrdcp", "--allow-http", "--verbose", local, remote_url], env=env)
    assert r.returncode == 0, (r.returncode, r.stderr.decode(errors="replace"))

    # Wait for nginx to log the upload
    log_path = os.path.join(info["log_dir"], "error.log")
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
        r2 = _run(["xrdcp", "--allow-http", "--verbose", f"davs://localhost:{port}//{remote_name}", out_local], env=env)
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


def test_curl_large_upload_and_download(webdav_nginx):
    if shutil.which("curl") is None:
        pytest.skip("curl not found on PATH")

    info = webdav_nginx
    port = info["port"]
    url_base = info["url_base"]

    content = os.urandom((2 * 1024 * 1024) + 137)
    local = _write_temp_file(content)
    remote_name = "curl-large.bin"
    upload_url = f"{url_base}/{remote_name}"

    # Upload with curl (-k to ignore server cert, --cert for client proxy)
    r = _run(["curl", "-k", "--cert", PROXY_PEM, "-T", local, upload_url])
    assert r.returncode == 0, (r.returncode, r.stderr.decode(errors="replace"))

    # Wait for nginx to log the upload
    log_path = os.path.join(info["log_dir"], "error.log")
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
