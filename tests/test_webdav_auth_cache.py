"""
WebDAV x509 authentication cache tests.

These tests use a dedicated nginx instance so they can exercise two TLS
configurations without disturbing the main test server:

  - optional_no_ca: forces the module's cached CA/CRL store/manual verifier
  - optional + ssl_client_certificate: allows the nginx-verified fast path
"""

import os
import shutil
import socket
import subprocess
import time

import pytest
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

NGINX_BIN = "/tmp/nginx-1.28.3/objs/nginx"
WORKDIR = "/tmp/xrd-webdav-auth-cache-test"

PKI_DIR = "/tmp/xrd-test/pki"
CA_CERT = os.path.join(PKI_DIR, "ca", "ca.pem")
PROXY_PEM = os.path.join(PKI_DIR, "user", "proxy_std.pem")
SERVER_CERT = os.path.join(PKI_DIR, "server", "hostcert.pem")
SERVER_KEY = os.path.join(PKI_DIR, "server", "hostkey.pem")
DATA_ROOT = "/tmp/xrd-test/data"
TEST_FILE = "auth_cache_probe.txt"


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
def webdav_auth_cache_nginx():
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")

    for path in (CA_CERT, PROXY_PEM, SERVER_CERT, SERVER_KEY):
        if not os.path.exists(path):
            pytest.skip(f"required PKI file not found: {path}")

    manual_port = _free_port()
    nginx_port = _free_port()

    shutil.rmtree(WORKDIR, ignore_errors=True)
    conf_dir = os.path.join(WORKDIR, "conf")
    log_dir = os.path.join(WORKDIR, "logs")
    tmp_dir = os.path.join(WORKDIR, "tmp")
    os.makedirs(conf_dir, exist_ok=True)
    os.makedirs(log_dir, exist_ok=True)
    os.makedirs(tmp_dir, exist_ok=True)
    os.makedirs(DATA_ROOT, exist_ok=True)

    with open(os.path.join(DATA_ROOT, TEST_FILE), "wb") as fh:
        fh.write(b"webdav auth cache probe\n")

    conf_path = os.path.join(conf_dir, "nginx.conf")
    with open(conf_path, "w") as fh:
        fh.write(f"""\
daemon off;
worker_processes 1;
error_log {log_dir}/error.log info;
pid       {log_dir}/nginx.pid;

events {{ worker_connections 128; }}

http {{
    access_log off;
    keepalive_timeout 30;
    client_body_temp_path {tmp_dir};
    proxy_temp_path       {tmp_dir};
    fastcgi_temp_path     {tmp_dir};
    uwsgi_temp_path       {tmp_dir};
    scgi_temp_path        {tmp_dir};

    server {{
        listen 127.0.0.1:{manual_port} ssl;
        server_name localhost;

        ssl_certificate     {SERVER_CERT};
        ssl_certificate_key {SERVER_KEY};
        ssl_verify_client   optional_no_ca;
        ssl_verify_depth    10;

        xrootd_webdav_proxy_certs on;

        location / {{
            xrootd_webdav         on;
            xrootd_webdav_root    {DATA_ROOT};
            xrootd_webdav_cafile  {CA_CERT};
            xrootd_webdav_auth    required;
        }}
    }}

    server {{
        listen 127.0.0.1:{nginx_port} ssl;
        server_name localhost;

        ssl_certificate        {SERVER_CERT};
        ssl_certificate_key    {SERVER_KEY};
        ssl_client_certificate {CA_CERT};
        ssl_verify_client      optional;
        ssl_verify_depth       10;

        xrootd_webdav_proxy_certs on;

        location / {{
            xrootd_webdav         on;
            xrootd_webdav_root    {DATA_ROOT};
            xrootd_webdav_cafile  {CA_CERT};
            xrootd_webdav_auth    required;
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

    ok_manual = _wait_for_port("127.0.0.1", manual_port, proc)
    ok_nginx = _wait_for_port("127.0.0.1", nginx_port, proc)
    if not ok_manual or not ok_nginx:
        proc.terminate()
        proc.wait(timeout=5)
        with open(stderr_path) as fh:
            stderr = fh.read()
        pytest.fail(
            "WebDAV auth-cache nginx did not start\n"
            f"manual={ok_manual} nginx={ok_nginx}\nstderr:\n{stderr}"
        )

    yield {
        "proc": proc,
        "manual_url": f"https://127.0.0.1:{manual_port}/{TEST_FILE}",
        "nginx_url": f"https://127.0.0.1:{nginx_port}/{TEST_FILE}",
        "log": os.path.join(log_dir, "error.log"),
        "startup_log": stderr_path,
    }

    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def _read_log(path):
    if not os.path.exists(path):
        return ""
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def test_cached_ca_store_built_once_and_reused(webdav_auth_cache_nginx):
    info = webdav_auth_cache_nginx
    log_before = _read_log(info["startup_log"])
    built_before = log_before.count("xrootd_webdav: cached CA store built")
    assert built_before == 2, log_before

    for _ in range(3):
        resp = requests.get(info["manual_url"], cert=PROXY_PEM, verify=False)
        assert resp.status_code == 200

    startup_after = _read_log(info["startup_log"])
    runtime_after = _read_log(info["log"])
    assert startup_after.count("xrootd_webdav: cached CA store built") == built_before
    assert "GSI auth OK source=manual" in runtime_after


def test_keepalive_reuses_tls_connection_auth_cache(webdav_auth_cache_nginx):
    info = webdav_auth_cache_nginx

    with requests.Session() as session:
        session.cert = PROXY_PEM
        session.verify = False
        first = session.get(info["manual_url"])
        second = session.get(info["manual_url"])

    assert first.status_code == 200
    assert second.status_code == 200

    log = _read_log(info["log"])
    assert (
        "GSI auth reused from TLS connection cache" in log
        or "GSI auth reused from TLS session cache" in log
    ), log


def test_nginx_verified_client_cert_fast_path(webdav_auth_cache_nginx):
    info = webdav_auth_cache_nginx

    resp = requests.get(info["nginx_url"], cert=PROXY_PEM, verify=False)
    assert resp.status_code == 200

    log = _read_log(info["log"])
    assert "GSI auth OK source=nginx" in log, log
