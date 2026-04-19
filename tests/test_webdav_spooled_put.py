"""
Regression test for WebDAV PUT bodies that nginx spools to a temp file.

The WebDAV handler receives large HTTPS request bodies after nginx has already
written them to client_body_temp_path. This test forces that path with
client_body_in_file_only so uploads exercise the module's temp-file copy path
instead of the small in-memory buffer case.
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
WORKDIR = "/tmp/xrd-webdav-spooled-put-test"

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
def webdav_spooled_put_nginx():
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")

    for path in (CA_CERT, PROXY_PEM, SERVER_CERT, SERVER_KEY):
        if not os.path.exists(path):
            pytest.skip(f"required PKI file not found: {path}")

    port = _free_port()

    shutil.rmtree(WORKDIR, ignore_errors=True)
    conf_dir = os.path.join(WORKDIR, "conf")
    log_dir = os.path.join(WORKDIR, "logs")
    tmp_dir = os.path.join(WORKDIR, "tmp")
    data_dir = os.path.join(WORKDIR, "data")
    os.makedirs(conf_dir, exist_ok=True)
    os.makedirs(log_dir, exist_ok=True)
    os.makedirs(tmp_dir, exist_ok=True)
    os.makedirs(data_dir, exist_ok=True)

    conf_path = os.path.join(conf_dir, "nginx.conf")
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
            xrootd_webdav         on;
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
        pytest.fail(f"WebDAV spool-test nginx did not start\nstderr:\n{stderr}")

    yield {
        "proc": proc,
        "data_dir": data_dir,
        "url_base": f"https://127.0.0.1:{port}",
    }

    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def test_put_spooled_request_body_round_trips(webdav_spooled_put_nginx):
    info = webdav_spooled_put_nginx
    name = "spooled-upload.bin"
    payload = os.urandom((2 * 1024 * 1024) + 137)

    resp = requests.put(
        f"{info['url_base']}/{name}",
        data=payload,
        cert=PROXY_PEM,
        verify=False,
        timeout=30,
    )

    assert resp.status_code == 201, resp.text

    with open(os.path.join(info["data_dir"], name), "rb") as fh:
        assert fh.read() == payload
