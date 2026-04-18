"""
tests/test_webdav_tpc.py

HTTP third-party-copy integration tests for the nginx WebDAV plugin.

The nginx fixture starts several HTTPS WebDAV endpoints so COPY can be tested
against different source and destination policies:

  - nginx+plugin source with required x509 auth
  - nginx+plugin source with no auth
  - nginx+plugin destination with TPC enabled via CA file
  - nginx+plugin destination with TPC enabled via CA directory
  - nginx+plugin destinations that are read-only, TPC-disabled, or missing
    outbound service credentials

Optional xrootd interop tests start an official XrdHttp/XrdHttpTPC endpoint
when the local xrootd binary and HTTP plugins are installed.

Run:
    pytest tests/test_webdav_tpc.py -v
"""

import os
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

import pytest


NGINX_BIN = "/tmp/nginx-1.28.3/objs/nginx"
XROOTD_BIN = "xrootd"

PKI_DIR = Path("/tmp/xrd-test/pki")
CA_DIR = PKI_DIR / "ca"
CA_PEM = CA_DIR / "ca.pem"
CLIENT_CERT = PKI_DIR / "user" / "usercert.pem"
CLIENT_KEY = PKI_DIR / "user" / "userkey.pem"
SERVER_CERT = PKI_DIR / "server" / "hostcert.pem"
SERVER_KEY = PKI_DIR / "server" / "hostkey.pem"


@dataclass(frozen=True)
class TpcNginx:
    workdir: Path
    source_required_port: int
    source_open_port: int
    dest_cafile_port: int
    dest_cadir_port: int
    dest_no_service_cert_port: int
    dest_disabled_port: int
    dest_readonly_port: int
    source_required_root: Path
    source_open_root: Path
    dest_cafile_root: Path
    dest_cadir_root: Path
    dest_no_service_cert_root: Path
    dest_disabled_root: Path
    dest_readonly_root: Path


@dataclass(frozen=True)
class ReferenceXrdHttp:
    workdir: Path
    data_root: Path
    http_port: int


def _require_common_tools():
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")
    if shutil.which("curl") is None:
        pytest.skip("curl not found")
    for path in (CA_PEM, CLIENT_CERT, CLIENT_KEY, SERVER_CERT, SERVER_KEY):
        if not path.exists():
            pytest.skip(f"test PKI file not found: {path}")


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _curl(*args, timeout=30):
    cmd = [
        "curl",
        "-sk",
        "--cert",
        str(CLIENT_CERT),
        "--key",
        str(CLIENT_KEY),
        "--cacert",
        str(CA_PEM),
        *args,
    ]
    return subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )


def _copy_pull(dest_port: int, dest_path: str, source_url: str, *headers, timeout=30):
    args = [
        "-X",
        "COPY",
        f"https://localhost:{dest_port}{dest_path}",
        "-H",
        "Credential: none",
        "-H",
        f"Source: {source_url}",
    ]
    for header in headers:
        args.extend(["-H", header])
    return _curl(*args, "-w", "%{http_code}", "-o", "/dev/null", timeout=timeout)


def _copy_code(dest_port: int, dest_path: str, source_url: str, *headers, timeout=30) -> int:
    result = _copy_pull(dest_port, dest_path, source_url, *headers, timeout=timeout)
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    return int(result.stdout.strip())


def _wait_for_https(port: int, proc, timeout=10):
    deadline = time.monotonic() + timeout
    last_stderr = b""
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return False, last_stderr
        try:
            result = _curl(
                "-X",
                "OPTIONS",
                f"https://localhost:{port}/",
                "-o",
                "/dev/null",
                timeout=3,
            )
        except subprocess.TimeoutExpired:
            time.sleep(0.2)
            continue
        last_stderr = result.stderr
        if result.returncode == 0:
            return True, last_stderr
        time.sleep(0.2)
    return False, last_stderr


def _write(path: Path, content: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


def _wait_for_file(path: Path, content: bytes, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists() and path.read_bytes() == content:
            return True
        time.sleep(0.2)
    return False


def _xrd_library(*names):
    for dirname in (Path("/usr/lib64"), Path("/usr/lib")):
        for name in names:
            candidate = dirname / name
            if candidate.exists():
                return candidate
    return None


@pytest.fixture(scope="module")
def tpc_nginx(tmp_path_factory):
    _require_common_tools()

    workdir = tmp_path_factory.mktemp("webdav-tpc-nginx")
    conf_dir = workdir / "conf"
    log_dir = workdir / "logs"
    temp_dir = workdir / "tmp"
    for directory in (conf_dir, log_dir, temp_dir):
        directory.mkdir(parents=True, exist_ok=True)

    roots = {
        name: workdir / "data" / name
        for name in (
            "source_required",
            "source_open",
            "dest_cafile",
            "dest_cadir",
            "dest_no_service_cert",
            "dest_disabled",
            "dest_readonly",
        )
    }
    for root in roots.values():
        root.mkdir(parents=True, exist_ok=True)

    ports = {
        "source_required": _free_port(),
        "source_open": _free_port(),
        "dest_cafile": _free_port(),
        "dest_cadir": _free_port(),
        "dest_no_service_cert": _free_port(),
        "dest_disabled": _free_port(),
        "dest_readonly": _free_port(),
    }

    def server_block(port, root, auth, extra, allow_write="on"):
        return f"""
    server {{
        listen {port} ssl;
        server_name localhost;

        ssl_certificate     {SERVER_CERT};
        ssl_certificate_key {SERVER_KEY};
        ssl_verify_client   optional_no_ca;
        ssl_verify_depth    10;

        xrootd_webdav_proxy_certs on;
        client_max_body_size 1g;

        location / {{
            xrootd_webdav         on;
            xrootd_webdav_root    {root};
            xrootd_webdav_cafile  {CA_PEM};
            xrootd_webdav_auth    {auth};
            xrootd_webdav_allow_write {allow_write};
{extra}
        }}
    }}
"""

    tpc_cafile = f"""\
            xrootd_webdav_tpc on;
            xrootd_webdav_tpc_cert {CLIENT_CERT};
            xrootd_webdav_tpc_key {CLIENT_KEY};
            xrootd_webdav_tpc_cafile {CA_PEM};
            xrootd_webdav_tpc_timeout 10;
"""
    tpc_no_service_cert = f"""\
            xrootd_webdav_tpc on;
            xrootd_webdav_tpc_cafile {CA_PEM};
            xrootd_webdav_tpc_timeout 10;
"""
    tpc_disabled = "            xrootd_webdav_tpc off;\n"
    tpc_readonly = f"""\
            xrootd_webdav_tpc on;
            xrootd_webdav_tpc_cert {CLIENT_CERT};
            xrootd_webdav_tpc_key {CLIENT_KEY};
            xrootd_webdav_tpc_cafile {CA_PEM};
            xrootd_webdav_tpc_timeout 10;
"""

    cadir_dest = f"""
    server {{
        listen {ports["dest_cadir"]} ssl;
        server_name localhost;

        ssl_certificate     {SERVER_CERT};
        ssl_certificate_key {SERVER_KEY};
        ssl_verify_client   optional_no_ca;
        ssl_verify_depth    10;

        xrootd_webdav_proxy_certs on;
        client_max_body_size 1g;

        location / {{
            xrootd_webdav         on;
            xrootd_webdav_root    {roots["dest_cadir"]};
            xrootd_webdav_cadir   {CA_DIR};
            xrootd_webdav_auth    required;
            xrootd_webdav_allow_write on;
            xrootd_webdav_tpc on;
            xrootd_webdav_tpc_cert {CLIENT_CERT};
            xrootd_webdav_tpc_key {CLIENT_KEY};
            xrootd_webdav_tpc_cadir {CA_DIR};
            xrootd_webdav_tpc_timeout 10;
        }}
    }}
"""

    conf = f"""\
daemon off;
worker_processes 2;
error_log {log_dir}/error.log debug;
pid       {log_dir}/nginx.pid;

events {{ worker_connections 128; }}

http {{
    access_log            {log_dir}/access.log;
    client_body_temp_path {temp_dir}/client_body;
    proxy_temp_path       {temp_dir}/proxy;
    fastcgi_temp_path     {temp_dir}/fastcgi;
    uwsgi_temp_path       {temp_dir}/uwsgi;
    scgi_temp_path        {temp_dir}/scgi;

{server_block(ports["source_required"], roots["source_required"], "required", "")}
{server_block(ports["source_open"], roots["source_open"], "none", "")}
{server_block(ports["dest_cafile"], roots["dest_cafile"], "required", tpc_cafile)}
{cadir_dest}
{server_block(ports["dest_no_service_cert"], roots["dest_no_service_cert"], "required", tpc_no_service_cert)}
{server_block(ports["dest_disabled"], roots["dest_disabled"], "required", tpc_disabled)}
{server_block(ports["dest_readonly"], roots["dest_readonly"], "required", tpc_readonly, allow_write="off")}
}}
"""
    conf_path = conf_dir / "nginx.conf"
    conf_path.write_text(conf)

    test_result = subprocess.run(
        [NGINX_BIN, "-p", str(workdir), "-c", str(conf_path), "-t"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
    )
    assert test_result.returncode == 0, test_result.stderr.decode(errors="replace")

    stderr_path = log_dir / "stderr.log"
    stderr_fh = open(stderr_path, "wb")
    proc = subprocess.Popen(
        [NGINX_BIN, "-p", str(workdir), "-c", str(conf_path)],
        stdout=subprocess.DEVNULL,
        stderr=stderr_fh,
    )
    stderr_fh.close()

    try:
        for port in ports.values():
            ready, stderr = _wait_for_https(port, proc)
            if not ready:
                proc.terminate()
                proc.wait(timeout=5)
                pytest.fail(
                    f"nginx WebDAV TPC fixture did not start on port {port}.\n"
                    f"curl stderr: {stderr.decode(errors='replace')}\n"
                    f"nginx stderr: {stderr_path.read_text(errors='replace')}"
                )

        yield TpcNginx(
            workdir=workdir,
            source_required_port=ports["source_required"],
            source_open_port=ports["source_open"],
            dest_cafile_port=ports["dest_cafile"],
            dest_cadir_port=ports["dest_cadir"],
            dest_no_service_cert_port=ports["dest_no_service_cert"],
            dest_disabled_port=ports["dest_disabled"],
            dest_readonly_port=ports["dest_readonly"],
            source_required_root=roots["source_required"],
            source_open_root=roots["source_open"],
            dest_cafile_root=roots["dest_cafile"],
            dest_cadir_root=roots["dest_cadir"],
            dest_no_service_cert_root=roots["dest_no_service_cert"],
            dest_disabled_root=roots["dest_disabled"],
            dest_readonly_root=roots["dest_readonly"],
        )
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


@pytest.fixture(scope="module")
def reference_xrd_http(tmp_path_factory):
    if shutil.which(XROOTD_BIN) is None:
        pytest.skip("xrootd binary not found")

    http_lib = _xrd_library("libXrdHttp-5.so", "libXrdHttp.so")
    tpc_lib = _xrd_library("libXrdHttpTPC-5.so", "libXrdHttpTPC.so")
    sec_lib = _xrd_library("libXrdSec-5.so", "libXrdSec.so")
    if http_lib is None:
        pytest.skip("XrdHttp plugin not found")
    if tpc_lib is None:
        pytest.skip("XrdHttpTPC plugin not found")
    if sec_lib is None:
        pytest.skip("XrdSec plugin not found")
    for path in (CA_PEM, SERVER_CERT, SERVER_KEY):
        if not path.exists():
            pytest.skip(f"test PKI file not found: {path}")

    workdir = tmp_path_factory.mktemp("webdav-tpc-xrootd")
    data_root = workdir / "data"
    admin_dir = workdir / "admin"
    run_dir = workdir / "run"
    for directory in (data_root, admin_dir, run_dir):
        directory.mkdir(parents=True, exist_ok=True)

    root_port = _free_port()
    http_port = _free_port()
    cfg_path = workdir / "xrootd-http.cfg"
    log_path = workdir / "xrootd-http.log"
    cfg_path.write_text(
        f"""\
all.role server
all.export /
oss.localroot {data_root}
all.adminpath {admin_dir}
all.pidpath {run_dir}

xrd.port {root_port}
xrootd.seclib {sec_lib}
xrd.protocol XrdHttp:{http_port} {http_lib}

http.cert {SERVER_CERT}
http.key {SERVER_KEY}
http.cadir {CA_DIR}
http.desthttps yes
http.selfhttps2http no
http.exthandler xrdtpc {tpc_lib}
tpc.timeout 10
"""
    )

    proc = subprocess.Popen(
        [XROOTD_BIN, "-c", str(cfg_path), "-l", str(log_path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        ready = False
        probe_path = data_root / "probe.txt"
        probe_path.write_text("xrootd http probe\n")
        for _ in range(40):
            if proc.poll() is not None:
                break
            result = _curl(
                f"https://localhost:{http_port}/probe.txt",
                "-o",
                "/dev/null",
                timeout=3,
            )
            if result.returncode == 0:
                ready = True
                break
            time.sleep(0.25)
        if not ready:
            proc.terminate()
            proc.wait(timeout=5)
            log = log_path.read_text(errors="replace") if log_path.exists() else ""
            pytest.skip(
                "reference XrdHttp endpoint did not start; "
                f"log tail:\n{log[-3000:]}"
            )

        yield ReferenceXrdHttp(workdir=workdir, data_root=data_root, http_port=http_port)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


class TestNginxPluginToPluginTPC:
    def test_required_source_to_required_destination(self, tpc_nginx):
        content = b"nginx plugin source requiring x509 auth\n"
        _write(tpc_nginx.source_required_root / "required-source.txt", content)

        source = (
            f"https://localhost:{tpc_nginx.source_required_port}"
            "/required-source.txt"
        )
        code = _copy_code(
            tpc_nginx.dest_cafile_port,
            "/copied-from-required.txt",
            source,
            "TransferHeaderX-Test-Tpc: plugin-required",
        )

        assert code == 201
        assert (tpc_nginx.dest_cafile_root / "copied-from-required.txt").read_bytes() == content

    def test_open_source_to_cadir_destination(self, tpc_nginx):
        content = b"nginx plugin open source, destination trusts a CA directory\n"
        _write(tpc_nginx.source_open_root / "open-source.txt", content)

        source = f"https://localhost:{tpc_nginx.source_open_port}/open-source.txt"
        code = _copy_code(tpc_nginx.dest_cadir_port, "/copied-via-cadir.txt", source)

        assert code == 201
        assert (tpc_nginx.dest_cadir_root / "copied-via-cadir.txt").read_bytes() == content

    def test_overwrite_false_preserves_existing_destination(self, tpc_nginx):
        _write(tpc_nginx.source_open_root / "overwrite-source.txt", b"new content\n")
        existing = tpc_nginx.dest_cafile_root / "overwrite-target.txt"
        _write(existing, b"existing content\n")

        source = f"https://localhost:{tpc_nginx.source_open_port}/overwrite-source.txt"
        code = _copy_code(
            tpc_nginx.dest_cafile_port,
            "/overwrite-target.txt",
            source,
            "Overwrite: F",
        )

        assert code == 412
        assert existing.read_bytes() == b"existing content\n"

    def test_tpc_disabled_destination_rejects_copy(self, tpc_nginx):
        _write(tpc_nginx.source_open_root / "disabled-source.txt", b"disabled dest\n")

        source = f"https://localhost:{tpc_nginx.source_open_port}/disabled-source.txt"
        code = _copy_code(tpc_nginx.dest_disabled_port, "/should-not-copy.txt", source)

        assert code == 405
        assert not (tpc_nginx.dest_disabled_root / "should-not-copy.txt").exists()

    def test_readonly_destination_rejects_copy_before_pull(self, tpc_nginx):
        _write(tpc_nginx.source_open_root / "readonly-source.txt", b"readonly dest\n")

        source = f"https://localhost:{tpc_nginx.source_open_port}/readonly-source.txt"
        code = _copy_code(tpc_nginx.dest_readonly_port, "/should-not-copy.txt", source)

        assert code == 403
        assert not (tpc_nginx.dest_readonly_root / "should-not-copy.txt").exists()

    def test_missing_service_credential_cannot_pull_required_source(self, tpc_nginx):
        content = b"requires outbound client cert\n"
        _write(tpc_nginx.source_required_root / "needs-cert.txt", content)

        source = f"https://localhost:{tpc_nginx.source_required_port}/needs-cert.txt"
        code = _copy_code(
            tpc_nginx.dest_no_service_cert_port,
            "/missing-service-cert.txt",
            source,
        )

        assert code == 502
        assert not (tpc_nginx.dest_no_service_cert_root / "missing-service-cert.txt").exists()


class TestXrootdHttpInteropTPC:
    def test_xrootd_http_source_to_nginx_plugin_destination(self, tpc_nginx, reference_xrd_http):
        content = b"xrootd http source pulled into nginx plugin destination\n"
        _write(reference_xrd_http.data_root / "xrd-source.txt", content)

        source = f"https://localhost:{reference_xrd_http.http_port}/xrd-source.txt"
        code = _copy_code(tpc_nginx.dest_cafile_port, "/from-xrootd-http.txt", source)

        assert code == 201
        assert (tpc_nginx.dest_cafile_root / "from-xrootd-http.txt").read_bytes() == content

    def test_nginx_plugin_source_to_xrootd_http_destination(self, tpc_nginx, reference_xrd_http):
        content = b"nginx plugin source pulled into xrootd http destination\n"
        _write(tpc_nginx.source_open_root / "nginx-source-for-xrd.txt", content)

        source = f"https://localhost:{tpc_nginx.source_open_port}/nginx-source-for-xrd.txt"
        result = _curl(
            "-X",
            "COPY",
            f"https://localhost:{reference_xrd_http.http_port}/from-nginx-plugin.txt",
            "-H",
            "Credential: none",
            "-H",
            f"Source: {source}",
            "-w",
            "%{http_code}",
            "-o",
            "/dev/null",
            timeout=30,
        )

        assert result.returncode == 0, result.stderr.decode(errors="replace")
        assert int(result.stdout.strip()) in (200, 201, 202)
        assert _wait_for_file(
            reference_xrd_http.data_root / "from-nginx-plugin.txt",
            content,
        )
