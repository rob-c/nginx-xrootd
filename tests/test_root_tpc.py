"""
tests/test_root_tpc.py

Native root:// third-party-copy coverage for the nginx stream plugin.

The current nginx stream module supports normal root:// reads and writes, but
does not implement native XRootD TPC rendezvous/delegation.  These tests pin
that behavior so xrdcp --tpc only fails instead of silently falling back, while
xrdcp --tpc first still falls back to a normal root:// copy.

Run:
    pytest tests/test_root_tpc.py -v
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
XRDFS_BIN = "xrdfs"
XRDCP_BIN = "xrdcp"


@dataclass(frozen=True)
class NginxRoot:
    workdir: Path
    data_root: Path
    url: str


@dataclass(frozen=True)
class ReferenceRootTPC:
    workdir: Path
    data_root: Path
    url: str


def _anon_env() -> dict:
    env = os.environ.copy()
    for key in (
        "X509_CERT_DIR",
        "X509_USER_PROXY",
        "X509_USER_CERT",
        "X509_USER_KEY",
        "XrdSecPROTOCOL",
        "XRD_SECPROTOCOL",
    ):
        env.pop(key, None)
    return env


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _run(cmd, *, timeout=30):
    return subprocess.run(
        cmd,
        env=_anon_env(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )


def _logical_name(prefix: str) -> str:
    return f"{prefix}_{os.getpid()}_{time.monotonic_ns()}.dat"


def _write(path: Path, content: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


def _unlink(path: Path):
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def _has_complete_content(path: Path, content: bytes) -> bool:
    try:
        return path.read_bytes() == content
    except FileNotFoundError:
        return False


def _xrdcp_tpc(mode: str, src: str, dst: str):
    return _run(
        [XRDCP_BIN, "-f", "-s", "--tpc", mode, src, dst],
        timeout=40,
    )


def _query_tpc(url: str):
    return _run([XRDFS_BIN, url, "query", "config", "tpc"], timeout=10)


def _query_output(result) -> str:
    return result.stdout.decode(errors="replace").strip()


def _reports_tpc_enabled(result) -> bool:
    out = _query_output(result)
    if out == "1":
        return True
    for line in out.splitlines():
        if line.strip() in ("tpc=1", "tpc 1"):
            return True
    return False


def _reports_tpc_disabled(result) -> bool:
    out = _query_output(result)
    if out == "0":
        return True
    for line in out.splitlines():
        if line.strip() in ("tpc=0", "tpc 0"):
            return True
    return False


@pytest.fixture(scope="module")
def nginx_root(tmp_path_factory):
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")
    if shutil.which(XRDFS_BIN) is None:
        pytest.skip("xrdfs not found")
    if shutil.which(XRDCP_BIN) is None:
        pytest.skip("xrdcp not found")

    workdir = tmp_path_factory.mktemp("root-tpc-nginx")
    conf_dir = workdir / "conf"
    log_dir = workdir / "logs"
    data_root = workdir / "data"
    for directory in (conf_dir, log_dir, data_root):
        directory.mkdir(parents=True, exist_ok=True)

    port = _free_port()
    url = f"root://localhost:{port}"
    conf_path = conf_dir / "nginx.conf"
    conf_path.write_text(
        f"""\
daemon off;
worker_processes 1;
error_log {log_dir}/error.log debug;
pid       {log_dir}/nginx.pid;

thread_pool default threads=4 max_queue=65536;
events {{ worker_connections 64; }}

stream {{
    server {{
        listen {port};
        xrootd on;
        xrootd_root {data_root};
        xrootd_auth none;
        xrootd_allow_write on;
        xrootd_access_log {log_dir}/xrootd_access.log;
    }}
}}
"""
    )

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
        ready = False
        last_result = None
        for _ in range(30):
            if proc.poll() is not None:
                break
            try:
                result = _query_tpc(url)
            except subprocess.TimeoutExpired:
                time.sleep(0.5)
                continue
            last_result = result
            if result.returncode == 0:
                ready = True
                break
            time.sleep(0.5)

        if not ready:
            proc.terminate()
            proc.wait(timeout=5)
            stdout = ""
            stderr = ""
            if last_result is not None:
                stdout = last_result.stdout.decode(errors="replace")
                stderr = last_result.stderr.decode(errors="replace")
            pytest.fail(
                f"nginx root:// fixture did not start on port {port}.\n"
                f"xrdfs stdout: {stdout}\n"
                f"xrdfs stderr: {stderr}\n"
                f"nginx stderr: {stderr_path.read_text(errors='replace')}"
            )

        yield NginxRoot(workdir=workdir, data_root=data_root, url=url)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


@pytest.fixture(scope="module")
def reference_root_tpc(tmp_path_factory):
    if shutil.which(XROOTD_BIN) is None:
        pytest.skip("xrootd binary not found")
    xrdcp = shutil.which(XRDCP_BIN)
    if xrdcp is None:
        pytest.skip("xrdcp not found")

    workdir = tmp_path_factory.mktemp("root-tpc-xrootd")
    data_root = workdir / "data"
    admin_dir = workdir / "admin"
    run_dir = workdir / "run"
    for directory in (data_root, admin_dir, run_dir):
        directory.mkdir(parents=True, exist_ok=True)

    port = _free_port()
    url = f"root://localhost:{port}"
    cfg_path = workdir / "xrootd-tpc.cfg"
    log_path = workdir / "xrootd-tpc.log"
    cfg_path.write_text(
        f"""\
all.role server
all.export /
oss.localroot {data_root}
all.adminpath {admin_dir}
all.pidpath {run_dir}

xrd.port {port}
xrd.trace off
ofs.tpc streams 4 pgm {xrdcp} --server
"""
    )

    proc = subprocess.Popen(
        [XROOTD_BIN, "-c", str(cfg_path), "-l", str(log_path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        ready = False
        for _ in range(30):
            if proc.poll() is not None:
                break
            try:
                result = _query_tpc(url)
            except subprocess.TimeoutExpired:
                time.sleep(0.5)
                continue
            if result.returncode == 0:
                ready = True
                break
            time.sleep(0.5)
        if not ready:
            proc.terminate()
            proc.wait(timeout=5)
            log = log_path.read_text(errors="replace") if log_path.exists() else ""
            pytest.skip(
                "reference root:// xrootd endpoint did not start; "
                f"log tail:\n{log[-3000:]}"
            )

        query = _query_tpc(url)
        if query.returncode != 0 or not _reports_tpc_enabled(query):
            proc.terminate()
            proc.wait(timeout=5)
            pytest.skip(
                "reference xrootd did not advertise native TPC support; "
                f"stdout={query.stdout.decode(errors='replace')!r} "
                f"stderr={query.stderr.decode(errors='replace')!r}"
            )

        yield ReferenceRootTPC(workdir=workdir, data_root=data_root, url=url)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


class TestNginxRootTPCUnsupported:
    def test_query_config_tpc_reports_unsupported(self, nginx_root):
        result = _query_tpc(nginx_root.url)

        assert result.returncode == 0, result.stderr.decode(errors="replace")
        assert _reports_tpc_disabled(result), _query_output(result)

    def test_tpc_only_between_nginx_root_endpoints_fails(self, nginx_root):
        content = b"native root tpc should not be accepted by nginx yet\n"
        src_name = _logical_name("root_tpc_nginx_src")
        dst_name = _logical_name("root_tpc_nginx_dst")
        src_path = nginx_root.data_root / src_name
        dst_path = nginx_root.data_root / dst_name
        _write(src_path, content)
        _unlink(dst_path)

        try:
            result = _xrdcp_tpc(
                "only",
                f"{nginx_root.url}//{src_name}",
                f"{nginx_root.url}//{dst_name}",
            )

            assert result.returncode != 0
            assert not _has_complete_content(dst_path, content)
        finally:
            _unlink(src_path)
            _unlink(dst_path)

    def test_tpc_first_between_nginx_root_endpoints_falls_back(self, nginx_root):
        content = b"native root tpc first falls back to classic copy\n"
        src_name = _logical_name("root_tpc_first_src")
        dst_name = _logical_name("root_tpc_first_dst")
        src_path = nginx_root.data_root / src_name
        dst_path = nginx_root.data_root / dst_name
        _write(src_path, content)
        _unlink(dst_path)

        try:
            result = _xrdcp_tpc(
                "first",
                f"{nginx_root.url}//{src_name}",
                f"{nginx_root.url}//{dst_name}",
            )

            assert result.returncode == 0, result.stderr.decode(errors="replace")
            assert dst_path.read_bytes() == content
        finally:
            _unlink(src_path)
            _unlink(dst_path)


class TestReferenceXrootdToNginxRootTPCUnsupported:
    def test_tpc_only_xrootd_source_to_nginx_destination_fails(
        self, nginx_root, reference_root_tpc
    ):
        content = b"reference xrootd source to nginx root tpc dest\n"
        src_name = _logical_name("root_tpc_ref_src")
        dst_name = _logical_name("root_tpc_nginx_dest")
        src_path = reference_root_tpc.data_root / src_name
        dst_path = nginx_root.data_root / dst_name
        _write(src_path, content)
        _unlink(dst_path)

        try:
            result = _xrdcp_tpc(
                "only",
                f"{reference_root_tpc.url}//{src_name}",
                f"{nginx_root.url}//{dst_name}",
            )

            assert result.returncode != 0
            assert not _has_complete_content(dst_path, content)
        finally:
            _unlink(src_path)
            _unlink(dst_path)

    def test_tpc_only_nginx_source_to_xrootd_destination_fails(
        self, nginx_root, reference_root_tpc
    ):
        content = b"nginx root source to reference xrootd tpc dest\n"
        src_name = _logical_name("root_tpc_nginx_src")
        dst_name = _logical_name("root_tpc_ref_dest")
        src_path = nginx_root.data_root / src_name
        dst_path = reference_root_tpc.data_root / dst_name
        _write(src_path, content)
        _unlink(dst_path)

        try:
            result = _xrdcp_tpc(
                "only",
                f"{nginx_root.url}//{src_name}",
                f"{reference_root_tpc.url}//{dst_name}",
            )

            assert result.returncode != 0
            assert not _has_complete_content(dst_path, content)
        finally:
            _unlink(src_path)
            _unlink(dst_path)

    def test_tpc_first_xrootd_to_nginx_falls_back(
        self, nginx_root, reference_root_tpc
    ):
        content = b"reference xrootd to nginx root tpc first fallback\n"
        src_name = _logical_name("root_tpc_first_ref_src")
        dst_name = _logical_name("root_tpc_first_nginx_dest")
        src_path = reference_root_tpc.data_root / src_name
        dst_path = nginx_root.data_root / dst_name
        _write(src_path, content)
        _unlink(dst_path)

        try:
            result = _xrdcp_tpc(
                "first",
                f"{reference_root_tpc.url}//{src_name}",
                f"{nginx_root.url}//{dst_name}",
            )

            assert result.returncode == 0, result.stderr.decode(errors="replace")
            assert dst_path.read_bytes() == content
        finally:
            _unlink(src_path)
            _unlink(dst_path)
