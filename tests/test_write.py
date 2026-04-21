"""
Write / upload tests for nginx-xrootd anonymous mode.

Tests xrdcp uploads and the XRootD File API for:
  - small file upload (single pgwrite)
  - medium file upload (multiple pgwrite chunks)
  - overwrite of existing file
  - data integrity (md5 round-trip)
  - write-then-read via separate connection

Run:
    pytest tests/test_write.py -v -s
"""

import hashlib
import os
import tempfile

import pytest
from XRootD import client
from XRootD.client.flags import OpenFlags
from settings import CA_DIR as DEFAULT_CA_DIR, DATA_ROOT as DEFAULT_DATA_ROOT, PROXY_STD

ANON_URL = ""
GSI_URL  = ""
DATA_DIR = DEFAULT_DATA_ROOT
CA_DIR   = DEFAULT_CA_DIR
PROXY_PEM = PROXY_STD


@pytest.fixture(scope="module", autouse=True)
def _configure(test_env):
    """Bind module constants from the shared test environment."""
    global ANON_URL, GSI_URL, DATA_DIR, CA_DIR, PROXY_PEM
    ANON_URL  = test_env["anon_url"]
    GSI_URL   = test_env["gsi_url"]
    DATA_DIR  = test_env["data_dir"]
    CA_DIR    = test_env["ca_dir"]
    PROXY_PEM = test_env["proxy_pem"]


def _md5(path: str) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _xrdcp_put(local_path: str, remote_name: str, force: bool = False) -> int:
    """Upload local_path to the anonymous server, return exit code."""
    flag = "-f" if force else ""
    cmd = f"xrdcp {flag} {local_path} {ANON_URL}//{remote_name}"
    return os.system(cmd)


def _xrdcp_put_gsi(local_path: str, remote_name: str, force: bool = False) -> int:
    """Upload local_path to the GSI server using the test proxy cert."""
    flag = "-f" if force else ""
    env = f"X509_CERT_DIR={CA_DIR} X509_USER_PROXY={PROXY_PEM}"
    cmd = f"{env} xrdcp {flag} {local_path} {GSI_URL}//{remote_name}"
    return os.system(cmd)


@pytest.fixture(autouse=True)
def cleanup_uploads():
    """Remove uploaded files from the data dir after each test."""
    yield
    for f in os.listdir(DATA_DIR):
        if f.startswith("_test_write_") or f.startswith("_test_gsi_write_"):
            try:
                os.unlink(os.path.join(DATA_DIR, f))
            except OSError:
                pass


class TestWriteAnon:

    def test_upload_small_file(self):
        """Upload a tiny file and verify contents round-trip."""
        content = b"Hello from nginx-xrootd write test!\n"
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(content)
            local = tmp.name

        remote = "_test_write_small.txt"
        assert _xrdcp_put(local, remote) == 0, "xrdcp upload failed"

        dest = os.path.join(DATA_DIR, remote)
        assert os.path.exists(dest), "uploaded file not found on disk"
        assert open(dest, "rb").read() == content, "file content mismatch"
        os.unlink(local)

    def test_upload_medium_file(self):
        """Upload a 20 MiB file (multiple pgwrite chunks) and verify MD5."""
        size = 20 * 1024 * 1024
        data = os.urandom(size)
        expected_md5 = hashlib.md5(data).hexdigest()

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(data)
            local = tmp.name

        remote = "_test_write_medium.bin"
        assert _xrdcp_put(local, remote) == 0, "xrdcp upload failed"

        dest = os.path.join(DATA_DIR, remote)
        assert os.path.getsize(dest) == size, f"size mismatch: {os.path.getsize(dest)} != {size}"
        assert _md5(dest) == expected_md5, "MD5 mismatch after upload"
        os.unlink(local)

    def test_upload_overwrite(self):
        """Overwrite an existing file with xrdcp -f."""
        remote = "_test_write_overwrite.txt"
        dest = os.path.join(DATA_DIR, remote)

        # First upload
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as tmp:
            tmp.write(b"original content\n")
            local = tmp.name
        assert _xrdcp_put(local, remote) == 0
        os.unlink(local)

        # Overwrite
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as tmp:
            tmp.write(b"replaced content\n")
            local = tmp.name
        assert _xrdcp_put(local, remote, force=True) == 0, "xrdcp -f upload failed"

        assert open(dest, "rb").read() == b"replaced content\n", "overwrite failed"
        os.unlink(local)

    def test_write_then_read_via_api(self):
        """Write a file with xrdcp, then read it back with XRootD File API."""
        content = b"Round-trip test: " + os.urandom(128)
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(content)
            local = tmp.name

        remote = "_test_write_roundtrip.bin"
        assert _xrdcp_put(local, remote) == 0
        os.unlink(local)

        # Read back via XRootD client
        f = client.File()
        status, _ = f.open(f"{ANON_URL}//{remote}", OpenFlags.READ)
        assert status.ok, f"open for read failed: {status.message}"

        status, st = f.stat()
        assert status.ok
        assert st.size == len(content), f"stat size {st.size} != {len(content)}"

        status, data = f.read(offset=0, size=len(content))
        assert status.ok, f"read failed: {status.message}"
        assert data == content, "read-back data does not match written data"
        f.close()

    def test_upload_rejected_without_credentials_on_gsi_port(self):
        """Uploading to the GSI port without a proxy cert must fail authentication."""
        content = b"should not be written\n"
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(content)
            local = tmp.name

        # xrdcp to the GSI port with no proxy — must not exit 0
        cmd = (
            "env -u X509_USER_PROXY -u X509_CERT_DIR "
            f"xrdcp {local} root://localhost:11095//_test_write_nocreds.txt 2>/dev/null"
        )
        rc = os.system(cmd)
        os.unlink(local)

        assert rc != 0, "Expected xrdcp to fail on GSI server without credentials"
        assert not os.path.exists(
            os.path.join(DATA_DIR, "_test_write_nocreds.txt")
        ), "File should not have been created without valid GSI credentials"


class TestWriteGSI:
    """Upload tests that authenticate via GSI proxy certificate on port 11095."""

    def test_gsi_upload_small_file(self):
        """Upload a small file over GSI and verify contents on disk."""
        content = b"Hello from nginx-xrootd GSI write test!\n"
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(content)
            local = tmp.name

        remote = "_test_gsi_write_small.txt"
        assert _xrdcp_put_gsi(local, remote) == 0, "GSI xrdcp upload failed"
        os.unlink(local)

        dest = os.path.join(DATA_DIR, remote)
        assert os.path.exists(dest), "uploaded file not found on disk"
        assert open(dest, "rb").read() == content, "file content mismatch"

    def test_gsi_upload_large_file(self):
        """Upload a 50 MiB file over GSI and verify MD5 integrity."""
        size = 50 * 1024 * 1024
        data = os.urandom(size)
        expected_md5 = hashlib.md5(data).hexdigest()

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(data)
            local = tmp.name

        remote = "_test_gsi_write_large.bin"
        assert _xrdcp_put_gsi(local, remote) == 0, "GSI xrdcp large upload failed"
        os.unlink(local)

        dest = os.path.join(DATA_DIR, remote)
        assert os.path.getsize(dest) == size, (
            f"size mismatch: {os.path.getsize(dest)} != {size}"
        )
        assert _md5(dest) == expected_md5, "MD5 mismatch after GSI large upload"

    def test_gsi_write_then_read_back(self):
        """Write via GSI xrdcp, read back via XRootD File API with GSI auth."""
        content = b"GSI round-trip: " + os.urandom(128)
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(content)
            local = tmp.name

        remote = "_test_gsi_write_roundtrip.bin"
        assert _xrdcp_put_gsi(local, remote) == 0, "GSI upload failed"
        os.unlink(local)

        os.environ["X509_CERT_DIR"] = CA_DIR
        os.environ["X509_USER_PROXY"] = PROXY_PEM
        try:
            f = client.File()
            status, _ = f.open(f"{GSI_URL}//{remote}", OpenFlags.READ)
            assert status.ok, f"GSI open for read failed: {status.message}"

            status, st = f.stat()
            assert status.ok
            assert st.size == len(content), f"stat size {st.size} != {len(content)}"

            status, data = f.read(offset=0, size=len(content))
            assert status.ok, f"GSI read failed: {status.message}"
            assert data == content, "read-back data does not match written data"
            f.close()
        finally:
            os.environ.pop("X509_CERT_DIR", None)
            os.environ.pop("X509_USER_PROXY", None)
