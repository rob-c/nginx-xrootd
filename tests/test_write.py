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

ANON_URL = "root://localhost:11094"
DATA_DIR = "/tmp/xrd-test/data"


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


@pytest.fixture(autouse=True)
def cleanup_uploads():
    """Remove uploaded files from the data dir after each test."""
    yield
    for f in os.listdir(DATA_DIR):
        if f.startswith("_test_write_"):
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

    def test_upload_respects_read_only_on_gsi_port(self):
        """The GSI server (port 11095) has no xrootd_allow_write, so uploads must fail."""
        content = b"should not be written\n"
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(content)
            local = tmp.name

        # xrdcp to the GSI port (no write allowed) — must not exit 0
        cmd = f"xrdcp {local} root://localhost:11095//_test_write_readonly.txt 2>/dev/null"
        rc = os.system(cmd)
        os.unlink(local)

        assert rc != 0, "Expected xrdcp to fail on read-only GSI server"
        assert not os.path.exists(
            os.path.join(DATA_DIR, "_test_write_readonly.txt")
        ), "File should not have been created on read-only server"
