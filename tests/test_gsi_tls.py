"""
Functional read tests for root:// with GSI authentication + in-protocol TLS
(xrootd_tls).

The server on port 11096 advertises kXR_haveTLS in its kXR_protocol response,
so the XRootD client upgrades the connection to TLS before sending kXR_auth.
This validates that the full read path works correctly over an encrypted
transport with x509 proxy-certificate authentication.

Prerequisites:
  - nginx running with xrootd_tls + xrootd_auth gsi on port 11096
  - Test PKI at /tmp/xrd-test/pki/
  - Test data at /tmp/xrd-test/data/ (test.txt, random.bin)

Run:
    pytest tests/test_gsi_tls.py -v
    pytest tests/test_gsi_tls.py -v -k partial   # just partial-read tests
"""

import hashlib
import os
import subprocess
import tempfile

import pytest
from XRootD import client
from XRootD.client.flags import DirListFlags, OpenFlags, StatInfoFlags
from settings import CA_DIR as DEFAULT_CA_DIR, DATA_ROOT as DEFAULT_DATA_ROOT, PROXY_STD

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

GSI_TLS_URL = ""
GSI_URL     = ""
ANON_URL    = ""

DATA_ROOT = DEFAULT_DATA_ROOT
CA_DIR    = DEFAULT_CA_DIR
PROXY_PEM = PROXY_STD

TEST_FILES = {
    "test.txt":   {"size": 24,      "content": b"hello from nginx-xrootd\n"},
    "random.bin": {"size": 5242880, "content": None},
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
def _configure(test_env):
    """Bind module constants and set GSI env vars from the shared test environment."""
    global GSI_TLS_URL, GSI_URL, ANON_URL, DATA_ROOT, CA_DIR, PROXY_PEM
    GSI_TLS_URL = test_env["gsi_tls_url"]
    GSI_URL     = test_env["gsi_url"]
    ANON_URL    = test_env["anon_url"]
    DATA_ROOT   = test_env["data_dir"]
    CA_DIR      = test_env["ca_dir"]
    PROXY_PEM   = test_env["proxy_pem"]
    old = {}
    for k, v in [("X509_CERT_DIR", CA_DIR), ("X509_USER_PROXY", PROXY_PEM)]:
        old[k] = os.environ.get(k)
        os.environ[k] = v
    yield
    for k, v in old.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


@pytest.fixture(scope="module")
def fs():
    """FileSystem handle for the GSI+TLS endpoint."""
    return client.FileSystem(GSI_TLS_URL)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def md5_of_file(path: str) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def md5_of_bytes(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def xrd_read_all(url: str) -> bytes:
    """Read all bytes from an XRootD URL using File.read()."""
    f = client.File()
    status, _ = f.open(url)
    assert status.ok, f"open({url}) failed: {status.message}"
    status, st = f.stat()
    assert status.ok
    status, data = f.read(size=st.size)
    assert status.ok, f"read failed: {status.message}"
    f.close()
    return data


# ===========================================================================
# Connection and metadata tests
# ===========================================================================

class TestGSITLSConnection:
    """Verify that GSI+TLS connections succeed and metadata ops work."""

    def test_stat_root(self, fs):
        """stat('/') returns a directory entry over GSI+TLS."""
        status, info = fs.stat("/")
        assert status.ok, f"stat('/') failed: {status.message}"
        assert info.flags & StatInfoFlags.IS_DIR
        assert info.flags & StatInfoFlags.IS_READABLE

    def test_stat_file(self, fs):
        """stat on a regular file returns the correct size."""
        status, info = fs.stat("/test.txt")
        assert status.ok, f"stat('/test.txt') failed: {status.message}"
        assert info.size == TEST_FILES["test.txt"]["size"]
        assert not (info.flags & StatInfoFlags.IS_DIR)

    def test_stat_nonexistent(self, fs):
        """stat on a missing path returns an error."""
        status, info = fs.stat("/no_such_file.txt")
        assert not status.ok

    def test_dirlist(self, fs):
        """dirlist('/') lists expected test files."""
        status, listing = fs.dirlist("/")
        assert status.ok, f"dirlist failed: {status.message}"
        names = {e.name for e in listing}
        assert "test.txt" in names
        assert "random.bin" in names

    def test_dirlist_with_stat(self, fs):
        """dirlist with STAT flag returns file sizes."""
        status, listing = fs.dirlist("/", DirListFlags.STAT)
        assert status.ok
        for entry in listing:
            if entry.name == "test.txt":
                assert entry.statinfo.size == TEST_FILES["test.txt"]["size"]

    def test_ping(self, fs):
        """Ping succeeds over the TLS-upgraded connection."""
        status, _ = fs.ping()
        assert status.ok, f"ping failed: {status.message}"


# ===========================================================================
# Read tests
# ===========================================================================

class TestGSITLSRead:
    """Verify reads over GSI+TLS return correct data."""

    def test_read_small_file(self):
        """Read a small text file and verify exact content."""
        data = xrd_read_all(f"{GSI_TLS_URL}//test.txt")
        assert data == TEST_FILES["test.txt"]["content"]

    def test_read_large_file_integrity(self):
        """Read a 5 MB binary file and verify md5 matches on-disk copy."""
        expected_md5 = md5_of_file(os.path.join(DATA_ROOT, "random.bin"))
        data = xrd_read_all(f"{GSI_TLS_URL}//random.bin")
        assert len(data) == TEST_FILES["random.bin"]["size"]
        assert md5_of_bytes(data) == expected_md5

    def test_partial_read_offset_size(self):
        """Partial read with explicit offset and size."""
        f = client.File()
        status, _ = f.open(f"{GSI_TLS_URL}//test.txt")
        assert status.ok
        # "hello from nginx-xrootd\n" — bytes 6..9 == "from"
        status, data = f.read(offset=6, size=4)
        assert status.ok
        assert data == b"from"
        f.close()

    def test_partial_read_first_byte(self):
        """Read just the first byte of a file."""
        f = client.File()
        status, _ = f.open(f"{GSI_TLS_URL}//test.txt")
        assert status.ok
        status, data = f.read(offset=0, size=1)
        assert status.ok
        assert data == b"h"
        f.close()

    def test_partial_read_last_byte(self):
        """Read just the last byte of a file."""
        f = client.File()
        status, _ = f.open(f"{GSI_TLS_URL}//test.txt")
        assert status.ok
        status, data = f.read(offset=23, size=1)
        assert status.ok
        assert data == b"\n"
        f.close()

    def test_read_at_eof(self):
        """Read starting at exactly the file size returns empty data."""
        f = client.File()
        status, _ = f.open(f"{GSI_TLS_URL}//test.txt")
        assert status.ok
        status, data = f.read(offset=24, size=10)
        assert status.ok
        assert data == b""
        f.close()

    def test_read_spanning_eof(self):
        """Read that spans past EOF is truncated to available bytes."""
        f = client.File()
        status, _ = f.open(f"{GSI_TLS_URL}//test.txt")
        assert status.ok
        status, data = f.read(offset=20, size=100)
        assert status.ok
        assert data == b"otd\n"  # bytes 20-23 of "hello from nginx-xrootd\n"
        f.close()

    def test_sequential_reads(self):
        """Multiple sequential reads from different offsets on one open handle."""
        f = client.File()
        status, _ = f.open(f"{GSI_TLS_URL}//test.txt")
        assert status.ok

        pieces = []
        offset = 0
        chunk_size = 8
        while True:
            status, data = f.read(offset=offset, size=chunk_size)
            assert status.ok
            if not data:
                break
            pieces.append(data)
            offset += len(data)

        f.close()
        assembled = b"".join(pieces)
        assert assembled == TEST_FILES["test.txt"]["content"]

    def test_large_file_chunked_read(self):
        """Read a 5 MB file in 64 KB chunks and verify integrity."""
        expected_md5 = md5_of_file(os.path.join(DATA_ROOT, "random.bin"))
        f = client.File()
        status, _ = f.open(f"{GSI_TLS_URL}//random.bin")
        assert status.ok

        h = hashlib.md5()
        offset = 0
        chunk_size = 65536
        total = 0
        while True:
            status, data = f.read(offset=offset, size=chunk_size)
            assert status.ok
            if not data:
                break
            h.update(data)
            total += len(data)
            offset += len(data)

        f.close()
        assert total == TEST_FILES["random.bin"]["size"]
        assert h.hexdigest() == expected_md5


# ===========================================================================
# Vector read (readv) tests
# ===========================================================================

class TestGSITLSReadV:
    """Verify kXR_readv works correctly over GSI+TLS."""

    def test_vector_read_basic(self):
        """Vector read of two non-overlapping regions."""
        f = client.File()
        status, _ = f.open(f"{GSI_TLS_URL}//test.txt", OpenFlags.READ)
        assert status.ok

        chunks = [(0, 5), (6, 4)]   # "hello", "from"
        status, result = f.vector_read(chunks)
        assert status.ok
        vdata = result.chunks
        assert vdata[0].buffer == b"hello"
        assert vdata[1].buffer == b"from"
        f.close()

    def test_vector_read_large_file(self):
        """Vector read of scattered regions in a 5 MB file matches direct reads."""
        ref_data = open(os.path.join(DATA_ROOT, "random.bin"), "rb").read()

        f = client.File()
        status, _ = f.open(f"{GSI_TLS_URL}//random.bin", OpenFlags.READ)
        assert status.ok

        chunks = [
            (0, 4096),
            (1048576, 8192),       # 1 MB offset
            (4194304, 4096),       # 4 MB offset
            (5242880 - 1024, 1024) # last 1 KB
        ]
        status, result = f.vector_read(chunks)
        assert status.ok

        for i, (off, length) in enumerate(chunks):
            assert result.chunks[i].buffer == ref_data[off:off + length]

        f.close()


# ===========================================================================
# CopyProcess tests
# ===========================================================================

class TestGSITLSCopy:
    """Verify CopyProcess works over GSI+TLS."""

    def test_copy_small_file(self):
        """Copy a small file to a local temp path and verify content."""
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp_path = tmp.name
        try:
            cp = client.CopyProcess()
            cp.add_job(f"{GSI_TLS_URL}//test.txt", tmp_path, force=True)
            cp.prepare()
            status, results = cp.run()
            assert status.ok, f"copy failed: {status.message}"
            assert results[0]["status"].ok
            with open(tmp_path, "rb") as f:
                assert f.read() == TEST_FILES["test.txt"]["content"]
        finally:
            os.unlink(tmp_path)

    def test_copy_large_file_integrity(self):
        """Copy a 5 MB file and verify md5."""
        expected_md5 = md5_of_file(os.path.join(DATA_ROOT, "random.bin"))
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp_path = tmp.name
        try:
            cp = client.CopyProcess()
            cp.add_job(f"{GSI_TLS_URL}//random.bin", tmp_path, force=True)
            cp.prepare()
            status, results = cp.run()
            assert status.ok, f"copy failed: {status.message}"
            assert md5_of_file(tmp_path) == expected_md5
        finally:
            os.unlink(tmp_path)


# ===========================================================================
# Cross-endpoint data consistency
# ===========================================================================

class TestGSITLSCrossCheck:
    """Verify data from GSI+TLS matches other endpoints."""

    def test_data_matches_plain_gsi(self):
        """Data read via GSI+TLS equals data from plain GSI (no TLS)."""
        tls_data = xrd_read_all(f"{GSI_TLS_URL}//random.bin")
        gsi_data = xrd_read_all(f"{GSI_URL}//random.bin")
        assert tls_data == gsi_data

    def test_data_matches_anon(self):
        """Data read via GSI+TLS equals data from anonymous endpoint."""
        tls_data = xrd_read_all(f"{GSI_TLS_URL}//test.txt")
        anon_data = xrd_read_all(f"{ANON_URL}//test.txt")
        assert tls_data == anon_data

    def test_stat_matches_plain_gsi(self, fs):
        """Stat info from GSI+TLS matches plain GSI endpoint."""
        gsi_fs = client.FileSystem(GSI_URL)

        status_tls, info_tls = fs.stat("/test.txt")
        status_gsi, info_gsi = gsi_fs.stat("/test.txt")

        assert status_tls.ok
        assert status_gsi.ok
        assert info_tls.size == info_gsi.size
        assert info_tls.flags == info_gsi.flags


# ===========================================================================
# Auth failure tests
# ===========================================================================

class TestGSITLSAuthFailure:
    """Verify auth failures over the TLS-enabled endpoint."""

    def test_wrong_ca_rejected(self):
        """Unknown CA dir causes auth failure (fresh subprocess)."""
        script = """\
import os, sys
os.environ["X509_CERT_DIR"]  = "/nonexistent/ca"
os.environ["X509_USER_PROXY"] = "{proxy}"
from XRootD import client
fs = client.FileSystem("{url}")
status, _ = fs.stat("/test.txt")
sys.exit(0 if not status.ok else 1)
""".format(proxy=PROXY_PEM, url=GSI_TLS_URL)

        result = subprocess.run(
            ["python3", "-c", script],
            capture_output=True, timeout=15
        )
        assert result.returncode == 0, (
            "Expected auth failure with bad CA dir but got success\n"
            f"stderr: {result.stderr.decode()}"
        )

    def test_open_nonexistent_returns_error(self):
        """Opening a non-existent file returns an error, not a crash."""
        f = client.File()
        status, _ = f.open(f"{GSI_TLS_URL}//no_such_file.txt")
        assert not status.ok
        f.close()


# ===========================================================================
# Write tests
# ===========================================================================

WRITE_PREFIX = "_test_gsi_tls_"


@pytest.fixture(autouse=False)
def cleanup_gsi_tls_writes():
    """Remove uploaded files from the data dir after each test."""
    yield
    for fname in os.listdir(DATA_ROOT):
        if fname.startswith(WRITE_PREFIX):
            try:
                os.unlink(os.path.join(DATA_ROOT, fname))
            except OSError:
                pass


class TestGSITLSWrite:
    """Verify writes over GSI+TLS (xrdcp and File API)."""

    def test_write_small_file_api(self, cleanup_gsi_tls_writes):
        """Write a small file via File API and verify on disk."""
        content = b"GSI+TLS write test small file\n"
        remote = f"{WRITE_PREFIX}small.txt"

        f = client.File()
        status, _ = f.open(
            f"{GSI_TLS_URL}//{remote}",
            OpenFlags.DELETE | OpenFlags.NEW,
        )
        assert status.ok, f"open for write failed: {status.message}"
        status, _ = f.write(content)
        assert status.ok, f"write failed: {status.message}"
        f.close()

        disk_path = os.path.join(DATA_ROOT, remote)
        assert os.path.exists(disk_path), "file not created on disk"
        assert open(disk_path, "rb").read() == content

    def test_write_then_read_back(self, cleanup_gsi_tls_writes):
        """Write via File API, then read back on the same endpoint."""
        content = b"round-trip: " + os.urandom(128)
        remote = f"{WRITE_PREFIX}roundtrip.bin"

        # Write
        f = client.File()
        status, _ = f.open(
            f"{GSI_TLS_URL}//{remote}",
            OpenFlags.DELETE | OpenFlags.NEW,
        )
        assert status.ok, f"open for write failed: {status.message}"
        status, _ = f.write(content)
        assert status.ok
        f.close()

        # Read back
        data = xrd_read_all(f"{GSI_TLS_URL}//{remote}")
        assert data == content

    def test_write_medium_file_integrity(self, cleanup_gsi_tls_writes):
        """Write a 1 MB file and verify MD5 on disk."""
        size = 1024 * 1024
        content = os.urandom(size)
        expected_md5 = md5_of_bytes(content)
        remote = f"{WRITE_PREFIX}medium.bin"

        f = client.File()
        status, _ = f.open(
            f"{GSI_TLS_URL}//{remote}",
            OpenFlags.DELETE | OpenFlags.NEW,
        )
        assert status.ok, f"open for write failed: {status.message}"
        status, _ = f.write(content)
        assert status.ok
        f.close()

        disk_path = os.path.join(DATA_ROOT, remote)
        assert os.path.getsize(disk_path) == size
        assert md5_of_file(disk_path) == expected_md5

    def test_xrdcp_upload(self, cleanup_gsi_tls_writes):
        """Upload a file via xrdcp to the GSI+TLS endpoint."""
        content = b"xrdcp GSI+TLS upload test\n"
        remote = f"{WRITE_PREFIX}xrdcp.txt"
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(content)
            local = tmp.name
        try:
            env = (
                f"X509_CERT_DIR={CA_DIR} "
                f"X509_USER_PROXY={PROXY_PEM}"
            )
            cmd = f"{env} xrdcp -f {local} {GSI_TLS_URL}//{remote} 2>&1"
            rc = os.system(cmd)
            assert rc == 0, "xrdcp upload failed"

            disk_path = os.path.join(DATA_ROOT, remote)
            assert os.path.exists(disk_path)
            assert open(disk_path, "rb").read() == content
        finally:
            os.unlink(local)

    def test_xrdcp_large_upload_integrity(self, cleanup_gsi_tls_writes):
        """Upload a 10 MB file via xrdcp and verify MD5."""
        size = 10 * 1024 * 1024
        content = os.urandom(size)
        expected_md5 = md5_of_bytes(content)
        remote = f"{WRITE_PREFIX}xrdcp_large.bin"

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(content)
            local = tmp.name
        try:
            env = (
                f"X509_CERT_DIR={CA_DIR} "
                f"X509_USER_PROXY={PROXY_PEM}"
            )
            cmd = f"{env} xrdcp -f {local} {GSI_TLS_URL}//{remote} 2>&1"
            rc = os.system(cmd)
            assert rc == 0, "xrdcp large upload failed"

            disk_path = os.path.join(DATA_ROOT, remote)
            assert os.path.getsize(disk_path) == size
            assert md5_of_file(disk_path) == expected_md5
        finally:
            os.unlink(local)

    def test_overwrite_existing_file(self, cleanup_gsi_tls_writes):
        """Overwrite an existing file and verify new content."""
        remote = f"{WRITE_PREFIX}overwrite.txt"

        # Write original
        f = client.File()
        status, _ = f.open(
            f"{GSI_TLS_URL}//{remote}",
            OpenFlags.DELETE | OpenFlags.NEW,
        )
        assert status.ok
        status, _ = f.write(b"original\n")
        assert status.ok
        f.close()

        # Overwrite
        f = client.File()
        status, _ = f.open(
            f"{GSI_TLS_URL}//{remote}",
            OpenFlags.DELETE | OpenFlags.NEW,
        )
        assert status.ok
        status, _ = f.write(b"replaced\n")
        assert status.ok
        f.close()

        disk_path = os.path.join(DATA_ROOT, remote)
        assert open(disk_path, "rb").read() == b"replaced\n"

    def test_write_read_cross_endpoint(self, cleanup_gsi_tls_writes):
        """Write via GSI+TLS, read back via plain GSI — data matches."""
        content = b"cross-endpoint: " + os.urandom(64)
        remote = f"{WRITE_PREFIX}cross.bin"

        f = client.File()
        status, _ = f.open(
            f"{GSI_TLS_URL}//{remote}",
            OpenFlags.DELETE | OpenFlags.NEW,
        )
        assert status.ok
        status, _ = f.write(content)
        assert status.ok
        f.close()

        data = xrd_read_all(f"{GSI_URL}//{remote}")
        assert data == content
