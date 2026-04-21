"""
Tests for nginx-xrootd stream module.

Tests both the anonymous endpoint (port 11094) and the GSI/x509 authenticated
endpoint (port 11095) using the XRootD Python client library.

Prerequisites:
  - nginx running: /tmp/nginx-1.28.3/objs/nginx -c /tmp/xrd-test/conf/nginx.conf
  - Test PKI at /tmp/xrd-test/pki/
  - Test data at /tmp/xrd-test/data/
  - Proxy cert regenerated if expired: python3 utils/make_proxy.py

Run:
  pytest tests/test_xrootd.py -v
  pytest tests/test_xrootd.py -v -k anon   # anonymous only
  pytest tests/test_xrootd.py -v -k gsi    # GSI only
"""

import hashlib
import os
import subprocess
import tempfile

import pytest
from XRootD import client
from XRootD.client.flags import DirListFlags, OpenFlags, QueryCode, StatInfoFlags
from settings import CA_DIR as DEFAULT_CA_DIR, DATA_ROOT as DEFAULT_DATA_ROOT, PROXY_STD

# ---------------------------------------------------------------------------
# Configuration — populated by the _configure fixture from test_env
# ---------------------------------------------------------------------------

ANON_URL  = ""
GSI_URL   = ""

DATA_ROOT = DEFAULT_DATA_ROOT
CA_DIR    = DEFAULT_CA_DIR
PROXY_PEM = PROXY_STD

# Known test files (relative to DATA_ROOT / server root "/")
TEST_FILES = {
    "test.txt":   {"size": 24,      "content": b"hello from nginx-xrootd\n"},
    "random.bin": {"size": 5242880, "content": None},   # content checked via md5
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
def _configure(test_env):
    """Bind module constants and set GSI env vars from the shared test environment."""
    global ANON_URL, GSI_URL, DATA_ROOT, CA_DIR, PROXY_PEM
    ANON_URL  = test_env["anon_url"]
    GSI_URL   = test_env["gsi_url"]
    DATA_ROOT = test_env["data_dir"]
    CA_DIR    = test_env["ca_dir"]
    PROXY_PEM = test_env["proxy_pem"]
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
def anon_fs():
    return client.FileSystem(ANON_URL)


@pytest.fixture(scope="module")
def gsi_fs():
    return client.FileSystem(GSI_URL)


# ---------------------------------------------------------------------------
# Helper
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
    size = st.size
    status, data = f.read(size=size)
    assert status.ok, f"read failed: {status.message}"
    f.close()
    return data


# ===========================================================================
# Anonymous endpoint tests (port 11094)
# ===========================================================================

class TestAnonymous:

    def test_stat_root(self, anon_fs):
        """stat('/') returns a directory entry."""
        status, info = anon_fs.stat("/")
        assert status.ok, f"stat('/') failed: {status.message}"
        assert info.flags & StatInfoFlags.IS_DIR
        assert info.flags & StatInfoFlags.IS_READABLE

    def test_dirlist_root(self, anon_fs):
        """dirlist('/') lists the expected test files."""
        status, listing = anon_fs.dirlist("/")
        assert status.ok, f"dirlist('/') failed: {status.message}"
        names = {e.name for e in listing}
        assert "test.txt"   in names
        assert "random.bin" in names

    def test_dirlist_with_stat(self, anon_fs):
        """dirlist with STAT flag returns size information."""
        status, listing = anon_fs.dirlist("/", DirListFlags.STAT)
        assert status.ok
        for entry in listing:
            if entry.name == "test.txt":
                assert entry.statinfo.size == TEST_FILES["test.txt"]["size"]

    def test_stat_file(self, anon_fs):
        """stat on a regular file returns the correct size."""
        status, info = anon_fs.stat("/test.txt")
        assert status.ok, f"stat('/test.txt') failed: {status.message}"
        assert info.size == TEST_FILES["test.txt"]["size"]
        assert not (info.flags & StatInfoFlags.IS_DIR)

    def test_stat_nonexistent(self, anon_fs):
        """stat on a missing path returns an error status."""
        status, info = anon_fs.stat("/no_such_file.txt")
        assert not status.ok

    def test_read_small_file(self, anon_fs):
        """Read a small text file and verify content."""
        data = xrd_read_all(f"{ANON_URL}//test.txt")
        assert data == TEST_FILES["test.txt"]["content"]

    def test_read_large_file_integrity(self, anon_fs):
        """Read a 5 MB binary file via XRootD and verify md5 matches disk."""
        expected_md5 = md5_of_file(os.path.join(DATA_ROOT, "random.bin"))
        data = xrd_read_all(f"{ANON_URL}//random.bin")
        assert len(data) == TEST_FILES["random.bin"]["size"]
        assert md5_of_bytes(data) == expected_md5

    def test_copy_small_file(self):
        """CopyProcess: copy a small file to a temp path and verify."""
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp_path = tmp.name
        try:
            cp = client.CopyProcess()
            cp.add_job(f"{ANON_URL}//test.txt", tmp_path, force=True)
            cp.prepare()
            status, results = cp.run()
            assert status.ok, f"copy failed: {status.message}"
            assert results[0]["status"].ok
            with open(tmp_path, "rb") as f:
                assert f.read() == TEST_FILES["test.txt"]["content"]
        finally:
            os.unlink(tmp_path)

    def test_copy_large_file_integrity(self):
        """CopyProcess: copy a 5 MB file and verify md5 matches the source."""
        expected_md5 = md5_of_file(os.path.join(DATA_ROOT, "random.bin"))
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp_path = tmp.name
        try:
            cp = client.CopyProcess()
            cp.add_job(f"{ANON_URL}//random.bin", tmp_path, force=True)
            cp.prepare()
            status, results = cp.run()
            assert status.ok, f"copy failed: {status.message}"
            assert md5_of_file(tmp_path) == expected_md5
        finally:
            os.unlink(tmp_path)

    def test_open_read_partial(self):
        """Read a partial range of bytes from a file (offset + size)."""
        f = client.File()
        status, _ = f.open(f"{ANON_URL}//test.txt")
        assert status.ok
        status, data = f.read(offset=6, size=4)
        assert status.ok
        assert data == b"from"
        f.close()

    def test_open_nonexistent_returns_error(self):
        """Opening a non-existent file returns an error status."""
        f = client.File()
        status, _ = f.open(f"{ANON_URL}//no_such_file.txt")
        assert not status.ok
        f.close()

    def test_ping(self, anon_fs):
        """Ping the server."""
        status, _ = anon_fs.ping()
        assert status.ok, f"ping failed: {status.message}"


# ===========================================================================
# GSI / x509 authenticated endpoint tests (port 11095)
# ===========================================================================

class TestGSI:
    """
    These tests require a valid proxy certificate at PROXY_PEM and the CA
    directory at CA_DIR.  Environment variables are set by the gsi_env fixture.
    """

    def test_gsi_stat_root(self, gsi_fs):
        """GSI: stat('/') on authenticated endpoint succeeds."""
        status, info = gsi_fs.stat("/")
        assert status.ok, f"GSI stat('/') failed: {status.message}"
        assert info.flags & StatInfoFlags.IS_DIR
        assert info.flags & StatInfoFlags.IS_READABLE

    def test_gsi_dirlist(self, gsi_fs):
        """GSI: dirlist returns expected files."""
        status, listing = gsi_fs.dirlist("/")
        assert status.ok, f"GSI dirlist failed: {status.message}"
        names = {e.name for e in listing}
        assert "test.txt" in names
        assert "random.bin" in names

    def test_gsi_stat_file(self, gsi_fs):
        """GSI: stat on a file returns correct size."""
        status, info = gsi_fs.stat("/test.txt")
        assert status.ok, f"GSI stat file failed: {status.message}"
        assert info.size == TEST_FILES["test.txt"]["size"]

    def test_gsi_read_small_file(self):
        """GSI: read a small file, verify content matches reference."""
        data = xrd_read_all(f"{GSI_URL}//test.txt")
        assert data == TEST_FILES["test.txt"]["content"]

    def test_gsi_read_large_file_integrity(self):
        """GSI: read a 5 MB binary file and verify md5 matches disk."""
        expected_md5 = md5_of_file(os.path.join(DATA_ROOT, "random.bin"))
        data = xrd_read_all(f"{GSI_URL}//random.bin")
        assert len(data) == TEST_FILES["random.bin"]["size"]
        assert md5_of_bytes(data) == expected_md5

    def test_gsi_copy_small_file(self):
        """GSI: CopyProcess copy a small file and verify content."""
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp_path = tmp.name
        try:
            cp = client.CopyProcess()
            cp.add_job(f"{GSI_URL}//test.txt", tmp_path, force=True)
            cp.prepare()
            status, results = cp.run()
            assert status.ok, f"GSI copy failed: {status.message}"
            assert results[0]["status"].ok
            with open(tmp_path, "rb") as f:
                assert f.read() == TEST_FILES["test.txt"]["content"]
        finally:
            os.unlink(tmp_path)

    def test_gsi_copy_large_file_integrity(self):
        """GSI: CopyProcess copy a 5 MB binary file and verify md5."""
        expected_md5 = md5_of_file(os.path.join(DATA_ROOT, "random.bin"))
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp_path = tmp.name
        try:
            cp = client.CopyProcess()
            cp.add_job(f"{GSI_URL}//random.bin", tmp_path, force=True)
            cp.prepare()
            status, results = cp.run()
            assert status.ok, f"GSI copy failed: {status.message}"
            assert md5_of_file(tmp_path) == expected_md5
        finally:
            os.unlink(tmp_path)

    def test_gsi_ping(self, gsi_fs):
        """GSI: ping succeeds after authentication."""
        status, _ = gsi_fs.ping()
        assert status.ok, f"GSI ping failed: {status.message}"

    def test_gsi_open_read_partial(self):
        """GSI: partial read (offset + size) returns correct bytes."""
        f = client.File()
        status, _ = f.open(f"{GSI_URL}//test.txt")
        assert status.ok
        status, data = f.read(offset=6, size=4)
        assert status.ok
        assert data == b"from"
        f.close()

    def test_gsi_stat_nonexistent(self, gsi_fs):
        """GSI: stat on missing file returns error."""
        status, info = gsi_fs.stat("/no_such_file.txt")
        assert not status.ok

    def test_gsi_anon_same_data(self):
        """Data read via GSI endpoint equals data read via anonymous endpoint."""
        anon_data = xrd_read_all(f"{ANON_URL}//random.bin")
        gsi_data  = xrd_read_all(f"{GSI_URL}//random.bin")
        assert anon_data == gsi_data

    def test_gsi_proxy_subject_in_stat_flags(self, gsi_fs):
        """GSI: stat returns IS_READABLE for files (proxy auth allows access)."""
        status, info = gsi_fs.stat("/test.txt")
        assert status.ok
        assert info.flags & StatInfoFlags.IS_READABLE
        assert not (info.flags & StatInfoFlags.IS_DIR)

    def test_gsi_wrong_ca_rejected(self):
        """GSI: unknown CA dir causes auth failure (tested in fresh subprocess).

        The XRootD C++ client pools connections within a process, so env-var
        changes only take effect in a fresh process.  We use subprocess.run.
        """
        script = """\
import os, sys
os.environ["X509_CERT_DIR"]  = "/nonexistent/ca"
os.environ["X509_USER_PROXY"] = "{proxy}"
from XRootD import client
fs = client.FileSystem("{url}")
status, _ = fs.stat("/test.txt")
sys.exit(0 if not status.ok else 1)
""".format(proxy=PROXY_PEM, url=GSI_URL)

        result = subprocess.run(
            ["python3", "-c", script],
            capture_output=True, timeout=15
        )
        # exit 0 = stat failed (expected), exit 1 = stat succeeded (bad)
        assert result.returncode == 0, (
            "Expected auth failure with bad CA dir but got success\n"
            f"stderr: {result.stderr.decode()}"
        )
