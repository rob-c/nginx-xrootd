"""
Filesystem operation tests for nginx-xrootd: mkdir, rmdir, rm, mv, chmod.

Tests both the anonymous (port 11094) and GSI (port 11095) endpoints.
Uses the XRootD Python FileSystem API so operations go through the full
XRootD protocol stack rather than xrdcp.

Run:
    pytest tests/test_fs_ops.py -v -s
"""

import os
import stat
import tempfile

import pytest
from XRootD import client
from XRootD.client.flags import MkDirFlags, AccessMode
from settings import CA_DIR as DEFAULT_CA_DIR, DATA_ROOT as DEFAULT_DATA_ROOT, PROXY_STD

ANON_URL  = ""
GSI_URL   = ""
DATA_DIR  = DEFAULT_DATA_ROOT
CA_DIR    = DEFAULT_CA_DIR
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


def anon_fs() -> client.FileSystem:
    return client.FileSystem(ANON_URL)


def gsi_fs() -> client.FileSystem:
    os.environ["X509_CERT_DIR"]  = CA_DIR
    os.environ["X509_USER_PROXY"] = PROXY_PEM
    return client.FileSystem(GSI_URL)


@pytest.fixture(autouse=True)
def clean_test_paths():
    """Remove any _fstest_* artefacts before and after each test."""
    _cleanup()
    yield
    _cleanup()


def _cleanup():
    base = DATA_DIR
    for name in os.listdir(base):
        if not name.startswith("_fstest_"):
            continue
        full = os.path.join(base, name)
        if os.path.isdir(full):
            # remove tree
            for root, dirs, files in os.walk(full, topdown=False):
                for f in files:
                    try:
                        os.unlink(os.path.join(root, f))
                    except OSError:
                        pass
                for d in dirs:
                    try:
                        os.rmdir(os.path.join(root, d))
                    except OSError:
                        pass
            try:
                os.rmdir(full)
            except OSError:
                pass
        else:
            try:
                os.unlink(full)
            except OSError:
                pass


# ---------------------------------------------------------------------------
# kXR_mkdir
# ---------------------------------------------------------------------------

class TestMkdir:

    def test_mkdir_simple(self):
        """Create a single directory."""
        fs = anon_fs()
        status, _ = fs.mkdir("/_fstest_mkdir_simple", MkDirFlags.NONE)
        assert status.ok, f"mkdir failed: {status.message}"
        assert os.path.isdir(os.path.join(DATA_DIR, "_fstest_mkdir_simple"))

    def test_mkdir_with_parents(self):
        """Create nested directories in one call (MkDirFlags.MAKEPATH)."""
        fs = anon_fs()
        status, _ = fs.mkdir("/_fstest_mkdir_parents/sub/deep",
                              MkDirFlags.MAKEPATH)
        assert status.ok, f"mkdir -p failed: {status.message}"
        assert os.path.isdir(
            os.path.join(DATA_DIR, "_fstest_mkdir_parents", "sub", "deep")
        )

    def test_mkdir_idempotent(self):
        """mkdir on an existing directory must succeed (not error)."""
        path = os.path.join(DATA_DIR, "_fstest_mkdir_idem")
        os.makedirs(path, exist_ok=True)
        fs = anon_fs()
        status, _ = fs.mkdir("/_fstest_mkdir_idem", MkDirFlags.NONE)
        assert status.ok, f"mkdir on existing dir failed: {status.message}"

    def test_mkdir_gsi(self):
        """Create a directory over the GSI endpoint."""
        fs = gsi_fs()
        status, _ = fs.mkdir("/_fstest_mkdir_gsi", MkDirFlags.NONE)
        assert status.ok, f"GSI mkdir failed: {status.message}"
        assert os.path.isdir(os.path.join(DATA_DIR, "_fstest_mkdir_gsi"))


# ---------------------------------------------------------------------------
# kXR_rmdir
# ---------------------------------------------------------------------------

class TestRmdir:

    def test_rmdir_empty(self):
        """Remove an empty directory."""
        path = os.path.join(DATA_DIR, "_fstest_rmdir_empty")
        os.makedirs(path, exist_ok=True)
        fs = anon_fs()
        status, _ = fs.rmdir("/_fstest_rmdir_empty")
        assert status.ok, f"rmdir failed: {status.message}"
        assert not os.path.exists(path)

    def test_rmdir_nonempty_fails(self):
        """Removing a non-empty directory must fail."""
        path = os.path.join(DATA_DIR, "_fstest_rmdir_nonempty")
        os.makedirs(path, exist_ok=True)
        open(os.path.join(path, "file.txt"), "w").close()
        fs = anon_fs()
        status, _ = fs.rmdir("/_fstest_rmdir_nonempty")
        assert not status.ok, "Expected rmdir of non-empty dir to fail"

    def test_rmdir_nonexistent_fails(self):
        """Removing a directory that doesn't exist must fail."""
        fs = anon_fs()
        status, _ = fs.rmdir("/_fstest_rmdir_gone")
        assert not status.ok, "Expected rmdir of nonexistent dir to fail"

    def test_rmdir_gsi(self):
        """Remove a directory over the GSI endpoint."""
        path = os.path.join(DATA_DIR, "_fstest_rmdir_gsi")
        os.makedirs(path, exist_ok=True)
        fs = gsi_fs()
        status, _ = fs.rmdir("/_fstest_rmdir_gsi")
        assert status.ok, f"GSI rmdir failed: {status.message}"
        assert not os.path.exists(path)


# ---------------------------------------------------------------------------
# kXR_rm (file removal)
# ---------------------------------------------------------------------------

class TestRm:

    def test_rm_file(self):
        """Remove an existing file."""
        path = os.path.join(DATA_DIR, "_fstest_rm_file.txt")
        open(path, "w").write("delete me\n")
        fs = anon_fs()
        status, _ = fs.rm("/_fstest_rm_file.txt")
        assert status.ok, f"rm failed: {status.message}"
        assert not os.path.exists(path)

    def test_rm_nonexistent_fails(self):
        """Removing a file that doesn't exist must fail."""
        fs = anon_fs()
        status, _ = fs.rm("/_fstest_rm_gone.txt")
        assert not status.ok, "Expected rm of nonexistent file to fail"

    def test_rm_gsi(self):
        """Remove a file over the GSI endpoint."""
        path = os.path.join(DATA_DIR, "_fstest_rm_gsi.txt")
        open(path, "w").write("gsi delete me\n")
        fs = gsi_fs()
        status, _ = fs.rm("/_fstest_rm_gsi.txt")
        assert status.ok, f"GSI rm failed: {status.message}"
        assert not os.path.exists(path)


# ---------------------------------------------------------------------------
# kXR_mv (rename/move)
# ---------------------------------------------------------------------------

class TestMv:

    def test_mv_file(self):
        """Rename a file."""
        src = os.path.join(DATA_DIR, "_fstest_mv_src.txt")
        dst = os.path.join(DATA_DIR, "_fstest_mv_dst.txt")
        open(src, "w").write("move me\n")
        fs = anon_fs()
        status, _ = fs.mv("/_fstest_mv_src.txt", "/_fstest_mv_dst.txt")
        assert status.ok, f"mv failed: {status.message}"
        assert not os.path.exists(src), "source should be gone after mv"
        assert open(dst).read() == "move me\n", "destination content wrong"

    def test_mv_directory(self):
        """Rename a directory."""
        src = os.path.join(DATA_DIR, "_fstest_mv_dir_src")
        dst = os.path.join(DATA_DIR, "_fstest_mv_dir_dst")
        os.makedirs(src, exist_ok=True)
        fs = anon_fs()
        status, _ = fs.mv("/_fstest_mv_dir_src", "/_fstest_mv_dir_dst")
        assert status.ok, f"mv dir failed: {status.message}"
        assert not os.path.exists(src)
        assert os.path.isdir(dst)

    def test_mv_nonexistent_source_fails(self):
        """Moving a nonexistent source must fail."""
        fs = anon_fs()
        status, _ = fs.mv("/_fstest_mv_gone.txt", "/_fstest_mv_dst2.txt")
        assert not status.ok, "Expected mv of nonexistent source to fail"

    def test_mv_gsi(self):
        """Rename a file over the GSI endpoint."""
        src = os.path.join(DATA_DIR, "_fstest_mv_gsi_src.txt")
        dst = os.path.join(DATA_DIR, "_fstest_mv_gsi_dst.txt")
        open(src, "w").write("gsi move\n")
        fs = gsi_fs()
        status, _ = fs.mv("/_fstest_mv_gsi_src.txt", "/_fstest_mv_gsi_dst.txt")
        assert status.ok, f"GSI mv failed: {status.message}"
        assert not os.path.exists(src)
        assert os.path.exists(dst)


# ---------------------------------------------------------------------------
# kXR_chmod
# ---------------------------------------------------------------------------

class TestChmod:

    def test_chmod_file(self):
        """Change file permissions."""
        path = os.path.join(DATA_DIR, "_fstest_chmod_file.txt")
        open(path, "w").write("chmod me\n")
        os.chmod(path, 0o644)
        fs = anon_fs()
        # Set to 0o444 (read-only for all)
        status, _ = fs.chmod("/_fstest_chmod_file.txt",
                              AccessMode.UR | AccessMode.GR | AccessMode.OR)
        assert status.ok, f"chmod failed: {status.message}"
        mode = stat.S_IMODE(os.stat(path).st_mode)
        assert mode == 0o444, f"expected 0o444, got 0o{mode:o}"

    def test_chmod_directory(self):
        """Change directory permissions."""
        path = os.path.join(DATA_DIR, "_fstest_chmod_dir")
        os.makedirs(path, exist_ok=True)
        os.chmod(path, 0o755)
        fs = anon_fs()
        status, _ = fs.chmod("/_fstest_chmod_dir",
                              AccessMode.UR | AccessMode.UW | AccessMode.UX |
                              AccessMode.GR | AccessMode.GX)
        assert status.ok, f"chmod dir failed: {status.message}"
        mode = stat.S_IMODE(os.stat(path).st_mode)
        assert mode == 0o750, f"expected 0o750, got 0o{mode:o}"

    def test_chmod_nonexistent_fails(self):
        """chmod on a nonexistent path must fail."""
        fs = anon_fs()
        status, _ = fs.chmod("/_fstest_chmod_gone.txt", AccessMode.UR)
        assert not status.ok, "Expected chmod of nonexistent path to fail"

    def test_chmod_gsi(self):
        """Change file permissions over the GSI endpoint."""
        path = os.path.join(DATA_DIR, "_fstest_chmod_gsi.txt")
        open(path, "w").write("gsi chmod\n")
        os.chmod(path, 0o644)
        fs = gsi_fs()
        status, _ = fs.chmod("/_fstest_chmod_gsi.txt",
                              AccessMode.UR | AccessMode.GR | AccessMode.OR)
        assert status.ok, f"GSI chmod failed: {status.message}"
        mode = stat.S_IMODE(os.stat(path).st_mode)
        assert mode == 0o444, f"expected 0o444, got 0o{mode:o}"
