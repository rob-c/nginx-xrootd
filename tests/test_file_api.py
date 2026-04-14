"""
Comprehensive file-management tests for nginx-xrootd via the XRootD Python API.

Covers the File API (open/read/write/truncate/sync/stat) and the FileSystem
API (stat, dirlist, truncate, mkdir, rmdir, rm, mv, chmod) on both the
anonymous (port 11094) and GSI (port 11095) endpoints.

Run:
    pytest tests/test_file_api.py -v -s
"""

import hashlib
import os
import stat
import tempfile

import pytest
from XRootD import client
from XRootD.client.flags import (
    AccessMode,
    DirListFlags,
    MkDirFlags,
    OpenFlags,
    StatInfoFlags,
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

ANON_URL  = "root://localhost:11094"
GSI_URL   = "root://localhost:11095"
DATA_DIR  = "/tmp/xrd-test/data"
CA_DIR    = "/tmp/xrd-test/pki/ca"
PROXY_PEM = "/tmp/xrd-test/pki/user/proxy_std.pem"

PREFIX = "_api_test_"   # all test files/dirs carry this prefix


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def anon_fs() -> client.FileSystem:
    return client.FileSystem(ANON_URL)


def gsi_fs() -> client.FileSystem:
    os.environ["X509_CERT_DIR"]   = CA_DIR
    os.environ["X509_USER_PROXY"] = PROXY_PEM
    return client.FileSystem(GSI_URL)


def anon_file() -> client.File:
    return client.File()


def gsi_file() -> client.File:
    os.environ["X509_CERT_DIR"]   = CA_DIR
    os.environ["X509_USER_PROXY"] = PROXY_PEM
    return client.File()


def disk(name: str) -> str:
    """Absolute on-disk path for a name inside DATA_DIR."""
    return os.path.join(DATA_DIR, name.lstrip("/"))


def md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def md5file(path: str) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def clean_prefix():
    """Remove all PREFIX artefacts before and after every test."""
    _cleanup_prefix()
    yield
    _cleanup_prefix()


def _cleanup_prefix():
    for name in list(os.listdir(DATA_DIR)):
        if not name.startswith(PREFIX):
            continue
        full = os.path.join(DATA_DIR, name)
        if os.path.isfile(full) or os.path.islink(full):
            os.unlink(full)
        elif os.path.isdir(full):
            _rmtree(full)


def _rmtree(path: str):
    for root, dirs, files in os.walk(path, topdown=False):
        for f in files:
            os.unlink(os.path.join(root, f))
        for d in dirs:
            os.rmdir(os.path.join(root, d))
    os.rmdir(path)


# ---------------------------------------------------------------------------
# TestFileCreate — opening files for writing
# ---------------------------------------------------------------------------

class TestFileCreate:

    def test_create_new_file(self):
        """Open a new file (NEW flag), close it, confirm it exists on disk."""
        f = anon_file()
        status, _ = f.open(f"{ANON_URL}//{PREFIX}new.txt",
                            OpenFlags.NEW | OpenFlags.UPDATE)
        assert status.ok, f"open NEW failed: {status.message}"
        f.close()
        assert os.path.exists(disk(f"{PREFIX}new.txt"))

    def test_create_new_file_gsi(self):
        """Create a file over the GSI endpoint."""
        f = gsi_file()
        status, _ = f.open(f"{GSI_URL}//{PREFIX}gsi_new.txt",
                            OpenFlags.NEW | OpenFlags.UPDATE)
        assert status.ok, f"GSI open NEW failed: {status.message}"
        f.close()
        assert os.path.exists(disk(f"{PREFIX}gsi_new.txt"))

    def test_create_existing_file_new_flag_fails(self):
        """NEW flag on an existing path must fail."""
        p = disk(f"{PREFIX}exists.txt")
        open(p, "w").write("pre-existing\n")
        f = anon_file()
        status, _ = f.open(f"{ANON_URL}//{PREFIX}exists.txt",
                            OpenFlags.NEW | OpenFlags.UPDATE)
        assert not status.ok, "Expected NEW on existing file to fail"

    def test_create_with_delete_flag_truncates(self):
        """DELETE flag creates file or truncates if it already exists."""
        p = disk(f"{PREFIX}trunc.txt")
        open(p, "wb").write(b"original content that should be gone")
        f = anon_file()
        status, _ = f.open(f"{ANON_URL}//{PREFIX}trunc.txt",
                            OpenFlags.DELETE | OpenFlags.UPDATE)
        assert status.ok, f"open DELETE failed: {status.message}"
        f.write(b"new", offset=0)
        f.close()
        assert open(p, "rb").read() == b"new"

    def test_create_with_force_flag_overwrites(self):
        """FORCE flag opens existing file without failing."""
        p = disk(f"{PREFIX}force.txt")
        open(p, "wb").write(b"old")
        f = anon_file()
        status, _ = f.open(f"{ANON_URL}//{PREFIX}force.txt",
                            OpenFlags.DELETE | OpenFlags.FORCE | OpenFlags.UPDATE)
        assert status.ok, f"open FORCE failed: {status.message}"
        f.close()

    def test_create_with_makepath_flag(self):
        """MAKEPATH flag creates parent directories automatically."""
        f = anon_file()
        status, _ = f.open(
            f"{ANON_URL}//{PREFIX}subdir/deep/{PREFIX}file.txt",
            OpenFlags.NEW | OpenFlags.UPDATE | OpenFlags.MAKEPATH,
        )
        assert status.ok, f"open MAKEPATH failed: {status.message}"
        f.close()
        assert os.path.isfile(disk(f"{PREFIX}subdir/deep/{PREFIX}file.txt"))

    def test_open_nonexistent_for_read_fails(self):
        """Opening a nonexistent path for read must fail."""
        f = anon_file()
        status, _ = f.open(f"{ANON_URL}//{PREFIX}ghost.txt", OpenFlags.READ)
        assert not status.ok, "Expected open of nonexistent file to fail"

    def test_open_directory_for_read_fails(self):
        """Opening a directory as a file must fail."""
        os.makedirs(disk(f"{PREFIX}adir"), exist_ok=True)
        f = anon_file()
        status, _ = f.open(f"{ANON_URL}//{PREFIX}adir", OpenFlags.READ)
        assert not status.ok, "Expected open of directory to fail"


# ---------------------------------------------------------------------------
# TestFileWrite — write, read-back, and data integrity
# ---------------------------------------------------------------------------

class TestFileWrite:

    def test_write_and_read_back(self):
        """Write data, close, re-open for read, verify bytes match."""
        content = b"The quick brown fox jumps over the lazy dog\n"
        f = anon_file()
        f.open(f"{ANON_URL}//{PREFIX}rw.txt",
               OpenFlags.NEW | OpenFlags.UPDATE)
        status, _ = f.write(content, offset=0)
        assert status.ok, f"write failed: {status.message}"
        f.close()

        g = anon_file()
        g.open(f"{ANON_URL}//{PREFIX}rw.txt", OpenFlags.READ)
        status, data = g.read(offset=0, size=len(content))
        assert status.ok, f"read failed: {status.message}"
        assert data == content
        g.close()

    def test_write_at_offset(self):
        """Write data at a non-zero offset; bytes before offset are zero-filled."""
        f = anon_file()
        f.open(f"{ANON_URL}//{PREFIX}offset.bin",
               OpenFlags.NEW | OpenFlags.UPDATE)
        f.write(b"WORLD", offset=6)
        f.close()
        raw = open(disk(f"{PREFIX}offset.bin"), "rb").read()
        assert raw == b"\x00" * 6 + b"WORLD"

    def test_write_overwrite_middle(self):
        """Overwrite bytes in the middle of an existing file."""
        p = disk(f"{PREFIX}mid.txt")
        open(p, "wb").write(b"Hello World!")
        f = anon_file()
        f.open(f"{ANON_URL}//{PREFIX}mid.txt", OpenFlags.UPDATE)
        f.write(b"XRootD", offset=6)
        f.close()
        assert open(p, "rb").read() == b"Hello XRootD"

    def test_write_multiple_chunks(self):
        """Write in several calls; verify the assembled file is correct."""
        chunks = [b"chunk%d:" % i + b"x" * 100 for i in range(8)]
        f = anon_file()
        f.open(f"{ANON_URL}//{PREFIX}chunks.bin",
               OpenFlags.NEW | OpenFlags.UPDATE)
        offset = 0
        for chunk in chunks:
            status, _ = f.write(chunk, offset=offset)
            assert status.ok
            offset += len(chunk)
        f.close()
        expected = b"".join(chunks)
        assert open(disk(f"{PREFIX}chunks.bin"), "rb").read() == expected

    def test_write_large_file_md5(self):
        """Upload 30 MiB via xrdcp and verify MD5 integrity."""
        size = 30 * 1024 * 1024
        data = os.urandom(size)
        expected = md5(data)
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(data)
            local = tmp.name
        rc = os.system(
            f"xrdcp {local} {ANON_URL}//{PREFIX}large.bin 2>/dev/null"
        )
        os.unlink(local)
        assert rc == 0, "xrdcp upload failed"
        assert md5file(disk(f"{PREFIX}large.bin")) == expected

    def test_partial_read(self):
        """Read a sub-range of a file."""
        content = b"0123456789ABCDEF"
        p = disk(f"{PREFIX}partial.bin")
        open(p, "wb").write(content)
        f = anon_file()
        f.open(f"{ANON_URL}//{PREFIX}partial.bin", OpenFlags.READ)
        status, data = f.read(offset=4, size=6)
        assert status.ok
        assert data == b"456789"
        f.close()

    def test_read_beyond_eof_returns_short(self):
        """Reading past EOF returns fewer bytes than requested (not an error)."""
        content = b"short"
        p = disk(f"{PREFIX}short.bin")
        open(p, "wb").write(content)
        f = anon_file()
        f.open(f"{ANON_URL}//{PREFIX}short.bin", OpenFlags.READ)
        status, data = f.read(offset=0, size=1000)
        assert status.ok
        assert data == content
        f.close()

    def test_read_from_write_only_file_fails(self):
        """Reading from a file opened write-only must be rejected."""
        f = anon_file()
        f.open(f"{ANON_URL}//{PREFIX}wo.txt",
               OpenFlags.NEW | OpenFlags.WRITE)
        status, _ = f.read(offset=0, size=10)
        assert not status.ok, "Expected read on write-only file to fail"
        f.close()

    def test_write_to_read_only_file_fails(self):
        """Writing to a file opened read-only must be rejected."""
        p = disk(f"{PREFIX}ro.txt")
        open(p, "wb").write(b"read only")
        f = anon_file()
        f.open(f"{ANON_URL}//{PREFIX}ro.txt", OpenFlags.READ)
        status, _ = f.write(b"oops", offset=0)
        assert not status.ok, "Expected write on read-only file to fail"
        f.close()

    def test_write_to_server_without_allow_write_fails(self):
        """Anonymous write blocked when xrootd_allow_write is off — tested via
        GSI port without credentials (rejects auth, not write flag)."""
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(b"blocked")
            local = tmp.name
        cmd = (
            "env -u X509_USER_PROXY -u X509_CERT_DIR "
            f"xrdcp {local} {GSI_URL}//{PREFIX}blocked.txt 2>/dev/null"
        )
        rc = os.system(cmd)
        os.unlink(local)
        assert rc != 0, "Expected write without GSI creds to fail"

    def test_gsi_write_and_read_back(self):
        """Write and read back a file over the GSI endpoint."""
        content = b"GSI write/read round-trip: " + os.urandom(64)
        f = gsi_file()
        f.open(f"{GSI_URL}//{PREFIX}gsi_rw.bin",
               OpenFlags.NEW | OpenFlags.UPDATE)
        f.write(content, offset=0)
        f.close()

        g = gsi_file()
        g.open(f"{GSI_URL}//{PREFIX}gsi_rw.bin", OpenFlags.READ)
        status, data = g.read(offset=0, size=len(content))
        assert status.ok
        assert data == content
        g.close()


# ---------------------------------------------------------------------------
# TestFileSync — fsync via File API
# ---------------------------------------------------------------------------

class TestFileSync:

    def test_sync_flushes_to_disk(self):
        """sync() succeeds and data is on disk immediately after."""
        content = b"synced content"
        f = anon_file()
        f.open(f"{ANON_URL}//{PREFIX}sync.txt",
               OpenFlags.NEW | OpenFlags.UPDATE)
        f.write(content, offset=0)
        status, _ = f.sync()
        assert status.ok, f"sync failed: {status.message}"
        assert open(disk(f"{PREFIX}sync.txt"), "rb").read() == content
        f.close()

    def test_sync_on_read_only_file(self):
        """sync() on a read-only file handle succeeds (nothing to flush)."""
        p = disk(f"{PREFIX}sync_ro.txt")
        open(p, "wb").write(b"data")
        f = anon_file()
        f.open(f"{ANON_URL}//{PREFIX}sync_ro.txt", OpenFlags.READ)
        status, _ = f.sync()
        assert status.ok, f"sync on read-only failed: {status.message}"
        f.close()


# ---------------------------------------------------------------------------
# TestFileTruncate — truncate via File and FileSystem APIs
# ---------------------------------------------------------------------------

class TestFileTruncate:

    def test_truncate_shrink_via_handle(self):
        """File.truncate() to a smaller size trims the file."""
        content = b"Hello, World! Extra bytes here."
        f = anon_file()
        f.open(f"{ANON_URL}//{PREFIX}trunc_shrink.txt",
               OpenFlags.NEW | OpenFlags.UPDATE)
        f.write(content, offset=0)
        f.sync()
        status, _ = f.truncate(13)
        assert status.ok, f"truncate failed: {status.message}"
        f.close()
        assert open(disk(f"{PREFIX}trunc_shrink.txt"), "rb").read() == b"Hello, World!"

    def test_truncate_extend_via_handle(self):
        """File.truncate() to a larger size zero-extends the file."""
        f = anon_file()
        f.open(f"{ANON_URL}//{PREFIX}trunc_ext.bin",
               OpenFlags.NEW | OpenFlags.UPDATE)
        f.write(b"AB", offset=0)
        f.sync()
        status, _ = f.truncate(5)
        assert status.ok, f"truncate extend failed: {status.message}"
        f.close()
        assert open(disk(f"{PREFIX}trunc_ext.bin"), "rb").read() == b"AB\x00\x00\x00"

    def test_truncate_to_zero(self):
        """Truncate a file to zero bytes."""
        p = disk(f"{PREFIX}zero.txt")
        open(p, "wb").write(b"some content")
        f = anon_file()
        f.open(f"{ANON_URL}//{PREFIX}zero.txt", OpenFlags.UPDATE)
        status, _ = f.truncate(0)
        assert status.ok
        f.close()
        assert os.path.getsize(p) == 0

    def test_fs_truncate_path_based(self):
        """FileSystem.truncate() by path shortens the file."""
        p = disk(f"{PREFIX}fs_trunc.bin")
        open(p, "wb").write(b"x" * 500)
        fs = anon_fs()
        status, _ = fs.truncate(f"/{PREFIX}fs_trunc.bin", 100)
        assert status.ok, f"fs.truncate failed: {status.message}"
        assert os.path.getsize(p) == 100

    def test_fs_truncate_nonexistent_fails(self):
        """FileSystem.truncate() on a nonexistent path must fail."""
        fs = anon_fs()
        status, _ = fs.truncate(f"/{PREFIX}ghost.bin", 0)
        assert not status.ok, "Expected truncate of nonexistent file to fail"

    def test_truncate_gsi(self):
        """Truncate a file over the GSI endpoint."""
        p = disk(f"{PREFIX}gsi_trunc.txt")
        open(p, "wb").write(b"too long content here")
        fs = gsi_fs()
        status, _ = fs.truncate(f"/{PREFIX}gsi_trunc.txt", 8)
        assert status.ok, f"GSI truncate failed: {status.message}"
        assert os.path.getsize(p) == 8


# ---------------------------------------------------------------------------
# TestStat — stat via FileSystem and File APIs
# ---------------------------------------------------------------------------

class TestStat:

    def test_stat_regular_file(self):
        """Stat a regular file: correct size and IS_READABLE flag."""
        content = b"stat me"
        p = disk(f"{PREFIX}stat_file.txt")
        open(p, "wb").write(content)
        fs = anon_fs()
        status, info = fs.stat(f"/{PREFIX}stat_file.txt")
        assert status.ok, f"stat failed: {status.message}"
        assert info.size == len(content)
        assert info.flags & StatInfoFlags.IS_READABLE

    def test_stat_directory(self):
        """Stat a directory: IS_DIR flag must be set."""
        p = disk(f"{PREFIX}stat_dir")
        os.makedirs(p, exist_ok=True)
        fs = anon_fs()
        status, info = fs.stat(f"/{PREFIX}stat_dir")
        assert status.ok, f"stat dir failed: {status.message}"
        assert info.flags & StatInfoFlags.IS_DIR

    def test_stat_nonexistent_fails(self):
        """Stat of a nonexistent path must return an error."""
        fs = anon_fs()
        status, _ = fs.stat(f"/{PREFIX}ghost.txt")
        assert not status.ok, "Expected stat of nonexistent file to fail"

    def test_stat_root(self):
        """Stat the root directory: IS_DIR, no error."""
        fs = anon_fs()
        status, info = fs.stat("/")
        assert status.ok, f"stat root failed: {status.message}"
        assert info.flags & StatInfoFlags.IS_DIR

    def test_stat_size_after_write(self):
        """stat reflects updated size after writing."""
        content = b"x" * 4096
        p = disk(f"{PREFIX}stat_size.bin")
        open(p, "wb").write(content)
        fs = anon_fs()
        status, info = fs.stat(f"/{PREFIX}stat_size.bin")
        assert status.ok
        assert info.size == 4096

    def test_stat_modtime_is_recent(self):
        """stat modtime is set to a plausible timestamp."""
        import time
        p = disk(f"{PREFIX}stat_mtime.txt")
        open(p, "w").write("hello")
        fs = anon_fs()
        status, info = fs.stat(f"/{PREFIX}stat_mtime.txt")
        assert status.ok
        assert info.modtime > 0
        assert abs(info.modtime - time.time()) < 60, (
            f"modtime {info.modtime} suspiciously far from now"
        )

    def test_handle_stat_read_open(self):
        """File.stat() via handle returns correct size for a read-opened file."""
        content = b"handle stat data"
        p = disk(f"{PREFIX}hstat.bin")
        open(p, "wb").write(content)
        f = anon_file()
        f.open(f"{ANON_URL}//{PREFIX}hstat.bin", OpenFlags.READ)
        status, info = f.stat()
        assert status.ok, f"handle stat failed: {status.message}"
        assert info.size == len(content)
        f.close()

    def test_stat_gsi(self):
        """Stat a file over the GSI endpoint."""
        content = b"gsi stat test"
        p = disk(f"{PREFIX}gsi_stat.txt")
        open(p, "wb").write(content)
        fs = gsi_fs()
        status, info = fs.stat(f"/{PREFIX}gsi_stat.txt")
        assert status.ok, f"GSI stat failed: {status.message}"
        assert info.size == len(content)


# ---------------------------------------------------------------------------
# TestDirList — directory listing
# ---------------------------------------------------------------------------

class TestDirList:

    def _names(self, listing) -> set:
        return {e.name for e in listing} if listing else set()

    def test_dirlist_root(self):
        """Listing the root succeeds and returns at least one entry."""
        open(disk(f"{PREFIX}dl_file.txt"), "w").write("x")
        fs = anon_fs()
        status, listing = fs.dirlist("/")
        assert status.ok, f"dirlist failed: {status.message}"
        names = self._names(listing)
        assert f"{PREFIX}dl_file.txt" in names

    def test_dirlist_with_stat(self):
        """DirListFlags.STAT provides statinfo for each entry."""
        p = disk(f"{PREFIX}dl_stat.bin")
        open(p, "wb").write(b"y" * 42)
        fs = anon_fs()
        status, listing = fs.dirlist("/", DirListFlags.STAT)
        assert status.ok
        entry = next(
            (e for e in listing if e.name == f"{PREFIX}dl_stat.bin"), None
        )
        assert entry is not None, "Expected file in listing"
        assert entry.statinfo is not None
        assert entry.statinfo.size == 42

    def test_dirlist_subdirectory(self):
        """List a subdirectory; only its immediate children appear."""
        sub = disk(f"{PREFIX}dl_sub")
        os.makedirs(sub, exist_ok=True)
        open(os.path.join(sub, "child.txt"), "w").write("c")
        os.makedirs(os.path.join(sub, "nested"), exist_ok=True)
        fs = anon_fs()
        status, listing = fs.dirlist(f"/{PREFIX}dl_sub")
        assert status.ok, f"dirlist subdir failed: {status.message}"
        names = self._names(listing)
        assert "child.txt" in names
        assert "nested" in names

    def test_dirlist_empty_directory(self):
        """Listing an empty directory succeeds with zero entries."""
        os.makedirs(disk(f"{PREFIX}dl_empty"), exist_ok=True)
        fs = anon_fs()
        status, listing = fs.dirlist(f"/{PREFIX}dl_empty")
        assert status.ok, f"dirlist empty dir failed: {status.message}"
        assert len(list(listing)) == 0

    def test_dirlist_nonexistent_fails(self):
        """Listing a nonexistent directory must fail."""
        fs = anon_fs()
        status, _ = fs.dirlist(f"/{PREFIX}dl_ghost")
        assert not status.ok, "Expected dirlist of nonexistent dir to fail"

    def test_dirlist_distinguishes_files_and_dirs(self):
        """STAT listing marks directories with IS_DIR flag."""
        sub = disk(f"{PREFIX}dl_types")
        os.makedirs(sub, exist_ok=True)
        open(os.path.join(sub, "file.txt"), "w").write("f")
        os.makedirs(os.path.join(sub, "subdir"), exist_ok=True)
        fs = anon_fs()
        status, listing = fs.dirlist(f"/{PREFIX}dl_types", DirListFlags.STAT)
        assert status.ok
        by_name = {e.name: e for e in listing}
        assert by_name["file.txt"].statinfo.flags & StatInfoFlags.IS_DIR == 0
        assert by_name["subdir"].statinfo.flags & StatInfoFlags.IS_DIR

    def test_dirlist_gsi(self):
        """List a directory over the GSI endpoint."""
        sub = disk(f"{PREFIX}dl_gsi")
        os.makedirs(sub, exist_ok=True)
        open(os.path.join(sub, "gsi_child.txt"), "w").write("g")
        fs = gsi_fs()
        status, listing = fs.dirlist(f"/{PREFIX}dl_gsi")
        assert status.ok, f"GSI dirlist failed: {status.message}"
        assert "gsi_child.txt" in self._names(listing)


# ---------------------------------------------------------------------------
# TestMkdir — directory creation (extended)
# ---------------------------------------------------------------------------

class TestMkdir:

    def test_mkdir_basic(self):
        fs = anon_fs()
        status, _ = fs.mkdir(f"/{PREFIX}mkdir_basic", MkDirFlags.NONE)
        assert status.ok, f"mkdir failed: {status.message}"
        assert os.path.isdir(disk(f"{PREFIX}mkdir_basic"))

    def test_mkdir_nested_with_makepath(self):
        fs = anon_fs()
        status, _ = fs.mkdir(
            f"/{PREFIX}mkdir_nested/a/b/c", MkDirFlags.MAKEPATH
        )
        assert status.ok, f"mkdir -p failed: {status.message}"
        assert os.path.isdir(disk(f"{PREFIX}mkdir_nested/a/b/c"))

    def test_mkdir_idempotent(self):
        """mkdir on an existing directory must not return an error."""
        os.makedirs(disk(f"{PREFIX}mkdir_idem"), exist_ok=True)
        fs = anon_fs()
        status, _ = fs.mkdir(f"/{PREFIX}mkdir_idem", MkDirFlags.NONE)
        assert status.ok, f"mkdir on existing failed: {status.message}"

    def test_mkdir_gsi(self):
        fs = gsi_fs()
        status, _ = fs.mkdir(f"/{PREFIX}mkdir_gsi", MkDirFlags.NONE)
        assert status.ok, f"GSI mkdir failed: {status.message}"
        assert os.path.isdir(disk(f"{PREFIX}mkdir_gsi"))


# ---------------------------------------------------------------------------
# TestRmdir — directory removal (extended)
# ---------------------------------------------------------------------------

class TestRmdir:

    def test_rmdir_empty(self):
        os.makedirs(disk(f"{PREFIX}rmdir_empty"), exist_ok=True)
        fs = anon_fs()
        status, _ = fs.rmdir(f"/{PREFIX}rmdir_empty")
        assert status.ok, f"rmdir failed: {status.message}"
        assert not os.path.exists(disk(f"{PREFIX}rmdir_empty"))

    def test_rmdir_nonempty_fails(self):
        d = disk(f"{PREFIX}rmdir_full")
        os.makedirs(d, exist_ok=True)
        open(os.path.join(d, "f.txt"), "w").close()
        fs = anon_fs()
        status, _ = fs.rmdir(f"/{PREFIX}rmdir_full")
        assert not status.ok, "Expected rmdir of non-empty dir to fail"

    def test_rmdir_nonexistent_fails(self):
        fs = anon_fs()
        status, _ = fs.rmdir(f"/{PREFIX}rmdir_ghost")
        assert not status.ok, "Expected rmdir of nonexistent dir to fail"

    def test_rmdir_on_file_fails(self):
        """rmdir on a regular file must fail."""
        open(disk(f"{PREFIX}rmdir_isfile.txt"), "w").close()
        fs = anon_fs()
        status, _ = fs.rmdir(f"/{PREFIX}rmdir_isfile.txt")
        assert not status.ok, "Expected rmdir on a file to fail"

    def test_rmdir_gsi(self):
        os.makedirs(disk(f"{PREFIX}rmdir_gsi"), exist_ok=True)
        fs = gsi_fs()
        status, _ = fs.rmdir(f"/{PREFIX}rmdir_gsi")
        assert status.ok, f"GSI rmdir failed: {status.message}"


# ---------------------------------------------------------------------------
# TestRm — file removal (extended)
# ---------------------------------------------------------------------------

class TestRm:

    def test_rm_file(self):
        p = disk(f"{PREFIX}rm_file.txt")
        open(p, "w").write("delete me")
        fs = anon_fs()
        status, _ = fs.rm(f"/{PREFIX}rm_file.txt")
        assert status.ok, f"rm failed: {status.message}"
        assert not os.path.exists(p)

    def test_rm_nonexistent_fails(self):
        fs = anon_fs()
        status, _ = fs.rm(f"/{PREFIX}rm_ghost.txt")
        assert not status.ok, "Expected rm of nonexistent file to fail"

    def test_rm_directory_fails(self):
        """rm on a directory must fail; use rmdir instead."""
        os.makedirs(disk(f"{PREFIX}rm_dir"), exist_ok=True)
        fs = anon_fs()
        status, _ = fs.rm(f"/{PREFIX}rm_dir")
        assert not status.ok, "Expected rm on directory to fail"

    def test_rm_gsi(self):
        p = disk(f"{PREFIX}rm_gsi.txt")
        open(p, "w").write("gsi delete me")
        fs = gsi_fs()
        status, _ = fs.rm(f"/{PREFIX}rm_gsi.txt")
        assert status.ok, f"GSI rm failed: {status.message}"
        assert not os.path.exists(p)

    def test_rm_then_recreate(self):
        """After rm, the same name can be created again."""
        p = disk(f"{PREFIX}rm_recr.txt")
        open(p, "w").write("v1")
        fs = anon_fs()
        fs.rm(f"/{PREFIX}rm_recr.txt")
        assert not os.path.exists(p)
        f = anon_file()
        status, _ = f.open(f"{ANON_URL}//{PREFIX}rm_recr.txt",
                            OpenFlags.NEW | OpenFlags.UPDATE)
        assert status.ok, "Expected re-create after rm to succeed"
        f.write(b"v2", offset=0)
        f.close()
        assert open(p, "rb").read() == b"v2"


# ---------------------------------------------------------------------------
# TestMv — rename / move (extended)
# ---------------------------------------------------------------------------

class TestMv:

    def test_mv_file(self):
        src = disk(f"{PREFIX}mv_src.txt")
        dst = disk(f"{PREFIX}mv_dst.txt")
        open(src, "w").write("move me")
        fs = anon_fs()
        status, _ = fs.mv(f"/{PREFIX}mv_src.txt", f"/{PREFIX}mv_dst.txt")
        assert status.ok, f"mv failed: {status.message}"
        assert not os.path.exists(src)
        assert open(dst).read() == "move me"

    def test_mv_directory(self):
        src = disk(f"{PREFIX}mv_dir_src")
        dst = disk(f"{PREFIX}mv_dir_dst")
        os.makedirs(src, exist_ok=True)
        open(os.path.join(src, "f.txt"), "w").close()
        fs = anon_fs()
        status, _ = fs.mv(f"/{PREFIX}mv_dir_src", f"/{PREFIX}mv_dir_dst")
        assert status.ok, f"mv dir failed: {status.message}"
        assert not os.path.exists(src)
        assert os.path.isdir(dst)
        assert os.path.exists(os.path.join(dst, "f.txt"))

    def test_mv_overwrites_destination(self):
        """mv onto an existing file replaces it (rename() semantics)."""
        src = disk(f"{PREFIX}mv_ow_src.txt")
        dst = disk(f"{PREFIX}mv_ow_dst.txt")
        open(src, "wb").write(b"source content")
        open(dst, "wb").write(b"old destination")
        fs = anon_fs()
        status, _ = fs.mv(f"/{PREFIX}mv_ow_src.txt", f"/{PREFIX}mv_ow_dst.txt")
        assert status.ok, f"mv overwrite failed: {status.message}"
        assert not os.path.exists(src)
        assert open(dst, "rb").read() == b"source content"

    def test_mv_nonexistent_source_fails(self):
        fs = anon_fs()
        status, _ = fs.mv(f"/{PREFIX}mv_ghost.txt", f"/{PREFIX}mv_nowhere.txt")
        assert not status.ok, "Expected mv of nonexistent source to fail"

    def test_mv_gsi(self):
        src = disk(f"{PREFIX}mv_gsi_src.txt")
        dst = disk(f"{PREFIX}mv_gsi_dst.txt")
        open(src, "w").write("gsi move")
        fs = gsi_fs()
        status, _ = fs.mv(f"/{PREFIX}mv_gsi_src.txt", f"/{PREFIX}mv_gsi_dst.txt")
        assert status.ok, f"GSI mv failed: {status.message}"
        assert not os.path.exists(src)
        assert os.path.exists(dst)


# ---------------------------------------------------------------------------
# TestChmod — permission changes (extended)
# ---------------------------------------------------------------------------

class TestChmod:

    def test_chmod_file_to_readonly(self):
        p = disk(f"{PREFIX}chmod_ro.txt")
        open(p, "w").write("data")
        os.chmod(p, 0o644)
        fs = anon_fs()
        status, _ = fs.chmod(
            f"/{PREFIX}chmod_ro.txt",
            AccessMode.UR | AccessMode.GR | AccessMode.OR,
        )
        assert status.ok, f"chmod failed: {status.message}"
        assert stat.S_IMODE(os.stat(p).st_mode) == 0o444

    def test_chmod_file_to_executable(self):
        p = disk(f"{PREFIX}chmod_exec.sh")
        open(p, "w").write("#!/bin/sh\n")
        os.chmod(p, 0o644)
        fs = anon_fs()
        status, _ = fs.chmod(
            f"/{PREFIX}chmod_exec.sh",
            AccessMode.UR | AccessMode.UW | AccessMode.UX |
            AccessMode.GR | AccessMode.GX |
            AccessMode.OR | AccessMode.OX,
        )
        assert status.ok
        assert stat.S_IMODE(os.stat(p).st_mode) == 0o755

    def test_chmod_directory(self):
        d = disk(f"{PREFIX}chmod_dir")
        os.makedirs(d, exist_ok=True)
        os.chmod(d, 0o755)
        fs = anon_fs()
        status, _ = fs.chmod(
            f"/{PREFIX}chmod_dir",
            AccessMode.UR | AccessMode.UW | AccessMode.UX |
            AccessMode.GR | AccessMode.GX,
        )
        assert status.ok, f"chmod dir failed: {status.message}"
        assert stat.S_IMODE(os.stat(d).st_mode) == 0o750

    def test_chmod_nonexistent_fails(self):
        fs = anon_fs()
        status, _ = fs.chmod(f"/{PREFIX}chmod_ghost.txt", AccessMode.UR)
        assert not status.ok, "Expected chmod of nonexistent path to fail"

    def test_chmod_stat_reflects_change(self):
        """After chmod, stat flags show the new permissions."""
        p = disk(f"{PREFIX}chmod_stat.txt")
        open(p, "wb").write(b"data")
        os.chmod(p, 0o000)          # no permissions
        fs = anon_fs()
        fs.chmod(
            f"/{PREFIX}chmod_stat.txt",
            AccessMode.UR | AccessMode.GR | AccessMode.OR,
        )
        status, info = fs.stat(f"/{PREFIX}chmod_stat.txt")
        assert status.ok
        assert info.flags & StatInfoFlags.IS_READABLE

    def test_chmod_gsi(self):
        p = disk(f"{PREFIX}chmod_gsi.txt")
        open(p, "w").write("gsi chmod")
        os.chmod(p, 0o644)
        fs = gsi_fs()
        status, _ = fs.chmod(
            f"/{PREFIX}chmod_gsi.txt",
            AccessMode.UR | AccessMode.GR | AccessMode.OR,
        )
        assert status.ok, f"GSI chmod failed: {status.message}"
        assert stat.S_IMODE(os.stat(p).st_mode) == 0o444


# ---------------------------------------------------------------------------
# TestPathSecurity — path traversal boundaries
# ---------------------------------------------------------------------------

class TestPathSecurity:

    def test_open_dotdot_path_rejected(self):
        """Paths containing '..' must be rejected at open."""
        f = anon_file()
        status, _ = f.open(f"{ANON_URL}//../../etc/passwd", OpenFlags.READ)
        assert not status.ok, "Expected .. traversal to be rejected"

    def test_stat_dotdot_path_rejected(self):
        """Paths containing '..' must be rejected at stat."""
        fs = anon_fs()
        status, _ = fs.stat("/../../etc/passwd")
        assert not status.ok, "Expected .. traversal in stat to be rejected"

    def test_rm_dotdot_path_rejected(self):
        """rm with '..' in path must be rejected."""
        fs = anon_fs()
        status, _ = fs.rm("/../../tmp/something")
        assert not status.ok, "Expected .. traversal in rm to be rejected"

    def test_mkdir_dotdot_path_rejected(self):
        """mkdir with '..' must be rejected."""
        fs = anon_fs()
        status, _ = fs.mkdir("/../../tmp/evil", MkDirFlags.MAKEPATH)
        assert not status.ok, "Expected .. traversal in mkdir to be rejected"
