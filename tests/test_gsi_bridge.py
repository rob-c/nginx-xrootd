"""
tests/test_gsi_bridge.py

Cross-server GSI transfer tests: copy files between an official xrootd server
and the nginx-xrootd plugin, both using GSI/x509 authentication and the local
test CA.

Topology
--------
                       GSI proxy cert (local test CA)
                               │
      xrootd server            │           nginx-xrootd plugin
      port 11097               │           port 11095
      /tmp/xrd-gsi-bridge/data │           /tmp/xrd-test/data
           │                   │                 │
           └─── xrdcp ─────────┴─── xrdcp ───────┘

Both servers use:
  - The same test CA: /tmp/xrd-test/pki/ca/
  - The same server certificate: /tmp/xrd-test/pki/server/hostcert.pem
  - The same user proxy:         /tmp/xrd-test/pki/user/proxy_std.pem

Tests
-----
  - xrootd → nginx  : copy a file from xrootd server to nginx endpoint
  - nginx  → xrootd : copy a file from nginx endpoint to xrootd server
  - round-trip      : upload to xrootd, copy to nginx, read back; check bytes
  - large file      : 10 MB transfer in each direction
  - auth required   : transfers without a proxy cert must fail on both servers
  - integrity       : adler32 checksums match after transfer

Run against already-running nginx-xrootd (port 11095) and a reference xrootd
server started by the session fixture on port 11097.

    pytest tests/test_gsi_bridge.py -v

Environment required:
    X509_CERT_DIR  — must not be set (we set it explicitly in each call)
    X509_USER_PROXY — must not be set (we set it explicitly)
"""

import hashlib
import os
import subprocess
import tempfile
import time
import zlib

import pytest
from XRootD import client
from XRootD.client.flags import OpenFlags, QueryCode

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CA_DIR     = "/tmp/xrd-test/pki/ca"
PROXY_PEM  = "/tmp/xrd-test/pki/user/proxy_std.pem"
SERVER_CERT = "/tmp/xrd-test/pki/server/hostcert.pem"
SERVER_KEY  = "/tmp/xrd-test/pki/server/hostkey.pem"

NGINX_PORT = 11095
NGINX_URL  = f"root://localhost:{NGINX_PORT}"

REF_PORT   = 11097
REF_URL    = f"root://localhost:{REF_PORT}"

BRIDGE_DATA = "/tmp/xrd-gsi-bridge/data"
NGINX_DATA  = "/tmp/xrd-test/data"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _gsi_env() -> dict:
    """Environment variables for GSI-authenticated xrdcp / XRootD client calls."""
    env = os.environ.copy()
    env["X509_CERT_DIR"]   = CA_DIR
    env["X509_USER_PROXY"] = PROXY_PEM
    env["XrdSecPROTOCOL"]  = "gsi"
    # Remove any conflicting env vars from the parent shell
    env.pop("X509_USER_CERT", None)
    env.pop("X509_USER_KEY",  None)
    return env


def _no_gsi_env() -> dict:
    """Environment with no proxy certificate — auth should fail."""
    env = os.environ.copy()
    env.pop("X509_CERT_DIR",    None)
    env.pop("X509_USER_PROXY",  None)
    env.pop("X509_USER_CERT",   None)
    env.pop("X509_USER_KEY",    None)
    env["XrdSecPROTOCOL"] = "gsi"
    return env


def _gsi_client(url: str) -> client.FileSystem:
    """Return a FileSystem connected to *url* with GSI credentials."""
    env_patch = {
        "XRD_SECPROTOCOL":  "gsi",
    }
    # The Python XRootD client reads X509_* from the process environment.
    os.environ["X509_CERT_DIR"]   = CA_DIR
    os.environ["X509_USER_PROXY"] = PROXY_PEM
    os.environ["XrdSecPROTOCOL"]  = "gsi"
    return client.FileSystem(url)


def _xrdcp(src: str, dst: str, *, gsi: bool = True, extra_args: str = "") -> int:
    """
    Run xrdcp src → dst and return the exit code.

    src/dst may be local paths or root:// URLs.
    When gsi=True, injects X509_* and XrdSecPROTOCOL into the environment.
    Always force overwrite so repeated test runs do not fail on stale artifacts.
    """
    env = _gsi_env() if gsi else _no_gsi_env()
    cmd = f"xrdcp -f -s {extra_args} {src} {dst}"
    # Capture stdout/stderr so successful runs stay quiet and failures are inspectable.
    result = subprocess.run(cmd, shell=True, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.returncode


def _adler32(path: str) -> int:
    """Compute adler32 of a local file."""
    csum = 1
    with open(path, "rb") as f:
        # Adler32 is defined as an iterative checksum, so stream the file in chunks.
        for chunk in iter(lambda: f.read(65536), b""):
            csum = zlib.adler32(chunk, csum)
    return csum & 0xFFFFFFFF


def _md5(path: str) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _write_local(content: bytes) -> str:
    """Write *content* to a temp file and return the path."""
    fd, path = tempfile.mkstemp(prefix="xrd_bridge_", suffix=".bin")
    os.write(fd, content)
    os.close(fd)
    return path


# ---------------------------------------------------------------------------
# Session fixture: start reference xrootd with GSI authentication
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session", autouse=True)
def reference_xrootd_gsi(tmp_path_factory):
    """
    Start an official xrootd server on REF_PORT with GSI authentication
    enabled, using the same test CA and server certificates as the nginx-xrootd
    instance.

    The server's data directory is separate from the nginx data directory so we
    can distinguish which server read a particular file.

    Configuration directives:
      xrootd.seclib   — loads the xrootd security plugin framework
      sec.protocol gsi — enables the GSI protocol plugin (libXrdSecgsi)
        -certdir   : directory containing CA hashes (*.0 and *.signing_policy)
        -cert/-key : server certificate and private key
        -gmapopt:10: do not require a grid-mapfile entry; accept all valid certs
      acc.authdb      — 'u * / lr' grants all authenticated users read access
    """
    os.makedirs(BRIDGE_DATA, exist_ok=True)
    os.makedirs("/tmp/xrd-gsi-bridge/admin-conf", exist_ok=True)
    os.makedirs("/tmp/xrd-gsi-bridge/run-conf",   exist_ok=True)

    authdb_path = "/tmp/xrd-gsi-bridge/authdb"
    with open(authdb_path, "w") as f:
        # Grant all authenticated users read access to everything
        f.write("u * / lr\n")

    cfg_path = "/tmp/xrd-gsi-bridge/server.cfg"
    cfg = (
        f"xrd.port {REF_PORT}\n"
        f"oss.localroot {BRIDGE_DATA}\n"
        "all.export /\n"
        f"all.adminpath /tmp/xrd-gsi-bridge/admin-conf\n"
        f"all.pidpath   /tmp/xrd-gsi-bridge/run-conf\n"
        "xrd.trace off\n"
        # Security: load the xrootd security framework
        "xrootd.seclib /usr/lib64/libXrdSec-5.so\n"
        # Enable GSI protocol with our test CA and server certificate
        f"sec.protocol gsi "
        f"-certdir:{CA_DIR} "
        f"-cert:{SERVER_CERT} "
        f"-key:{SERVER_KEY} "
        f"-gmapopt:10\n"          # accept any valid cert; no grid-mapfile needed
        f"acc.authdb {authdb_path}\n"
    )
    with open(cfg_path, "w") as f:
        f.write(cfg)

    log_path = "/tmp/xrd-gsi-bridge/server.log"
    proc = subprocess.Popen(
        ["xrootd", "-c", cfg_path, "-l", log_path],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # Wait up to 15 s for GSI server to accept connections.
    # Older xrdfs builds do not implement a ping subcommand, so use a simple
    # authenticated directory listing rather than an anonymous Python client.
    ready = False
    for _ in range(30):
        try:
            # We probe with a real authenticated filesystem op, not just TCP reachability.
            r = subprocess.run(
                ["xrdfs", REF_URL, "ls", "/"],
                env=_gsi_env(),
                capture_output=True,
                timeout=5,
            )
        except subprocess.TimeoutExpired:
            # Early timeouts are normal while the auth plugin and listener come up.
            time.sleep(0.5)
            continue
        if r.returncode == 0:
            ready = True
            break
        time.sleep(0.5)

    if not ready:
        proc.terminate()
        with open(log_path) as fh:
            pytest.fail(
                f"Reference xrootd GSI server did not start on port {REF_PORT}.\n"
                f"Log:\n{fh.read()[-3000:]}"
            )

    yield proc

    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


# ---------------------------------------------------------------------------
# Helper fixture: ensure nginx GSI endpoint is reachable
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def nginx_gsi_ready():
    """Verify nginx-xrootd GSI endpoint on port 11095 is up before running tests."""
    for _ in range(10):
        try:
            r = subprocess.run(
                ["xrdfs", NGINX_URL, "ls", "/"],
                env=_gsi_env(),
                capture_output=True,
                timeout=5,
            )
        except subprocess.TimeoutExpired:
            # Keep polling; a slow handshake here is not yet a hard failure.
            time.sleep(0.5)
            continue
        if r.returncode == 0:
            return
        time.sleep(0.5)
    pytest.skip(
        f"nginx-xrootd GSI endpoint not reachable at {NGINX_URL}. "
        "Start nginx with: /tmp/nginx-1.28.3/objs/nginx -p /tmp/xrd-test "
        "-c /tmp/xrd-test/conf/nginx.conf"
    )


# ---------------------------------------------------------------------------
# Tests: xrootd → nginx (GSI on both ends)
# ---------------------------------------------------------------------------

class TestXrootdToNginx:
    """Copy files from the official xrootd server to the nginx-xrootd endpoint."""

    def test_small_file_transfer(self, reference_xrootd_gsi, nginx_gsi_ready):
        """Copy a small file from xrootd to nginx; verify content is identical."""
        content = b"Hello from official xrootd server via GSI!\n" * 10
        filename = "bridge_small_xrd_to_nginx.txt"

        # Write source file into xrootd's data directory
        src_path = os.path.join(BRIDGE_DATA, filename)
        with open(src_path, "wb") as f:
            f.write(content)

        # Copy xrootd → nginx via xrdcp (GSI on both ends)
        rc = _xrdcp(
            f"{REF_URL}//{filename}",
            f"{NGINX_URL}//{filename}",
        )
        assert rc == 0, "xrdcp xrootd→nginx failed"

        # Verify on nginx side
        dst_path = os.path.join(NGINX_DATA, filename)
        assert os.path.exists(dst_path), "File not found in nginx data dir"
        with open(dst_path, "rb") as f:
            got = f.read()
        assert got == content, "File content mismatch after xrootd→nginx transfer"

    def test_large_file_transfer(self, reference_xrootd_gsi, nginx_gsi_ready):
        """Transfer a 10 MB file from xrootd to nginx and verify md5."""
        size = 10 * 1024 * 1024
        content = bytes(range(256)) * (size // 256)
        filename = "bridge_large_xrd_to_nginx.bin"

        src_path = os.path.join(BRIDGE_DATA, filename)
        with open(src_path, "wb") as f:
            f.write(content)
        expected_md5 = _md5(src_path)

        rc = _xrdcp(
            f"{REF_URL}//{filename}",
            f"{NGINX_URL}//{filename}",
        )
        assert rc == 0, "xrdcp large file xrootd→nginx failed"

        dst_path = os.path.join(NGINX_DATA, filename)
        assert os.path.exists(dst_path)
        assert _md5(dst_path) == expected_md5, "md5 mismatch after 10 MB xrootd→nginx"

    def test_checksum_preserved(self, reference_xrootd_gsi, nginx_gsi_ready):
        """Adler32 checksum returned by nginx must match the source file's checksum."""
        content = b"checksum integrity test " * 512
        filename = "bridge_cksum_xrd_to_nginx.txt"

        src_path = os.path.join(BRIDGE_DATA, filename)
        with open(src_path, "wb") as f:
            f.write(content)
        expected = _adler32(src_path)

        rc = _xrdcp(f"{REF_URL}//{filename}", f"{NGINX_URL}//{filename}")
        assert rc == 0

        # Query checksum from nginx via GSI
        os.environ["X509_CERT_DIR"]   = CA_DIR
        os.environ["X509_USER_PROXY"] = PROXY_PEM
        os.environ["XrdSecPROTOCOL"]  = "gsi"
        fs = client.FileSystem(NGINX_URL)
        st, resp = fs.query(QueryCode.CHECKSUM, f"/{filename}")
        assert st.ok, f"Checksum query failed: {st.message}"

        # Response: b"adler32 <hex>\x00"
        parts = resp.decode("ascii", errors="replace").strip("\x00").split()
        assert len(parts) == 2 and parts[0] == "adler32"
        got = int(parts[1], 16)
        assert got == expected, (
            f"Checksum mismatch: nginx returned {got:#010x}, expected {expected:#010x}"
        )


# ---------------------------------------------------------------------------
# Tests: nginx → xrootd (GSI on both ends)
# ---------------------------------------------------------------------------

class TestNginxToXrootd:
    """Copy files from the nginx-xrootd endpoint to the official xrootd server."""

    def test_small_file_transfer(self, reference_xrootd_gsi, nginx_gsi_ready):
        """Upload to nginx, then copy nginx → xrootd; verify content."""
        content = b"Hello from nginx-xrootd via GSI!\n" * 10
        filename = "bridge_small_nginx_to_xrd.txt"

        # Upload to nginx
        local = _write_local(content)
        try:
            rc = _xrdcp(local, f"{NGINX_URL}//{filename}")
            assert rc == 0, "Upload to nginx failed"

            # Copy nginx → xrootd
            rc = _xrdcp(
                f"{NGINX_URL}//{filename}",
                f"{REF_URL}//{filename}",
            )
            assert rc == 0, "xrdcp nginx→xrootd failed"

            # Verify on disk in xrootd data dir
            dst_path = os.path.join(BRIDGE_DATA, filename)
            assert os.path.exists(dst_path)
            with open(dst_path, "rb") as f:
                got = f.read()
            assert got == content
        finally:
            os.unlink(local)

    def test_large_file_transfer(self, reference_xrootd_gsi, nginx_gsi_ready):
        """Upload 10 MB to nginx, copy to xrootd, verify md5."""
        size = 10 * 1024 * 1024
        content = os.urandom(size)
        filename = "bridge_large_nginx_to_xrd.bin"

        local = _write_local(content)
        try:
            expected_md5 = _md5(local)

            rc = _xrdcp(local, f"{NGINX_URL}//{filename}")
            assert rc == 0, "Upload 10 MB to nginx failed"

            rc = _xrdcp(
                f"{NGINX_URL}//{filename}",
                f"{REF_URL}//{filename}",
            )
            assert rc == 0, "xrdcp 10 MB nginx→xrootd failed"

            dst_path = os.path.join(BRIDGE_DATA, filename)
            assert _md5(dst_path) == expected_md5
        finally:
            os.unlink(local)


# ---------------------------------------------------------------------------
# Tests: round-trip transfers
# ---------------------------------------------------------------------------

class TestRoundTrip:
    """Upload, bridge, and read back to verify end-to-end GSI transfer integrity."""

    def test_xrootd_to_nginx_and_back(self, reference_xrootd_gsi, nginx_gsi_ready):
        """
        Write a file on xrootd → copy to nginx → read back from nginx.
        Verifies the full path: xrootd GSI read + nginx GSI write + nginx GSI read.
        """
        content = b"round-trip: xrootd write, nginx read\n" * 200
        filename = "bridge_roundtrip_fwd.txt"

        src_path = os.path.join(BRIDGE_DATA, filename)
        with open(src_path, "wb") as f:
            f.write(content)

        # xrootd → nginx
        rc = _xrdcp(f"{REF_URL}//{filename}", f"{NGINX_URL}//{filename}")
        assert rc == 0, "xrootd→nginx copy failed"

        # Read back from nginx via Python client (GSI)
        os.environ["X509_CERT_DIR"]   = CA_DIR
        os.environ["X509_USER_PROXY"] = PROXY_PEM
        os.environ["XrdSecPROTOCOL"]  = "gsi"
        f_obj = client.File()
        st, _ = f_obj.open(f"{NGINX_URL}//{filename}", OpenFlags.READ)
        assert st.ok, f"nginx GSI open failed: {st.message}"
        st, data = f_obj.read()
        assert st.ok
        f_obj.close()
        assert data == content, "Round-trip content mismatch (xrootd write → nginx read)"

    def test_nginx_to_xrootd_and_back(self, reference_xrootd_gsi, nginx_gsi_ready):
        """
        Upload to nginx → copy to xrootd → read back from xrootd.
        Verifies: nginx GSI write + xrootd GSI read.
        """
        content = b"round-trip: nginx write, xrootd read\n" * 200
        filename = "bridge_roundtrip_rev.txt"

        local = _write_local(content)
        try:
            rc = _xrdcp(local, f"{NGINX_URL}//{filename}")
            assert rc == 0, "Upload to nginx failed"

            rc = _xrdcp(
                f"{NGINX_URL}//{filename}",
                f"{REF_URL}//{filename}",
            )
            assert rc == 0, "nginx→xrootd copy failed"

            # Read back via xrdcp to a local temp file
            local_out = _write_local(b"")  # empty placeholder
            os.unlink(local_out)
            rc = _xrdcp(f"{REF_URL}//{filename}", local_out)
            assert rc == 0, "xrootd read-back failed"
            with open(local_out, "rb") as fh:
                got = fh.read()
            os.unlink(local_out)
            assert got == content, "Round-trip content mismatch (nginx write → xrootd read)"
        finally:
            os.unlink(local)

    def test_integrity_across_multiple_chunks(self, reference_xrootd_gsi, nginx_gsi_ready):
        """
        Transfer a file large enough to require multiple xrdcp read chunks (>4 MB),
        verifying that chunked reassembly produces identical bytes on both ends.
        """
        size = 12 * 1024 * 1024   # 12 MB — forces at least 3 read chunks
        content = os.urandom(size)
        filename = "bridge_multichunk.bin"

        src_path = os.path.join(BRIDGE_DATA, filename)
        with open(src_path, "wb") as f:
            f.write(content)
        expected_md5 = _md5(src_path)

        # xrootd → nginx
        rc = _xrdcp(f"{REF_URL}//{filename}", f"{NGINX_URL}//{filename}")
        assert rc == 0, "Multi-chunk xrootd→nginx failed"

        # Read back from nginx
        local_out = src_path + ".verify"
        rc = _xrdcp(f"{NGINX_URL}//{filename}", local_out)
        assert rc == 0, "Multi-chunk nginx read-back failed"
        try:
            assert _md5(local_out) == expected_md5
        finally:
            os.unlink(local_out)


# ---------------------------------------------------------------------------
# Tests: authentication enforcement
# ---------------------------------------------------------------------------

class TestAuthEnforcement:
    """Verify that GSI authentication is required and rejected credentials fail."""

    def test_no_proxy_rejected_by_nginx(self, reference_xrootd_gsi, nginx_gsi_ready):
        """
        xrdcp to nginx GSI port without a proxy certificate must fail.
        The server should refuse the connection at the authentication stage.
        """
        local = _write_local(b"should not be written\n")
        try:
            rc = _xrdcp(
                local,
                f"{NGINX_URL}//bridge_auth_test_no_proxy.txt",
                gsi=False,   # no X509 env vars
            )
            assert rc != 0, (
                "xrdcp to GSI nginx port without credentials should have failed"
            )
        finally:
            os.unlink(local)

    def test_no_proxy_rejected_by_xrootd(self, reference_xrootd_gsi, nginx_gsi_ready):
        """
        xrdcp to reference xrootd GSI port without a proxy must also fail,
        confirming the test CA setup enforces authentication on the xrootd side too.
        """
        local = _write_local(b"should not be written\n")
        try:
            # Write a file into xrootd's data dir to try reading without a proxy
            src_path = os.path.join(BRIDGE_DATA, "bridge_no_proxy_src.txt")
            with open(src_path, "wb") as f:
                f.write(b"secret")

            local_out = local + ".out"
            rc = _xrdcp(
                f"{REF_URL}//bridge_no_proxy_src.txt",
                local_out,
                gsi=False,
            )
            assert rc != 0, (
                "xrdcp from GSI xrootd port without credentials should have failed"
            )
            assert not os.path.exists(local_out), (
                "Output file should not exist when auth fails"
            )
        finally:
            os.unlink(local)

    def test_valid_proxy_accepted_by_both(self, reference_xrootd_gsi, nginx_gsi_ready):
        """
        With a valid proxy, transfers to both servers must succeed.
        This is the positive control for the auth tests above.
        """
        content = b"valid proxy accepted\n"
        filename = "bridge_auth_valid.txt"

        # Write to xrootd
        src_path = os.path.join(BRIDGE_DATA, filename)
        with open(src_path, "wb") as f:
            f.write(content)

        # Read from xrootd — must succeed
        local_out = src_path + ".verify"
        rc = _xrdcp(f"{REF_URL}//{filename}", local_out, gsi=True)
        assert rc == 0, "Valid GSI proxy should be accepted by xrootd"
        os.unlink(local_out)

        # Write to nginx — must succeed
        local = _write_local(content)
        try:
            rc = _xrdcp(local, f"{NGINX_URL}//{filename}", gsi=True)
            assert rc == 0, "Valid GSI proxy should be accepted by nginx-xrootd"
        finally:
            os.unlink(local)


# ---------------------------------------------------------------------------
# Tests: directory listing via GSI
# ---------------------------------------------------------------------------

class TestDirlistGSI:
    """Verify directory listing works across both GSI endpoints."""

    def test_nginx_dirlist_after_bridge_transfer(self, reference_xrootd_gsi, nginx_gsi_ready):
        """
        Files copied from xrootd to nginx must appear in nginx's directory listing.
        """
        filename = "bridge_dirlist_test.txt"
        content  = b"dirlist test file\n"

        src_path = os.path.join(BRIDGE_DATA, filename)
        with open(src_path, "wb") as f:
            f.write(content)

        rc = _xrdcp(f"{REF_URL}//{filename}", f"{NGINX_URL}//{filename}")
        assert rc == 0

        os.environ["X509_CERT_DIR"]   = CA_DIR
        os.environ["X509_USER_PROXY"] = PROXY_PEM
        os.environ["XrdSecPROTOCOL"]  = "gsi"
        from XRootD.client.flags import DirListFlags
        fs = client.FileSystem(NGINX_URL)
        st, listing = fs.dirlist("/", DirListFlags.STAT)
        assert st.ok, f"nginx GSI dirlist failed: {st.message}"
        names = [e.name for e in listing]
        assert filename in names, (
            f"{filename!r} not found in nginx directory listing.\n"
            f"Got: {names}"
        )

    def test_xrootd_dirlist_after_bridge_transfer(self, reference_xrootd_gsi, nginx_gsi_ready):
        """
        Files copied from nginx to xrootd must appear in xrootd's directory listing.
        """
        filename = "bridge_dirlist_xrd.txt"
        content  = b"dirlist xrootd test file\n"

        local = _write_local(content)
        try:
            rc = _xrdcp(local, f"{NGINX_URL}//{filename}")
            assert rc == 0

            rc = _xrdcp(f"{NGINX_URL}//{filename}", f"{REF_URL}//{filename}")
            assert rc == 0
        finally:
            os.unlink(local)

        from XRootD.client.flags import DirListFlags
        os.environ["X509_CERT_DIR"]   = CA_DIR
        os.environ["X509_USER_PROXY"] = PROXY_PEM
        os.environ["XrdSecPROTOCOL"]  = "gsi"
        fs = client.FileSystem(REF_URL)
        st, listing = fs.dirlist("/", DirListFlags.STAT)
        assert st.ok, f"xrootd GSI dirlist failed: {st.message}"
        names = [e.name for e in listing]
        assert filename in names, (
            f"{filename!r} not found in xrootd directory listing.\n"
            f"Got: {names}"
        )
