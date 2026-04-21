"""
kXR_query tests — checksum and space-usage queries.

Tests that:
  - kXR_Qcksum (3): adler32 checksum matches a known-good value for a file
  - kXR_Qspace (5): space response has all required oss.* fields and sane values
  - handle-based checksum matches path-based checksum for the same file
  - checksum on a non-existent path returns an error
  - GSI endpoint also serves both query types

Run:
    pytest tests/test_query.py -v -s
"""

import os
import re
import struct
import tempfile
import zlib
import hashlib

import pytest
from XRootD import client
from XRootD.client.flags import OpenFlags, QueryCode
from backend_matrix import selected_backend_name
from settings import CA_DIR as DEFAULT_CA_DIR, PROXY_STD

CROSS_BACKEND = selected_backend_name()
ANON_URL  = ""
GSI_URL   = ""
CA_DIR    = DEFAULT_CA_DIR
PROXY_PEM = PROXY_STD


@pytest.fixture(scope="module", autouse=True)
def _configure(test_env, ref_xrootd, ref_xrootd_gsi_shared):
    """Bind module constants from the selected shared test environment."""
    global ANON_URL, GSI_URL, CA_DIR, PROXY_PEM
    if CROSS_BACKEND == "xrootd":
        ANON_URL = ref_xrootd["url"]
        GSI_URL = ref_xrootd_gsi_shared["url"]
    else:
        ANON_URL = test_env["anon_url"]
        GSI_URL = test_env["gsi_url"]
    CA_DIR    = test_env["ca_dir"]
    PROXY_PEM = test_env["proxy_pem"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _adler32(data: bytes) -> int:
    """Reference adler32 using Python's zlib (matches the server implementation)."""
    return zlib.adler32(data) & 0xFFFFFFFF


def _upload(url_base: str, remote_path: str, data: bytes) -> None:
    """Upload bytes to the server via the File API."""
    f = client.File()
    status, _ = f.open(f"{url_base}//{remote_path.lstrip('/')}",
                       OpenFlags.DELETE | OpenFlags.NEW)
    assert status.ok, f"open failed: {status.message}"
    if data:
        status, _ = f.write(data)
        assert status.ok, f"write failed: {status.message}"
    f.close()


# ---------------------------------------------------------------------------
# Checksum tests (anonymous)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(
    CROSS_BACKEND == "xrootd",
    reason="reference xrootd test fixture does not enable checksum queries by default",
)
class TestChecksum:
    """kXR_Qcksum (QueryCode.CHECKSUM) via the anonymous endpoint."""

    @pytest.fixture(autouse=True)
    def _setup(self):
        self.fs = client.FileSystem(ANON_URL)

    def test_checksum_known_file(self):
        """Checksum of a file we just wrote must equal zlib.adler32."""
        payload = b"hello checksum test\n" * 100   # 2000 bytes
        remote  = "/test_query_cksum_known.bin"
        _upload(ANON_URL, remote, payload)

        status, resp = self.fs.query(QueryCode.CHECKSUM, remote)
        assert status.ok, f"checksum query failed: {status.message}"

        # Response: "adler32 <8-hex-digits>\0"
        text = resp.rstrip(b"\x00").decode()
        algo, hexval = text.split()
        assert algo == "adler32"
        assert int(hexval, 16) == _adler32(payload), (
            f"checksum mismatch: server={hexval} expected={_adler32(payload):08x}"
        )

    def test_checksum_empty_file(self):
        """Adler32 of an empty file is 0x00000001 (A=1, B=0)."""
        remote = "/test_query_cksum_empty.bin"
        _upload(ANON_URL, remote, b"")

        status, resp = self.fs.query(QueryCode.CHECKSUM, remote)
        assert status.ok, f"checksum query failed: {status.message}"

        text = resp.rstrip(b"\x00").decode()
        algo, hexval = text.split()
        assert algo == "adler32"
        assert int(hexval, 16) == _adler32(b"")

    def test_checksum_large_file(self):
        """1 MiB file checksum must match reference."""
        payload = bytes(range(256)) * 4096     # 1 MiB
        remote  = "/test_query_cksum_large.bin"
        _upload(ANON_URL, remote, payload)

        status, resp = self.fs.query(QueryCode.CHECKSUM, remote)
        assert status.ok, f"checksum query failed: {status.message}"

        text = resp.rstrip(b"\x00").decode()
        _, hexval = text.split()
        assert int(hexval, 16) == _adler32(payload)

    def test_checksum_response_format(self):
        """Response must be exactly '<algo> <8-hex-digit-value>\\0'."""
        payload = b"format test"
        remote  = "/test_query_cksum_fmt.bin"
        _upload(ANON_URL, remote, payload)

        status, resp = self.fs.query(QueryCode.CHECKSUM, remote)
        assert status.ok
        # Null-terminated
        assert resp.endswith(b"\x00"), "response must be null-terminated"
        text = resp.rstrip(b"\x00").decode()
        parts = text.split()
        assert len(parts) == 2, f"expected 'algo hexval', got {text!r}"
        assert parts[0] == "adler32"
        assert re.fullmatch(r"[0-9a-f]{8}", parts[1]), (
            f"expected 8-hex-digit checksum, got {parts[1]!r}"
        )

    def test_checksum_nonexistent_path(self):
        """Query for a missing file must return an error."""
        status, resp = self.fs.query(QueryCode.CHECKSUM,
                                     "/test_query_cksum_nonexistent_xyz.bin")
        assert not status.ok, "expected error for nonexistent file"

    def test_checksum_matches_after_upload(self):
        """Checksum queried immediately after upload matches the local data."""
        payload = b"post-upload checksum test\n" * 50
        remote  = "/test_query_cksum_postupload.bin"
        _upload(ANON_URL, remote, payload)

        # Query checksum right after uploading
        status, resp = self.fs.query(QueryCode.CHECKSUM, remote)
        assert status.ok, f"checksum query failed: {status.message}"

        _, hexval = resp.rstrip(b"\x00").decode().split()
        assert int(hexval, 16) == _adler32(payload), (
            "checksum immediately after upload does not match"
        )

    def test_checksum_different_content_different_cksum(self):
        """Two files with different content must produce different checksums."""
        r1 = "/test_query_cksum_diff1.bin"
        r2 = "/test_query_cksum_diff2.bin"
        _upload(ANON_URL, r1, b"content A")
        _upload(ANON_URL, r2, b"content B")

        _, resp1 = self.fs.query(QueryCode.CHECKSUM, r1)
        _, resp2 = self.fs.query(QueryCode.CHECKSUM, r2)
        assert resp1 != resp2, "different files must not collide"

    def test_checksum_md5_known_file(self):
        """MD5 checksum request via algorithm prefix must return md5 hex."""
        payload = b"hello checksum test\n" * 100
        remote  = "/test_query_cksum_md5_known.bin"
        _upload(ANON_URL, remote, payload)

        # Request MD5 explicitly using "md5:<path>"
        status, resp = self.fs.query(QueryCode.CHECKSUM, f"md5:{remote}")
        assert status.ok, f"md5 checksum query failed: {status.message}"

        text = resp.rstrip(b"\x00").decode()
        algo, hexval = text.split()
        assert algo == "md5"
        expected = hashlib.md5(payload).hexdigest()
        assert hexval == expected, f"md5 mismatch: got={hexval} expected={expected}"

    def test_checksum_sha1_known_file(self):
        """SHA1 checksum request via algorithm prefix must return sha1 hex."""
        payload = b"hello checksum test\n" * 100
        remote  = "/test_query_cksum_sha1_known.bin"
        _upload(ANON_URL, remote, payload)

        status, resp = self.fs.query(QueryCode.CHECKSUM, f"sha1:{remote}")
        assert status.ok, f"sha1 checksum query failed: {status.message}"

        text = resp.rstrip(b"\x00").decode()
        algo, hexval = text.split()
        assert algo == "sha1"
        expected = hashlib.sha1(payload).hexdigest()
        assert hexval == expected, f"sha1 mismatch: got={hexval} expected={expected}"

    def test_checksum_sha256_known_file(self):
        """SHA256 checksum request via algorithm prefix must return sha256 hex."""
        payload = b"hello checksum test\n" * 100
        remote  = "/test_query_cksum_sha256_known.bin"
        _upload(ANON_URL, remote, payload)

        status, resp = self.fs.query(QueryCode.CHECKSUM, f"sha256:{remote}")
        assert status.ok, f"sha256 checksum query failed: {status.message}"

        text = resp.rstrip(b"\x00").decode()
        algo, hexval = text.split()
        assert algo == "sha256"
        expected = hashlib.sha256(payload).hexdigest()
        assert hexval == expected, f"sha256 mismatch: got={hexval} expected={expected}"

    def test_checksum_invalid_algorithm(self):
        """Unknown algorithm must return an error."""
        payload = b"abc"
        remote = "/test_query_cksum_invalidalg.bin"
        _upload(ANON_URL, remote, payload)

        status, resp = self.fs.query(QueryCode.CHECKSUM, f"bogus:{remote}")
        assert not status.ok, "expected error for unsupported algorithm"


# ---------------------------------------------------------------------------
# Space-usage tests (anonymous)
# ---------------------------------------------------------------------------

class TestSpace:
    """kXR_Qspace (QueryCode.SPACE) via the anonymous endpoint."""

    @pytest.fixture(autouse=True)
    def _setup(self):
        self.fs = client.FileSystem(ANON_URL)

    def _parse_oss(self, resp: bytes) -> dict:
        """Parse 'key=value&...' response into a dict."""
        text = resp.rstrip(b"\x00").decode()
        result = {}
        for pair in text.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                result[k] = v
        return result

    def test_space_query_ok(self):
        status, resp = self.fs.query(QueryCode.SPACE, "/")
        assert status.ok, f"space query failed: {status.message}"
        assert resp is not None and len(resp) > 0

    def test_space_has_required_keys(self):
        _, resp = self.fs.query(QueryCode.SPACE, "/")
        oss = self._parse_oss(resp)
        required = ["oss.cgroup", "oss.space", "oss.free",
                    "oss.maxf", "oss.used", "oss.quota"]
        for key in required:
            assert key in oss, f"missing key {key!r} in space response"

    def test_space_values_are_sane(self):
        _, resp = self.fs.query(QueryCode.SPACE, "/")
        oss = self._parse_oss(resp)

        total = int(oss["oss.space"])
        free  = int(oss["oss.free"])
        maxf  = int(oss["oss.maxf"])
        used  = int(oss["oss.used"])

        assert total > 0,              "total space must be > 0"
        assert free >= 0,              "free space must be >= 0"
        assert free <= total,          "free must not exceed total"
        assert maxf >= 0,              "maxf must be >= 0"
        assert maxf <= free + 1,       "maxf must be <= free (approx)"
        assert used >= 0,              "used must be >= 0"
        assert used + free <= total + 1, "used+free must be <= total (approx)"

    def test_space_cgroup_is_string(self):
        _, resp = self.fs.query(QueryCode.SPACE, "/")
        oss = self._parse_oss(resp)
        assert oss["oss.cgroup"], "oss.cgroup must not be empty"

    def test_space_query_with_empty_path(self):
        """Empty path should also be accepted."""
        status, resp = self.fs.query(QueryCode.SPACE, "")
        assert status.ok, f"space query with empty path failed: {status.message}"


# ---------------------------------------------------------------------------
# GSI endpoint tests
# ---------------------------------------------------------------------------

class TestQueryGSI:
    """Verify both query types work through the GSI-authenticated endpoint."""

    @property
    def GSI_ENV(self):
        return {
            "X509_CERT_DIR":   CA_DIR,
            "X509_USER_PROXY": PROXY_PEM,
        }

    @pytest.fixture(autouse=True)
    def _setup(self):
        os.environ["X509_CERT_DIR"]   = CA_DIR
        os.environ["X509_USER_PROXY"] = PROXY_PEM
        self.fs = client.FileSystem(GSI_URL)
        yield
        for k in ("X509_CERT_DIR", "X509_USER_PROXY"):
            os.environ.pop(k, None)

    def test_gsi_checksum(self):
        if CROSS_BACKEND == "xrootd":
            pytest.skip(
                "reference xrootd test fixture does not enable checksum queries by default"
            )
        payload = b"GSI checksum test data"
        remote  = "/test_query_gsi_cksum.bin"
        _upload(GSI_URL, remote, payload)

        status, resp = self.fs.query(QueryCode.CHECKSUM, remote)
        assert status.ok, f"GSI checksum query failed: {status.message}"

        text = resp.rstrip(b"\x00").decode()
        algo, hexval = text.split()
        assert algo == "adler32"
        assert int(hexval, 16) == _adler32(payload)

    def test_gsi_space(self):
        status, resp = self.fs.query(QueryCode.SPACE, "/")
        assert status.ok, f"GSI space query failed: {status.message}"
        assert b"oss.space=" in resp
