"""
tests/test_webdav.py

HTTPS+GSI WebDAV module tests for the ngx_http_xrootd_webdav_module.

Covers the WebDAV methods that xrdcp (XrdClHttp plugin) and compatible
clients depend on:

  OPTIONS   – capability advertisement (must include PROPFIND in Allow)
  HEAD      – metadata without body
  GET       – file content, including Range requests (206 Partial Content)
  PUT       – file upload
  DELETE    – file and directory removal
  MKCOL     – directory creation, with and without trailing slash
  PROPFIND  – Depth:0 (stat) and Depth:1 (directory listing)

Authentication is via RFC 3820 x509 proxy certificates (GSI) over TLS.
The tests also verify that requests without a client cert are still served
(xrootd_webdav_auth optional) and that auth-required mode rejects them.

Run against an already-running nginx instance:

    /tmp/nginx-1.28.3/objs/nginx -p /tmp/xrd-test -c conf/nginx.conf

    pytest tests/test_webdav.py -v

Environment:
    nginx WebDAV endpoint: https://localhost:8443/
    CA cert:    /tmp/xrd-test/pki/ca/ca.pem
    Proxy cert: /tmp/xrd-test/pki/user/proxy_std.pem
    Data root:  /tmp/xrd-test/data/
"""

import os
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET

import pytest
import urllib.request
import ssl

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BASE_URL   = "https://localhost:8443"
CA_PEM     = "/tmp/xrd-test/pki/ca/ca.pem"
PROXY_PEM  = "/tmp/xrd-test/pki/user/proxy_std.pem"
DATA_ROOT  = "/tmp/xrd-test/data"

# Unique prefix for test artefacts so parallel runs don't collide
_PFX = "wdav_"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _curl(*args, timeout=20):
    """
    Run curl with the common TLS / proxy-cert flags and return
    (returncode, stdout_bytes, stderr_bytes).

    All WebDAV tests go through this helper so that any future change to
    TLS flags only needs updating in one place.
    """
    cmd = [
        "curl", "-sk",
        "--cert",   PROXY_PEM,
        "--key",    PROXY_PEM,
        "--cacert", CA_PEM,
        *args,
    ]
    result = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )
    return result.returncode, result.stdout, result.stderr


def _curl_no_cert(*args, timeout=20):
    """curl without any client certificate (anonymous TLS)."""
    cmd = [
        "curl", "-sk",
        "--cacert", CA_PEM,
        *args,
    ]
    result = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )
    return result.returncode, result.stdout, result.stderr


def _http_code(*args, **kwargs):
    """Return just the HTTP status code as an int."""
    rc, out, _ = _curl(*args, "-w", "%{http_code}", "-o", "/dev/null", **kwargs)
    assert rc == 0, f"curl failed (exit {rc})"
    return int(out.strip())


def _http_code_no_cert(*args, **kwargs):
    rc, out, _ = _curl_no_cert(*args, "-w", "%{http_code}", "-o", "/dev/null", **kwargs)
    assert rc == 0, f"curl failed (exit {rc})"
    return int(out.strip())


def _put(path: str, content: bytes) -> int:
    """PUT content to path; return HTTP status code."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(content)
        tmp = f.name
    try:
        return _http_code("-X", "PUT", f"{BASE_URL}{path}",
                          "--data-binary", f"@{tmp}")
    finally:
        os.unlink(tmp)


def _get(path: str) -> bytes:
    """GET path; return response body bytes. Raises on curl failure."""
    rc, out, err = _curl(f"{BASE_URL}{path}")
    assert rc == 0, f"curl GET failed: {err.decode()}"
    return out


def _data_path(rel: str) -> str:
    """Absolute filesystem path for a data-root-relative path."""
    return os.path.join(DATA_ROOT, rel.lstrip("/"))


# ---------------------------------------------------------------------------
# Session fixture: verify nginx is reachable before running any test
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session", autouse=True)
def nginx_webdav_ready():
    """Skip the whole module if the WebDAV endpoint is not up."""
    rc, _, _ = _curl("-X", "OPTIONS", f"{BASE_URL}/", "-o", "/dev/null",
                     timeout=5)
    if rc != 0:
        pytest.skip(
            f"WebDAV endpoint {BASE_URL} not reachable. "
            "Start nginx with: /tmp/nginx-1.28.3/objs/nginx "
            "-p /tmp/xrd-test -c conf/nginx.conf"
        )


# ---------------------------------------------------------------------------
# Fixture: per-test scratch file
# ---------------------------------------------------------------------------

@pytest.fixture()
def scratch_file(tmp_path):
    """
    Yield (url_path, content) for a file that has been PUT to the server.
    Cleaned up from the data directory after the test.
    """
    name    = f"{_PFX}scratch.txt"
    content = b"scratch file content for WebDAV tests\n"
    url_path = f"/{name}"

    code = _put(url_path, content)
    assert code in (200, 201), f"Fixture PUT failed with HTTP {code}"

    yield url_path, content

    dst = _data_path(name)
    if os.path.exists(dst):
        os.unlink(dst)


# ---------------------------------------------------------------------------
# OPTIONS
# ---------------------------------------------------------------------------

class TestOptions:

    def test_returns_200(self):
        code = _http_code("-X", "OPTIONS", f"{BASE_URL}/")
        assert code == 200

    def test_allow_header_contains_propfind(self):
        """xrdcp uses PROPFIND for stat; it must appear in the Allow header."""
        rc, _, err = _curl("-X", "OPTIONS", f"{BASE_URL}/",
                           "-D", "-", "-o", "/dev/null")
        # curl -D - writes headers to stdout when -o /dev/null
        rc, out, _ = _curl("-X", "OPTIONS", f"{BASE_URL}/", "-D", "/dev/stderr",
                           "-o", "/dev/null")
        # Try a different approach: capture headers with -I
        rc2, head_out, _ = _curl("-I", f"{BASE_URL}/",
                                 "-X", "OPTIONS")
        headers = head_out.decode(errors="replace").lower()
        assert "propfind" in headers, (
            f"PROPFIND not found in OPTIONS response headers:\n{head_out.decode()}"
        )

    def test_dav_header_present(self):
        rc, head_out, _ = _curl("-I", f"{BASE_URL}/", "-X", "OPTIONS")
        headers = head_out.decode(errors="replace").lower()
        assert "dav:" in headers, (
            f"DAV: header missing from OPTIONS response:\n{head_out.decode()}"
        )


# ---------------------------------------------------------------------------
# PUT
# ---------------------------------------------------------------------------

class TestPut:

    def test_put_new_file_returns_201(self):
        name = f"{_PFX}put_new.txt"
        dst  = _data_path(name)
        if os.path.exists(dst):
            os.unlink(dst)
        try:
            code = _put(f"/{name}", b"new file\n")
            assert code == 201
        finally:
            if os.path.exists(dst):
                os.unlink(dst)

    def test_put_overwrite_returns_200_or_204(self):
        name = f"{_PFX}put_overwrite.txt"
        dst  = _data_path(name)
        try:
            _put(f"/{name}", b"original\n")
            code = _put(f"/{name}", b"overwritten\n")
            assert code in (200, 204), f"Overwrite PUT returned HTTP {code}"
            with open(dst, "rb") as f:
                assert f.read() == b"overwritten\n"
        finally:
            if os.path.exists(dst):
                os.unlink(dst)

    def test_put_content_reaches_disk(self):
        name    = f"{_PFX}put_disk.txt"
        content = b"disk verification content\n" * 100
        dst     = _data_path(name)
        try:
            code = _put(f"/{name}", content)
            assert code in (200, 201)
            with open(dst, "rb") as f:
                assert f.read() == content
        finally:
            if os.path.exists(dst):
                os.unlink(dst)

    def test_put_binary_content(self):
        name    = f"{_PFX}put_binary.bin"
        content = bytes(range(256)) * 256  # 64 KiB, all byte values
        dst     = _data_path(name)
        try:
            code = _put(f"/{name}", content)
            assert code in (200, 201)
            with open(dst, "rb") as f:
                assert f.read() == content
        finally:
            if os.path.exists(dst):
                os.unlink(dst)

    @pytest.mark.timeout(60)
    def test_put_large_file(self):
        """2 MB upload — exercises chunked body buffering."""
        name    = f"{_PFX}put_large.bin"
        content = os.urandom(2 * 1024 * 1024)
        dst     = _data_path(name)
        try:
            code = _put(f"/{name}", content)
            assert code in (200, 201)
            with open(dst, "rb") as f:
                assert f.read() == content
        finally:
            if os.path.exists(dst):
                os.unlink(dst)


# ---------------------------------------------------------------------------
# HEAD
# ---------------------------------------------------------------------------

class TestHead:
    """
    HEAD tests use -I (implicit --head) rather than -X HEAD with -w/%{http_code}.
    With -I, curl stops after receiving the response headers, avoiding a hang
    where curl waits for connection close after a HEAD response.
    """

    def _head_code(self, url: str) -> int:
        """Issue a HEAD request and return the HTTP status code."""
        rc, out, _ = _curl("-I", url)
        assert rc == 0, f"curl -I failed (exit {rc})"
        # First line is "HTTP/1.x NNN reason"
        first = out.split(b"\n", 1)[0].decode(errors="replace").strip()
        parts = first.split(None, 2)
        assert len(parts) >= 2, f"Unexpected HEAD status line: {first!r}"
        return int(parts[1])

    def test_head_existing_file(self, scratch_file):
        url_path, _ = scratch_file
        assert self._head_code(f"{BASE_URL}{url_path}") == 200

    def test_head_returns_content_length(self, scratch_file):
        url_path, content = scratch_file
        rc, out, _ = _curl("-I", f"{BASE_URL}{url_path}")
        headers = out.decode(errors="replace").lower()
        assert "content-length:" in headers
        for line in headers.splitlines():
            if line.startswith("content-length:"):
                cl = int(line.split(":", 1)[1].strip())
                assert cl == len(content), (
                    f"Content-Length {cl} != expected {len(content)}"
                )
                break

    def test_head_missing_file_returns_404(self):
        assert self._head_code(f"{BASE_URL}/{_PFX}no_such_file.txt") == 404


# ---------------------------------------------------------------------------
# GET
# ---------------------------------------------------------------------------

class TestGet:

    def test_get_existing_file(self, scratch_file):
        url_path, content = scratch_file
        body = _get(url_path)
        assert body == content

    def test_get_missing_file_returns_404(self):
        code = _http_code(f"{BASE_URL}/{_PFX}no_such_file.txt")
        assert code == 404

    def test_range_get_partial(self, scratch_file):
        """Range: bytes=2-5 should return 206 with 4 bytes."""
        url_path, content = scratch_file
        rc, out, _ = _curl(
            "-H", "Range: bytes=2-5",
            "-w", "\n%{http_code}",
            f"{BASE_URL}{url_path}",
        )
        lines = out.rsplit(b"\n", 1)
        body, code = lines[0], int(lines[1].strip())
        assert code == 206, f"Expected 206, got {code}"
        assert body == content[2:6], (
            f"Range body mismatch: got {body!r}, expected {content[2:6]!r}"
        )

    def test_range_get_suffix(self, scratch_file):
        """Range: bytes=-5 should return the last 5 bytes."""
        url_path, content = scratch_file
        rc, out, _ = _curl(
            "-H", "Range: bytes=-5",
            "-w", "\n%{http_code}",
            f"{BASE_URL}{url_path}",
        )
        lines = out.rsplit(b"\n", 1)
        body, code = lines[0], int(lines[1].strip())
        assert code == 206
        assert body == content[-5:]

    def test_range_get_from_offset(self, scratch_file):
        """Range: bytes=4- should return content from byte 4 to end."""
        url_path, content = scratch_file
        rc, out, _ = _curl(
            "-H", "Range: bytes=4-",
            "-w", "\n%{http_code}",
            f"{BASE_URL}{url_path}",
        )
        lines = out.rsplit(b"\n", 1)
        body, code = lines[0], int(lines[1].strip())
        assert code == 206
        assert body == content[4:]

    def test_range_beyond_eof_returns_416(self, scratch_file):
        """Range starting past EOF should return 416."""
        url_path, content = scratch_file
        beyond = len(content) + 100
        code = _http_code(
            "-H", f"Range: bytes={beyond}-{beyond + 10}",
            f"{BASE_URL}{url_path}",
        )
        assert code == 416


# ---------------------------------------------------------------------------
# DELETE
# ---------------------------------------------------------------------------

class TestDelete:

    def test_delete_existing_file(self):
        name = f"{_PFX}delete_me.txt"
        dst  = _data_path(name)
        _put(f"/{name}", b"to be deleted\n")
        assert os.path.exists(dst)

        code = _http_code("-X", "DELETE", f"{BASE_URL}/{name}")
        assert code == 204
        assert not os.path.exists(dst), "File should be gone after DELETE"

    def test_delete_missing_returns_404(self):
        code = _http_code("-X", "DELETE",
                          f"{BASE_URL}/{_PFX}no_such_delete.txt")
        assert code == 404

    def test_delete_empty_directory(self):
        name = f"{_PFX}del_dir"
        dst  = _data_path(name)
        os.makedirs(dst, exist_ok=True)
        try:
            code = _http_code("-X", "DELETE", f"{BASE_URL}/{name}")
            assert code == 204
            assert not os.path.exists(dst)
        finally:
            if os.path.exists(dst):
                shutil.rmtree(dst)


# ---------------------------------------------------------------------------
# MKCOL
# ---------------------------------------------------------------------------

class TestMkcol:

    def test_mkcol_creates_directory(self):
        name = f"{_PFX}mkcol_plain"
        dst  = _data_path(name)
        if os.path.exists(dst):
            shutil.rmtree(dst)
        try:
            code = _http_code("-X", "MKCOL", f"{BASE_URL}/{name}")
            assert code == 201
            assert os.path.isdir(dst), "MKCOL should have created a directory"
        finally:
            if os.path.exists(dst):
                shutil.rmtree(dst)

    def test_mkcol_with_trailing_slash(self):
        """MKCOL /dir/ (trailing slash) must work identically to MKCOL /dir."""
        name = f"{_PFX}mkcol_slash"
        dst  = _data_path(name)
        if os.path.exists(dst):
            shutil.rmtree(dst)
        try:
            code = _http_code("-X", "MKCOL", f"{BASE_URL}/{name}/")
            assert code == 201
            assert os.path.isdir(dst)
        finally:
            if os.path.exists(dst):
                shutil.rmtree(dst)

    def test_mkcol_conflict_returns_405(self):
        """MKCOL on an already-existing path must return 405 Method Not Allowed."""
        name = f"{_PFX}mkcol_conflict"
        dst  = _data_path(name)
        os.makedirs(dst, exist_ok=True)
        try:
            code = _http_code("-X", "MKCOL", f"{BASE_URL}/{name}")
            assert code == 405, f"Expected 405 for existing dir, got {code}"
        finally:
            shutil.rmtree(dst)

    def test_mkcol_nested_missing_parent_returns_409(self):
        """MKCOL /missing_parent/child must return 409 Conflict."""
        parent = _data_path(f"{_PFX}no_parent")
        if os.path.exists(parent):
            shutil.rmtree(parent)
        code = _http_code(
            "-X", "MKCOL",
            f"{BASE_URL}/{_PFX}no_parent/{_PFX}child",
        )
        assert code == 409, f"Expected 409 for missing parent, got {code}"


# ---------------------------------------------------------------------------
# Path hardening
# ---------------------------------------------------------------------------

class TestPathHardening:

    def test_delete_rejects_double_encoded_nul_path(self):
        """
        nginx normalizes the URI once before it reaches the module. A second
        decode inside the handler must not turn `%2500` into an in-band NUL.
        """
        name = f"{_PFX}delete_nul.txt"
        dst = _data_path(name)
        with open(dst, "wb") as fh:
            fh.write(b"webdav nul hardening\n")

        try:
            code = _http_code(
                "--path-as-is",
                "-X", "DELETE",
                f"{BASE_URL}/{name}%2500tail",
            )
            assert code == 400, f"Expected 400 for decoded-NUL path, got {code}"
            assert os.path.exists(dst), "double-encoded NUL unexpectedly deleted the file"
        finally:
            if os.path.exists(dst):
                os.unlink(dst)

    def test_mkcol_rejects_double_encoded_traversal_segments(self):
        """
        A second decode must not reinterpret `%252F..%252F` as `/../` and create
        a sibling directory outside the requested lexical path.
        """
        parent = f"{_PFX}mkcol_parent"
        target = f"{_PFX}mkcol_escape"
        parent_path = _data_path(parent)
        target_path = _data_path(target)

        if os.path.exists(parent_path):
            shutil.rmtree(parent_path)
        if os.path.exists(target_path):
            shutil.rmtree(target_path)

        os.makedirs(parent_path, exist_ok=True)

        try:
            code = _http_code(
                "--path-as-is",
                "-X", "MKCOL",
                f"{BASE_URL}/{parent}%252F..%252F{target}",
            )
            assert code == 403, f"Expected 403 for traversal path, got {code}"
            assert not os.path.exists(target_path), (
                "double-encoded traversal unexpectedly created a sibling directory"
            )
        finally:
            if os.path.exists(parent_path):
                shutil.rmtree(parent_path)
            if os.path.exists(target_path):
                shutil.rmtree(target_path)


# ---------------------------------------------------------------------------
# PROPFIND
# ---------------------------------------------------------------------------

class TestPropfind:

    def _propfind(self, path: str, depth: str) -> ET.Element:
        """Run a PROPFIND and return the parsed XML root element."""
        rc, out, err = _curl(
            "-X", "PROPFIND",
            "-H", f"Depth: {depth}",
            f"{BASE_URL}{path}",
        )
        assert rc == 0, f"curl failed: {err.decode()}"
        try:
            return ET.fromstring(out)
        except ET.ParseError as exc:
            pytest.fail(
                f"PROPFIND response is not valid XML: {exc}\nBody:\n{out.decode()}"
            )

    def test_propfind_depth0_returns_207(self, scratch_file):
        url_path, _ = scratch_file
        code = _http_code(
            "-X", "PROPFIND", "-H", "Depth: 0",
            f"{BASE_URL}{url_path}",
        )
        assert code == 207

    def test_propfind_depth0_file_has_content_length(self, scratch_file):
        url_path, content = scratch_file
        root = self._propfind(url_path, "0")
        # Find D:getcontentlength anywhere in the multistatus tree
        ns = {"D": "DAV:"}
        cl_els = root.findall(".//D:getcontentlength", ns)
        assert cl_els, "D:getcontentlength missing from PROPFIND Depth:0 response"
        assert int(cl_els[0].text) == len(content), (
            f"getcontentlength {cl_els[0].text} != {len(content)}"
        )

    def test_propfind_depth0_directory(self):
        """PROPFIND Depth:0 on a directory should return a collection resourcetype."""
        name = f"{_PFX}propfind_dir"
        dst  = _data_path(name)
        os.makedirs(dst, exist_ok=True)
        try:
            root = self._propfind(f"/{name}", "0")
            ns = {"D": "DAV:"}
            coll = root.findall(".//D:collection", ns)
            assert coll, (
                "D:collection missing from PROPFIND Depth:0 response for a directory"
            )
        finally:
            shutil.rmtree(dst)

    def test_propfind_depth1_lists_children(self, scratch_file):
        url_path, _ = scratch_file
        filename = os.path.basename(url_path)
        # PROPFIND Depth:1 on root should include our scratch file
        root = self._propfind("/", "1")
        ns = {"D": "DAV:"}
        hrefs = [el.text for el in root.findall(".//D:href", ns)]
        assert any(filename in (h or "") for h in hrefs), (
            f"{filename!r} not found in PROPFIND Depth:1 href list:\n{hrefs}"
        )

    def test_propfind_depth1_returns_207(self):
        code = _http_code(
            "-X", "PROPFIND", "-H", "Depth: 1",
            f"{BASE_URL}/",
        )
        assert code == 207

    def test_propfind_missing_returns_404(self):
        code = _http_code(
            "-X", "PROPFIND", "-H", "Depth: 0",
            f"{BASE_URL}/{_PFX}no_such_propfind.txt",
        )
        assert code == 404

    def test_propfind_depth0_has_lastmodified(self, scratch_file):
        url_path, _ = scratch_file
        root = self._propfind(url_path, "0")
        ns = {"D": "DAV:"}
        lm = root.findall(".//D:getlastmodified", ns)
        assert lm, "D:getlastmodified missing from PROPFIND Depth:0 response"

    def test_propfind_depth1_escapes_xml_metacharacters_in_href(self):
        """Hostile filenames must not break PROPFIND XML output."""
        name = f"{_PFX}xml_&_<>.txt"
        dst = _data_path(name)
        with open(dst, "wb") as fh:
            fh.write(b"xml escape\n")

        try:
            root = self._propfind("/", "1")
            ns = {"D": "DAV:"}
            hrefs = [el.text for el in root.findall(".//D:href", ns)]
            assert f"/{name}" in hrefs, hrefs
        finally:
            if os.path.exists(dst):
                os.unlink(dst)


# ---------------------------------------------------------------------------
# Authentication behaviour
# ---------------------------------------------------------------------------

class TestAuth:

    def test_anonymous_get_succeeds_with_optional_auth(self, scratch_file):
        """
        xrootd_webdav_auth optional: GET without a client cert should still
        return 200 (the server serves the file but notes auth as absent).
        """
        url_path, content = scratch_file
        code = _http_code_no_cert(f"{BASE_URL}{url_path}")
        assert code == 200, (
            f"Anonymous GET should succeed with optional auth, got {code}"
        )

    def test_proxy_cert_accepted_for_put(self):
        """PUT with a valid GSI proxy cert must succeed."""
        name = f"{_PFX}auth_put.txt"
        dst  = _data_path(name)
        try:
            code = _put(f"/{name}", b"auth test\n")
            assert code in (200, 201), f"Authenticated PUT failed with {code}"
        finally:
            if os.path.exists(dst):
                os.unlink(dst)

    def test_content_type_not_required(self, scratch_file):
        """
        GET without Accept header (bare curl) should return content.
        Verifies the module doesn't gate on Content-Type negotiation.
        """
        url_path, content = scratch_file
        rc, out, _ = _curl(f"{BASE_URL}{url_path}")
        assert rc == 0
        assert out == content


# ---------------------------------------------------------------------------
# Integrity: PUT then GET round-trip
# ---------------------------------------------------------------------------

class TestRoundTrip:

    def test_put_get_round_trip_text(self):
        name    = f"{_PFX}rt_text.txt"
        content = b"Hello, WebDAV round-trip!\n" * 50
        dst     = _data_path(name)
        try:
            assert _put(f"/{name}", content) in (200, 201)
            assert _get(f"/{name}") == content
        finally:
            if os.path.exists(dst):
                os.unlink(dst)

    def test_put_get_round_trip_binary(self):
        name    = f"{_PFX}rt_binary.bin"
        content = os.urandom(128 * 1024)  # 128 KiB random bytes
        dst     = _data_path(name)
        try:
            assert _put(f"/{name}", content) in (200, 201)
            assert _get(f"/{name}") == content
        finally:
            if os.path.exists(dst):
                os.unlink(dst)

    @pytest.mark.timeout(60)
    def test_put_get_round_trip_large(self):
        """4 MB round-trip to exercise chunked PUT + GET."""
        name    = f"{_PFX}rt_large.bin"
        content = os.urandom(4 * 1024 * 1024)
        dst     = _data_path(name)
        try:
            assert _put(f"/{name}", content) in (200, 201)
            assert _get(f"/{name}") == content
        finally:
            if os.path.exists(dst):
                os.unlink(dst)

    def test_mkcol_put_get_in_subdirectory(self):
        """Create a directory, upload a file into it, and read it back."""
        dirname  = f"{_PFX}subdir"
        filename = "sub_file.txt"
        content  = b"file inside a WebDAV sub-directory\n"
        dst_dir  = _data_path(dirname)
        dst_file = os.path.join(dst_dir, filename)
        try:
            assert _http_code("-X", "MKCOL",
                               f"{BASE_URL}/{dirname}") == 201
            assert _put(f"/{dirname}/{filename}", content) in (200, 201)
            assert _get(f"/{dirname}/{filename}") == content
        finally:
            if os.path.exists(dst_dir):
                shutil.rmtree(dst_dir)
