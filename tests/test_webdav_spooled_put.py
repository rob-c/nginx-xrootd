"""
Regression test for WebDAV PUT bodies that nginx spools to a temp file.

The WebDAV handler receives large HTTPS request bodies after nginx has already
written them to client_body_temp_path. This test forces that path with
client_body_in_file_only so uploads exercise the module's temp-file copy path
instead of the small in-memory buffer case.
"""

import os

import pytest
import requests
import urllib3
from settings import DATA_ROOT as DEFAULT_DATA_ROOT, PROXY_STD

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PROXY_PEM = PROXY_STD

WEBDAV_URL = ""
DATA_DIR   = DEFAULT_DATA_ROOT


@pytest.fixture(scope="module", autouse=True)
def _configure(test_env):
    """Bind module constants from the shared test environment."""
    global WEBDAV_URL, DATA_DIR
    WEBDAV_URL = test_env["webdav_url"]
    DATA_DIR   = test_env["data_dir"]


def test_put_spooled_request_body_round_trips():
    name = "spooled-upload.bin"
    payload = os.urandom((2 * 1024 * 1024) + 137)

    resp = requests.put(
        f"{WEBDAV_URL}/{name}",
        data=payload,
        cert=PROXY_PEM,
        verify=False,
        timeout=30,
    )

    assert resp.status_code in (201, 204), resp.text

    with open(os.path.join(DATA_DIR, name), "rb") as fh:
        assert fh.read() == payload
