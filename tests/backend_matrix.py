"""Helpers for selecting the backend used by cross-compatible test modules."""

import os
from urllib.parse import urlparse


def selected_backend_name() -> str:
    """Return the backend selected for the current pytest process."""
    name = os.environ.get("TEST_CROSS_BACKEND", "nginx").strip().lower()
    if name not in {"nginx", "xrootd"}:
        raise RuntimeError(
            "TEST_CROSS_BACKEND must be 'nginx' or 'xrootd', "
            f"got {name!r}"
        )
    return name


def root_endpoint_parts(url: str, default_port: int = 1094) -> tuple[str, int]:
    """Parse a root:// style URL into host/port parts for raw-socket tests."""
    parsed = urlparse(url if "://" in url else f"root://{url}")
    return parsed.hostname or "127.0.0.1", parsed.port or default_port
