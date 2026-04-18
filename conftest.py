"""Pytest compatibility helpers for optional plugins.

This project prefers pytest-timeout, but test runs should stay warning-free
when that plugin is not present in the active environment.
"""


def pytest_addoption(parser):
    """Register timeout ini keys when pytest-timeout is unavailable."""
    try:
        parser.addini(
            "timeout",
            "Default per-test timeout in seconds (pytest-timeout).",
            default="30",
        )
    except ValueError:
        # Already provided by pytest-timeout.
        pass

    try:
        parser.addini(
            "timeout_method",
            "Timeout backend (pytest-timeout).",
            default="thread",
        )
    except ValueError:
        # Already provided by pytest-timeout.
        pass


def pytest_configure(config):
    # Keep marker warnings quiet when pytest-timeout is not installed.
    config.addinivalue_line(
        "markers",
        "timeout(seconds): per-test timeout (handled by pytest-timeout when installed)",
    )
