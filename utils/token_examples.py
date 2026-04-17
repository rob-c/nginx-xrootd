#!/usr/bin/env python3
"""
Generate a few custom WLCG bearer tokens using utils/make_token.py.

This is the runnable version of the custom-token example referenced by
docs/test-tokens.md.
"""

import argparse
import os
import sys


UTILS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, UTILS_DIR)

from make_token import TokenIssuer  # noqa: E402


def main():
    parser = argparse.ArgumentParser(
        description="Generate example WLCG bearer tokens"
    )
    parser.add_argument(
        "token_dir",
        nargs="?",
        default="/tmp/xrd-test/tokens",
        help="Token signing authority directory",
    )
    args = parser.parse_args()

    issuer = TokenIssuer(args.token_dir)

    token = issuer.generate(
        sub="alice",
        scope="storage.read:/",
        lifetime=7200,
    )
    print("Read-only token:")
    print(token)
    print()

    token = issuer.generate(
        sub="bob",
        scope="storage.read:/ storage.write:/uploads",
        groups=["/cms", "/atlas"],
        lifetime=3600,
    )
    print("Read-write token with groups:")
    print(token)


if __name__ == "__main__":
    main()
