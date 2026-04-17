#!/usr/bin/env python3
"""
Smoke-test an nginx-xrootd endpoint with the XRootD Python client.
"""

import argparse
import sys

from XRootD import client
from XRootD.client.flags import OpenFlags


def require_ok(status, action):
    if not status.ok:
        print(f"{action} failed: {status}", file=sys.stderr)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Run a simple XRootD Python client smoke test"
    )
    parser.add_argument(
        "--url",
        default="root://localhost:1094",
        help="Base XRootD URL",
    )
    parser.add_argument(
        "--path",
        default="/test.txt",
        help="Path to read after listing /",
    )
    args = parser.parse_args()

    fs = client.FileSystem(args.url)
    status, listing = fs.dirlist("/")
    require_ok(status, "dirlist")
    print([entry.name for entry in listing])

    path = "/" + args.path.lstrip("/")
    file_url = f"{args.url.rstrip('/')}/{path}"
    f = client.File()
    status, _ = f.open(file_url, OpenFlags.READ)
    require_ok(status, "open")
    status, data = f.read()
    require_ok(status, "read")
    print(data)
    f.close()


if __name__ == "__main__":
    main()
