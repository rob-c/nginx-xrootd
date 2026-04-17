#!/usr/bin/env python3
"""
Decode JWT header/payload data and optionally print key IDs from a JWKS file.

This is a debugging helper only. It does not verify the JWT signature.
"""

import argparse
import base64
import json
import sys


def b64url_decode(part):
    padding = "=" * ((4 - len(part) % 4) % 4)
    return base64.urlsafe_b64decode(part + padding)


def print_json(label, value):
    print(f"{label}:")
    print(json.dumps(value, indent=2, sort_keys=True))


def decode_token(token):
    parts = token.strip().split(".")
    if len(parts) < 2:
        raise ValueError("token does not have JWT header.payload segments")

    header = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    return header, payload


def main():
    parser = argparse.ArgumentParser(
        description="Inspect an nginx-xrootd test JWT and/or JWKS file"
    )
    parser.add_argument(
        "token",
        nargs="?",
        help="JWT to inspect, or '-' to read from stdin",
    )
    parser.add_argument(
        "--jwks",
        help="JWKS file whose key IDs should be printed",
    )
    args = parser.parse_args()

    if args.token:
        token = sys.stdin.read().strip() if args.token == "-" else args.token
        header, payload = decode_token(token)
        print_json("Header", header)
        print()
        print_json("Payload", payload)

    if args.jwks:
        if args.token:
            print()
        with open(args.jwks, "r", encoding="utf-8") as f:
            jwks = json.load(f)
        key_ids = [key.get("kid", "<missing kid>") for key in jwks.get("keys", [])]
        print("JWKS key IDs:")
        for key_id in key_ids:
            print(f"  {key_id}")


if __name__ == "__main__":
    main()
