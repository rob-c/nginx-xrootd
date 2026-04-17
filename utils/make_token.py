#!/usr/bin/env python3
"""
Generate WLCG-profile JWT tokens for testing nginx-xrootd token authentication.

Creates a local signing authority (RSA keypair + JWKS) and generates
JWT tokens with configurable claims and scopes.

Usage:
    # Initialize signing authority (creates keys + JWKS)
    python3 utils/make_token.py init [TOKEN_DIR]

    # Generate a read-only token
    python3 utils/make_token.py gen --scope "storage.read:/" [TOKEN_DIR]

    # Generate a read-write token for /data
    python3 utils/make_token.py gen --scope "storage.read:/ storage.write:/" [TOKEN_DIR]

    # Generate a token with WLCG group claims
    python3 utils/make_token.py gen --scope "storage.read:/" --groups "/cms,/atlas" [TOKEN_DIR]

    # Generate negative-test tokens
    python3 utils/make_token.py gen --kind expired [TOKEN_DIR]

Token directory layout:
    TOKEN_DIR/
        signing_key.pem      RSA-2048 private key
        jwks.json            JSON Web Key Set (public key)
"""

import base64
import json
import os
import sys
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding


# ---------------------------------------------------------------------------
# Base64URL helpers (no padding, URL-safe)
# ---------------------------------------------------------------------------

def b64url_encode(data: bytes) -> str:
    """Base64url-encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(s: str) -> bytes:
    """Base64url-decode with padding restoration."""
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


def int_to_b64url(n: int) -> str:
    """Encode a positive integer as base64url."""
    byte_len = (n.bit_length() + 7) // 8
    raw = n.to_bytes(byte_len, byteorder="big")
    return b64url_encode(raw)


# ---------------------------------------------------------------------------
# TokenIssuer — manages a local signing authority
# ---------------------------------------------------------------------------

class TokenIssuer:
    """Manages a local signing authority for WLCG JWT tokens."""

    DEFAULT_ISSUER   = "https://test.example.com"
    DEFAULT_AUDIENCE = "nginx-xrootd"
    DEFAULT_KID      = "test-key-1"

    def __init__(self, token_dir: str,
                 issuer: str = DEFAULT_ISSUER,
                 audience: str = DEFAULT_AUDIENCE):
        self.token_dir = token_dir
        self.issuer = issuer
        self.audience = audience
        self._key = None

    @property
    def key_path(self) -> str:
        return os.path.join(self.token_dir, "signing_key.pem")

    @property
    def jwks_path(self) -> str:
        return os.path.join(self.token_dir, "jwks.json")

    @property
    def private_key(self):
        if self._key is None:
            with open(self.key_path, "rb") as f:
                self._key = serialization.load_pem_private_key(
                    f.read(), password=None
                )
        return self._key

    # ------------------------------------------------------------------
    # Key management
    # ------------------------------------------------------------------

    def init_keys(self):
        """Generate a new RSA-2048 keypair and write JWKS."""
        os.makedirs(self.token_dir, exist_ok=True)

        # Generate private key
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self._key = key

        # Write private key (restricted permissions)
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with open(self.key_path, "wb") as f:
            f.write(pem)
        os.chmod(self.key_path, 0o400)

        # Write JWKS (public key)
        pub = key.public_key()
        numbers = pub.public_numbers()
        jwks = {
            "keys": [{
                "kty": "RSA",
                "kid": self.DEFAULT_KID,
                "use": "sig",
                "alg": "RS256",
                "n": int_to_b64url(numbers.n),
                "e": int_to_b64url(numbers.e),
            }]
        }
        with open(self.jwks_path, "w") as f:
            json.dump(jwks, f, indent=2)

        print(f"Signing key: {self.key_path}")
        print(f"JWKS:        {self.jwks_path}")

    # ------------------------------------------------------------------
    # Token generation
    # ------------------------------------------------------------------

    def _sign_jwt(self, header: dict, payload: dict) -> str:
        """Create a signed JWT from header and payload dicts."""
        h_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
        p_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
        sig_input = f"{h_b64}.{p_b64}".encode("ascii")

        signature = self.private_key.sign(
            sig_input,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        s_b64 = b64url_encode(signature)
        return f"{h_b64}.{p_b64}.{s_b64}"

    def generate(self,
                 sub: str = "testuser",
                 scope: str = "storage.read:/",
                 groups: list[str] | None = None,
                 lifetime: int = 3600,
                 audience: str | None = None,
                 issuer: str | None = None) -> str:
        """Generate a signed JWT with the given claims."""
        now = int(time.time())
        header = {
            "alg": "RS256",
            "typ": "JWT",
            "kid": self.DEFAULT_KID,
        }
        payload = {
            "iss": issuer or self.issuer,
            "sub": sub,
            "aud": audience or self.audience,
            "exp": now + lifetime,
            "iat": now,
            "nbf": now,
            "scope": scope,
            "wlcg.ver": "1.0",
        }
        if groups:
            payload["wlcg.groups"] = groups
        return self._sign_jwt(header, payload)

    def generate_expired(self, **kwargs) -> str:
        """Generate a token that expired 1 hour ago."""
        now = int(time.time())
        header = {
            "alg": "RS256",
            "typ": "JWT",
            "kid": self.DEFAULT_KID,
        }
        payload = {
            "iss": kwargs.get("issuer", self.issuer),
            "sub": kwargs.get("sub", "testuser"),
            "aud": kwargs.get("audience", self.audience),
            "exp": now - 3600,   # expired 1 hour ago
            "iat": now - 7200,
            "nbf": now - 7200,
            "scope": kwargs.get("scope", "storage.read:/"),
            "wlcg.ver": "1.0",
        }
        if "groups" in kwargs and kwargs["groups"]:
            payload["wlcg.groups"] = kwargs["groups"]
        return self._sign_jwt(header, payload)

    def generate_bad_signature(self, **kwargs) -> str:
        """Generate a token with a valid structure but corrupted signature."""
        token = self.generate(**kwargs)
        parts = token.rsplit(".", 1)
        # Flip some bytes in the signature
        sig = b64url_decode(parts[1])
        corrupted = bytes([b ^ 0xFF for b in sig[:8]]) + sig[8:]
        parts[1] = b64url_encode(corrupted)
        return f"{parts[0]}.{parts[1]}"

    def generate_wrong_issuer(self, **kwargs) -> str:
        """Generate a token with a different issuer."""
        return self.generate(issuer="https://evil.example.com", **kwargs)

    def generate_wrong_audience(self, **kwargs) -> str:
        """Generate a token with a different audience."""
        return self.generate(audience="wrong-audience", **kwargs)

    def generate_no_scope(self, **kwargs) -> str:
        """Generate a valid token without any scope claim."""
        now = int(time.time())
        header = {
            "alg": "RS256",
            "typ": "JWT",
            "kid": self.DEFAULT_KID,
        }
        payload = {
            "iss": self.issuer,
            "sub": kwargs.get("sub", "testuser"),
            "aud": self.audience,
            "exp": now + 3600,
            "iat": now,
            "nbf": now,
            "wlcg.ver": "1.0",
        }
        return self._sign_jwt(header, payload)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="WLCG token signing authority for nginx-xrootd testing"
    )
    sub = parser.add_subparsers(dest="command")

    # init
    init_p = sub.add_parser("init", help="Initialize signing authority")
    init_p.add_argument("token_dir", nargs="?",
                        default="/tmp/xrd-test/tokens")

    # gen
    gen_p = sub.add_parser("gen", help="Generate a signed token")
    gen_p.add_argument("token_dir", nargs="?",
                       default="/tmp/xrd-test/tokens")
    gen_p.add_argument("--sub", default="testuser", help="Subject claim")
    gen_p.add_argument("--scope", default="storage.read:/",
                       help="Space-separated scopes")
    gen_p.add_argument("--groups", default=None,
                       help="Comma-separated WLCG groups")
    gen_p.add_argument("--lifetime", type=int, default=3600,
                       help="Token lifetime in seconds")
    gen_p.add_argument("--issuer", default=None)
    gen_p.add_argument("--audience", default=None)
    gen_p.add_argument("--output", "-o", default=None,
                       help="Write token to file instead of stdout")
    gen_p.add_argument("--kind", default="valid",
                       choices=[
                           "valid",
                           "expired",
                           "bad-signature",
                           "wrong-issuer",
                           "wrong-audience",
                           "no-scope",
                       ],
                       help="Token variant to generate")

    args = parser.parse_args()

    if args.command == "init":
        issuer = TokenIssuer(args.token_dir)
        issuer.init_keys()

    elif args.command == "gen":
        issuer = TokenIssuer(args.token_dir)
        groups = args.groups.split(",") if args.groups else None
        kwargs = {
            "sub": args.sub,
            "scope": args.scope,
        }
        if groups:
            kwargs["groups"] = groups
        if args.audience:
            kwargs["audience"] = args.audience
        if args.issuer:
            kwargs["issuer"] = args.issuer

        if args.kind == "valid":
            token = issuer.generate(
                lifetime=args.lifetime,
                **kwargs,
            )
        elif args.kind == "expired":
            token = issuer.generate_expired(**kwargs)
        elif args.kind == "bad-signature":
            token = issuer.generate_bad_signature(
                lifetime=args.lifetime,
                **kwargs,
            )
        elif args.kind == "wrong-issuer":
            token = issuer.generate_wrong_issuer(
                sub=args.sub,
                scope=args.scope,
                groups=groups,
                lifetime=args.lifetime,
                **({"audience": args.audience} if args.audience else {}),
            )
        elif args.kind == "wrong-audience":
            token = issuer.generate_wrong_audience(
                sub=args.sub,
                scope=args.scope,
                groups=groups,
                lifetime=args.lifetime,
                **({"issuer": args.issuer} if args.issuer else {}),
            )
        elif args.kind == "no-scope":
            token = issuer.generate_no_scope(sub=args.sub)

        if args.output:
            with open(args.output, "w") as f:
                f.write(token)
            print(f"Token written to {args.output}")
        else:
            print(token)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
