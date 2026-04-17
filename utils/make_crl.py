#!/usr/bin/env python3
"""
Generate a PEM certificate revocation list for the local nginx-xrootd test CA.

By default this revokes /tmp/xrd-test/pki/user/usercert.pem and writes the CRL
to /tmp/xrd-test/pki/ca/test-user.crl.pem.
"""

import argparse
import datetime
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import CertificateRevocationListBuilder
from cryptography.x509 import RevokedCertificateBuilder


def load_cert(path):
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def main():
    parser = argparse.ArgumentParser(
        description="Generate a PEM CRL for the nginx-xrootd test CA"
    )
    parser.add_argument(
        "pki_dir",
        nargs="?",
        default="/tmp/xrd-test/pki",
        help="PKI directory containing ca/ and user/ subdirectories",
    )
    parser.add_argument(
        "--cert",
        default=None,
        help="Certificate to revoke (default: PKI_DIR/user/usercert.pem)",
    )
    parser.add_argument(
        "--out",
        default=None,
        help="Output CRL path (default: PKI_DIR/ca/test-user.crl.pem)",
    )
    parser.add_argument(
        "--days",
        type=int,
        default=30,
        help="CRL validity in days",
    )
    args = parser.parse_args()

    ca_cert_path = os.path.join(args.pki_dir, "ca", "ca.pem")
    ca_key_path = os.path.join(args.pki_dir, "ca", "ca.key")
    revoke_cert_path = args.cert or os.path.join(
        args.pki_dir, "user", "usercert.pem"
    )
    out_path = args.out or os.path.join(
        args.pki_dir, "ca", "test-user.crl.pem"
    )

    ca_cert = load_cert(ca_cert_path)
    revoke_cert = load_cert(revoke_cert_path)
    with open(ca_key_path, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)

    now = datetime.datetime.now(datetime.timezone.utc)
    revoked = (
        RevokedCertificateBuilder()
        .serial_number(revoke_cert.serial_number)
        .revocation_date(now - datetime.timedelta(hours=1))
        .build()
    )

    crl = (
        CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now - datetime.timedelta(hours=1))
        .next_update(now + datetime.timedelta(days=args.days))
        .add_revoked_certificate(revoked)
        .sign(ca_key, hashes.SHA256())
    )

    out_dir = os.path.dirname(out_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    with open(out_path, "wb") as f:
        f.write(crl.public_bytes(serialization.Encoding.PEM))

    print(f"CRL written to {out_path}")
    print(f"Revoked serial: {revoke_cert.serial_number}")
    print(f"Issuer: {ca_cert.subject.rfc4514_string()}")


if __name__ == "__main__":
    main()
