#!/usr/bin/env python3
"""
Create a proper RFC 3820 proxy certificate with proxyCertInfo extension
(OID 1.3.6.1.5.5.7.1.14).

This is required for XrdSecGSI to recognize the cert as a valid proxy.

Usage:
    python3 utils/make_proxy.py [PKI_DIR]

    PKI_DIR defaults to /tmp/xrd-test/pki.  The script expects:
        PKI_DIR/user/usercert.pem
        PKI_DIR/user/userkey.pem
    and writes:
        PKI_DIR/user/proxy_std.pem   (cert + key + chain, mode 0400)
        PKI_DIR/user/proxy.pem       (cert only)
        PKI_DIR/user/proxykey.pem    (key only, mode 0400)
"""
import datetime
import os
import sys

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import CertificateBuilder, Name, NameAttribute

# ---------------------------------------------------------------------------
# PKI directory — override via first CLI argument
# ---------------------------------------------------------------------------

PKI_DIR = sys.argv[1] if len(sys.argv) > 1 else "/tmp/xrd-test/pki"

USER_CERT = os.path.join(PKI_DIR, "user", "usercert.pem")
USER_KEY  = os.path.join(PKI_DIR, "user", "userkey.pem")

# ---------------------------------------------------------------------------
# Load user cert and key (the proxy issuer)
# ---------------------------------------------------------------------------

with open(USER_CERT, "rb") as f:
    user_cert = x509.load_pem_x509_certificate(f.read())

with open(USER_KEY, "rb") as f:
    user_key = serialization.load_pem_private_key(f.read(), password=None)

# ---------------------------------------------------------------------------
# Generate an ephemeral RSA key for the proxy
# ---------------------------------------------------------------------------

proxy_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend(),
)

# Proxy subject: user DN + CN=<serial>
proxy_serial = 12346
user_name_attrs = list(user_cert.subject)
proxy_subject = Name(
    user_name_attrs + [NameAttribute(NameOID.COMMON_NAME, str(proxy_serial))]
)

now = datetime.datetime.now(datetime.timezone.utc)

# ---------------------------------------------------------------------------
# DER-encode the proxyCertInfo extension (RFC 3820)
# ---------------------------------------------------------------------------
# OID: 1.3.6.1.5.5.7.1.14  (id-pe-proxyCertInfo)
#
# ProxyCertInfo ::= SEQUENCE {
#     pCPathLenConstraint  INTEGER OPTIONAL,
#     proxyPolicy          ProxyPolicy
# }
# ProxyPolicy ::= SEQUENCE {
#     policyLanguage   OBJECT IDENTIFIER,
#     policy           OCTET STRING OPTIONAL
# }
#
# We use id-ppl-inheritAll (1.3.6.1.5.5.7.21.1) — the proxy inherits all
# rights from its issuer.


def encode_oid(oid_str):
    """Encode an OID string to DER content bytes."""
    parts = [int(x) for x in oid_str.split(".")]
    encoded = [40 * parts[0] + parts[1]]
    for part in parts[2:]:
        if part == 0:
            encoded.append(0)
        else:
            chunks = []
            while part > 0:
                chunks.append(part & 0x7F)
                part >>= 7
            chunks.reverse()
            for i in range(len(chunks) - 1):
                chunks[i] |= 0x80
            encoded.extend(chunks)
    return bytes(encoded)


def der_length(length):
    """Encode a DER length field."""
    if length < 0x80:
        return bytes([length])
    elif length < 0x100:
        return bytes([0x81, length])
    else:
        return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])


def der_tlv(tag, value):
    return bytes([tag]) + der_length(len(value)) + value


def der_sequence(value):
    return der_tlv(0x30, value)


def der_oid(oid_str):
    return der_tlv(0x06, encode_oid(oid_str))


id_ppl_inheritAll = "1.3.6.1.5.5.7.21.1"
proxy_policy = der_sequence(der_oid(id_ppl_inheritAll))
proxy_cert_info = der_sequence(proxy_policy)

PROXY_CERT_INFO_OID = x509.ObjectIdentifier("1.3.6.1.5.5.7.1.14")

# ---------------------------------------------------------------------------
# Build and sign the proxy certificate
# ---------------------------------------------------------------------------

builder = (
    CertificateBuilder()
    .subject_name(proxy_subject)
    .issuer_name(user_cert.subject)
    .public_key(proxy_key.public_key())
    .serial_number(proxy_serial)
    .not_valid_before(now - datetime.timedelta(minutes=5))
    .not_valid_after(now + datetime.timedelta(hours=12))
    .add_extension(
        x509.UnrecognizedExtension(PROXY_CERT_INFO_OID, proxy_cert_info),
        critical=True,
    )
    .add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )
)

proxy_cert = builder.sign(user_key, hashes.SHA256())

# ---------------------------------------------------------------------------
# Write output files
# ---------------------------------------------------------------------------

proxy_key_pem = proxy_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption(),
)
proxy_cert_pem = proxy_cert.public_bytes(serialization.Encoding.PEM)

with open(USER_CERT, "rb") as f:
    user_cert_pem = f.read()

# Standard GSI proxy file: cert + key + chain (user cert)
proxy_std_path = os.path.join(PKI_DIR, "user", "proxy_std.pem")
if os.path.exists(proxy_std_path):
    os.chmod(proxy_std_path, 0o600)
with open(proxy_std_path, "wb") as f:
    f.write(proxy_cert_pem)
    f.write(proxy_key_pem)
    f.write(user_cert_pem)
os.chmod(proxy_std_path, 0o400)

# Separate files for inspection
proxy_cert_path = os.path.join(PKI_DIR, "user", "proxy.pem")
proxy_key_path = os.path.join(PKI_DIR, "user", "proxykey.pem")

with open(proxy_cert_path, "wb") as f:
    f.write(proxy_cert_pem)
if os.path.exists(proxy_key_path):
    os.chmod(proxy_key_path, 0o600)
with open(proxy_key_path, "wb") as f:
    f.write(proxy_key_pem)
os.chmod(proxy_key_path, 0o400)

print(f"Proxy certificate created successfully.")
print(f"Subject: {proxy_cert.subject.rfc4514_string()}")
print(f"Issuer:  {proxy_cert.issuer.rfc4514_string()}")
print(f"Serial:  {proxy_cert.serial_number}")
print(f"Valid:   {proxy_cert.not_valid_before_utc} - {proxy_cert.not_valid_after_utc}")
print(f"Extensions:")
for ext in proxy_cert.extensions:
    print(f"  {ext.oid.dotted_string} critical={ext.critical}")
print()
print(f"Files written:")
print(f"  {proxy_std_path} (cert+key+chain, 0400)")
print(f"  {proxy_cert_path}")
print(f"  {proxy_key_path} (0400)")
