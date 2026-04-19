#!/usr/bin/env python3
"""
Pure-Python replacement for voms-proxy-fake from the VOMS project.

Generates an RFC 3820 proxy certificate containing a VOMS Attribute
Certificate (AC) that libvomsapi's VOMS_Retrieve() accepts.

Usage (same flags as the C++ voms-proxy-fake):

    python3 utils/voms_proxy_fake.py \\
        -cert   usercert.pem \\
        -key    userkey.pem \\
        -certdir /path/to/ca \\
        -hostcert vomscert.pem \\
        -hostkey  vomskey.pem \\
        -voms cms \\
        -fqan "/cms/Role=NULL/Capability=NULL" \\
        -uri  "voms.test.local:15000" \\
        -out  proxy_cms.pem \\
        -hours 24

Requires: cryptography (listed in requirements.txt).
"""

import argparse
import datetime
import os
import struct
import sys
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils as asym_utils
from cryptography.x509 import (
    CertificateBuilder, Name, NameAttribute, ObjectIdentifier,
    UnrecognizedExtension,
)
from cryptography.x509.oid import NameOID


# ---------------------------------------------------------------------------
# DER encoding helpers
# ---------------------------------------------------------------------------

def _der_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    elif length < 0x100:
        return bytes([0x81, length])
    elif length < 0x10000:
        return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])
    else:
        return bytes([0x83, (length >> 16) & 0xFF,
                      (length >> 8) & 0xFF, length & 0xFF])


def _der_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _der_length(len(value)) + value


def _der_seq(value: bytes) -> bytes:
    return _der_tlv(0x30, value)


def _der_set(value: bytes) -> bytes:
    return _der_tlv(0x31, value)


def _der_int(n: int) -> bytes:
    """Encode an ASN.1 INTEGER (signed, big-endian)."""
    if n == 0:
        return _der_tlv(0x02, b'\x00')
    # Convert to signed big-endian bytes
    byte_len = (n.bit_length() + 8) // 8  # +8 for sign bit headroom
    raw = n.to_bytes(byte_len, byteorder='big', signed=False)
    # Strip leading zero bytes, but keep one if high bit set
    while len(raw) > 1 and raw[0] == 0 and raw[1] < 0x80:
        raw = raw[1:]
    return _der_tlv(0x02, raw)


def _der_oid_content(oid_str: str) -> bytes:
    parts = [int(x) for x in oid_str.split('.')]
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


def _der_oid(oid_str: str) -> bytes:
    return _der_tlv(0x06, _der_oid_content(oid_str))


def _der_octet_string(value: bytes) -> bytes:
    return _der_tlv(0x04, value)


def _der_bit_string(value: bytes) -> bytes:
    # Pad bits = 0 (whole bytes)
    return _der_tlv(0x03, b'\x00' + value)


def _der_utf8(value: str) -> bytes:
    return _der_tlv(0x0C, value.encode('utf-8'))


def _der_ia5(value: str) -> bytes:
    return _der_tlv(0x16, value.encode('ascii'))


def _der_gentime(dt: datetime.datetime) -> bytes:
    s = dt.strftime('%Y%m%d%H%M%SZ')
    return _der_tlv(0x18, s.encode('ascii'))


def _der_explicit(tag_num: int, value: bytes) -> bytes:
    """CONTEXT-SPECIFIC EXPLICIT [tag_num] CONSTRUCTED."""
    return _der_tlv(0xA0 | tag_num, value)


def _der_implicit_prim(tag_num: int, value: bytes) -> bytes:
    """CONTEXT-SPECIFIC IMPLICIT [tag_num] PRIMITIVE."""
    return _der_tlv(0x80 | tag_num, value)


def _der_null() -> bytes:
    return b'\x05\x00'


def _der_bool_true() -> bytes:
    return _der_tlv(0x01, b'\xFF')


# ---------------------------------------------------------------------------
# X.500 Name to DER
# ---------------------------------------------------------------------------

_NAME_OID_MAP = {
    NameOID.DOMAIN_COMPONENT: '0.9.2342.19200300.100.1.25',
    NameOID.COMMON_NAME: '2.5.4.3',
    NameOID.ORGANIZATION_NAME: '2.5.4.10',
    NameOID.ORGANIZATIONAL_UNIT_NAME: '2.5.4.11',
    NameOID.COUNTRY_NAME: '2.5.4.6',
    NameOID.LOCALITY_NAME: '2.5.4.7',
    NameOID.STATE_OR_PROVINCE_NAME: '2.5.4.8',
    NameOID.EMAIL_ADDRESS: '1.2.840.113549.1.9.1',
}


def _encode_name_attr(attr: x509.NameAttribute) -> bytes:
    """Encode a single RDN attribute as SET { SEQUENCE { OID, value } }."""
    oid_str = _NAME_OID_MAP.get(attr.oid, attr.oid.dotted_string)
    oid_der = _der_oid(oid_str)

    # domainComponent uses IA5STRING, most others use UTF8STRING
    if attr.oid == NameOID.DOMAIN_COMPONENT:
        val_der = _der_ia5(attr.value)
    else:
        val_der = _der_utf8(attr.value)

    return _der_set(_der_seq(oid_der + val_der))


def _encode_name(name: x509.Name) -> bytes:
    """Encode an X.500 Name as DER SEQUENCE of SET of AttributeTypeAndValue."""
    body = b''
    for attr in name:
        body += _encode_name_attr(attr)
    return _der_seq(body)


def _encode_general_name_dn(name: x509.Name) -> bytes:
    """GeneralName [4] directoryName (EXPLICIT)."""
    return _der_explicit(4, _encode_name(name))


def _encode_general_names(name: x509.Name) -> bytes:
    """GeneralNames SEQUENCE of one directoryName."""
    return _der_seq(_encode_general_name_dn(name))


# ---------------------------------------------------------------------------
# VOMS Attribute Certificate builder
# ---------------------------------------------------------------------------

OID_VOMS_FQANS = '1.3.6.1.4.1.8005.100.100.4'
OID_VOMS_CERTS = '1.3.6.1.4.1.8005.100.100.10'
OID_NO_REV_AVAIL = '2.5.29.56'
OID_AUTH_KEY_ID = '2.5.29.35'
OID_SHA256_RSA = '1.2.840.113549.1.1.11'


def _build_voms_ac(
    user_cert: x509.Certificate,
    voms_cert: x509.Certificate,
    voms_key,
    vo: str,
    fqan: str,
    uri: str,
    hours: int,
) -> bytes:
    """Build and sign a VOMS Attribute Certificate as raw DER."""

    now = datetime.datetime.now(datetime.timezone.utc)
    not_before = now - datetime.timedelta(minutes=5)
    not_after = now + datetime.timedelta(hours=hours)

    # --- Holder (identifies the user cert) ---
    # holder ::= SEQUENCE {
    #   baseCertificateID [0] IMPLICIT IssuerSerial {
    #     issuer GeneralNames,   -- user cert subject (VOMS convention)
    #     serial INTEGER
    #   }
    # }
    holder_issuer_dn = _encode_general_names(user_cert.subject)
    holder_serial = _der_int(user_cert.serial_number)
    holder = _der_seq(_der_explicit(0, holder_issuer_dn + holder_serial))

    # --- Issuer (v2Form — the VOMS server) ---
    # AttCertIssuer ::= [0] IMPLICIT v2Form SEQUENCE {
    #   issuerName GeneralNames
    # }
    issuer_dn = _der_seq(_der_explicit(4, _encode_name(voms_cert.subject)))
    ac_issuer = _der_explicit(0, issuer_dn)

    # --- Signature algorithm identifier ---
    sig_alg = _der_seq(_der_oid(OID_SHA256_RSA) + _der_null())

    # --- Serial number ---
    ac_serial = _der_int(1)

    # --- Validity ---
    validity = _der_seq(_der_gentime(not_before) + _der_gentime(not_after))

    # --- Attributes (VOMS FQANs) ---
    # The FQAN attribute value structure:
    # SEQUENCE {
    #   [0] { [6] IA5 "vo://uri" }      -- policy authority
    #   SEQUENCE { OCTET STRING fqan }   -- list of FQANs
    # }
    policy_uri = f"{vo}://{uri}"
    policy_authority = _der_explicit(0,
        _der_implicit_prim(6, policy_uri.encode('ascii'))
    )
    fqan_list = _der_seq(_der_octet_string(fqan.encode('ascii')))
    fqan_value = _der_seq(policy_authority + fqan_list)
    fqan_attr = _der_seq(
        _der_oid(OID_VOMS_FQANS) + _der_set(fqan_value)
    )
    attributes = _der_seq(fqan_attr)

    # --- Extensions ---
    # 1. Embedded VOMS signing cert (OID_VOMS_CERTS)
    # Value is SEQUENCE OF SEQUENCE OF Certificate (chain-of-chains).
    voms_cert_der = voms_cert.public_bytes(serialization.Encoding.DER)
    certs_ext = _der_seq(
        _der_oid(OID_VOMS_CERTS) +
        _der_octet_string(_der_seq(_der_seq(voms_cert_der)))
    )

    # 2. noRevocationAvailable
    no_rev = _der_seq(
        _der_oid(OID_NO_REV_AVAIL) +
        _der_octet_string(_der_null())
    )

    # 3. authorityKeyIdentifier (VOMS cert's SKI)
    try:
        ski_ext = voms_cert.extensions.get_extension_for_oid(
            ObjectIdentifier('2.5.29.14')
        )
        ski_bytes = ski_ext.value.digest
    except x509.ExtensionNotFound:
        ski_bytes = None

    extensions_body = certs_ext + no_rev
    if ski_bytes is not None:
        aki_value = _der_seq(_der_implicit_prim(0, ski_bytes))
        aki_ext = _der_seq(
            _der_oid(OID_AUTH_KEY_ID) +
            _der_octet_string(aki_value)
        )
        extensions_body += aki_ext

    extensions = _der_seq(extensions_body)

    # --- TBSAttributeCertificate ---
    # version (v2 = 1)
    tbs = (
        _der_int(1) +      # version
        holder +            # holder
        ac_issuer +         # issuer
        sig_alg +           # signature algorithm
        ac_serial +         # serial
        validity +          # validity
        attributes +        # attributes
        extensions          # extensions
    )
    tbs_der = _der_seq(tbs)

    # --- Sign TBS with VOMS key ---
    signature = voms_key.sign(
        tbs_der,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )

    # --- AttributeCertificate ::= SEQUENCE { tbs, sigAlg, sig } ---
    ac = _der_seq(tbs_der + sig_alg + _der_bit_string(signature))

    # VOMS wraps ACs in: SEQUENCE { SEQUENCE { ac } }
    return _der_seq(_der_seq(ac))


# ---------------------------------------------------------------------------
# Proxy certificate builder (RFC 3820 with VOMS AC extension)
# ---------------------------------------------------------------------------

OID_PROXY_CERT_INFO = '1.3.6.1.5.5.7.1.14'
OID_VOMS_EXTENSION  = '1.3.6.1.4.1.8005.100.100.5'


def _proxy_cert_info_der() -> bytes:
    """DER-encode proxyCertInfo with id-ppl-inheritAll policy."""
    id_ppl_inherit_all = '1.3.6.1.5.5.7.21.1'
    proxy_policy = _der_seq(_der_oid(id_ppl_inherit_all))
    return _der_seq(proxy_policy)


def build_voms_proxy(
    user_cert_path: str,
    user_key_path: str,
    voms_cert_path: str,
    voms_key_path: str,
    vo: str,
    fqan: str,
    uri: str,
    out_path: str,
    hours: int = 24,
):
    # Load credentials
    with open(user_cert_path, 'rb') as f:
        user_cert = x509.load_pem_x509_certificate(f.read())
    with open(user_key_path, 'rb') as f:
        user_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(voms_cert_path, 'rb') as f:
        voms_cert = x509.load_pem_x509_certificate(f.read())
    with open(voms_key_path, 'rb') as f:
        voms_key = serialization.load_pem_private_key(f.read(), password=None)

    # Generate proxy key
    proxy_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Proxy serial (random-ish, matches voms-proxy-fake's behavior)
    import random
    proxy_serial = random.randint(100000000, 2147483647)

    # Proxy subject: user DN + CN=<serial>
    user_name_attrs = list(user_cert.subject)
    proxy_subject = Name(
        user_name_attrs + [NameAttribute(NameOID.COMMON_NAME, str(proxy_serial))]
    )

    now = datetime.datetime.now(datetime.timezone.utc)

    # Build the VOMS Attribute Certificate
    voms_ac_der = _build_voms_ac(
        user_cert, voms_cert, voms_key,
        vo, fqan, uri, hours,
    )

    # Build proxy certificate
    builder = (
        CertificateBuilder()
        .subject_name(proxy_subject)
        .issuer_name(user_cert.subject)
        .public_key(proxy_key.public_key())
        .serial_number(proxy_serial)
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(hours=hours))
        .add_extension(
            UnrecognizedExtension(
                ObjectIdentifier(OID_VOMS_EXTENSION),
                voms_ac_der,
            ),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            UnrecognizedExtension(
                ObjectIdentifier(OID_PROXY_CERT_INFO),
                _proxy_cert_info_der(),
            ),
            critical=True,
        )
    )

    proxy_cert = builder.sign(user_key, hashes.SHA256())

    # Write output: proxy cert + proxy key + user cert (chain)
    proxy_cert_pem = proxy_cert.public_bytes(serialization.Encoding.PEM)
    proxy_key_pem = proxy_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(user_cert_path, 'rb') as f:
        user_cert_pem = f.read()

    combined = proxy_cert_pem + proxy_key_pem + user_cert_pem

    out_dir = os.path.dirname(out_path) or '.'
    os.makedirs(out_dir, exist_ok=True)

    # Existing proxy files are intentionally mode 0400. Replacing them via
    # O_TRUNC fails once the file is no longer owner-writable, so write a new
    # file in the same directory and atomically swap it into place instead.
    fd, tmp_path = tempfile.mkstemp(prefix='.voms-proxy-', dir=out_dir)
    try:
        try:
            os.write(fd, combined)
            os.fchmod(fd, 0o400)
        finally:
            os.close(fd)

        os.replace(tmp_path, out_path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except FileNotFoundError:
            pass
        raise

    not_after = now + datetime.timedelta(hours=hours)
    print(f"Your proxy is valid until {not_after.strftime('%c %Z')}")


# ---------------------------------------------------------------------------
# CLI — compatible with voms-proxy-fake flags
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(
        description='Generate a VOMS proxy certificate (pure-Python replacement for voms-proxy-fake)',
    )
    p.add_argument('-cert',     required=True, help='User certificate PEM')
    p.add_argument('-key',      required=True, help='User private key PEM')
    p.add_argument('-certdir',  required=False, help='Trusted CA directory (unused, accepted for compat)')
    p.add_argument('-hostcert', required=True, help='VOMS server certificate PEM')
    p.add_argument('-hostkey',  required=True, help='VOMS server private key PEM')
    p.add_argument('-voms',     required=True, help='VO name')
    p.add_argument('-fqan',     required=True, help='FQAN string (e.g. /cms/Role=NULL/Capability=NULL)')
    p.add_argument('-uri',      required=True, help='VOMS server URI (hostname:port)')
    p.add_argument('-out',      required=True, help='Output proxy file path')
    p.add_argument('-hours',    type=int, default=24, help='Proxy validity in hours (default: 24)')
    p.add_argument('-rfc',      action='store_true', help='RFC proxy (always true, accepted for compat)')

    args = p.parse_args()

    build_voms_proxy(
        user_cert_path=args.cert,
        user_key_path=args.key,
        voms_cert_path=args.hostcert,
        voms_key_path=args.hostkey,
        vo=args.voms,
        fqan=args.fqan,
        uri=args.uri,
        out_path=args.out,
        hours=args.hours,
    )


if __name__ == '__main__':
    main()
