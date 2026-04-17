# Test PKI and VOMS from scratch

This guide walks through creating an entire test Certificate Authority, host/user certificates, RFC 3820 proxy certificates, and a VOMS infrastructure — all using standard command-line tools and a small Python script. Everything is self-signed and local; no external CA is involved.

The generated material is used by the nginx-xrootd test suite but is also a useful reference for understanding how GSI and VOMS authentication work in XRootD.

---

## Prerequisites

```bash
# Tools
openssl version          # 1.1.1+ or 3.x
voms-proxy-fake --help   # from voms-clients-cpp package

# Python (for RFC 3820 proxy generation)
pip install cryptography
```

---

## 1. Directory layout

```bash
PKI=/tmp/xrd-test/pki

mkdir -p $PKI/{ca,server,user,voms,vomsdir}
```

| Directory | Contents |
|---|---|
| `ca/` | Root CA certificate, private key, hash symlinks, signing policy |
| `server/` | Host certificate and key (for nginx TLS) |
| `user/` | End-entity user certificate, key, and proxy certificates |
| `voms/` | VOMS signing certificate and key |
| `vomsdir/` | Per-VO LSC files that map VO names to VOMS server certs |

---

## 2. Create the test CA

### 2.1 Generate the CA key and self-signed certificate

```bash
cd $PKI/ca

# 4096-bit RSA key
openssl genrsa -out ca.key 4096
chmod 400 ca.key

# Self-signed CA cert, 10 years, with BasicConstraints: CA:TRUE
openssl req -new -x509 \
    -key ca.key \
    -out ca.pem \
    -days 3650 \
    -subj "/DC=test/DC=xrootd/CN=Test XRootD CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "subjectKeyIdentifier=hash" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"
```

Verify:

```bash
openssl x509 -in ca.pem -noout -subject -issuer -dates
# subject=  DC = test, DC = xrootd, CN = Test XRootD CA
# issuer=   DC = test, DC = xrootd, CN = Test XRootD CA
# notBefore= ...
# notAfter=  ... (10 years)
```

### 2.2 Create hash symlinks

XRootD (and OpenSSL) locate trusted CA certificates by a hash of the subject name. Two hash formats exist:

- **New-style** (`openssl x509 -subject_hash`): used by OpenSSL 1.0+
- **Old-style** (`openssl x509 -subject_hash_old`): used by older OpenSSL and some XRootD builds

You need symlinks for both:

```bash
cd $PKI/ca

NEW_HASH=$(openssl x509 -in ca.pem -noout -subject_hash)
OLD_HASH=$(openssl x509 -in ca.pem -noout -subject_hash_old)

ln -sf ca.pem "${NEW_HASH}.0"
ln -sf ca.pem "${OLD_HASH}.0"

echo "New hash: $NEW_HASH  Old hash: $OLD_HASH"
# Example: New hash: 03628dcb  Old hash: f79132b2
```

### 2.3 Create signing policy files

Grid middleware requires a `signing_policy` file alongside each hash symlink. This defines which Distinguished Names the CA is trusted to sign:

```bash
cd $PKI/ca

CA_DN="/DC=test/DC=xrootd/CN=Test XRootD CA"

for HASH in "$NEW_HASH" "$OLD_HASH"; do
    cat > "${HASH}.signing_policy" <<EOF
access_id_CA    X509    '${CA_DN}'
pos_rights      globus  CA:sign
cond_subjects   globus  '"/DC=test/DC=xrootd/*"'
EOF
done
```

The `cond_subjects` line restricts the CA to only sign certificates with subjects under `/DC=test/DC=xrootd/`.

### 2.4 Verify the CA directory

```bash
ls -la $PKI/ca/
# ca.key            (private key, mode 0400)
# ca.pem            (CA certificate)
# 03628dcb.0 -> ca.pem
# 03628dcb.signing_policy
# f79132b2.0 -> ca.pem
# f79132b2.signing_policy
```

---

## 3. Create the host (server) certificate

The host certificate is what nginx presents to TLS clients (XRootD GSI, WebDAV HTTPS).

```bash
cd $PKI/server

# Generate host key
openssl genrsa -out hostkey.pem 2048
chmod 400 hostkey.pem

# Create CSR
openssl req -new \
    -key hostkey.pem \
    -out host.csr \
    -subj "/DC=test/DC=xrootd/CN=localhost"

# Sign with the CA
openssl x509 -req \
    -in host.csr \
    -CA $PKI/ca/ca.pem \
    -CAkey $PKI/ca/ca.key \
    -CAcreateserial \
    -out hostcert.pem \
    -days 3650
```

Verify the chain:

```bash
openssl verify -CAfile $PKI/ca/ca.pem $PKI/server/hostcert.pem
# hostcert.pem: OK
```

---

## 4. Create the user certificate

The user certificate represents a grid user. The test suite gives the user an extra `CN` component (simulating a UID or registration number):

```bash
cd $PKI/user

# Generate user key
openssl genrsa -out userkey.pem 2048
chmod 400 userkey.pem

# Create CSR
openssl req -new \
    -key userkey.pem \
    -out user.csr \
    -subj "/DC=test/DC=xrootd/CN=Test User/CN=12345"

# Sign with the CA
openssl x509 -req \
    -in user.csr \
    -CA $PKI/ca/ca.pem \
    -CAkey $PKI/ca/ca.key \
    -CAcreateserial \
    -out usercert.pem \
    -days 3650
```

Verify:

```bash
openssl verify -CAfile $PKI/ca/ca.pem $PKI/user/usercert.pem
# usercert.pem: OK

openssl x509 -in usercert.pem -noout -subject
# subject= DC = test, DC = xrootd, CN = Test User, CN = 12345
```

---

## 5. Create GSI proxy certificates

An RFC 3820 proxy certificate is a short-lived credential derived from the user's certificate. XRootD's GSI authentication requires a `proxyCertInfo` extension (OID `1.3.6.1.5.5.7.1.14`) for the library to recognize it as a proxy rather than an end-entity certificate.

### 5.1 Understanding the proxy structure

A proxy certificate file (in GSI convention) contains, in order:

1. **Proxy certificate** — signed by the user's private key
2. **Proxy private key** — the proxy's own ephemeral key
3. **User certificate** — the issuer, to complete the chain

The proxy subject name is the user's DN with an additional `CN=<unique>` appended: `/DC=test/DC=xrootd/CN=Test User/CN=12345/CN=12346`

### 5.2 The proxyCertInfo extension

The critical extension that marks a certificate as an RFC 3820 proxy:

```
OID: 1.3.6.1.5.5.7.1.14  (id-pe-proxyCertInfo)

ProxyCertInfo ::= SEQUENCE {
    pCPathLenConstraint  INTEGER OPTIONAL,
    proxyPolicy          ProxyPolicy
}

ProxyPolicy ::= SEQUENCE {
    policyLanguage   OBJECT IDENTIFIER,
    policy           OCTET STRING OPTIONAL
}
```

Most grid proxies use `id-ppl-inheritAll` (`1.3.6.1.5.5.7.21.1`) as the policy language, meaning the proxy inherits all rights from its issuer (the user cert).

### 5.3 Generate the proxy with Python

The Python `cryptography` library does not have native RFC 3820 support, so the extension must be DER-encoded manually. The implementation lives in [`utils/make_proxy.py`](../utils/make_proxy.py); run that helper instead of copying Python from this guide:

```bash
# From the project root (uses default PKI path /tmp/xrd-test/pki)
python3 utils/make_proxy.py

# Or with a custom PKI directory
python3 utils/make_proxy.py /path/to/pki
```

### 5.4 Verify the proxy

```bash
# Inspect the proxy certificate (first cert in the file)
openssl x509 -in $PKI/user/proxy_std.pem -noout -subject -issuer -dates -ext proxyCertInfo

# Verify the chain: proxy → user → CA
openssl verify -CAfile $PKI/ca/ca.pem \
    -untrusted $PKI/user/usercert.pem \
    $PKI/user/proxy_std.pem
```

Note: OpenSSL's `verify` command may not fully understand RFC 3820 proxies. A successful chain verification confirms the signature chain is valid; actual proxy semantics are handled by XRootD's `XrdSecGSI` library.

### 5.5 Test the proxy with XRootD

```bash
export X509_USER_PROXY=$PKI/user/proxy_std.pem
export X509_CERT_DIR=$PKI/ca

# List the root directory on the GSI server (port 11095)
xrdfs root://localhost:11095 ls /

# Copy a file
echo "proxy test" > /tmp/proxy_test.txt
xrdcp /tmp/proxy_test.txt root://localhost:11095//proxy_test.txt
xrdcp root://localhost:11095//proxy_test.txt /tmp/proxy_test_downloaded.txt
diff /tmp/proxy_test.txt /tmp/proxy_test_downloaded.txt
```

---

## 6. VOMS infrastructure

VOMS (Virtual Organization Membership Service) adds VO membership attributes to a proxy certificate via an Attribute Certificate (AC) embedded as an X.509 extension. The nginx-xrootd module can enforce VO membership on specific paths with `xrootd_require_vo`.

### 6.1 Create the VOMS signing certificate

The VOMS signing cert is **not** the CA — it is a separate certificate that signs the Attribute Certificate embedded in a VOMS proxy. It must have a `SubjectKeyIdentifier` extension so that `voms-proxy-fake` can generate the corresponding `AuthorityKeyIdentifier` in the AC.

```bash
cd $PKI/voms

# Generate key
openssl genrsa -out vomskey.pem 2048
chmod 400 vomskey.pem

# Create CSR
openssl req -new \
    -key vomskey.pem \
    -out voms.csr \
    -subj "/DC=test/DC=xrootd/CN=voms.test.local"

# Extension config file
cat > voms_ext.conf <<EOF
[voms_ext]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
basicConstraints = CA:FALSE
EOF

# Sign with the CA
openssl x509 -req \
    -in voms.csr \
    -CA $PKI/ca/ca.pem \
    -CAkey $PKI/ca/ca.key \
    -CAcreateserial \
    -out vomscert.pem \
    -days 365 \
    -extensions voms_ext \
    -extfile voms_ext.conf
```

Verify:

```bash
openssl x509 -in vomscert.pem -noout -subject -ext subjectKeyIdentifier
# subject= DC = test, DC = xrootd, CN = voms.test.local
# X509v3 Subject Key Identifier:
#     XX:XX:XX:XX:...
```

### 6.2 Create vomsdir LSC files

The `vomsdir` tells the XRootD VOMS library which certificate to trust for each VO's attribute assertions. Each VO gets a directory containing an `.lsc` file named after the VOMS server hostname:

```bash
# Get the VOMS cert's subject and issuer DNs in OpenSSL one-line format
VOMS_SUBJECT=$(openssl x509 -in $PKI/voms/vomscert.pem -noout -subject -nameopt compat \
    | sed 's/^subject= *//')
VOMS_ISSUER=$(openssl x509 -in $PKI/voms/vomscert.pem -noout -issuer -nameopt compat \
    | sed 's/^issuer= *//')

echo "VOMS Subject: $VOMS_SUBJECT"
echo "VOMS Issuer:  $VOMS_ISSUER"

# Create LSC files for each VO
for VO in cms atlas; do
    mkdir -p $PKI/vomsdir/$VO
    cat > $PKI/vomsdir/$VO/voms.test.local.lsc <<EOF
$VOMS_SUBJECT
$VOMS_ISSUER
EOF
done
```

An LSC file has exactly two lines:

1. The VOMS signing certificate's subject DN
2. The VOMS signing certificate's issuer DN (our CA)

### 6.3 Verify the vomsdir

```bash
cat $PKI/vomsdir/cms/voms.test.local.lsc
# /DC=test/DC=xrootd/CN=voms.test.local
# /DC=test/DC=xrootd/CN=Test XRootD CA

cat $PKI/vomsdir/atlas/voms.test.local.lsc
# (same content — both VOs use the same signing cert in this test setup)
```

---

## 7. Generate VOMS proxies

A VOMS proxy is a standard GSI proxy with an additional extension containing the Attribute Certificate. The `voms-proxy-fake` tool generates these without needing a running VOMS server.

### 7.1 Generate per-VO proxies

```bash
# CMS proxy
voms-proxy-fake \
    -cert     $PKI/user/usercert.pem \
    -key      $PKI/user/userkey.pem \
    -certdir  $PKI/ca \
    -hostcert $PKI/voms/vomscert.pem \
    -hostkey  $PKI/voms/vomskey.pem \
    -voms     cms \
    -fqan     "/cms/Role=NULL/Capability=NULL" \
    -uri      "voms.test.local:15000" \
    -out      $PKI/user/proxy_cms.pem \
    -hours    24

# ATLAS proxy
voms-proxy-fake \
    -cert     $PKI/user/usercert.pem \
    -key      $PKI/user/userkey.pem \
    -certdir  $PKI/ca \
    -hostcert $PKI/voms/vomscert.pem \
    -hostkey  $PKI/voms/vomskey.pem \
    -voms     atlas \
    -fqan     "/atlas/Role=NULL/Capability=NULL" \
    -uri      "voms.test.local:15000" \
    -out      $PKI/user/proxy_atlas.pem \
    -hours    24
```

Explanation of arguments:

| Flag | Purpose |
|---|---|
| `-cert`, `-key` | The user certificate and key (proxy issuer) |
| `-certdir` | Directory containing trusted CA hashes (for chain verification) |
| `-hostcert`, `-hostkey` | The VOMS signing cert and key (signs the Attribute Certificate) |
| `-voms` | The VO name embedded in the AC |
| `-fqan` | Fully Qualified Attribute Name: `/<vo>/Role=.../Capability=...` |
| `-uri` | VOMS server URI embedded in the AC (cosmetic — no actual VOMS server contacted) |
| `-out` | Output proxy file path |
| `-hours` | Proxy lifetime |

### 7.2 Inspect the VOMS proxy

```bash
# Basic cert info
openssl x509 -in $PKI/user/proxy_cms.pem -noout -subject -issuer
# subject= DC = test, DC = xrootd, CN = Test User, CN = 12345, CN = <serial>
# issuer=  DC = test, DC = xrootd, CN = Test User, CN = 12345

# Dump the full ASN.1 structure to see the VOMS AC
openssl x509 -in $PKI/user/proxy_cms.pem -noout -text | grep -A5 "VOMS\|1.3.6.1.4.1.8005"
```

### 7.3 Check proxy expiry

```bash
# Returns 0 if proxy is valid for at least 1 more hour
openssl x509 -in $PKI/user/proxy_cms.pem -noout -checkend 3600
echo "Exit code: $?"   # 0 = valid, 1 = expires within 1 hour
```

---

## 8. Test the complete setup

This section demonstrates verifying every layer of the authentication stack.

### 8.1 Anonymous access (port 11094)

No certificates needed:

```bash
xrdfs root://localhost:11094 ls /
# Expected: test.txt, cms/, atlas/, public/

echo "anon test" | xrdcp - root://localhost:11094//anon_upload.txt
xrdcp root://localhost:11094//anon_upload.txt -
# Expected: anon test
```

### 8.2 GSI access with plain proxy (port 11095)

```bash
export X509_USER_PROXY=$PKI/user/proxy_std.pem
export X509_CERT_DIR=$PKI/ca

xrdfs root://localhost:11095 ls /
# Expected: same listing

xrdfs root://localhost:11095 stat /test.txt
# Expected: file metadata (size, flags, etc.)
```

### 8.3 VO ACL enforcement (port 11096)

This server requires VO membership for `/cms/` and `/atlas/` paths. Start the VO test server first (or use `pytest tests/test_vo_acl.py` which starts it automatically):

```bash
# With CMS proxy — can access /cms/ but not /atlas/
export X509_USER_PROXY=$PKI/user/proxy_cms.pem
xrdfs root://localhost:11096 ls /cms/
# Expected: seed.txt

xrdfs root://localhost:11096 ls /atlas/
# Expected: DENIED (wrong VO)

# With ATLAS proxy — opposite
export X509_USER_PROXY=$PKI/user/proxy_atlas.pem
xrdfs root://localhost:11096 ls /atlas/
# Expected: seed.txt

xrdfs root://localhost:11096 ls /cms/
# Expected: DENIED (wrong VO)

# /public/ is unrestricted regardless of VO
xrdfs root://localhost:11096 ls /public/
# Expected: seed.txt

# Plain GSI proxy (no VOMS) — can access /public/ but not /cms/ or /atlas/
export X509_USER_PROXY=$PKI/user/proxy_std.pem
xrdfs root://localhost:11096 ls /public/
# Expected: seed.txt

xrdfs root://localhost:11096 ls /cms/
# Expected: DENIED (no VOMS extension)
```

### 8.4 Run the automated test suite

```bash
cd /path/to/nginx-xrootd
source .venv/bin/activate

# Run all tests
pytest -v

# Run VO ACL tests specifically (starts its own nginx on 11096)
pytest tests/test_vo_acl.py -v

# Expected: all selected tests pass
```

---

## 9. nginx.conf — VO ACL directives

For reference, the VO-enforced server block uses these directives:

```nginx
stream {
    server {
        listen 11096;
        xrootd on;
        xrootd_root /tmp/xrd-test/data;
        xrootd_auth gsi;
        xrootd_allow_write on;

        xrootd_certificate     /tmp/xrd-test/pki/server/hostcert.pem;
        xrootd_certificate_key /tmp/xrd-test/pki/server/hostkey.pem;
        xrootd_trusted_ca      /tmp/xrd-test/pki/ca/ca.pem;

        # VOMS configuration
        xrootd_vomsdir         /tmp/xrd-test/pki/vomsdir;
        xrootd_voms_cert_dir   /tmp/xrd-test/pki/ca;

        # Path-based VO restrictions
        xrootd_require_vo /cms   cms;
        xrootd_require_vo /atlas atlas;
        # /public/ is not listed — accessible to any authenticated user
    }
}
```

| Directive | Purpose |
|---|---|
| `xrootd_vomsdir` | Path to the vomsdir containing per-VO LSC files |
| `xrootd_voms_cert_dir` | Path to the directory with trusted CA hashes (for verifying the VOMS signing cert chain) |
| `xrootd_require_vo <path> <vo>` | Restrict `<path>` so that only proxies bearing a VOMS AC for `<vo>` are admitted |

---

## 10. Certificate revocation lists

The stream and WebDAV GSI paths can reject revoked certificates using PEM CRLs.

### 10.1 Generate a test CRL

For a local test CA, generate a CRL that revokes the user certificate:

```bash
python3 utils/make_crl.py /tmp/xrd-test/pki
```

### 10.2 Configure stream and WebDAV CRL checks

```nginx
stream {
    server {
        listen 11100;
        xrootd on;
        xrootd_root /tmp/xrd-test/data;
        xrootd_auth gsi;
        xrootd_certificate     /tmp/xrd-test/pki/server/hostcert.pem;
        xrootd_certificate_key /tmp/xrd-test/pki/server/hostkey.pem;
        xrootd_trusted_ca      /tmp/xrd-test/pki/ca/ca.pem;
        xrootd_crl             /tmp/xrd-test/pki/ca/test-user.crl.pem;
        xrootd_crl_reload      300;
    }
}

http {
    server {
        listen 8444 ssl;
        ssl_certificate     /tmp/xrd-test/pki/server/hostcert.pem;
        ssl_certificate_key /tmp/xrd-test/pki/server/hostkey.pem;
        ssl_verify_client   optional_no_ca;
        xrootd_webdav_proxy_certs on;

        location / {
            xrootd_webdav         on;
            xrootd_webdav_root    /tmp/xrd-test/data;
            xrootd_webdav_cafile  /tmp/xrd-test/pki/ca/ca.pem;
            xrootd_webdav_crl     /tmp/xrd-test/pki/ca/test-user.crl.pem;
            xrootd_webdav_auth    required;
        }
    }
}
```

The automated CRL tests generate their own CRL and sidecar nginx instance on stream port 11100 and WebDAV port 8444:

```bash
pytest tests/test_crl.py -v
```

---

## 11. Troubleshooting

### Proxy not recognized as valid

```
Error: [ERROR] XrdSecGSI: proxy certificate lacks proxyCertInfo
```

The proxy was created without the RFC 3820 `proxyCertInfo` extension (OID `1.3.6.1.5.5.7.1.14`). Standard `openssl req -new -x509` does not generate this extension. Use the Python script from section 5.3 or a grid-aware tool like `voms-proxy-init`.

### CA hash not found

```
Error: unable to get local issuer certificate
```

Ensure both new-style and old-style hash symlinks exist in the CA directory:

```bash
ls $PKI/ca/*.0
# Should show at least two .0 symlinks pointing to ca.pem
```

### VOMS proxy rejected — wrong vomsdir

```
Error: [WARNING] VO cms: cannot verify VOMS signature
```

Check the LSC file contents. The subject and issuer DNs must match the VOMS signing cert exactly, in OpenSSL one-line format with each RDN preceded by `/`:

```bash
openssl x509 -in $PKI/voms/vomscert.pem -noout -subject -issuer -nameopt compat
diff <(head -1 $PKI/vomsdir/cms/voms.test.local.lsc) \
     <(openssl x509 -in $PKI/voms/vomscert.pem -noout -subject -nameopt compat | sed 's/^subject= *//')
```

### signing_policy missing

```
Error: [ERROR] XrdSecGSI: signing_policy not found for CA hash XXXXXXXX
```

Create the signing policy file for each hash:

```bash
ls $PKI/ca/*.signing_policy
# Should list signing_policy files for both hash values
```

### Expired proxy

Proxies are short-lived. Regenerate:

```bash
python3 utils/make_proxy.py              # plain GSI proxy (12 hours)
voms-proxy-fake ... -hours 24 ...       # VOMS proxy (24 hours)
```

The test suite's session fixture auto-regenerates expired proxies on each run.
