# Test tokens from scratch

This guide walks through creating a JWT/WLCG token signing authority, generating tokens, and testing them against nginx-xrootd — all using local tools with no external identity provider. It is the token equivalent of [test-pki.md](test-pki.md).

The generated material is used by the nginx-xrootd test suite but is also a useful reference for understanding how WLCG bearer-token authentication works in the native XRootD stream protocol and in WebDAV.

---

## Background: what are WLCG tokens?

If you are coming from the GSI/x509 world, WLCG tokens are the modern replacement for proxy certificates. Instead of a certificate chain rooted in a grid CA, the client presents a signed JSON Web Token (JWT) that says _who they are_, _what they can do_, and _when it expires_.

Key concepts:

| Concept | GSI equivalent | What it means |
|---|---|---|
| **Issuer** (`iss`) | Certificate Authority | The entity that signed the token — you trust tokens from this issuer |
| **Audience** (`aud`) | Host certificate CN | Which service the token is intended for — your server's identifier |
| **Subject** (`sub`) | Certificate DN | Who the token represents — a username or service account |
| **Scope** (`scope`) | VOMS FQAN | What the bearer can do — `storage.read:/`, `storage.write:/data` etc. |
| **JWKS** | CA certificate | The public key used to verify the token's signature |
| **Expiry** (`exp`) | Proxy lifetime | When the token stops being valid |

The server validates a token by:
1. Decoding the JWT header to find the key ID (`kid`)
2. Looking up the corresponding public key in its configured JWKS file
3. Verifying the RS256 signature
4. Checking `iss`, `aud`, `exp`, and `nbf` claims
5. Parsing `scope` and `wlcg.groups` claims for later authorization decisions

Current behavior is intentionally split by protocol. The native stream path validates tokens and stores scopes/groups, but write access is still controlled by `xrootd_allow_write` and path ACLs use `xrootd_require_vo` with `wlcg.groups`. WebDAV enforces `storage.write`/`storage.create` scopes for `PUT` requests authenticated by bearer token.

No network call to an identity provider is needed at validation time — the JWKS file contains everything.

---

## Prerequisites

```bash
# Python 3.8+ with the cryptography library
pip install cryptography

# XRootD client tools (for end-to-end testing)
# RHEL/CentOS:  yum install xrootd-client
# Ubuntu/Debian: apt install xrootd-client

# curl (for WebDAV testing)
curl --version
```

No external services, OAuth providers, or IAM registrations are needed. Everything runs locally.

---

## 1. Directory layout

```bash
TOKEN_DIR=/tmp/xrd-test/tokens

mkdir -p $TOKEN_DIR
```

| File | Contents |
|---|---|
| `signing_key.pem` | RSA-2048 private key (used to sign tokens) |
| `jwks.json` | JSON Web Key Set containing the matching public key (loaded by nginx) |

That is the entire signing authority. Two files.

---

## 2. Create the signing authority

### 2.1 Using the helper script (recommended)

The project includes a ready-made script at [`utils/make_token.py`](../utils/make_token.py):

```bash
python3 utils/make_token.py init /tmp/xrd-test/tokens
```

This generates:
- `/tmp/xrd-test/tokens/signing_key.pem` — the RSA-2048 private key (mode `0400`)
- `/tmp/xrd-test/tokens/jwks.json` — the corresponding public key in JWKS format

That is it. Your signing authority is ready.

### 2.2 What the helper creates

The signing authority is just an RSA keypair. The private key signs tokens; the public key, published as a JWKS, lets the server verify them. The implementation lives in [`utils/make_token.py`](../utils/make_token.py), primarily in `TokenIssuer.init_keys()`.

```bash
python3 utils/make_token.py init /tmp/xrd-test/tokens
# Signing key: /tmp/xrd-test/tokens/signing_key.pem
# JWKS:        /tmp/xrd-test/tokens/jwks.json
```

### 2.3 Inspect the JWKS

```bash
cat /tmp/xrd-test/tokens/jwks.json
```

```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "test-key-1",
      "use": "sig",
      "alg": "RS256",
      "n": "wJ3x...<base64url-encoded RSA modulus>...",
      "e": "AQAB"
    }
  ]
}
```

The `kid` (key ID) field is important: every token's header includes a `kid` that tells the server which key to use for verification. In a test setup with one key, this is always `"test-key-1"`.

The `e` value `"AQAB"` is the base64url encoding of 65537, the standard RSA public exponent.

---

## 3. Configure nginx

### 3.1 XRootD stream protocol (token auth on a dedicated port)

```nginx
stream {
    server {
        listen 11099;
        xrootd on;
        xrootd_root /tmp/xrd-test/data;
        xrootd_auth token;
        xrootd_allow_write on;

        xrootd_token_jwks     /tmp/xrd-test/tokens/jwks.json;
        xrootd_token_issuer   "https://test.example.com";
        xrootd_token_audience "nginx-xrootd";

        xrootd_access_log /tmp/xrd-test/logs/xrootd_access_token.log;
    }
}
```

| Directive | Purpose |
|---|---|
| `xrootd_auth token` | Require a JWT bearer token for every session |
| `xrootd_token_jwks` | Path to the JWKS file containing trusted public keys |
| `xrootd_token_issuer` | Expected `iss` claim — tokens from other issuers are rejected |
| `xrootd_token_audience` | Expected `aud` claim — tokens for other services are rejected |

### 3.2 WebDAV/HTTPS (Bearer header over HTTPS)

Token auth also works over HTTPS/WebDAV. The client sends the token in the `Authorization: Bearer <token>` HTTP header:

```nginx
http {
    server {
        listen 8443 ssl;
        server_name localhost;

        ssl_certificate     /tmp/xrd-test/pki/server/hostcert.pem;
        ssl_certificate_key /tmp/xrd-test/pki/server/hostkey.pem;

        location / {
            xrootd_webdav         on;
            xrootd_webdav_root    /tmp/xrd-test/data;
            xrootd_webdav_auth    optional;  # use required to reject anonymous fallback
            xrootd_webdav_allow_write on;

            xrootd_webdav_token_jwks     /tmp/xrd-test/tokens/jwks.json;
            xrootd_webdav_token_issuer   "https://test.example.com";
            xrootd_webdav_token_audience "nginx-xrootd";
        }
    }
}
```

### 3.3 Both GSI and token on the same port

If you want to accept either GSI proxy certificates or bearer tokens on a single port:

```nginx
stream {
    server {
        listen 1094;
        xrootd on;
        xrootd_auth both;    # accept GSI or token credentials
        xrootd_root /data;

        # GSI settings
        xrootd_certificate     /etc/grid-security/hostcert.pem;
        xrootd_certificate_key /etc/grid-security/hostkey.pem;
        xrootd_trusted_ca      /etc/grid-security/ca.pem;

        # Token settings
        xrootd_token_jwks     /etc/tokens/jwks.json;
        xrootd_token_issuer   "https://idp.example.com";
        xrootd_token_audience "my-storage";
    }
}
```

The module inspects the credential type in the `kXR_auth` request: `gsi` routes to the GSI handshake, `ztn` routes to token validation.

---

## 4. Generate tokens

### 4.1 Generate a read-only token (CLI)

```bash
python3 utils/make_token.py gen \
    --scope "storage.read:/" \
    /tmp/xrd-test/tokens
```

This prints the token to stdout:

```
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2V5LTEifQ.eyJpc3MiOiJodHRwczovL3Rlc3QuZXhhbXBsZS5jb20iLCJzdWIiOiJ0ZXN0dXNlciIsImF1ZCI6Im5naW54LXhyb290ZCIsImV4cCI6...
```

Save it to a file or an environment variable:

```bash
# To a file
python3 utils/make_token.py gen --scope "storage.read:/" -o /tmp/token.jwt

# To an environment variable
export BEARER_TOKEN=$(python3 utils/make_token.py gen \
    --scope "storage.read:/" /tmp/xrd-test/tokens)
```

### 4.2 Generate a read-write token

```bash
python3 utils/make_token.py gen \
    --scope "storage.read:/ storage.write:/" \
    /tmp/xrd-test/tokens
```

Multiple scopes are space-separated in the `--scope` argument.

### 4.3 Generate a path-scoped token

Restrict the token to specific paths:

```bash
# Read access to /public only
python3 utils/make_token.py gen \
    --scope "storage.read:/public" \
    /tmp/xrd-test/tokens

# Write access to /uploads, read access everywhere
python3 utils/make_token.py gen \
    --scope "storage.read:/ storage.write:/uploads" \
    /tmp/xrd-test/tokens
```

The helper emits standard WLCG scope strings. In the current server implementation, WebDAV uses write scopes for `PUT`; the native stream path parses scopes but does not yet enforce read/write scopes per path.

### 4.4 Generate a token with WLCG group claims

```bash
python3 utils/make_token.py gen \
    --scope "storage.read:/" \
    --groups "/cms,/atlas" \
    /tmp/xrd-test/tokens
```

This adds the `wlcg.groups` claim to the token payload:
```json
"wlcg.groups": ["/cms", "/atlas"]
```

### 4.5 All CLI options

```bash
python3 utils/make_token.py gen --help
```

| Flag | Default | Purpose |
|---|---|---|
| `--scope` | `storage.read:/` | Space-separated WLCG scopes |
| `--sub` | `testuser` | Subject claim (who the token represents) |
| `--groups` | none | Comma-separated WLCG groups |
| `--lifetime` | `3600` | Token validity in seconds |
| `--issuer` | `https://test.example.com` | Override the issuer claim |
| `--audience` | `nginx-xrootd` | Override the audience claim |
| `--kind` | `valid` | Token variant: `valid`, `expired`, `bad-signature`, `wrong-issuer`, `wrong-audience`, or `no-scope` |
| `-o FILE` | stdout | Write token to a file |

### 4.6 Generate custom example tokens with Python

If you want a runnable example of using the `TokenIssuer` class directly, run the helper in `utils/`:

```bash
python3 utils/token_examples.py /tmp/xrd-test/tokens
```

That script prints a two-hour read-only token for `alice` and a read/write token for `bob` with `/cms` and `/atlas` group claims.

The `TokenIssuer` class also has convenience methods for generating invalid tokens (useful for negative testing):

| Method | What it generates |
|---|---|
| `generate()` | Valid token with specified claims |
| `generate_expired()` | Token that expired 1 hour ago |
| `generate_bad_signature()` | Structurally valid token with a corrupted signature |
| `generate_wrong_issuer()` | Token signed by your key but with `iss` set to `https://evil.example.com` |
| `generate_wrong_audience()` | Token with `aud` set to `wrong-audience` |
| `generate_no_scope()` | Valid token with no `scope` claim at all |

---

## 5. Inspect a token

A JWT is three base64url-encoded segments separated by dots: `header.payload.signature`. You can decode the first two segments to see the claims.

### 5.1 With the inspection helper

```bash
TOKEN=$(python3 utils/make_token.py gen --scope "storage.read:/" /tmp/xrd-test/tokens)
python3 utils/inspect_token.py "$TOKEN"
```

Output:

```
Header:
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "test-key-1"
}

Payload:
{
  "iss": "https://test.example.com",
  "sub": "testuser",
  "aud": "nginx-xrootd",
  "exp": 1713400000,
  "iat": 1713396400,
  "nbf": 1713396400,
  "scope": "storage.read:/",
  "wlcg.ver": "1.0"
}
```

### 5.2 From stdin

```bash
python3 utils/make_token.py gen --scope "storage.read:/" /tmp/xrd-test/tokens \
    | python3 utils/inspect_token.py -
```

### 5.3 Understanding the claims

| Claim | Example | Meaning |
|---|---|---|
| `iss` | `https://test.example.com` | Who signed the token (must match `xrootd_token_issuer`) |
| `sub` | `testuser` | Who the token represents |
| `aud` | `nginx-xrootd` | Which service the token is for (must match `xrootd_token_audience`) |
| `exp` | `1713400000` | Unix timestamp when the token expires |
| `iat` | `1713396400` | Unix timestamp when the token was issued |
| `nbf` | `1713396400` | "Not before" — token is not valid before this time |
| `scope` | `storage.read:/ storage.write:/data` | Space-separated WLCG authorization scopes; currently enforced for WebDAV `PUT` write scope checks |
| `wlcg.ver` | `1.0` | WLCG token profile version |
| `wlcg.groups` | `["/cms", "/atlas"]` | Optional — VO group memberships |

---

## 6. Test the complete setup

### 6.1 Seed the data directory

```bash
mkdir -p /tmp/xrd-test/data
echo "hello from token auth" > /tmp/xrd-test/data/test.txt
```

### 6.2 XRootD protocol — using xrdfs with a bearer token

The `xrdfs` and `xrdcp` clients read a bearer token from the `BEARER_TOKEN` environment variable:

```bash
# Generate a read-only token
export BEARER_TOKEN=$(python3 utils/make_token.py gen \
    --scope "storage.read:/" /tmp/xrd-test/tokens)

# List the root directory (port 11099 = token-only)
xrdfs root://localhost:11099 ls /
# Expected: test.txt

# Stat a file
xrdfs root://localhost:11099 stat /test.txt
# Expected: size, flags, modtime

# Copy a file down
xrdcp root://localhost:11099//test.txt /tmp/downloaded.txt
cat /tmp/downloaded.txt
# Expected: hello from token auth
```

### 6.3 XRootD protocol — uploading on a write-enabled token listener

```bash
# Generate a token. The stream listener validates the token; xrootd_allow_write
# controls whether writes are accepted.
export BEARER_TOKEN=$(python3 utils/make_token.py gen \
    --scope "storage.read:/ storage.write:/" /tmp/xrd-test/tokens)

# Upload a file
echo "uploaded via token" > /tmp/upload_test.txt
xrdcp /tmp/upload_test.txt root://localhost:11099//upload_test.txt

# Read it back
xrdcp root://localhost:11099//upload_test.txt -
# Expected: uploaded via token
```

### 6.4 XRootD protocol — understand the write gate

Native stream token authentication currently parses `storage.read` and `storage.write` scopes but does not enforce them per operation. A valid token can write when the listener has `xrootd_allow_write on`; no token can write when `xrootd_allow_write off`.

Use separate listeners if you need a read-only token-authenticated stream endpoint:

```nginx
stream {
    server {
        listen 11099;
        xrootd on;
        xrootd_root /tmp/xrd-test/data;
        xrootd_auth token;
        # xrootd_allow_write is off by default
        xrootd_token_jwks     /tmp/xrd-test/tokens/jwks.json;
        xrootd_token_issuer   "https://test.example.com";
        xrootd_token_audience "nginx-xrootd";
    }
}
```

### 6.5 WebDAV/HTTPS — using curl with a Bearer header

```bash
# Generate a read-only token
TOKEN=$(python3 utils/make_token.py gen \
    --scope "storage.read:/" /tmp/xrd-test/tokens)

# GET a file (--insecure because the test cert is self-signed)
curl -k -H "Authorization: Bearer $TOKEN" \
    https://localhost:8443/test.txt
# Expected: hello from token auth

# PROPFIND (directory listing)
curl -k -X PROPFIND -H "Depth: 1" \
    -H "Authorization: Bearer $TOKEN" \
    https://localhost:8443/
# Expected: XML listing of files

# HEAD (file metadata)
curl -k -I -H "Authorization: Bearer $TOKEN" \
    https://localhost:8443/test.txt
# Expected: HTTP 200 with Content-Length header
```

### 6.6 WebDAV/HTTPS — upload with a write-scoped token

```bash
TOKEN=$(python3 utils/make_token.py gen \
    --scope "storage.read:/ storage.write:/" /tmp/xrd-test/tokens)

# PUT a file
curl -k -X PUT \
    -H "Authorization: Bearer $TOKEN" \
    -d "uploaded via webdav" \
    https://localhost:8443/webdav_upload.txt

# GET it back
curl -k -H "Authorization: Bearer $TOKEN" \
    https://localhost:8443/webdav_upload.txt
# Expected: uploaded via webdav
```

### 6.7 Check logs

After a successful native stream token authentication, nginx info/debug logs include the token subject and scope count. The current `xrootd_access_log` formatter labels non-GSI listeners as `anon` and does not print the token subject in the identity field.

```bash
grep 'token auth ok' /tmp/xrd-test/logs/error.log
tail /tmp/xrd-test/logs/xrootd_access_token.log
```

```
xrootd: token auth ok sub="testuser" scopes=1 groups=""
127.0.0.1 anon "-" [17/Apr/2026:14:23:44 +0000] "AUTH - testuser" OK 0 2ms
127.0.0.1 anon "-" [17/Apr/2026:14:23:45 +0000] "STAT /test.txt -" OK 0 2ms
```

For WebDAV, token-authenticated requests also appear in the normal nginx HTTP access log; bearer-token details are intentionally not logged.

---

## 7. Negative tests — verify rejection of bad tokens

These tests confirm the server actually validates tokens rather than accepting anything.

### 7.1 Expired token

```bash
# Generate a token that already expired
TOKEN=$(python3 utils/make_token.py gen --kind expired /tmp/xrd-test/tokens)

export BEARER_TOKEN="$TOKEN"
xrdfs root://localhost:11099 ls /
# Expected: authentication failure
```

### 7.2 Wrong issuer

```bash
TOKEN=$(python3 utils/make_token.py gen --kind wrong-issuer /tmp/xrd-test/tokens)

export BEARER_TOKEN="$TOKEN"
xrdfs root://localhost:11099 ls /
# Expected: authentication failure (issuer mismatch)
```

### 7.3 Wrong audience

```bash
TOKEN=$(python3 utils/make_token.py gen --kind wrong-audience /tmp/xrd-test/tokens)

export BEARER_TOKEN="$TOKEN"
xrdfs root://localhost:11099 ls /
# Expected: authentication failure (audience mismatch)
```

### 7.4 Corrupted signature

```bash
TOKEN=$(python3 utils/make_token.py gen --kind bad-signature /tmp/xrd-test/tokens)

export BEARER_TOKEN="$TOKEN"
xrdfs root://localhost:11099 ls /
# Expected: authentication failure (signature verification failed)
```

### 7.5 No token at all

```bash
unset BEARER_TOKEN
xrdfs root://localhost:11099 ls /
# Expected: authentication failure (no credentials)
```

### 7.6 Completely invalid string

```bash
export BEARER_TOKEN="this-is-not-a-jwt"
xrdfs root://localhost:11099 ls /
# Expected: authentication failure (malformed JWT)
```

### 7.7 Via WebDAV (all the same negative cases)

These examples assume `xrootd_webdav_auth required`. With the default `optional` mode, an invalid or absent bearer token can fall back to anonymous handling.

```bash
# Expired token over HTTPS
TOKEN=$(python3 utils/make_token.py gen --kind expired /tmp/xrd-test/tokens)

curl -k -H "Authorization: Bearer $TOKEN" \
    https://localhost:8443/test.txt
# Expected: HTTP 401 or 403

# No Authorization header at all
curl -k https://localhost:8443/test.txt
# Expected: HTTP 403
```

---

## 8. Run the automated test suite

The test suite covers all of the above (and more) automatically:

```bash
cd /path/to/nginx-xrootd
source .venv/bin/activate

# Run all token tests
pytest tests/test_token_auth.py -v
```

The test file (`tests/test_token_auth.py`) exercises:

| Test category | What it covers |
|---|---|
| Token generation | Valid tokens, expired, bad signature, wrong issuer/audience |
| XRootD stream auth | Raw-socket `kXR_auth` with `ztn` credential type |
| File operations | stat, dirlist, ping after token-authenticated native sessions |
| WebDAV/HTTPS | GET, PUT, HEAD, PROPFIND with `Authorization: Bearer` |
| Scope enforcement | WebDAV `PUT` requires matching write scope; out-of-scope writes are denied |
| WLCG groups | Tokens with `wlcg.groups` claim accepted and mapped to VO-style groups |
| Negative cases | Expired, wrong issuer, wrong audience, bad signature, no scope, garbage tokens |

---

## 9. How token auth works on the wire

If you do not care about the internals, skip this section.

### 9.1 XRootD stream protocol

Token authentication uses the `ztn` credential type (short for "ZeroTrust Network" — XRootD's name for bearer tokens):

```
Client                                       Server
──────                                       ──────
kXR_protocol (requests security info)  ─>
                                        <─  security requirements ("ztn" or "gsi&ztn")

kXR_login                              ─>
                                        <─  session ID + auth challenge
                                            "&P=ztn,v:10000"

kXR_auth [credtype: "ztn"]            ─>   "ztn\0<raw JWT bytes>"
                                        <─  JWT validated → kXR_ok (auth complete)
```

The entire token is sent in a single `kXR_auth` request. There is no multi-step handshake like GSI — it is one round-trip.

### 9.2 WebDAV/HTTPS

Over HTTPS, the token is a standard HTTP Bearer token:

```
Client                                       Server
──────                                       ──────
GET /test.txt HTTP/1.1
Authorization: Bearer eyJhbGc...            ─>
                                             <─  HTTP 200 + file contents
                                                 (or an auth error in required mode)
```

The server extracts the token from the `Authorization` header and validates it the same way as the stream path. In `required` auth mode, invalid or missing credentials return an error. In `optional` mode, failed token auth can fall back to anonymous handling.

---

## 10. Troubleshooting

### Token rejected — "issuer mismatch"

The token's `iss` claim does not match the `xrootd_token_issuer` directive. Check both values:

```bash
# What the server expects
grep xrootd_token_issuer /path/to/nginx.conf

# What the token contains
python3 utils/inspect_token.py "$BEARER_TOKEN" | grep iss
```

### Token rejected — "audience mismatch"

Same idea — the `aud` claim must match `xrootd_token_audience`:

```bash
grep xrootd_token_audience /path/to/nginx.conf
python3 utils/inspect_token.py "$BEARER_TOKEN" | grep aud
```

### Token rejected — "signature verification failed"

The JWKS file does not contain the public key matching the token's `kid`. Either the token was signed with a different key, or the JWKS was regenerated after token creation:

```bash
# Check the kid in the token header
python3 utils/inspect_token.py "$BEARER_TOKEN" | grep kid

# Check the kid in the JWKS
python3 utils/inspect_token.py --jwks /tmp/xrd-test/tokens/jwks.json
```

If they do not match, regenerate your tokens using the current signing key.

### Token rejected — "expired"

Tokens have a limited lifetime. The default in `make_token.py` is 1 hour. Generate a fresh one:

```bash
export BEARER_TOKEN=$(python3 utils/make_token.py gen \
    --scope "storage.read:/" /tmp/xrd-test/tokens)
```

For longer-lived test tokens, use `--lifetime`:

```bash
python3 utils/make_token.py gen --scope "storage.read:/" --lifetime 86400  # 24 hours
```

### xrdfs/xrdcp ignores the token

Make sure the `BEARER_TOKEN` environment variable is set (not `BEARER_TOKEN_FILE`, not `X509_USER_PROXY`):

```bash
echo "$BEARER_TOKEN" | head -c 20
# Should print the start of the JWT: eyJhbGciOiJS...
```

Some older XRootD client versions do not support `BEARER_TOKEN`. Check your client version:

```bash
xrdcp --version
```

### nginx does not start — "jwks.json not found"

The path in `xrootd_token_jwks` must exist when nginx starts. Generate the signing authority first:

```bash
python3 utils/make_token.py init /tmp/xrd-test/tokens
```

### Write denied even with a valid token

For WebDAV `PUT`, check that the token includes `storage.write` or `storage.create` scope for the target path:

```bash
python3 utils/inspect_token.py "$BEARER_TOKEN" | grep scope
# Should include: "storage.write:/"
```

Also verify that the server has `xrootd_webdav_allow_write on`.

For the native stream protocol, token scopes are not currently enforced for writes. If a native stream upload is denied, check `xrootd_allow_write on` first.

---

## Comparison: GSI proxy vs. bearer token

| Aspect | GSI proxy certificate | WLCG bearer token |
|---|---|---|
| **Format** | X.509 certificate chain (PEM) | JSON Web Token (JWT) |
| **Size** | ~3–5 KB (cert chain + key) | ~500 bytes (compact JSON + signature) |
| **Auth round-trips** | 2 (`certreq` → `cert`) | 1 (single `kXR_auth` with token) |
| **Crypto** | DH key exchange + x509 chain verify | RSA signature verify |
| **Server state** | DH parameters, certificate chain parsing | Stateless — just verify and check claims |
| **Authorisation** | DN-based identity plus optional VOMS VO ACLs | JWT scopes parsed; WebDAV `PUT` write-scope checks; stream path ACLs via `wlcg.groups` and `xrootd_require_vo` |
| **Trust root** | CA certificate (`xrootd_trusted_ca`) | JWKS public key (`xrootd_token_jwks`) |
| **Lifetime** | Typically 12 hours | Configurable (default 1 hour) |
| **Client env var** | `X509_USER_PROXY` | `BEARER_TOKEN` |
| **Wire credential** | `gsi` credential type | `ztn` credential type |
