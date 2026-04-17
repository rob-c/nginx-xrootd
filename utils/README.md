# Utilities

Standalone helper scripts for development, testing, and debugging the nginx-xrootd module. None of these are required at runtime — they support the build/test/debug cycle.

## Scripts

### make_proxy.py — RFC 3820 proxy certificate generator

Generates GSI proxy certificates that XRootD's `XrdSecGSI` library accepts. The test suite calls this automatically when a proxy is expired or absent.

```bash
# Default PKI directory (/tmp/xrd-test/pki)
python3 utils/make_proxy.py

# Custom PKI directory
python3 utils/make_proxy.py /path/to/pki
```

**Inputs** (must already exist):
- `PKI_DIR/user/usercert.pem` — end-entity user certificate
- `PKI_DIR/user/userkey.pem` — corresponding private key

**Outputs:**
- `PKI_DIR/user/proxy_std.pem` — combined cert + key + chain (mode `0400`), the file you set `X509_USER_PROXY` to
- `PKI_DIR/user/proxy.pem` — proxy certificate only
- `PKI_DIR/user/proxykey.pem` — proxy private key only (mode `0400`)

The proxy is valid for 12 hours. It includes the critical `proxyCertInfo` extension (OID `1.3.6.1.5.5.7.1.14`) with `id-ppl-inheritAll` policy, which is required for XRootD to recognize it as a proxy rather than an end-entity certificate.

**Requires:** `cryptography` (listed in `requirements.txt`).

See [docs/test-pki.md](../docs/test-pki.md) for the full PKI setup walkthrough.

---

### make_token.py — WLCG JWT token generator

Manages a local signing authority (RSA keypair + JWKS) and generates signed JWT tokens with configurable WLCG claims and scopes. The test suite uses this for all token authentication tests.

```bash
# Initialize signing authority (creates signing_key.pem + jwks.json)
python3 utils/make_token.py init /tmp/xrd-test/tokens

# Generate a read-only token (printed to stdout)
python3 utils/make_token.py gen --scope "storage.read:/" /tmp/xrd-test/tokens

# Generate a read-write token with groups
python3 utils/make_token.py gen \
    --scope "storage.read:/ storage.write:/" \
    --groups "/cms,/atlas" \
    /tmp/xrd-test/tokens

# Generate a negative-test token
python3 utils/make_token.py gen --kind expired /tmp/xrd-test/tokens

# Save a token to a file
python3 utils/make_token.py gen --scope "storage.read:/" -o /tmp/token.jwt
```

**Inputs** (for `gen` command):
- `TOKEN_DIR/signing_key.pem` — RSA private key (created by `init`)

**Outputs** (for `init` command):
- `TOKEN_DIR/signing_key.pem` — RSA-2048 private key (mode `0400`)
- `TOKEN_DIR/jwks.json` — JSON Web Key Set containing the public key (loaded by nginx)

The `TokenIssuer` class can also be imported directly in Python for programmatic token generation, including convenience methods for expired, bad-signature, wrong-issuer, and wrong-audience tokens.

**Requires:** `cryptography` (listed in `requirements.txt`).

See [docs/test-tokens.md](../docs/test-tokens.md) for the full token setup walkthrough.

---

### inspect_token.py — JWT/JWKS inspection helper

Decodes JWT header and payload data without verifying the signature, and can list key IDs from a JWKS file. Useful when debugging issuer, audience, scope, or `kid` mismatches.

```bash
# Inspect a token from an environment variable
python3 utils/inspect_token.py "$BEARER_TOKEN"

# Inspect a token from stdin
python3 utils/make_token.py gen /tmp/xrd-test/tokens | python3 utils/inspect_token.py -

# Print key IDs from a JWKS
python3 utils/inspect_token.py --jwks /tmp/xrd-test/tokens/jwks.json
```

---

### token_examples.py — custom token generation examples

Shows how to use `TokenIssuer` programmatically without copying Python from the docs. It prints a read-only token and a read/write token with WLCG group claims.

```bash
python3 utils/token_examples.py /tmp/xrd-test/tokens
```

---

### make_crl.py — test CRL generator

Generates a PEM certificate revocation list for the local test CA. By default it revokes `/tmp/xrd-test/pki/user/usercert.pem` and writes `/tmp/xrd-test/pki/ca/test-user.crl.pem`.

```bash
python3 utils/make_crl.py /tmp/xrd-test/pki

# Override the revoked certificate or output path
python3 utils/make_crl.py /tmp/xrd-test/pki \
    --cert /tmp/xrd-test/pki/user/usercert.pem \
    --out /tmp/xrd-test/pki/ca/test-user.crl.pem
```

---

### xrd_python_smoke.py — Python XRootD client smoke test

Lists `/` and reads a file using the XRootD Python client. This is the runnable helper used by the getting-started guide.

```bash
python3 utils/xrd_python_smoke.py --url root://localhost:1094 --path /test.txt
```

**Requires:** `xrootd` Python package.

---

### xrd_proxy.py — protocol traffic hex-dumper

A TCP relay that sits between a client and the nginx-xrootd server, printing every byte exchanged in both directions as hex. Useful for debugging wire-level protocol issues.

```bash
# Default: listen on 19941, forward to localhost:11094
python3 utils/xrd_proxy.py

# Custom ports
python3 utils/xrd_proxy.py 19941 11095
```

Then point your client at the proxy port:

```bash
xrdfs root://localhost:19941 ls /
```

Output format:

```
proxy ready on 19941 → 127.0.0.1:11094
connected to nginx
[C>S] 20B: 0000000000000000000000040000...
[S>C] 12B: 00000008000005200000...
[C>S] 24B: ...
```

Each line shows direction (`C>S` = client-to-server, `S>C` = server-to-client), byte count, and raw hex. Cross-reference with [docs/protocol-notes.md](../docs/protocol-notes.md) to decode the fields.

The proxy accepts one connection and exits. Run it again for the next session.

---

### xrd_ref_server.py — minimal reference XRootD server

A pure-Python XRootD data server that implements the bare minimum protocol to serve files. Used to calibrate expected client behaviour — when a test fails, run it against the reference server to determine whether the issue is in the client library or in nginx-xrootd.

```bash
# Default: port 19942, root /tmp/xrd-test/data
python3 utils/xrd_ref_server.py

# Custom port and root
python3 utils/xrd_ref_server.py 19942 /srv/data
```

Supported operations:

| Opcode | Operation |
|---|---|
| `kXR_protocol` | Protocol version negotiation |
| `kXR_login` | Session login (always succeeds, no auth) |
| `kXR_ping` | Keepalive |
| `kXR_stat` | File/directory metadata |
| `kXR_open` | Open a file for reading |
| `kXR_read` | Read bytes from an open file |
| `kXR_close` | Close a file handle |
| `kXR_dirlist` | Directory listing |
| `kXR_endsess` | End session |

All other opcodes return `kXR_error`. The server handles multiple concurrent connections via threads. It exits after 30 seconds of idle time.

**No dependencies** beyond the Python standard library.

---

### xrd_sec_probe.py — adversarial security probe

Runs a battery of protocol-level security tests against a target XRootD server. Each probe sends deliberately malformed or adversarial input, then verifies the server is still healthy.

```bash
# Default: localhost:11094
python3 utils/xrd_sec_probe.py

# Custom target
python3 utils/xrd_sec_probe.py localhost:11095
```

**Probe categories:**

| Prefix | Category | Count | What it tests |
|---|---|---|---|
| `LK-*` | Lockup | 9 | Partial handshakes, truncated headers, huge `dlen` values, stalled connections |
| `AE-*` | Auth enforcement | 8 | Sending data-plane requests (`stat`, `open`, `read`, `write`, `rm`, `mkdir`) before login |
| `HF-*` | Handshake fuzzing | 4 | Wrong magic fields, all-zero/all-0xFF handshake payloads |
| `OF-*` | Unknown opcodes | 5 | Opcode 0, 9999, 0xFFFF, all-zero/all-0xFF request frames |
| `PF-*` | Path fuzzing | 4 | `../../etc/passwd` traversal, null-byte injection, oversized paths |
| `RE-*` | Resource exhaustion | 4 | Connection storms, ping floods, file handle exhaustion, rapid connect/disconnect |
| `SM-*` | State machine | 4 | Use-after-close, read after endsess, double login, repeated protocol negotiation |
| `PV-*` | Protocol version | 4 | Edge-case client version fields, all-zero username, username `root` with pid 0 |
| `CC-*` | Concurrency | 2 | 16-thread ping storms, mixed ping+stat thread contention |

**Output** is a findings report:

```
  [✓] PASS      LK-01  partial handshake 10/20 bytes then nothing
  [✓] PASS      LK-02  partial handshake 19/20 bytes then nothing
  ...
  [★] FINDING   AE-01  kXR_stat before kXR_login
       Pre-login kXR_stat returned kXR_ok — authentication bypass.
```

After all probes complete, a summary groups results into PASS, FINDING, HANG, CRASH, and ERROR counts.

**No dependencies** beyond the Python standard library.
