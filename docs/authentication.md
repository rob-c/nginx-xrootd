# Authentication

The native XRootD module supports anonymous access, GSI/x509 proxy-certificate authentication, JWT/WLCG bearer-token authentication, or a mixed mode that accepts either GSI or bearer tokens. The WebDAV module can authenticate HTTPS requests with proxy certificates or `Authorization: Bearer` tokens.

---

## Anonymous access

The default. Any client can connect and provide any username — no certificate or password is checked.

```nginx
stream {
    server {
        listen 1094;
        xrootd on;
        xrootd_root /data/public;
        # xrootd_auth none;  ← this is the default, no need to write it
    }
}
```

Use this for public data, internal networks, or when access control is handled at the network layer.

---

## GSI / x509 authentication

GSI (Grid Security Infrastructure) is the standard authentication method across the WLCG computing grid. It uses x509 proxy certificates — short-lived credentials derived from your long-term grid certificate.

If you are new to GSI: think of it like SSH keys, but with a certificate authority (your home institution or CERN) vouching for who you are, and the "proxy" certificate being a temporary 12-hour credential you generate each morning with `voms-proxy-init` or `grid-proxy-init`.

### What you need

On the **server**:
- A host certificate (`hostcert.pem`) issued by a trusted CA — typically from your institution's grid CA
- The corresponding private key (`hostkey.pem`)
- The CA certificate that signed the client certificates you want to accept (`ca.pem`)

On the **client**:
- A valid proxy certificate (generated from their personal grid certificate)

### Configuration

```nginx
stream {
    server {
        listen 1095;
        xrootd on;
        xrootd_auth gsi;
        xrootd_root /data/store;
        xrootd_certificate     /etc/grid-security/hostcert.pem;
        xrootd_certificate_key /etc/grid-security/hostkey.pem;
        xrootd_trusted_ca      /etc/grid-security/ca.pem;
        xrootd_access_log /var/log/nginx/xrootd_gsi.log;
    }
}
```

The private key file must be readable by the nginx worker processes (typically running as `www-data` or `nginx`). The certificate and CA files can be world-readable.

### Testing GSI authentication

Generate a proxy certificate, then point `xrdcp` at it:

```bash
# Generate a proxy from your personal grid certificate
voms-proxy-init    # or: grid-proxy-init

# Tell xrdcp where the proxy lives (usually automatic, but explicit here)
export X509_USER_PROXY=$(voms-proxy-info -path)

# Copy a file
xrdcp /tmp/test.txt root://localhost:1095//test.txt
```

If authentication succeeds, the access log shows the client's subject DN:

```
192.168.1.1 gsi "/DC=org/OU=Users/CN=Alice Example" [14/Apr/2026:10:23:44 +0000] "AUTH - gsi" OK 0 48ms
```

### The authenticated identity

After a successful GSI handshake, the module extracts the subject Distinguished Name from the proxy certificate chain and stores it in the session. It appears in the access log and is available for downstream logging. The module does not currently perform authorisation based on the DN itself. Path-level authorisation is handled by `xrootd_require_vo` rules when `libvomsapi.so.1` is available at runtime (see [building.md](building.md)).

---

## How GSI authentication works (simplified)

If you do not care about the internals, skip this section.

The GSI handshake uses Diffie-Hellman key exchange to establish a shared session key, then the client sends their proxy certificate chain encrypted with that key. The server verifies the chain against its configured trusted CA.

```
Client                                       Server
──────                                       ──────
kXR_protocol (requests security info)  ─>
                                        <─  security requirements ("gsi" required)

kXR_login                              ─>
                                        <─  session ID + GSI challenge text
                                            "&P=gsi,v:10000,c:ssl,ca:<ca_hash>"

kXR_auth [step: "certreq"]             ─>   "here is a random nonce"
                                        <─  DH public key + server cert
                                            + server's signature of the nonce

kXR_auth [step: "cert"]                ─>   DH public key + proxy cert chain
                                            (AES-encrypted with DH session key)
                                        <─  auth complete (kXR_ok)
```

The proxy certificate is verified using standard OpenSSL chain verification (`X509_verify_cert`) with the `X509_V_FLAG_ALLOW_PROXY_CERTS` flag set to accept RFC 3820 proxy certificates.

---

## Using both anonymous and GSI on different ports

A common setup: public data on port 1094 (no credentials needed) and private or writable data on port 1095 (GSI required):

```nginx
stream {
    # Public read-only
    server {
        listen 1094;
        xrootd on;
        xrootd_root /data/public;
    }

    # Authenticated read-write
    server {
        listen 1095;
        xrootd on;
        xrootd_auth gsi;
        xrootd_allow_write on;
        xrootd_root /data/restricted;
        xrootd_certificate     /etc/grid-security/hostcert.pem;
        xrootd_certificate_key /etc/grid-security/hostkey.pem;
        xrootd_trusted_ca      /etc/grid-security/ca.pem;
    }
}
```

Clients use `root://host:1094//path` for public access and `root://host:1095//path` for authenticated access.

---

## Token / JWT (WLCG bearer token) authentication

WLCG bearer tokens are the modern alternative to GSI proxy certificates. Instead of an x509 certificate chain, the client presents a compact signed JWT asserting who they are, which service the token is for, and when it expires. No certificate infrastructure is required — just a trusted JWKS public key set.

If you are new to bearer tokens: think of one like an API key, but cryptographically signed and with built-in expiry. The server verifies the signature using a public key (published as a JWKS file) and checks claims like issuer, audience, expiry, and not-before time — all without contacting any external service.

### What you need

On the **server**:
- A JWKS file containing the public key(s) you trust (`jwks.json`)
- The expected issuer URL (matches the `iss` claim in tokens)
- The expected audience string (matches the `aud` claim in tokens)

On the **client**:
- A valid JWT token (set in the `BEARER_TOKEN` environment variable for `xrdcp`/`xrdfs`, or in an `Authorization: Bearer` HTTP header for WebDAV)

### Configuration

```nginx
stream {
    server {
        listen 1094;
        xrootd on;
        xrootd_auth token;
        xrootd_root /data/store;
        xrootd_allow_write on;
        xrootd_token_jwks     /etc/tokens/jwks.json;
        xrootd_token_issuer   "https://idp.example.com";
        xrootd_token_audience "my-storage";
        xrootd_access_log /var/log/nginx/xrootd_token.log;
    }
}
```

| Directive | Purpose |
|---|---|
| `xrootd_auth token` | Require a bearer token for every native XRootD session |
| `xrootd_token_jwks` | Path to the JWKS file containing trusted public keys |
| `xrootd_token_issuer` | Expected `iss` claim — tokens from other issuers are rejected |
| `xrootd_token_audience` | Expected `aud` claim — tokens for other services are rejected |

### Testing token authentication

Generate a token using the test signing authority, then point `xrdfs` at it:

```bash
# Generate a read-only token
export BEARER_TOKEN=$(python3 utils/make_token.py gen \
    --scope "storage.read:/" /path/to/token_dir)

# List files
xrdfs root://localhost:1094 ls /

# Copy a file
xrdcp root://localhost:1094//test.txt /tmp/test.txt
```

If authentication succeeds, the native stream session is marked authenticated and the token `sub` claim is stored internally as the session identity. Current stream access-log labels remain `anon` for non-GSI listeners and `gsi` for GSI-only listeners; token subjects are emitted in nginx info/debug logs rather than the `xrootd_access_log` identity field.

### Scopes and groups

Tokens may carry WLCG storage scopes:

| Scope | Meaning |
|---|---|
| `storage.read:/` | Read grant for `/` |
| `storage.write:/` | Write grant for `/` |
| `storage.read:/public` | Read grant scoped to `/public` |
| `storage.write:/uploads` | Write grant scoped to `/uploads` |

The current native XRootD stream path validates tokens and parses scopes, but write access is still governed by `xrootd_allow_write`; native stream operations do not yet enforce `storage.read` or `storage.write` scopes per path. WebDAV enforces `storage.write`/`storage.create` scopes for `PUT` requests when the request is accepted via a bearer token.

Tokens can also carry `wlcg.groups`. The stream module maps those groups into the same VO list used for VOMS, so `xrootd_require_vo` can protect paths for token-authenticated clients as well as GSI clients.

### The authenticated identity

After a successful token validation, the module extracts the `sub` (subject) claim from the JWT and stores it in the session. Token groups from `wlcg.groups` are stored as VO-style memberships for path ACL checks.

For the full walkthrough on setting up a test signing authority and generating tokens, see [test-tokens.md](test-tokens.md).

---

## Using both GSI and token on the same port

A server can accept either GSI proxy certificates or bearer tokens. The module inspects the credential type in the `kXR_auth` request (`gsi` or `ztn`) and routes to the appropriate handler:

```nginx
stream {
    server {
        listen 1094;
        xrootd on;
        xrootd_auth both;
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

This is the recommended production configuration for sites transitioning from GSI to tokens — existing clients with proxy certificates continue to work, while new clients can use bearer tokens.

---

## TLS / encrypted transport

The module does not implement XRootD-level TLS (`kXR_haveTLS` / `roots://`). To encrypt the connection:

**Option 1: stunnel in front of nginx**

Run stunnel on port 1093 (or any port) that wraps the XRootD connection and forwards it to nginx on 1094.

**Option 2: nginx `ssl_preread` (layer-4 TLS termination)**

Add an nginx `stream` block with `ssl_preread on` that terminates TLS and proxies the inner TCP connection to the XRootD server block. Clients use `roots://` (XRootD's TLS scheme), which is just XRootD over TLS.

This is currently outside the scope of this module.
