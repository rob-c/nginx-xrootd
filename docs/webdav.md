# WebDAV / HTTPS+GSI/Bearer

The `ngx_http_xrootd_webdav_module` adds a WebDAV content handler to nginx's HTTP layer. Together with TLS, GSI proxy-certificate support, and optional JWT bearer-token validation, it lets `xrdcp` use the `davs://host:8443/` URL scheme — the same transfer path used by Grid and WLCG workflows that prefer HTTP over the native `root://` protocol.

---

## How it works

`xrdcp --allow-http davs://host:8443/path` is handled by the `XrdClHttp` plugin, which speaks WebDAV (HTTP methods OPTIONS, GET with Range, HEAD, PUT, DELETE, MKCOL, PROPFIND) over TLS. Authentication can come from RFC 3820 proxy certificates or from an `Authorization: Bearer <JWT>` header.

nginx's built-in SSL stack does not accept RFC 3820 proxy certificates by default. This module patches the `SSL_CTX` in postconfiguration to set `X509_V_FLAG_ALLOW_PROXY_CERTS`, enabling proxy chains issued by your test CA. Per-request certificate verification is then performed using the configured CA directory or CA file. Bearer tokens are verified against a local JWKS file without a network call to an identity provider.

---

## nginx.conf setup

Add to the `http {}` block:

```nginx
http {
    server {
        listen 8443 ssl;
        server_name your.host.name;

        ssl_certificate     /etc/grid-security/hostcert.pem;
        ssl_certificate_key /etc/grid-security/hostkey.pem;

        # Request a client cert but don't reject connections that lack one.
        # Our module enforces auth policy per-request.
        ssl_verify_client optional_no_ca;
        ssl_verify_depth  10;

        # Patch the SSL_CTX to accept RFC 3820 proxy certificates.
        xrootd_webdav_proxy_certs on;

        # Allow uploads up to 1 GB
        client_max_body_size 1g;

        access_log /var/log/nginx/webdav_access.log;

        location / {
            xrootd_webdav         on;
            xrootd_webdav_root    /data;
            xrootd_webdav_cadir   /etc/grid-security/certificates;
            xrootd_webdav_auth    optional;    # or: none | required
            xrootd_webdav_allow_write on;

            # Optional HTTP-TPC pull support (COPY with a Source header)
            xrootd_webdav_tpc       on;
            xrootd_webdav_tpc_cert  /etc/grid-security/xrd/xrdcert.pem;
            xrootd_webdav_tpc_key   /etc/grid-security/xrd/xrdkey.pem;

            # Optional bearer-token auth
            xrootd_webdav_token_jwks     /etc/tokens/jwks.json;
            xrootd_webdav_token_issuer   "https://idp.example.com";
            xrootd_webdav_token_audience "my-storage";
        }
    }
}
```

---

## Directives

All `xrootd_webdav_*` directives go inside an `http` server or location block.

### `xrootd_webdav on|off`

**Context:** `location`

Activates the WebDAV content handler for this location.

---

### `xrootd_webdav_root <path>`

**Context:** `location` · **Default:** `/`

Filesystem directory that clients see as `/`. Path traversal and symlink-escape attempts are blocked.

---

### `xrootd_webdav_auth none|optional|required`

**Context:** `location` · **Default:** `optional`

- `none` — serve all requests without checking client certificates or bearer tokens
- `optional` — check a proxy certificate or bearer token if one is presented; unauthenticated requests are still served
- `required` — reject requests that do not present a valid proxy certificate or bearer token (returns 403)

With `optional`, an invalid bearer token is declined and the request may still proceed anonymously. Use `required` when token or proxy authentication must be mandatory.

---

### `xrootd_webdav_cadir <path>`

**Context:** `location`

Directory containing hashed CA certificates (the standard Grid format: `<hash>.0` files). Used for per-request proxy-certificate chain verification when `xrootd_webdav_auth` is `optional` or `required`.

---

### `xrootd_webdav_cafile <path>`

**Context:** `location`

Alternative to `xrootd_webdav_cadir`: a single PEM file containing one or more CA certificates.

---

### `xrootd_webdav_crl <path>`

**Context:** `location`

PEM CRL file used when verifying proxy-certificate chains. When configured, OpenSSL CRL checks are enabled for the full chain.

---

### `xrootd_webdav_allow_write on|off`

**Context:** `location` · **Default:** `off`

Enables PUT, DELETE, MKCOL, and HTTP-TPC COPY when `xrootd_webdav_tpc on` is also configured. Off by default so read-only deployments are safe without extra configuration. When the request is accepted via a bearer token, `PUT` and TPC `COPY` also require a matching `storage.write` or `storage.create` scope for the request path.

---

### `xrootd_webdav_tpc on|off`

**Context:** `location` · **Default:** `off`

Enables HTTP third-party copy pull requests using WebDAV `COPY` with a remote `Source` header. The destination is the request URI on this server.

This is an explicit opt-in because the nginx worker starts an external `curl` helper and the server makes an outbound HTTPS request to the `Source` URL. Only `https://` sources are accepted. The request waits for `curl` to finish, so set `xrootd_webdav_tpc_timeout` and size nginx workers accordingly for production transfers.

---

### `xrootd_webdav_tpc_curl <path>`

**Context:** `location` · **Default:** `/usr/bin/curl`

Path to the `curl` executable used for HTTP-TPC pulls. The helper is run without a shell.

---

### `xrootd_webdav_tpc_cert <path>`

**Context:** `location`

PEM certificate or proxy certificate used by the server when it pulls from the remote HTTPS source. For proxy PEM files that contain both certificate and private key, set only this directive or set `xrootd_webdav_tpc_key` to the same path.

---

### `xrootd_webdav_tpc_key <path>`

**Context:** `location` · **Default:** `xrootd_webdav_tpc_cert`

PEM private key used with `xrootd_webdav_tpc_cert`.

---

### `xrootd_webdav_tpc_cadir <path>`

**Context:** `location` · **Default:** `xrootd_webdav_cadir`

CA directory passed to `curl --capath` when verifying the source HTTPS endpoint.

---

### `xrootd_webdav_tpc_cafile <path>`

**Context:** `location` · **Default:** `xrootd_webdav_cafile`

CA bundle passed to `curl --cacert` when verifying the source HTTPS endpoint.

---

### `xrootd_webdav_tpc_timeout <seconds>`

**Context:** `location` · **Default:** `0` (curl default)

Maximum wall-clock time passed to `curl --max-time` for a single HTTP-TPC pull.

---

### `xrootd_webdav_proxy_certs on|off`

**Context:** `server` or `location` (HTTP) · **Default:** `off`

Sets `X509_V_FLAG_ALLOW_PROXY_CERTS` on the `SSL_CTX` for this server in postconfiguration. Without this, nginx's TLS layer rejects RFC 3820 proxy certificates with error 40 (`proxy certificates not allowed`) even when `ssl_verify_client optional_no_ca` is set.

In normal TLS deployments, put this in the `server {}` block so the SSL context is patched for the whole virtual server.

---

### `xrootd_webdav_verify_depth <n>`

**Context:** `location` · **Default:** `10`

Maximum depth for proxy-certificate chain verification.

---

### `xrootd_webdav_token_jwks <path>`

**Context:** `location`

Path to a JWKS file containing public keys trusted for JWT/WLCG bearer-token validation.

---

### `xrootd_webdav_token_issuer <string>`

**Context:** `location`

Expected JWT `iss` claim.

---

### `xrootd_webdav_token_audience <string>`

**Context:** `location`

Expected JWT `aud` claim.

---

## WebDAV methods supported

| Method | Notes |
|---|---|
| `OPTIONS` | Returns `Allow` header with all supported methods; `DAV: 1` |
| `GET` | Full file and RFC 7233 `Range` requests (including suffix ranges `bytes=-N`) |
| `HEAD` | Returns headers without body |
| `PUT` | Upload; returns 201 on create, 204 on overwrite |
| `DELETE` | Removes files and empty directories |
| `MKCOL` | Creates a directory; trailing slash in URL is accepted |
| `COPY` | HTTP-TPC pull when `xrootd_webdav_tpc on`; remote source comes from the `Source` header |
| `PROPFIND` | `Depth: 0` for stat, `Depth: 1` for directory listing; returns `207 Multi-Status` XML |

---

## Testing with curl

```bash
PROXY=/path/to/proxy_cert.pem
CA=/etc/grid-security/certificates/ca.pem

# OPTIONS
curl -sk --cert $PROXY --key $PROXY --cacert $CA \
  -X OPTIONS https://host:8443/ -I

# Upload
curl -sk --cert $PROXY --key $PROXY --cacert $CA \
  -X PUT https://host:8443/file.txt --data-binary @localfile.txt

# Download
curl -sk --cert $PROXY --key $PROXY --cacert $CA \
  https://host:8443/file.txt -o downloaded.txt

# Stat (PROPFIND Depth:0)
curl -sk --cert $PROXY --key $PROXY --cacert $CA \
  -X PROPFIND -H "Depth: 0" https://host:8443/file.txt

# Create directory
curl -sk --cert $PROXY --key $PROXY --cacert $CA \
  -X MKCOL https://host:8443/newdir/
```

Bearer-token requests use a normal HTTP `Authorization` header:

```bash
TOKEN=$(python3 utils/make_token.py gen \
  --scope "storage.read:/ storage.write:/" /tmp/xrd-test/tokens)

curl -sk -H "Authorization: Bearer $TOKEN" \
  https://host:8443/file.txt -o downloaded.txt

curl -sk -X PUT -H "Authorization: Bearer $TOKEN" \
  --data-binary @localfile.txt https://host:8443/file.txt
```

---

## HTTP-TPC pull

With `xrootd_webdav_tpc on`, this module accepts the WLCG-style WebDAV `COPY` pull shape:

```bash
curl -sk --cert /tmp/x509up_u$(id -u) --key /tmp/x509up_u$(id -u) \
  --capath /etc/grid-security/certificates \
  -X COPY \
  -H "Credential: none" \
  -H "Source: https://source.example.org:8443//store/input.dat" \
  https://dest.example.org:8443//store/output.dat
```

The server writes to a temporary file next to the destination and then renames it into place after `curl` succeeds. `Overwrite: F` fails with HTTP 412 if the destination exists; the default is overwrite (`Overwrite: T`).

`TransferHeader*` request headers are forwarded to the source request without the prefix. For example, `TransferHeaderAuthorization: Bearer <token>` becomes `Authorization: Bearer <token>` in the outbound source request.

This implementation does not implement GridSite or OIDC delegation endpoints. Requests that explicitly set `Credential: gridsite` or `Credential: oidc` are rejected with HTTP 400. Use `Credential: none` with configured service X.509 credentials or forwarded `TransferHeader*` authorization.

Native `root://` third-party copy is not the same protocol. It requires XRootD rendezvous-key handling and, for delegated copies, GSI credential delegation on the stream protocol. The current nginx stream module serves normal `root://` reads and writes, but does not yet implement native XRootD TPC.

---

## Testing with xrdcp

The `davs://` URL scheme requires the `XrdClHttp` plugin (`libXrdClHttp-5.so`), which ships with full xrootd builds but may be absent from client-only packages:

```bash
# Check whether the plugin is available
ls $(xrdcp --version 2>&1 | awk '/^v/{print "/usr/lib64"}')/*XrdClHttp* 2>/dev/null \
  || echo "XrdClHttp plugin not installed"

# Upload
X509_USER_PROXY=/path/to/proxy_cert.pem \
  xrdcp --allow-http /local/file.txt davs://host:8443//file.txt

# Download
X509_USER_PROXY=/path/to/proxy_cert.pem \
  xrdcp --allow-http davs://host:8443//file.txt /local/copy.txt
```

Set `X509_CERT_DIR` to your CA hash directory if the proxy's issuer CA is not in the system default location.

---

## Relationship to the native XRootD protocol

The WebDAV and native `root://` modules are independent; you can run both on the same nginx instance. They share the same `xrootd_root` / `xrootd_webdav_root` filesystem path if you want clients to access the same data via either protocol:

```nginx
stream {
    server {
        listen 1095;
        xrootd on;
        xrootd_root /data;
        xrootd_auth gsi;
        # ... GSI cert directives ...
    }
}

http {
    server {
        listen 8443 ssl;
        # ... TLS directives ...
        location / {
            xrootd_webdav      on;
            xrootd_webdav_root /data;   # same data directory
            xrootd_webdav_auth optional;
        }
    }
}
```
