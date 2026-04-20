# TLS in nginx-xrootd

This project now has three distinct encrypted transport patterns:

1. `davs://` - WebDAV over HTTPS in nginx's `http {}` layer
2. `root://` with an in-protocol TLS upgrade driven by `xrootd_tls on`
3. `roots://` using nginx stream SSL (`listen ... ssl`) from the first byte

They solve slightly different problems, and they are implemented in different
parts of the codebase.

---

## At a glance

| Client URL / mode | Where TLS starts | Main nginx config | Main code path | Notes |
|---|---|---|---|---|
| `davs://host:8443/...` | Before HTTP request parsing | `listen ... ssl` in `http {}` | `ngx_http_xrootd_webdav_module.c` | Standard HTTPS/WebDAV |
| `root://host:1094/...` + `xrootd_tls on` | After `kXR_protocol` advertises `kXR_haveTLS` | `xrootd_tls on` in `stream {}` | `ngx_xrootd_session.c`, `ngx_xrootd_connection.c` | Same TCP port, XRootD-native upgrade |
| `roots://host:1094/...` | Immediately after TCP connect | `listen ... ssl` in `stream {}` | nginx stream SSL + normal XRootD stream module | Transport TLS from byte 0 |

One listener should use one transport-TLS model. If a stream listener already
uses `listen ... ssl` for `roots://`, leave `xrootd_tls` off on that listener.

---

## Build requirements

To use every TLS mode you need nginx built with OpenSSL support in both the
stream and HTTP stacks:

```bash
./configure \
    --with-stream \
    --with-stream_ssl_module \
    --with-http_ssl_module \
    --with-threads \
    --add-module=/path/to/nginx-xrootd
```

If you only need WebDAV over HTTPS, `--with-http_ssl_module` is sufficient.
If you want `roots://` or `xrootd_tls`, `--with-stream_ssl_module` is required.

---

## Native XRootD TLS

The native `root://` path can run with authentication only, with an
in-protocol TLS upgrade, or behind nginx stream SSL.

### 1. GSI without transport TLS

With:

```nginx
xrootd_auth gsi;
xrootd_certificate ...;
xrootd_certificate_key ...;
xrootd_trusted_ca ...;
```

the module performs XRootD/GSI authentication. That protects the credential
exchange, but it does not automatically turn the whole session into a TLS
transport. Metadata and file payloads are still sent over the normal XRootD
stream unless you add one of the TLS modes below.

### 2. In-protocol TLS upgrade on `root://`

With:

```nginx
stream {
    server {
        listen 1095;
        xrootd on;
        xrootd_root /data;

        xrootd_auth gsi;
        xrootd_certificate     /etc/grid-security/hostcert.pem;
        xrootd_certificate_key /etc/grid-security/hostkey.pem;
        xrootd_trusted_ca      /etc/grid-security/certificates/ca.pem;

        xrootd_tls on;
    }
}
```

the module enables XRootD's in-band TLS negotiation:

1. The client connects with plain `root://`
2. It sends the normal XRootD handshake plus `kXR_protocol`
3. If the client set `kXR_ableTLS`, the server replies with
   `kXR_haveTLS | kXR_gotoTLS | kXR_tlsLogin`
4. The module marks the connection `tls_pending`
5. Once that `kXR_protocol` reply is fully sent, the stream state machine
   starts an nginx/OpenSSL server-side TLS handshake on the same socket
6. When the handshake completes, normal XRootD request parsing resumes
7. `kXR_login`, `kXR_auth`, and all later file traffic now run inside TLS

That flow is implemented in two places:

- `src/ngx_xrootd_session.c`
  - `xrootd_handle_protocol()` decides whether to advertise TLS
- `src/ngx_xrootd_connection.c`
  - `xrootd_start_tls()` creates the nginx SSL connection
  - `xrootd_tls_handshake_done()` restores the normal read/write handlers

Important details:

- `xrootd_tls on` requires `xrootd_certificate` and
  `xrootd_certificate_key`
- the TLS context is created at config time and currently enables TLS 1.2/1.3
- the upgrade only happens when the client explicitly offers `kXR_ableTLS`
- the module starts the TLS handshake only after the `kXR_protocol` response is
  fully flushed, so the cleartext XRootD framing stays valid

This works with anonymous, GSI, token, or mixed-auth listeners. The example
above uses GSI because that is the most common Grid deployment.

This is the closest match to "XRootD over TLS on the normal port" without
moving the listener to `roots://`.

### 3. `roots://` via nginx stream SSL

You can also terminate TLS before the XRootD protocol starts at all:

```nginx
stream {
    server {
        listen 1097 ssl;
        xrootd on;
        xrootd_root /data;

        xrootd_auth gsi;
        xrootd_certificate     /etc/grid-security/hostcert.pem;
        xrootd_certificate_key /etc/grid-security/hostkey.pem;
        xrootd_trusted_ca      /etc/grid-security/certificates/ca.pem;

        ssl_certificate     /etc/grid-security/hostcert.pem;
        ssl_certificate_key /etc/grid-security/hostkey.pem;
    }
}
```

In this mode nginx's stream SSL layer handles TLS from byte 0 and the XRootD
module sees an already-decrypted stream. Clients use `roots://...`.

This is useful when you want:

- transport encryption before any XRootD bytes are exchanged
- standard nginx stream SSL features such as session caches and TLS policy
- anonymous or token-authenticated XRootD over TLS, not only GSI

Do not also enable `xrootd_tls on` on the same listener. `roots://` is already
encrypted before the XRootD handshake begins.

---

## What the native stream actually advertises

The protocol negotiation currently looks like this:

- `kXR_protocol`
  - advertises auth protocols (`gsi`, `ztn`, or both) when the client asked for
    security negotiation
  - advertises `kXR_haveTLS` only when `xrootd_tls on` is configured and the
    client offered `kXR_ableTLS`
- `kXR_login`
  - returns the normal session id
  - appends `&P=...` parameters describing the enabled auth protocols
  - for GSI includes the CA hash used later in the GSI bootstrap
- `kXR_auth`
  - runs after the TLS upgrade if the connection took the `xrootd_tls` path

So the layering can be:

| Listener type | Auth mode | Encryption of file traffic |
|---|---|---|
| plain `root://`, no `xrootd_tls` | `gsi` | no |
| plain `root://` + `xrootd_tls on` | `none`, `gsi`, `token`, or `both` | yes, after `kXR_protocol` |
| `roots://` (`listen ... ssl`) | `none`, `gsi`, `token`, or `both` | yes, from connect onward |

---

## WebDAV / HTTPS TLS

WebDAV uses normal nginx HTTP SSL rather than the native XRootD stream state
machine.

Typical configuration:

```nginx
http {
    server {
        listen 8443 ssl;

        ssl_certificate     /etc/grid-security/hostcert.pem;
        ssl_certificate_key /etc/grid-security/hostkey.pem;
        ssl_verify_client   optional_no_ca;
        ssl_verify_depth    10;

        xrootd_webdav_proxy_certs on;

        location / {
            xrootd_webdav         on;
            xrootd_webdav_root    /data;
            xrootd_webdav_cadir   /etc/grid-security/certificates;
            xrootd_webdav_auth    required;
        }
    }
}
```

### Why WebDAV needs extra TLS glue

Grid and WLCG clients often authenticate with RFC 3820 proxy certificates.
Stock nginx/OpenSSL client-certificate handling does not always accept those
chains in the way Grid deployments expect.

The WebDAV module therefore adds several pieces on top of nginx's normal HTTPS
stack:

1. `xrootd_webdav_proxy_certs on`
   - patches the server `SSL_CTX` in postconfiguration
   - sets `X509_V_FLAG_ALLOW_PROXY_CERTS`
   - allows nginx's TLS layer to accept RFC 3820 proxy certs

2. Manual x509 verification in the request handler
   - uses a cached `X509_STORE` built from `xrootd_webdav_cadir`,
     `xrootd_webdav_cafile`, and `xrootd_webdav_crl`
   - applies `X509_V_FLAG_ALLOW_PROXY_CERTS`
   - respects `xrootd_webdav_verify_depth`

3. Fast path when nginx already verified the client cert
   - if nginx's own SSL trust inputs match the module's trust inputs, the
     module reuses `SSL_get_verify_result() == X509_V_OK` instead of running a
     second full `X509_verify_cert()`

4. TLS auth caching
   - verified subject DNs are cached on the live TLS connection
   - they are also cached on the `SSL_SESSION`
   - keepalive requests and resumed TLS sessions can skip repeated chain
     verification work

The relevant code lives in `src/ngx_http_xrootd_webdav_module.c`.

### WebDAV auth order

For an HTTPS/WebDAV request the order is:

1. TCP connect
2. TLS handshake in nginx HTTP SSL
3. HTTP request parsing
4. WebDAV auth decision:
   - cached TLS auth result, or
   - nginx-verified client certificate fast path, or
   - manual proxy-cert verification against the cached CA/CRL store, or
   - bearer-token verification against the locally loaded JWKS
5. WebDAV method handler (`GET`, `PUT`, `PROPFIND`, and so on)

Bearer-token validation is local only. The module loads JWKS keys at startup and
does not call out to an identity provider during request handling.

---

## Performance implications of TLS

TLS improves confidentiality and often simplifies firewalling and operational
policy, but it also changes the I/O path:

- every byte must be encrypted and decrypted
- some zero-copy paths are only available without TLS, or only when the
  platform SSL stack exposes a kernel-TLS sendfile path
- larger transfers benefit from session reuse and larger SSL write buffers

In this repository the most visible differences are:

- native `kXR_read` can use file-backed chain buffers and nginx's sendfile path
  on non-TLS stream connections
- native TLS reads fall back to memory-backed `pread()` responses because
  nginx's SSL send path does not reliably handle file-backed XRootD chains
  without kernel TLS support
- WebDAV over HTTPS still benefits from file-backed output buffers and nginx's
  HTTP send pipeline, but the effective copy/syscall profile depends on the
  nginx/OpenSSL build and platform support

For the code-level optimizations that help offset this overhead, see
[optimizations.md](optimizations.md).

---

## Recommended deployment choices

Choose the transport based on what you need:

- `davs://`
  - best when you need HTTP/WebDAV compatibility, proxies, bearer tokens, or
    HTTP-TPC
- `root://` + `xrootd_tls on`
  - best when clients already speak native XRootD and you want XRootD's
    negotiated in-band TLS model
- `roots://`
  - best when you want TLS from the first byte and want to use nginx stream SSL
    policy directly

If your main question is "why is HTTPS slower than raw XRootD/GSI?", the short
answer is that HTTPS adds both TLS record processing and HTTP/WebDAV framing.
The detailed code-level mitigations are documented in
[optimizations.md](optimizations.md).

---

## Tests and examples

- `tests/test_gsi_tls.py`
  - exercises the native `xrootd_tls` in-protocol upgrade path
- `tests/test_webdav_auth_cache.py`
  - exercises the WebDAV TLS auth caches and nginx-verified fast path
- `tests/nginx.perf.conf`
  - shows all three TLS patterns in one config:
    - `xrootd_tls on`
    - `roots://` via `listen ... ssl`
    - `davs://` via `http {}` + `listen ... ssl`
