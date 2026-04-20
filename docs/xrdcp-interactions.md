# xrdcp client interactions

This page describes the usual client/server flow when `xrdcp` talks to this
module over:

- native XRootD `root://`
- WebDAV over HTTPS `davs://`

It is intentionally higher-level than [operations.md](operations.md) and
[protocol-notes.md](protocol-notes.md). The goal here is to answer "what does
the client usually do next?" rather than to document every field in every wire
structure.

Exact request ordering can vary by:

- client version
- auth mode (`none`, `gsi`, `token`, `both`)
- whether TLS is `davs://`, `root://` + `xrootd_tls`, or `roots://`
- whether the client reuses an existing connection
- whether the client is uploading, downloading, checksumming, or probing

So treat these as the common interaction patterns, not as a promise that every
client build emits the exact same packet sequence.

---

## Two different transports

`xrdcp` can reach the same storage through two very different client stacks:

| URL | Client-side stack | Server-side module |
|---|---|---|
| `root://host//path` | XRootD native client | nginx stream XRootD module |
| `davs://host/path` with `--allow-http` | XrdClHttp / libcurl | nginx HTTP WebDAV module |

That distinction matters:

- `root://` speaks XRootD opcodes like `kXR_open`, `kXR_read`, and
  `kXR_pgwrite`
- `davs://` speaks HTTP/WebDAV methods like `OPTIONS`, `PROPFIND`, `GET`, and
  `PUT`

The same user action, "copy file A to file B", therefore looks very different
to the server depending on the URL scheme.

---

## Before the transfer starts

### Native `root://`

Typical user commands:

```bash
xrdcp /tmp/local.root root://host:1094//store/local.root
xrdcp root://host:1094//store/remote.root /tmp/remote.root
```

Common auth inputs:

- GSI/x509 proxy:
  - `X509_USER_PROXY=/path/to/proxy.pem`
  - `X509_CERT_DIR=/path/to/hashed/ca/dir`
- bearer token:
  - `BEARER_TOKEN=...`

### WebDAV `davs://`

Typical user commands:

```bash
xrdcp --allow-http /tmp/local.root davs://host:8443/store/local.root
xrdcp --allow-http davs://host:8443/store/remote.root /tmp/remote.root
```

The `--allow-http` flag is what tells `xrdcp` to load the HTTP/WebDAV client
plugin instead of using the native XRootD transport.

Common auth inputs:

- x509 proxy presented during the TLS handshake
- or `Authorization: Bearer ...` via the plugin's HTTP path when bearer tokens
  are in use

---

## Native `root://` interactions

The stream module is session-oriented. A connection has a protocol state
machine, login state, auth state, open-file table, and optional pending AIO or
pending send state.

### Session bring-up

The usual start of a native XRootD session looks like:

```text
client                              server
------                              ------
TCP connect                    ->
20-byte handshake              ->
kXR_protocol                   ->
                              <-  protocol reply (+ auth info, maybe TLS flags)
[optional native TLS upgrade]
kXR_login                      ->
                              <-  session id + auth parameters
kXR_auth                       ->
                              <-  auth success
```

Important notes:

- if the listener uses `xrootd_tls on`, the TLS upgrade happens after
  `kXR_protocol`
- if the listener uses `listen ... ssl`, the transport is already `roots://`
  and the XRootD module sees decrypted bytes from the start
- GSI auth is a multi-round XRootD auth exchange
- token auth is a single `kXR_auth` carrying the JWT under the `ztn` credential
  type

Relevant code:

- `src/ngx_xrootd_handshake.c`
- `src/ngx_xrootd_session.c`
- `src/ngx_xrootd_connection.c`
- `src/ngx_xrootd_gsi.c`

### Common native download flow

Once login/auth are complete, a download usually looks like:

```text
client                              server
------                              ------
[optional kXR_query kXR_Qconfig] ->
kXR_open (read)                 ->
                              <-  file handle
kXR_read / kXR_readv           ->
                              <-  data chunks
kXR_read / kXR_readv           ->
                              <-  more data
kXR_close                      ->
                              <-  ok
kXR_endsess                    ->
                              <-  ok
TCP close
```

Details worth knowing:

- `xrdcp` commonly queries `readv` and `chksum` capability via `kXR_Qconfig`
- simple streaming reads use repeated `kXR_read`
- sparse or metadata-heavy access patterns may use `kXR_readv`
- large replies are chunked with `kXR_oksofar`

The read-side handlers live in:

- `src/ngx_xrootd_read_handlers.c`
- `src/ngx_xrootd_query.c`
- `src/ngx_xrootd_aio.c`

### Common native upload flow

For current clients, uploads usually look like:

```text
client                              server
------                              ------
[session setup as above]
kXR_open (create/overwrite)    ->
                              <-  file handle
kXR_pgwrite                    ->
                              <-  pgwrite status
kXR_pgwrite                    ->
                              <-  pgwrite status
...
kXR_sync                       ->
                              <-  ok
kXR_close                      ->
                              <-  ok
kXR_endsess                    ->
                              <-  ok
```

Important details:

- modern `xrdcp` prefers `kXR_pgwrite`, not `kXR_write`
- overwrite semantics usually arrive as `kXR_new | kXR_delete`, which means
  "create or replace"
- large files arrive as multiple `kXR_pgwrite` requests
- `xrdcp` normally issues `kXR_sync` before closing the handle

Relevant code:

- `src/ngx_xrootd_write_handlers.c`
- `src/ngx_xrootd_response.c`

### Optional follow-up operations

Depending on flags and workflow, `xrdcp` may also ask for:

- `kXR_Qcksum` when checksum reporting is requested
- `kXR_stat` or `kXR_dirlist` for metadata checks
- `kXR_Qspace` or other queries in tooling around the transfer

### Native auth and transport variants

The same read/write pattern sits on top of several auth and TLS variants:

| Variant | What changes |
|---|---|
| anonymous `root://` | login succeeds without `kXR_auth` |
| GSI `root://` | `kXR_auth` runs the GSI certificate exchange |
| token `root://` | `kXR_auth` carries `ztn` + JWT |
| `root://` + `xrootd_tls on` | native TLS upgrade after `kXR_protocol` |
| `roots://` | TLS starts before any XRootD bytes |

For the TLS-specific details, see [tls.md](tls.md).

---

## WebDAV `davs://` interactions

The WebDAV module is request-oriented. There is still one TCP/TLS connection,
and clients often reuse it with keepalive, but each HTTP request is handled as a
fresh WebDAV operation.

### Session bring-up

The WebDAV path usually starts like:

```text
client                              server
------                              ------
TCP connect                    ->
TLS handshake                  ->
                              <-  server certificate request / response
[x509 proxy or bearer-token auth context established]
HTTP/WebDAV requests begin
```

If x509 auth is used:

- nginx HTTP SSL accepts the TLS connection
- the WebDAV module then verifies the client proxy chain itself, or reuses
  nginx's successful verification when the trust configuration matches

Relevant code:

- `src/ngx_http_xrootd_webdav_module.c`

### Common WebDAV download flow

A typical `xrdcp --allow-http` read usually looks like:

```text
client                              server
------                              ------
OPTIONS                        ->
                              <-  Allow + DAV headers
[often PROPFIND Depth:0]       ->
                              <-  metadata / stat info
GET [maybe with Range]         ->
                              <-  response body
```

Things to know:

- `OPTIONS` needs to advertise `PROPFIND`, because the HTTP plugin uses
  WebDAV-style metadata discovery
- the plugin commonly uses `PROPFIND` for stat-like operations
- the actual file bytes come from `GET`
- large reads may use HTTP `Range` rather than one monolithic `GET`

The corresponding server handlers are:

- `webdav_handle_options()`
- `webdav_handle_propfind()`
- `webdav_handle_get()`

### Common WebDAV upload flow

A typical `davs://` upload is much more HTTP-like than a native XRootD upload:

```text
client                              server
------                              ------
OPTIONS                        ->
                              <-  Allow + DAV headers
[often PROPFIND or HEAD]       ->
                              <-  current metadata / existence info
PUT                            ->
                              <-  201 create or 204 overwrite
```

Things to know:

- the upload is one HTTP `PUT`, not a stream of `kXR_pgwrite` requests
- nginx may hold the request body in memory or may spool it to a temp file
  before the module writes the destination file
- overwrites are expressed as another `PUT` to the same path
- the module returns `201` for create and `204` for overwrite

If the workflow includes directory creation or cleanup, higher-level WebDAV
methods may also appear:

- `MKCOL`
- `DELETE`
- `PROPFIND`

### WebDAV auth variants

WebDAV can authenticate via:

| Mechanism | What the server sees |
|---|---|
| x509 proxy over TLS | client cert in TLS handshake, verified by WebDAV module |
| bearer token | `Authorization: Bearer ...` header, verified against local JWKS |
| optional auth mode | request may proceed anonymously if policy allows it |

Unlike native `root://`, auth is evaluated per HTTP request, though the module
can reuse TLS connection and TLS session auth caches to avoid repeating the full
x509 verification work on every request.

---

## Side-by-side comparison

| User intent | Native `root://` | WebDAV `davs://` |
|---|---|---|
| negotiate features | `kXR_protocol`, optional `kXR_Qconfig` | `OPTIONS` |
| login | `kXR_login` | TLS + HTTP request context |
| authenticate | `kXR_auth` | TLS client cert or HTTP bearer token |
| stat a file | `kXR_stat` | `PROPFIND Depth:0` or sometimes `HEAD` |
| list directory | `kXR_dirlist` | `PROPFIND Depth:1` |
| download bytes | `kXR_read` / `kXR_readv` | `GET` with optional `Range` |
| upload bytes | `kXR_pgwrite` / `kXR_write` | `PUT` |
| flush writes | `kXR_sync` | end of `PUT` handling / file close |
| close handle / end session | `kXR_close`, `kXR_endsess` | HTTP request end, keepalive, then TCP close |

---

## Third-party copy is different again

It is worth calling out one special case because users often expect `xrdcp` to
hide it:

- native root TPC is its own XRootD rendezvous/delegation flow and is not
  currently implemented here
- WebDAV HTTP-TPC is implemented separately as WebDAV `COPY` pull support

So:

- `xrdcp --tpc only root://...` is expected to fail against this module's
  native stream listener
- `xrdcp --tpc first root://...` can still fall back to a normal streamed copy
- WebDAV TPC is a different HTTP code path entirely

See:

- `tests/test_root_tpc.py`
- `src/ngx_http_xrootd_webdav_tpc.c`

---

## Where to trace these flows in the code

If you want to step through the server side of an `xrdcp` session:

### Native `root://`

- `src/ngx_xrootd_handshake.c`
- `src/ngx_xrootd_session.c`
- `src/ngx_xrootd_gsi.c`
- `src/ngx_xrootd_read_handlers.c`
- `src/ngx_xrootd_write_handlers.c`
- `src/ngx_xrootd_query.c`
- `src/ngx_xrootd_connection.c`

### WebDAV `davs://`

- `src/ngx_http_xrootd_webdav_module.c`
- `src/ngx_http_xrootd_webdav_tpc.c`

### Tests that show real client behavior

- `tests/test_write.py`
- `tests/test_gsi_tls.py`
- `tests/test_webdav.py`
- `tests/test_root_tpc.py`

---

## Related docs

- [operations.md](operations.md) - opcode and method reference
- [tls.md](tls.md) - transport and auth layering
- [webdav.md](webdav.md) - HTTPS/WebDAV configuration
- [protocol-notes.md](protocol-notes.md) - low-level wire quirks
- [quirks.md](quirks.md) - design trade-offs and implementation compromises
