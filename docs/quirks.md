# Module quirks and compromises

This page collects the higher-level quirks and compromises in the native XRootD
and WebDAV modules.

It is different from [protocol-notes.md](protocol-notes.md):

- `protocol-notes.md` is about low-level wire behavior discovered by reverse
  engineering real clients
- this page is about the places where XRootD, WebDAV, nginx, and OpenSSL do
  not line up cleanly, so the implementation has to choose a compromise

None of these are necessarily bugs. Most are the result of fitting a
stateful storage protocol and a Grid-auth model into nginx's event-driven HTTP
and stream frameworks.

---

## Summary table

| Area | Why there is tension | Current compromise |
|---|---|---|
| native auth vs transport security | GSI auth and TLS are separate concepts in XRootD | GSI can run with or without TLS; `xrootd_tls` and `roots://` are separate choices |
| x509 proxies in WebDAV | nginx/OpenSSL does not naturally love RFC 3820 proxy chains | patch `SSL_CTX`, then verify proxy chains in module code |
| zero-copy vs TLS | file-backed send paths are easiest on cleartext sockets | cleartext native reads use sendfile-style chains; TLS paths fall back to memory-backed reads when needed |
| session model vs request model | native XRootD is session-oriented; WebDAV is HTTP request-oriented | stream keeps session state; WebDAV re-evaluates requests and uses caches to recover some session-like efficiency |
| token scopes | stream and WebDAV were implemented at different stages | stream parses token scopes but still gates writes mainly with `xrootd_allow_write`; WebDAV enforces write scopes for `PUT` and `COPY` |
| third-party copy | root TPC and HTTP-TPC are different protocols | native root TPC not implemented; WebDAV HTTP-TPC implemented separately with a helper process |
| nginx body handling | HTTP request bodies may be in memory or temp files | WebDAV `PUT` has separate fast paths for in-memory and spooled bodies |
| nginx connection context | HTTP module has fewer natural per-connection hooks than stream | WebDAV stores fd-cache state in SSL `ex_data` |
| real clients vs spec text | `xrdcp` behavior often differs from the nominal protocol docs | implementation follows working client behavior first |

---

## 1. Native GSI is not the same thing as transport TLS

This is one of the easiest things to misunderstand.

In the native `root://` path:

- GSI/x509 authentication proves identity and establishes the XRootD auth state
- transport TLS is separate

So these are all distinct deployments:

- `root://` + GSI auth, no transport TLS
- `root://` + GSI auth + `xrootd_tls on`
- `roots://` with nginx stream SSL

That split exists because it is how the XRootD ecosystem evolved. The module
does not try to pretend otherwise.

Practical consequence:

- "GSI enabled" does not automatically mean "all file data is inside TLS"

See [tls.md](tls.md).

---

## 2. WebDAV x509 proxy auth has to work around nginx's defaults

Grid clients use RFC 3820 proxy certificates. nginx's built-in TLS client-cert
verification is not, by itself, a complete answer for that environment.

The module therefore does two things:

1. patches the `SSL_CTX` with `X509_V_FLAG_ALLOW_PROXY_CERTS`
2. keeps its own CA/CRL store and can verify the proxy chain manually

That is a deliberate compromise:

- nginx still does the TLS handshake
- the storage module keeps authority over the Grid-specific auth decision

Why not leave it all to nginx?

- because proxy-certificate acceptance and Grid CA/CRL policy need behavior that
  stock nginx deployments do not naturally provide

The result is slightly more complex than a vanilla HTTPS application, but it
matches real x509 proxy clients much better.

---

## 3. Session-oriented stream vs request-oriented WebDAV

The native stream module is connection/session oriented:

- one login
- one auth completion
- open file handles live in the session context
- later requests operate on those handles

WebDAV is HTTP-oriented:

- each request stands alone
- auth policy is checked per request
- there is no native "open handle" concept

The implementation compromise is:

- stream uses a rich per-connection state machine
- WebDAV uses request handlers plus caches where useful

Practical consequence:

- native `root://` feels like a long-lived protocol session
- `davs://` feels like repeated HTTP method calls, even when the TCP/TLS
  connection is reused underneath

---

## 4. Zero-copy style reads are best on cleartext sockets

For cleartext native `root://` reads of regular files, the module builds
file-backed nginx chain buffers so the send path can use the platform sendfile
implementation.

Under TLS that gets much less clean:

- the SSL send path has different constraints
- file-backed XRootD chains are not the reliable choice on every TLS setup

So the current compromise is:

- use the file-backed fast path on cleartext native reads
- fall back to memory-backed `pread()` responses when the stream is under TLS

This is not as elegant as "one perfect zero-copy path everywhere", but it is a
correct and explicit trade-off.

See also [optimizations.md](optimizations.md).

---

## 5. `xrdcp` over WebDAV is not a thin wrapper around native XRootD

The `davs://` path is a different client stack:

- `OPTIONS`
- `PROPFIND`
- `GET`
- `PUT`
- `MKCOL`
- `DELETE`

That means the module has to satisfy the WebDAV expectations of the HTTP plugin,
not the opcode expectations of the stream client.

Examples:

- `OPTIONS` must advertise `PROPFIND`
- metadata comes from `PROPFIND`, not `kXR_stat`
- uploads are HTTP `PUT`, not `kXR_pgwrite`

So the implementation intentionally does not try to collapse the two worlds into
one internal abstraction. They share storage and auth concepts, but they are
still different protocol surfaces.

See [xrdcp-interactions.md](xrdcp-interactions.md).

---

## 6. Native root TPC and WebDAV HTTP-TPC are different features

There are two different "third-party copy" stories:

- native root TPC in the XRootD stream protocol
- HTTP-TPC via WebDAV `COPY`

The module currently implements only the HTTP/WebDAV side.

The compromise is very explicit:

- native root TPC is reported as unsupported
- WebDAV HTTP-TPC is handled in a dedicated helper path

And even the WebDAV TPC implementation is intentionally pragmatic:

- it shells out to `curl`
- it does not implement GridSite or OIDC delegation endpoints

That is not as feature-rich as a full XRootD daemon, but it keeps the scope of
the nginx module manageable and makes the HTTP behavior predictable.

---

## 7. Token auth is intentionally split by protocol

Today the token story is not symmetric:

- native stream:
  - validates JWTs
  - parses `scope` and `wlcg.groups`
  - still relies mainly on `xrootd_allow_write` and VO-style ACLs for actual
    path authorization
- WebDAV:
  - validates bearer tokens
  - enforces `storage.write` / `storage.create` for mutating requests like
    `PUT` and `COPY`

This is a compromise between shipping useful token support now and waiting for a
fully uniform authz model across both protocol stacks.

Practical consequence:

- do not assume stream and WebDAV token writes are governed by identical rules

The docs call this out in multiple places because it matters operationally.

---

## 8. nginx's HTTP body model shapes the WebDAV upload path

By the time WebDAV `PUT` handling runs, nginx may have:

- the whole body in memory
- or a temp file under `client_body_temp_path`
- or a chain of both

So the module cannot treat every upload as one neat contiguous socket stream.
Instead it uses different strategies:

- in-memory body:
  - optionally coalesce and offload the write to a thread pool
- spooled temp file:
  - prefer `copy_file_range()`
  - fall back to buffered copy if needed

That compromise is a direct consequence of plugging into nginx's HTTP request
lifecycle instead of writing a standalone WebDAV server from scratch.

---

## 9. The HTTP module has weaker per-connection storage than the stream module

The stream module naturally owns a session object for the whole life of the
connection. The HTTP content module does not get quite the same kind of durable
per-connection storage hook.

The compromise in WebDAV is to stash some connection-level state in SSL
`ex_data`, notably:

- x509 auth caches
- the per-connection fd table for keepalive `GET` reuse

That is a practical solution, but it means the nicest fast path is tied to TLS
connections, because that is where the stable OpenSSL connection object exists.

---

## 10. Some "spec purity" had to yield to real `xrdcp` behavior

Several implementation choices are driven by what real clients do, not by what
the protocol specification suggests at first glance.

Examples:

- v5 handshake reply format
- `SecurityInfo` in `kXR_protocol`
- plain-text GSI login parameters
- `kXR_pgwrite` needing a 32-byte `kXR_status` response
- one trailing NUL inside path payload length
- `kXR_new | kXR_delete` meaning overwrite

Those are not really optional. If the server follows the paper spec but not the
real client behavior, `xrdcp` hangs, disconnects, or misparses responses.

That is why [protocol-notes.md](protocol-notes.md) exists, and why some code
paths look stricter or stranger than a casual reading of the protocol might
suggest.

---

## 11. Some limits are intentionally small and explicit

A few limits are chosen to keep failure modes predictable:

- up to 16 open files per native connection
- 16 MiB maximum write payload per native request
- 1024 `readv` segments per request
- 256 MiB maximum total `readv` response

These are compromises between performance, memory use, and implementation
complexity. They are not declarations that the XRootD protocol itself could
never support larger values.

Practical consequence:

- if a future client starts sending much larger per-request payloads, the module
  may need another round of limit work rather than "just working forever"

---

## 12. Logging and metrics intentionally leave information out

Another deliberate compromise: observability is useful, but user-controlled
identity and path data are dangerous in logs and poisonous in Prometheus label
sets.

So the module:

- sanitizes client-controlled log strings
- keeps metric labels low-cardinality
- does not try to turn usernames, DNs, token subjects, or paths into metrics

That can feel less convenient when debugging one specific user transfer, but it
is the safer default for a long-running service.

---

## 13. Thread pools are optional, so synchronous fallback still exists

Both modules can use nginx thread pools for blocking file I/O, but nginx thread
pools are still configuration, not a guaranteed runtime feature of every build.

The compromise is:

- use async thread-pool paths when available
- fall back to synchronous I/O when not

That keeps the module usable in simpler builds, but it also means a deployment
without thread pools can still behave very differently under load from a tuned
deployment.

---

## 14. The module prefers explicit behavior over pretending to be the full xrootd daemon

Across both the stream and WebDAV code, a repeated design choice is:

- implement the pieces needed for the target workflows well
- be explicit about unsupported or intentionally simplified areas

Examples:

- native root TPC unsupported
- WebDAV TPC implemented separately and narrowly
- token path authorization still split by protocol
- no redirector/federation role
- no remote backend abstraction layer

This keeps the module understandable and maintainable inside nginx, even though
it means some advanced XRootD-daemon features are intentionally out of scope.

---

## Related docs

- [protocol-notes.md](protocol-notes.md) - low-level wire quirks
- [xrdcp-interactions.md](xrdcp-interactions.md) - end-to-end client flow
- [optimizations.md](optimizations.md) - performance-driven implementation choices
- [tls.md](tls.md) - auth and transport layering
- [development.md](development.md) - source layout and workflow
