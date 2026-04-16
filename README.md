# nginx-xrootd

An nginx module that makes nginx speak the [XRootD](https://xrootd.slac.stanford.edu/) `root://` protocol — the standard file transfer protocol used across High Energy Physics (CERN, SLAC, Fermilab).

Instead of running a separate `xrootd` daemon, you add this module to your existing nginx. You get XRootD file access plus everything nginx already gives you: TLS, access controls, rate limiting, load balancing, Prometheus metrics.

> **Not familiar with XRootD?** See [docs/background.md](docs/background.md) for a plain-English introduction.

---

## What this module does

At a high level, nginx-xrootd turns an nginx `stream {}` listener into an XRootD data server:

- nginx accepts the TCP connection and drives the event loop
- this module speaks the XRootD wire protocol on that connection
- filesystem operations are resolved under `xrootd_root`
- optional GSI/x509 authentication is enforced per connection
- request/byte counters are exported through an HTTP Prometheus endpoint

The implementation is deliberately narrow and pragmatic: it focuses on the subset of XRootD behavior required by `xrdcp`, `xrdfs`, and the Python XRootD client, while keeping nginx's operational model intact.

### Request flow

Each client connection follows the same broad lifecycle:

1. Initial 20-byte handshake
2. `kXR_protocol` capability negotiation
3. `kXR_login`
4. Optional `kXR_auth` exchange for GSI
5. Normal request/response traffic such as `open`, `read`, `write`, `dirlist`, `stat`

The module keeps one per-connection context with:

- the parser state machine
- the most recent request header and payload
- authenticated identity state
- the open-file handle table
- per-session transfer counters
- a pointer into the shared metrics slot for that listener

### Supported usage model

This project is aimed at:

- serving files from a local filesystem path via `root://`
- anonymous or GSI-authenticated clients
- read-heavy or mixed read/write data movement
- observability through nginx logs plus Prometheus metrics

It is not trying to be a full drop-in replacement for every advanced xrootd deployment feature or plugin ecosystem component.

---

## Quick start

```bash
# 1. Build nginx with this module
curl -O https://nginx.org/download/nginx-1.28.3.tar.gz
tar xzf nginx-1.28.3.tar.gz && cd nginx-1.28.3
./configure --with-stream --with-threads --add-module=/path/to/nginx-xrootd
make -j$(nproc) && sudo make install

# 2. Add to nginx.conf
# stream {
#     server {
#         listen 1094;
#         xrootd on;
#         xrootd_root /data/store;
#     }
# }

# 3. Test
xrdcp /local/file.txt root://localhost:1094//file.txt
xrdcp root://localhost:1094//file.txt /tmp/downloaded.txt
```

Full setup walkthrough: [docs/getting-started.md](docs/getting-started.md)

---

## Feature summary

### Authentication

- Anonymous mode with `xrootd_auth none`
- GSI/x509 mode with `xrootd_auth gsi`
- Per-request gating so mutating operations require a fully authenticated session

### Namespace and file operations

- `stat`, `open`, `read`, `readv`, `close`
- `mkdir`, `rm`, `rmdir`, `mv`, `chmod`, `truncate`
- checksum and space queries via `kXR_query`
- upload support through both `kXR_write` and `kXR_pgwrite`

### Operational features

- nginx thread-pool support for async disk I/O
- xrootd-specific access logging
- Prometheus metrics exporter via an HTTP location
- path hardening against traversal, symlink-escape, and malformed payloads
- log sanitization so client-controlled strings cannot inject multiline or malformed log records

---

## Documentation

| | |
|---|---|
| [Getting started](docs/getting-started.md) | Build, install, first working server |
| [Configuration reference](docs/configuration.md) | All directives, examples |
| [Authentication](docs/authentication.md) | Anonymous and GSI/x509 setup |
| [Operations](docs/operations.md) | All supported XRootD operations |
| [Metrics & logging](docs/metrics-and-logging.md) | Prometheus metrics, access log format |
| [Background](docs/background.md) | What XRootD is and why this module exists |
| [Protocol notes](docs/protocol-notes.md) | Implementation details for developers |

---

## Development notes

### Source layout

- `src/ngx_xrootd_connection.c` contains the session state machine and send/recv flow
- `src/ngx_xrootd_handshake.c` handles handshake and opcode dispatch policy
- `src/ngx_xrootd_session.c` handles login, protocol negotiation, ping, and session teardown
- `src/ngx_xrootd_gsi.c` implements the GSI/x509 authentication exchange
- `src/ngx_xrootd_read_handlers.c` contains metadata and read-side operations
- `src/ngx_xrootd_write_handlers.c` contains write-side and namespace-mutating operations
- `src/ngx_xrootd_path.c` contains path extraction, root confinement, access logging, and shared sanitization helpers
- `src/ngx_http_xrootd_metrics_module.c` exports Prometheus metrics
- `tests/` covers client interoperability, throughput, bridge transfers, metrics, and security regressions

### Development workflow

For local development against the test harness in this repository:

```bash
cd /tmp/nginx-1.28.3
make -j$(nproc)

# Important: a reload only picks up config changes, not a rebuilt binary.
/tmp/nginx-1.28.3/objs/nginx -c /tmp/xrd-test/conf/nginx.conf -s stop || true
/tmp/nginx-1.28.3/objs/nginx -c /tmp/xrd-test/conf/nginx.conf

cd /path/to/nginx-xrootd
pytest -q
```

### Known client/runtime quirks

These came from real interoperability debugging and are easy to forget later:

- Some real XRootD clients include a single trailing NUL byte inside path `dlen`; the server should allow that terminator but still reject embedded NUL bytes before the end.
- In this repo's test environment, `xrdfs ... ping` is not implemented by the installed 5.9.2 client tools; use an authenticated `xrdfs ... ls /` as the readiness probe instead.
- Repeated transfer tests should use `xrdcp -f` or remove stale outputs first, otherwise reruns fail on existing files instead of exercising the server.
- Any client-controlled string that reaches logs should be passed through `xrootd_sanitize_log_string()` first so control bytes are escaped as `\xNN`.
- Many protocol details that look obvious from the spec are wrong in practice; check [docs/protocol-notes.md](docs/protocol-notes.md) before “simplifying” wire behavior.

### Documentation strategy in the source tree

The code intentionally carries heavy inline comments in protocol-dense areas. The rule followed in this repo is:

- explain wire-format quirks and client expectations
- explain ownership and lifetime of pool-allocated buffers
- explain why a loop or state transition is structured a particular way
- do not waste comments on single-line syntax that is already self-evident

That style is deliberate: this project is easier to maintain when protocol knowledge lives next to the code that depends on it.

---

## Status

226 tests pass against xrdcp / XRootD Python client v5.9.2 and nginx 1.28.3. Anonymous and GSI/x509 authentication both work for reads and writes, including metrics, bridge-transfer, and security-hardening coverage.

## License

[2-Clause BSD](https://opensource.org/licenses/BSD-2-Clause) — same as nginx.
