# nginx-xrootd

An nginx module that serves files over both the native [XRootD](https://xrootd.slac.stanford.edu/) `root://` protocol and WebDAV over HTTPS — the two transfer paths used by `xrdcp`, `xrdfs`, and the Python XRootD client across High Energy Physics (CERN, SLAC, Fermilab).

Instead of running a separate `xrootd` daemon, you add this module to your existing nginx and get XRootD plus everything nginx already provides: TLS, access controls, rate limiting, load balancing, Prometheus metrics, and shared GSI/JWT authentication plumbing.

> **New to XRootD?** See [docs/background.md](docs/background.md).

---

## Performance

1 GiB reads, localhost, nginx 1.28.3 + module vs xrootd v5.9.2, all transfers GSI/x509 authenticated ([how to reproduce](docs/benchmarks.md)):

| Protocol | Connections | nginx-xrootd | xrootd native | nginx p95 | xrootd p95 |
|---|---:|---:|---:|---:|---:|
| `root://` + GSI | 1  | 1,302 MiB/s | 1,790 MiB/s | 0.8 s | 0.6 s |
| `root://` + GSI | 8  | 4,305 MiB/s | 5,303 MiB/s | 1.9 s | 1.5 s |
| `root://` + GSI | 16 | 4,478 MiB/s | 5,329 MiB/s | 3.6 s | 3.1 s |
| `root://` + GSI | 32 | 5,349 MiB/s | 4,674 MiB/s | 6.1 s | 6.9 s |
| `root://` + GSI | 64 | 4,977 MiB/s | 4,421 MiB/s | 13.0 s | 14.7 s |
| `davs://` + x509 | 1  | 1,593 MiB/s | 1,940 MiB/s | 0.6 s | 0.5 s |
| `davs://` + x509 | 8  | 7,134 MiB/s | 5,392 MiB/s | 1.1 s | 1.5 s |
| `davs://` + x509 | 16 | 5,703 MiB/s | 5,845 MiB/s | 2.9 s | 2.8 s |
| `davs://` + x509 | 32 | 6,495 MiB/s | 5,797 MiB/s | 4.9 s | 5.6 s |
| `davs://` + x509 | 64 | 5,919 MiB/s | 5,538 MiB/s | 10.7 s | 11.7 s |

nginx-xrootd uses nginx's event-driven workers; both xrootd native protocols use one thread per connection and saturate under load. At single-connection, native xrootd has lower latency (less per-request framing overhead). At 128 simultaneous connections nginx-xrootd sustains 4.6× higher aggregate throughput on `root://` and 1.6× on `davs://`; xrootd native p95 latency climbs 5–57× higher. `davs://` vs `root://+GSI` throughput difference in nginx reflects TLS + HTTP framing overhead on top of the XRootD stream protocol.

---

## Protocols

| Protocol | Port | Use |
|---|---|---|
| XRootD `root://` (stream) | 1094 / 1095 | `xrdcp`, `xrdfs`, Python client |
| WebDAV over HTTPS (`davs://`) | 8443 | `xrdcp --allow-http`, HTTP clients |

Both protocols support anonymous access, GSI/x509 proxy-certificate authentication, and WLCG/JWT bearer-token authentication when configured.

Configuration is fail-fast: missing/unreadable certs, JWKS files, CRLs, or
required directories are validated during `nginx -t`/startup with explicit
`emerg` errors in the nginx log.

---

## Quick start

```bash
# Build nginx with this module
curl -O https://nginx.org/download/nginx-1.28.3.tar.gz
tar xzf nginx-1.28.3.tar.gz && cd nginx-1.28.3
./configure --with-stream --with-http_ssl_module --with-threads \
            --add-module=/path/to/nginx-xrootd
make -j$(nproc) && sudo make install
```

Minimal `nginx.conf` for both protocols:

```nginx
worker_processes auto;
thread_pool default threads=4 max_queue=65536;
events { worker_connections 1024; }

# XRootD native protocol
stream {
    server {
        listen 1094;
        xrootd on;
        xrootd_root /data;
        xrootd_allow_write on;
    }
}

# WebDAV over HTTPS (xrdcp davs://host:8443/)
http {
    server {
        listen 8443 ssl;
        ssl_certificate     /etc/grid-security/hostcert.pem;
        ssl_certificate_key /etc/grid-security/hostkey.pem;
        ssl_verify_client   optional_no_ca;
        xrootd_webdav_proxy_certs on;
        location / {
            xrootd_webdav      on;
            xrootd_webdav_root /data;
            xrootd_webdav_cadir /etc/grid-security/certificates;
        }
    }
    # Prometheus metrics
    server {
        listen 9100;
        location /metrics { xrootd_metrics on; }
    }
}
```

```bash
# Test XRootD protocol
xrdcp /local/file.txt root://localhost:1094//file.txt

# Test WebDAV protocol
xrdcp --allow-http /local/file.txt davs://localhost:8443//file.txt
```

Full setup: [docs/getting-started.md](docs/getting-started.md)

---

## Features

- **XRootD operations:** `stat`, `statx`, `open`, `read`, `pgread` (CRC32c), `readv`, `write`, `pgwrite`, `writev`, `close`, `mkdir`, `rm`, `rmdir`, `mv`, `chmod`, `truncate`, `locate`, `fattr` (get/set/del/list), checksum, space, stats, config, and filesystem queries
- **WebDAV operations:** OPTIONS, GET (with Range), HEAD, PUT, DELETE, MKCOL, PROPFIND, and opt-in HTTP-TPC COPY pull support for `https://` sources
- **Authentication:** anonymous access, GSI/x509 proxy certificates, and WLCG/JWT bearer tokens; `kXR_sigver` HMAC-SHA256 request signing verified for GSI sessions
- **TLS:** in-protocol `root://` upgrade (`kXR_wantTLS`/`kXR_ableTLS`), `roots://` (TLS-from-byte-one), and `davs://`
- **Async I/O:** nginx thread-pool support for `read`, `pgread`, `readv`, `write`, and WebDAV PUT — disk operations never block the event loop
- **Manager mode:** static path → backend mapping with `xrootd_manager_map`, catch-all `xrootd_upstream` forwarding, and server-side `kXR_redirect` support
- **Observability:** per-request access logs and Prometheus metrics (29 operation counters)

---

## Documentation

| | |
|---|---|
| [Getting started](docs/getting-started.md) | Build, install, first working server |
| [Benchmarks](docs/benchmarks.md) | How to reproduce the performance numbers above |
| [TLS implementation](docs/tls.md) | How TLS works for `davs://`, `root://` + `xrootd_tls`, and `roots://` |
| [Optimizations](docs/optimizations.md) | Code-level performance work and why it helps |
| [xrdcp interactions](docs/xrdcp-interactions.md) | Typical client/server flows for `xrdcp` over `root://` and `davs://` |
| [Quirks & compromises](docs/quirks.md) | Design mismatches, pragmatic trade-offs, and implementation gotchas |
| [Building from scratch](docs/building.md) | Detailed build guide with all dependencies |
| [Configuration reference](docs/configuration.md) | All directives |
| [WebDAV / HTTPS+GSI/Bearer](docs/webdav.md) | WebDAV setup, x509 proxy, and bearer-token compatibility |
| [Authentication](docs/authentication.md) | Anonymous, GSI/x509, and WLCG/JWT setup |
| [Test PKI & VOMS](docs/test-pki.md) | Generate test CA, certs, proxies, and VOMS infrastructure |
| [Test tokens](docs/test-tokens.md) | Generate local WLCG/JWT signing keys and bearer tokens |
| [Operations](docs/operations.md) | Supported XRootD operations |
| [Manager mode](docs/manager-mode.md) | Static path-to-backend mapping and redirect semantics |
| [Metrics & logging](docs/metrics-and-logging.md) | Prometheus metrics, access log format |
| [Development](docs/development.md) | Source layout, utilities, workflow, known quirks |
| [Utilities](utils/README.md) | Test and debug tools: proxy/token/CRL generators, protocol dumper, reference server, security probe |
| [Background](docs/background.md) | What XRootD is and why this module exists |
| [Protocol notes](docs/protocol-notes.md) | Wire-protocol details for developers |

---

## Status

The Python suite covers xrdcp / XRootD Python client behavior, WebDAV, HTTP-TPC interop, auth, ACLs, and hardening paths against nginx 1.28.3. Run `pytest -v` against the test nginx layout in [docs/building.md](docs/building.md) for a full pass/fail result.

For local test bring-up/teardown, use [`tests/manage_test_servers.sh`](tests/manage_test_servers.sh):

```bash
# start nginx test listener + reference xrootd (for conformance)
tests/manage_test_servers.sh start

# show status / stop both
tests/manage_test_servers.sh status
tests/manage_test_servers.sh stop
```

Running the cross-compatible native XRootD tests against both backends
----------------------------------------------------------------------

The portable native-protocol/API suite can be exercised against nginx-xrootd
and the official reference xrootd in one go:

```bash
tests/run_cross_compatible_tests.sh
```

That wrapper runs these modules twice, first with `TEST_CROSS_BACKEND=nginx`
and then with `TEST_CROSS_BACKEND=xrootd`:

- `tests/test_file_api.py`
- `tests/test_query.py`
- `tests/test_protocol_edge_cases.py`
- `tests/test_privilege_escalation.py`

Extra pytest arguments are passed through to both runs:

```bash
tests/run_cross_compatible_tests.sh -k read_only
```

If you want just one backend, set `TEST_CROSS_BACKEND` directly:

```bash
TEST_CROSS_BACKEND=xrootd pytest tests/test_protocol_edge_cases.py -v
```

On the reference-xrootd leg, checksum-query tests are skipped unless the
server is configured with checksum support.

Running tests against an external, preconfigured server
------------------------------------------------------

You can point the test-suite at an already-running nginx+plugin instance or
an official xrootd instance instead of having the test harness start local
processes. Set one or more of these environment variables before running
`pytest`:

- `TEST_NGINX_URL` — URL to the nginx WebDAV endpoint (e.g. `https://myhost:8443`).
- `TEST_REF_URL` — URL to a reference `root://` xrootd instance (e.g. `root://xrootd.example:1096`).
- `TEST_REF_GSI_URL` — URL to an xrootd instance configured with GSI (used by
    some GSI-specific fixtures).

When any of these are set, the corresponding fixtures will validate reachability
and then run tests against the provided server. This lets you run the full
test-suite against a production-like nginx+plugin or xrootd endpoint. Tests
will not `skip` simply because local binaries are missing if an appropriate
`TEST_*` variable is provided; instead they'll target the external server.

Example (run all tests against a single nginx+plugin instance):

```bash
export TEST_NGINX_URL=https://ci-nginx.example:8443
pytest -v
```

## License

[2-Clause BSD](https://opensource.org/licenses/BSD-2-Clause) — same as nginx.
