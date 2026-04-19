# nginx-xrootd

An nginx module that serves files over both the native [XRootD](https://xrootd.slac.stanford.edu/) `root://` protocol and WebDAV over HTTPS — the two transfer paths used by `xrdcp`, `xrdfs`, and the Python XRootD client across High Energy Physics (CERN, SLAC, Fermilab).

Instead of running a separate `xrootd` daemon, you add this module to your existing nginx and get XRootD plus everything nginx already provides: TLS, access controls, rate limiting, load balancing, Prometheus metrics, and shared GSI/JWT authentication plumbing.

> **New to XRootD?** See [docs/background.md](docs/background.md).

---

## Performance

1 GiB reads, localhost, nginx 1.28.3 + module vs xrootd v5.9.2, all transfers GSI/x509 authenticated ([how to reproduce](docs/benchmarks.md)):

| Protocol | Connections | nginx-xrootd | xrootd native | nginx p95 | xrootd p95 |
|---|---:|---:|---:|---:|---:|
| `root://` + GSI | 1 | 630 MiB/s | 1,060 MiB/s | 1.6 s | 1.0 s |
| `root://` + GSI | 8 | 5,885 MiB/s | 3,013 MiB/s | 1.4 s | 2.7 s |
| `root://` + GSI | 32 | 9,376 MiB/s | 2,842 MiB/s | 3.4 s | 11.4 s |
| `root://` + GSI | 128 | **10,402 MiB/s** | 2,272 MiB/s | **12.1 s** | 57.2 s |
| `davs://` + x509 | 1 | 935 MiB/s | 1,415 MiB/s | 1.1 s | 0.7 s |
| `davs://` + x509 | 8 | 3,288 MiB/s | 3,631 MiB/s | 2.5 s | 2.2 s |
| `davs://` + x509 | 32 | 3,445 MiB/s | 3,725 MiB/s | 8.9 s | 8.7 s |
| `davs://` + x509 | 128 | **3,697 MiB/s** | 2,268 MiB/s | **33.3 s** | 56.9 s |

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

- **XRootD operations:** `stat`, `open`, `read`, `readv`, `close`, `mkdir`, `rm`, `rmdir`, `mv`, `chmod`, `truncate`, checksum and space queries
- **WebDAV operations:** OPTIONS, GET (with Range), HEAD, PUT, DELETE, MKCOL, PROPFIND, and opt-in HTTP-TPC COPY pull support for `https://` sources
- **Authentication:** anonymous access, GSI/x509 proxy certificates, and WLCG/JWT bearer tokens
- **Async I/O:** nginx thread-pool support so disk operations never block the event loop
- **Observability:** per-request access logs and Prometheus metrics

---

## Documentation

| | |
|---|---|
| [Getting started](docs/getting-started.md) | Build, install, first working server |
| [Benchmarks](docs/benchmarks.md) | How to reproduce the performance numbers above |
| [Building from scratch](docs/building.md) | Detailed build guide with all dependencies |
| [Configuration reference](docs/configuration.md) | All directives |
| [WebDAV / HTTPS+GSI/Bearer](docs/webdav.md) | WebDAV setup, x509 proxy, and bearer-token compatibility |
| [Authentication](docs/authentication.md) | Anonymous, GSI/x509, and WLCG/JWT setup |
| [Test PKI & VOMS](docs/test-pki.md) | Generate test CA, certs, proxies, and VOMS infrastructure |
| [Test tokens](docs/test-tokens.md) | Generate local WLCG/JWT signing keys and bearer tokens |
| [Operations](docs/operations.md) | Supported XRootD operations |
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

## License

[2-Clause BSD](https://opensource.org/licenses/BSD-2-Clause) — same as nginx.
