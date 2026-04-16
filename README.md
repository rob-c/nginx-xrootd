# nginx-xrootd

An nginx module that serves files over both the native [XRootD](https://xrootd.slac.stanford.edu/) `root://` protocol and WebDAV over HTTPS — the two transfer paths used by `xrdcp`, `xrdfs`, and the Python XRootD client across High Energy Physics (CERN, SLAC, Fermilab).

Instead of running a separate `xrootd` daemon, you add this module to your existing nginx and get XRootD plus everything nginx already provides: TLS, access controls, rate limiting, load balancing, Prometheus metrics.

> **New to XRootD?** See [docs/background.md](docs/background.md).

---

## Protocols

| Protocol | Port | Use |
|---|---|---|
| XRootD `root://` (stream) | 1094 / 1095 | `xrdcp`, `xrdfs`, Python client |
| WebDAV over HTTPS (`davs://`) | 8443 | `xrdcp --allow-http`, HTTP clients |

Both protocols support anonymous and GSI/x509 proxy-certificate authentication.

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
- **WebDAV operations:** OPTIONS, GET (with Range), HEAD, PUT, DELETE, MKCOL, PROPFIND — the full set required by `xrdcp` via `davs://`
- **Authentication:** anonymous or GSI/x509 proxy certificates on both protocols
- **Async I/O:** nginx thread-pool support so disk operations never block the event loop
- **Observability:** per-request access logs and Prometheus metrics

---

## Documentation

| | |
|---|---|
| [Getting started](docs/getting-started.md) | Build, install, first working server |
| [Configuration reference](docs/configuration.md) | All directives |
| [WebDAV / HTTPS+GSI](docs/webdav.md) | WebDAV setup and xrdcp compatibility |
| [Authentication](docs/authentication.md) | Anonymous and GSI/x509 setup |
| [Operations](docs/operations.md) | Supported XRootD operations |
| [Metrics & logging](docs/metrics-and-logging.md) | Prometheus metrics, access log format |
| [Development](docs/development.md) | Source layout, workflow, known quirks |
| [Background](docs/background.md) | What XRootD is and why this module exists |
| [Protocol notes](docs/protocol-notes.md) | Wire-protocol details for developers |

---

## Status

302 tests pass against xrdcp / XRootD Python client v5.9.2 and nginx 1.28.3.

## License

[2-Clause BSD](https://opensource.org/licenses/BSD-2-Clause) — same as nginx.
