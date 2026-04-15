# nginx-xrootd

An nginx module that makes nginx speak the [XRootD](https://xrootd.slac.stanford.edu/) `root://` protocol — the standard file transfer protocol used across High Energy Physics (CERN, SLAC, Fermilab).

Instead of running a separate `xrootd` daemon, you add this module to your existing nginx. You get XRootD file access plus everything nginx already gives you: TLS, access controls, rate limiting, load balancing, Prometheus metrics.

> **Not familiar with XRootD?** See [docs/background.md](docs/background.md) for a plain-English introduction.

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

## Status

201 tests pass against xrdcp / XRootD Python client v5.9.2 and nginx 1.28.3. Anonymous and GSI/x509 authentication both work for reads and writes.

## License

[2-Clause BSD](https://opensource.org/licenses/BSD-2-Clause) — same as nginx.
