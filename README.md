# nginx-xrootd

An nginx stream module that speaks the [XRootD](https://xrootd.slac.stanford.edu/) `root://` protocol, turning nginx into a standards-compliant read-only XRootD data server.

This allows existing nginx infrastructure — TLS termination, access controls, rate limiting, load balancing, logging, reverse proxying — to be layered in front of XRootD file access without running a separate `xrootd` daemon.

Inspired by [dCache's xrootd4j](https://github.com/dCache/xrootd4j) Java re-implementation of the same protocol. Tested against nginx 1.28.3 (current stable).

---

## How it works

XRootD is a binary TCP protocol used throughout High Energy Physics for high-performance data access (CERN, SLAC, Fermilab). Clients connect to port 1094, perform a handshake and login, then issue requests to open, read, stat, and list files.

This module plugs into nginx's `stream {}` subsystem (layer-4 TCP handling) and drives the full XRootD state machine directly on the accepted connection, acting as a `kXR_DataServer`.

```
XRootD client (xrdcp, ROOT, etc.)
        │
        │  root://nginx-host//store/mc/sample.root
        │  TCP port 1094
        ▼
┌──────────────┐
│    nginx     │  stream { xrootd on; xrootd_root /data; }
│ (this module)│
└──────┬───────┘
       │  POSIX open/read/stat/readdir
       ▼
  /data/store/mc/sample.root
```

The protocol state machine:

```
CONNECT → HANDSHAKE → kXR_protocol → kXR_login
                                          │
                    ┌─────────────────────┤
                    │                     │
               kXR_stat              kXR_open
               kXR_ping                  │
               kXR_dirlist          kXR_read  (repeat)
               kXR_endsess          kXR_close
```

---

## Supported operations

| Request | Notes |
|---|---|
| Initial handshake | 20-byte client hello / 12-byte server response |
| `kXR_protocol` | Capability negotiation; advertises `kXR_isServer` |
| `kXR_login` | Anonymous login; any username accepted |
| `kXR_ping` | Liveness check |
| `kXR_stat` | Path-based and open-handle-based; returns inode, flags, size, mtime |
| `kXR_open` | Opens a file for reading; returns a 4-byte opaque handle |
| `kXR_read` | Reads up to 4 MB per request; clients retry at the new offset for larger reads |
| `kXR_close` | Closes an open handle |
| `kXR_dirlist` | Lists a directory; supports `kXR_dstat` for per-entry stat |
| `kXR_endsess` | Graceful session termination |
| Write ops | `kXR_write`, `kXR_mkdir`, `kXR_rm`, etc. return `kXR_fsReadOnly` |

Up to 16 files may be open simultaneously per connection.

---

## Building

nginx must be configured with `--with-stream`. The module is compiled in statically — no dynamic loading required.

**Quick start (building nginx from source):**

```bash
# Download nginx stable
curl -O https://nginx.org/download/nginx-1.28.3.tar.gz
tar xzf nginx-1.28.3.tar.gz

# Configure with this module
cd nginx-1.28.3
./configure --with-stream --add-module=/path/to/nginx-xrootd

# Build
make -j$(nproc)
sudo make install
```

**Adding to an existing nginx build tree:**

```bash
./configure [your existing flags] \
    --with-stream \
    --add-module=/path/to/nginx-xrootd
make -j$(nproc)
```

**Dependencies:** None beyond a standard C toolchain and the nginx source. No OpenSSL, PCRE, or zlib required for the module itself (nginx's own configure handles those).

---

## Configuration

```nginx
stream {
    server {
        listen 1094;          # standard XRootD port

        xrootd on;
        xrootd_root /data;    # files are served from under this path
    }
}
```

### Directives

| Directive | Context | Default | Description |
|---|---|---|---|
| `xrootd on\|off` | `server` | `off` | Enable the XRootD protocol handler |
| `xrootd_root path` | `server` | `/` | Filesystem root for file access. Paths arriving from clients are resolved relative to this directory. Path traversal attempts (`../../etc/passwd`) are rejected. |

### Multiple servers

nginx's stream module supports multiple listeners, so you can serve different directory trees on different ports, or combine XRootD with TLS:

```nginx
stream {
    # Plain XRootD on the standard port
    server {
        listen 1094;
        xrootd on;
        xrootd_root /data/public;
    }

    # A second tree on a non-standard port
    server {
        listen 11094;
        xrootd on;
        xrootd_root /data/scratch;
    }
}
```

---

## Security

**Path traversal** is prevented by calling `realpath(3)` on every client-supplied path and verifying the result is rooted under `xrootd_root`. Symlinks that escape the root are rejected.

**Authentication** is not implemented in this initial release — any username is accepted. This is appropriate for:
- Internal networks where network-level access control is enforced elsewhere
- nginx `allow`/`deny` directives in the `stream` block applied before the XRootD handler runs

**Write access** is permanently disabled. Any write-class request (`kXR_write`, `kXR_mkdir`, `kXR_rm`, `kXR_mv`, `kXR_chmod`, `kXR_truncate`, etc.) returns a `kXR_fsReadOnly` error.

**TLS** is not yet handled at the XRootD protocol level (the module does not negotiate `kXR_tlsLogin` / `kXR_haveTLS`). For encrypted transport, terminate TLS externally with `ssl_preread` or a separate stunnel/nginx SSL stream block in front.

---

## Protocol reference

The implementation was derived from three authoritative sources checked against each other:

- **[XRootD Protocol Specification v5.2.0](https://xrootd.web.cern.ch/doc/dev56/XRdv520.htm)** — official spec
- **[xrootd/xrootd](https://github.com/xrootd/xrootd)** `src/XProtocol/XProtocol.hh` — canonical C++ header with all wire constants
- **[dcache/xrootd4j](https://github.com/dCache/xrootd4j)** — dCache's Java re-implementation (useful cross-reference for message framing)

All multi-byte integers on the wire are big-endian. The packed structs in `src/xrootd_protocol.h` mirror `XProtocol.hh` exactly and are safe to cast directly against a receive buffer.

---

## Roadmap

Items deferred from this initial implementation, roughly in priority order:

- **GSI / token authentication** — plug into XRootD's `kXR_auth` / `kXR_authmore` handshake; support SciTokens and WLCG Bearer Tokens
- **TLS** — negotiate `kXR_haveTLS` / `kXR_gotoTLS` so clients can use `roots://`
- **`kXR_readv`** — vectored read (scatter-gather); important for ROOT file I/O patterns which issue many small reads at known offsets
- **Async file I/O** — replace synchronous `read(2)` with nginx's native async file I/O (`ngx_file_aio`) to avoid blocking worker processes on slow storage
- **`kXR_query`** — respond to checksum and space-usage queries
- **`kXR_locate`** — redirect clients to the optimal replica
- **RHEL 9 packaging** — RPM spec and `modulemd` for deployment via standard OS channels
- **Prometheus metrics** — expose per-server byte counters and open-file gauges via nginx's `ngx_http_stub_status`-style endpoint

---

## Repository layout

```
nginx-xrootd/
├── config                         # nginx build system integration
└── src/
    ├── xrootd_protocol.h          # XRootD wire constants and packed structs
    └── ngx_stream_xrootd_module.c # nginx stream module implementation
```

---

## License

Same as nginx: [2-Clause BSD](https://opensource.org/licenses/BSD-2-Clause).
