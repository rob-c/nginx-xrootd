# nginx-xrootd

An nginx stream module that speaks the [XRootD](https://xrootd.slac.stanford.edu/) `root://` protocol, turning nginx into a standards-compliant XRootD data server with optional write support.

This allows existing nginx infrastructure — TLS termination, access controls, rate limiting, load balancing, logging, reverse proxying — to be layered in front of XRootD file access without running a separate `xrootd` daemon.

Inspired by [dCache's xrootd4j](https://github.com/dCache/xrootd4j) Java re-implementation of the same protocol. Tested against nginx 1.28.3 (current stable) and xrdcp / XRootD Python client v5.9.2.

---

## How it works

XRootD is a binary TCP protocol used throughout High Energy Physics for high-performance data access (CERN, SLAC, Fermilab). Clients connect to port 1094, perform a handshake and login, then issue requests to open, read, write, stat, and list files.

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
       │  POSIX open/read/write/stat/readdir
       ▼
  /data/store/mc/sample.root
```

The protocol state machine:

```
CONNECT → HANDSHAKE → kXR_protocol → kXR_login [→ kXR_auth (GSI)]
                                          │
                    ┌─────────────────────┤
                    │                     │
               kXR_stat              kXR_open (rd or wr)
               kXR_ping                  │
               kXR_dirlist          kXR_read  / kXR_pgwrite  (repeat)
               kXR_mkdir            kXR_write / kXR_sync
               kXR_rmdir            kXR_truncate
               kXR_rm               kXR_close
               kXR_mv
               kXR_chmod
               kXR_truncate
               kXR_endsess
```

---

## Supported operations

| Request | Notes |
|---|---|
| Initial handshake | 20-byte client hello / standard 8-byte server response (v5 format) |
| `kXR_protocol` | Capability negotiation; advertises `kXR_isServer` |
| `kXR_login` | Accept username; anonymous or GSI auth depending on config |
| `kXR_ping` | Liveness check |
| `kXR_stat` | Path-based and open-handle-based; returns inode, size, flags, mtime |
| `kXR_open` | Opens a file for reading or writing; returns a 4-byte opaque handle |
| `kXR_read` | Reads up to 4 MB per request; clients retry at the new offset for larger reads |
| `kXR_pgwrite` | v5 paged write with CRC32c checksums; used by xrdcp for all uploads |
| `kXR_write` | v3/v4 raw write; offset + data payload |
| `kXR_sync` | fsync an open write handle |
| `kXR_truncate` | Truncate by path or open handle |
| `kXR_mkdir` | Create directory; recursive creation via `kXR_mkdirpath`; parent auto-creation via `kXR_mkpath` on open |
| `kXR_rmdir` | Remove an empty directory |
| `kXR_rm` | Remove a file |
| `kXR_mv` | Rename or move a file or directory (`rename(2)` — same filesystem only) |
| `kXR_chmod` | Change permission bits (9-bit Unix mode from request header) |
| `kXR_close` | Closes an open handle; logs throughput |
| `kXR_dirlist` | Lists a directory; supports `kXR_dstat` for per-entry stat (see [Protocol notes](#17-kxr_dirlist-dstat-sentinel)) |
| `kXR_readv` | Scatter-gather vector read; up to 1024 segments per request across any mix of open handles |
| `kXR_query` | Server queries — see [Queries](#queries) below |
| `kXR_endsess` | Graceful session termination |

Up to 16 files may be open simultaneously per connection. `kXR_readv` and `kXR_query` are available to all authenticated clients regardless of the `xrootd_allow_write` setting. Write operations (`kXR_pgwrite`, `kXR_write`, `kXR_mkdir`, `kXR_rmdir`, `kXR_rm`, `kXR_mv`, `kXR_chmod`, `kXR_sync`, `kXR_truncate`) require `xrootd_allow_write on` (default: off).

---

## Queries

The `kXR_query` request is supported for the following query types:

### Checksum (`kXR_Qcksum` / `QueryCode.CHECKSUM`)

Returns the adler32 checksum of a file identified by path. The response is a null-terminated ASCII string:

```
adler32 1a2b3c4d\0
```

The 8-hex-digit value matches the standard adler32 (Ziv-Lempel, same as `zlib.adler32()`). Used by xrdcp's `--cksum` flag to verify transfer integrity.

**Example (Python):**
```python
from XRootD import client
from XRootD.client.flags import QueryCode

fs = client.FileSystem("root://myserver:1094")
status, resp = fs.query(QueryCode.CHECKSUM, "/store/mc/sample.root")
# resp → b"adler32 1a2b3c4d\x00"
```

**Example (xrdfs):**
```bash
xrdfs myserver:1094 query checksum /store/mc/sample.root
# adler32 1a2b3c4d
```

### Space (`kXR_Qspace` / `QueryCode.SPACE`)

Returns storage space statistics for the configured `xrootd_root` filesystem. The response is an `oss.*` key-value string (null-terminated), matching the format used by the XRootD OSS layer:

```
oss.cgroup=default&oss.space=1081101176832&oss.free=250821832704&oss.maxf=250821832704&oss.used=775286988800&oss.quota=-1\0
```

| Key | Value |
|---|---|
| `oss.cgroup` | Storage group name (`"default"`) |
| `oss.space` | Total filesystem bytes |
| `oss.free` | Bytes available to unprivileged processes (`f_bavail × f_frsize`) |
| `oss.maxf` | Largest contiguous free segment (approximated as `oss.free`) |
| `oss.used` | Bytes in use |
| `oss.quota` | Quota limit (`-1` = no quota configured) |

**Example (Python):**
```python
status, resp = fs.query(QueryCode.SPACE, "/")
# resp → b"oss.cgroup=default&oss.space=1081101176832&..."
```

**Example (xrdfs):**
```bash
xrdfs myserver:1094 spaceinfo /
```

### Configuration (`kXR_Qconfig`)

Returns values for the configuration keys listed in the request payload (newline-separated). Advertises `adler32` as the supported checksum algorithm:

```
chksum=adler32
readv=1
```

Unknown keys echo back as `key=0`.

---

## Vector Read (`kXR_readv`)

`kXR_readv` performs scatter-gather reads in a single round-trip: the client sends a list of *(file handle, offset, length)* segments and the server streams back each chunk in request order.

**Limits:** up to 1024 segments per request; individual segment length is bounded only by the normal 4 MB read cap. The server caps the total response at 256 MiB as a safety limit.

**Python XRootD client:**

```python
from XRootD import client
from XRootD.client.flags import OpenFlags

f = client.File()
f.open("root://localhost:11094//data/file.root", OpenFlags.READ)

# Read three non-contiguous byte ranges in one request
chunks = [(0, 100), (4096, 512), (1_048_576, 8192)]
status, result = f.vector_read(chunks)

for chunk in result:
    print(f"offset={chunk.offset} size={len(chunk.buffer)}")

f.close()
```

**xrdfs command line:**

```bash
xrdfs localhost:11094 readv /data/file.root 0:100 4096:512 1048576:8192
```

**Wire format summary:** request payload = N × 16-byte `readahead_list` (fhandle[4] + rlen[4] + offset[8], all big-endian). Response = same headers prepended to each segment's data, concatenated; segments larger than `XROOTD_READ_MAX` are split across `kXR_oksofar` / `kXR_ok` boundaries identical to `kXR_read`.

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

**Dependencies:** None beyond a standard C toolchain and the nginx source. No OpenSSL, PCRE, or zlib required for the module itself (nginx's own configure handles those). GSI authentication does require OpenSSL (already a dependency of most nginx builds).

---

## Configuration

### Directives

| Directive | Context | Default | Description |
|---|---|---|---|
| `xrootd on\|off` | `server` | `off` | Enable the XRootD protocol handler |
| `xrootd_root path` | `server` | `/` | Filesystem root for file access. All client paths are resolved relative to this directory; path traversal is rejected. |
| `xrootd_auth none\|gsi` | `server` | `none` | Authentication mode |
| `xrootd_allow_write on\|off` | `server` | `off` | Allow write operations (`kXR_pgwrite`, `kXR_write`, `kXR_mkdir`, `kXR_rmdir`, `kXR_rm`, `kXR_mv`, `kXR_chmod`, `kXR_sync`, `kXR_truncate`). Off by default so read-only deployments are safe without any extra configuration. |
| `xrootd_certificate path` | `server` | — | Server certificate PEM (GSI only) |
| `xrootd_certificate_key path` | `server` | — | Server private key PEM (GSI only) |
| `xrootd_trusted_ca path` | `server` | — | CA certificate (or bundle) PEM (GSI only) |
| `xrootd_access_log path\|off` | `server` | `off` | Per-request access log file |
| `xrootd_thread_pool name` | `server` | `default` | Thread pool for async file I/O — must match a `thread_pool` directive at the main config level |

### Async file I/O

When nginx is compiled with `--with-threads` (the default for distribution packages), `kXR_read`, `kXR_write`, `kXR_pgwrite`, and `kXR_readv` offload blocking `pread(2)` / `pwrite(2)` calls to a thread pool, keeping the nginx event loop non-blocking. This prevents a slow disk or network filesystem from stalling other connections served by the same worker process.

The state machine uses an `XRD_ST_AIO` state to represent a request in-flight to the thread pool. While a request is in-flight the module continues to accept incoming TCP data so the client's kernel send buffer does not fill up and stall the connection. When the thread completes, the completion handler posts a read event so the next request is processed without waiting for the next epoll wake-up.

**Enable async I/O** by adding a `thread_pool` directive at the top level and referencing it from each `server {}` block:

```nginx
# At the top level (outside stream {})
thread_pool xrootd_io threads=8 max_queue=65536;

stream {
    server {
        listen 1094;
        xrootd on;
        xrootd_root /data;
        xrootd_thread_pool xrootd_io;   # enable async I/O
    }
}
```

If `xrootd_thread_pool` is omitted nginx looks for a pool named `"default"`. If no matching pool is found the module falls back to synchronous I/O with a notice in the error log.

### Read-only example

```nginx
thread_pool default threads=4 max_queue=65536;

stream {
    server {
        listen 1094;
        xrootd on;
        xrootd_root /data/public;
        xrootd_access_log /var/log/nginx/xrootd_access.log;
        # xrootd_thread_pool default;  # optional: explicit, otherwise auto
    }
}
```

### Read-write (anonymous) example

```nginx
stream {
    server {
        listen 1094;
        xrootd on;
        xrootd_root /data/upload;
        xrootd_allow_write on;
        xrootd_access_log /var/log/nginx/xrootd_access.log;
    }
}
```

### Read-only GSI example

```nginx
stream {
    server {
        listen 1095;
        xrootd on;
        xrootd_auth gsi;
        xrootd_root /data/store;
        xrootd_certificate     /etc/grid-security/hostcert.pem;
        xrootd_certificate_key /etc/grid-security/hostkey.pem;
        xrootd_trusted_ca      /etc/grid-security/ca.pem;
        xrootd_access_log /var/log/nginx/xrootd_gsi_access.log;
    }
}
```

### Read-write GSI example

```nginx
stream {
    server {
        listen 1095;
        xrootd on;
        xrootd_auth gsi;
        xrootd_allow_write on;
        xrootd_root /data/store;
        xrootd_certificate     /etc/grid-security/hostcert.pem;
        xrootd_certificate_key /etc/grid-security/hostkey.pem;
        xrootd_trusted_ca      /etc/grid-security/ca.pem;
        xrootd_access_log /var/log/nginx/xrootd_gsi_access.log;
    }
}
```

---

## Prometheus Metrics

The module exposes Prometheus-format counters via a companion HTTP module. Add an `http {}` block to your nginx configuration and enable the `xrootd_metrics` directive in a `location`:

```nginx
http {
    server {
        listen 9100;
        location /metrics {
            xrootd_metrics on;
        }
    }
}
```

Scrape with any Prometheus-compatible tool:

```bash
curl http://localhost:9100/metrics
```

### Available metrics

| Metric | Type | Labels | Description |
|---|---|---|---|
| `xrootd_connections_total` | counter | `port`, `auth` | TCP connections accepted since process start |
| `xrootd_connections_active` | gauge | `port`, `auth` | Currently open XRootD connections |
| `xrootd_bytes_rx_total` | counter | `port`, `auth` | Bytes received from clients (write data) |
| `xrootd_bytes_tx_total` | counter | `port`, `auth` | Bytes sent to clients (read data) |
| `xrootd_requests_total` | counter | `port`, `auth`, `op`, `status` | Requests completed, broken down by operation and outcome |

**Labels:**

| Label | Values | Meaning |
|---|---|---|
| `port` | `"1094"`, `"1095"`, … | TCP listen port for the server block |
| `auth` | `"anon"`, `"gsi"` | Authentication mode configured for the server |
| `op` | see below | XRootD request type |
| `status` | `"ok"`, `"error"` | Whether the operation succeeded |

**`op` values for `xrootd_requests_total`:**

`login`, `auth`, `stat`, `open_rd`, `open_wr`, `read`, `write`, `sync`, `close`, `dirlist`, `mkdir`, `rmdir`, `rm`, `mv`, `chmod`, `truncate`, `ping`

Error series (`status="error"`) are omitted from the output when the counter is zero to keep scrape output compact.

### Example output

```
# HELP xrootd_connections_total Total TCP connections accepted since process start.
# TYPE xrootd_connections_total counter
xrootd_connections_total{port="1094",auth="anon"} 42
xrootd_connections_total{port="1095",auth="gsi"} 7
# HELP xrootd_connections_active Currently open XRootD connections.
# TYPE xrootd_connections_active gauge
xrootd_connections_active{port="1094",auth="anon"} 3
xrootd_connections_active{port="1095",auth="gsi"} 0
# HELP xrootd_bytes_rx_total Bytes received from clients (write payloads).
# TYPE xrootd_bytes_rx_total counter
xrootd_bytes_rx_total{port="1094",auth="anon"} 12582912
# HELP xrootd_bytes_tx_total Bytes sent to clients (read data).
# TYPE xrootd_bytes_tx_total counter
xrootd_bytes_tx_total{port="1094",auth="anon"} 4194304
# HELP xrootd_requests_total XRootD requests completed, by operation and status.
# TYPE xrootd_requests_total counter
xrootd_requests_total{port="1094",auth="anon",op="login",status="ok"} 42
xrootd_requests_total{port="1094",auth="anon",op="open_wr",status="ok"} 18
xrootd_requests_total{port="1094",auth="anon",op="write",status="ok"} 18
xrootd_requests_total{port="1094",auth="anon",op="close",status="ok"} 35
```

### Directive reference

| Directive | Context | Default | Description |
|---|---|---|---|
| `xrootd_metrics on\|off` | `location` | `off` | Serve Prometheus metrics at this location |

Up to 16 stream server blocks are tracked simultaneously (`XROOTD_METRICS_MAX_SERVERS`). Counters are shared across all nginx worker processes via a shared memory zone and are incremented atomically. Counter values are preserved across `nginx -s reload`.

---

## Access Logging

Every client-visible operation is written to a per-server access log — one line per request, with transfer summaries on CLOSE and DISCONNECT.

### Log format

```
<ip> <auth> "<identity>" [<timestamp>] "<verb> <path> <detail>" <status> <bytes> <ms>ms ["<errmsg>"]
```

| Field | Meaning |
|---|---|
| `ip` | Client IP address |
| `auth` | `anon` or `gsi` |
| `identity` | X.509 subject DN for GSI; `-` for anonymous or pre-auth |
| `timestamp` | `DD/Mon/YYYY:HH:MM:SS +ZZZZ` |
| `verb` | `LOGIN` `AUTH` `OPEN` `READ` `WRITE` `SYNC` `STAT` `DIRLIST` `CLOSE` `DISCONNECT` `PING` |
| `path` | Resolved filesystem path, or `-` |
| `detail` | Operation-specific context (see below) |
| `status` | `OK` or `ERR` |
| `bytes` | File data bytes transferred; `0` for non-data operations |
| `ms` | Server-side time in milliseconds |
| `errmsg` | Error description (only on `ERR` lines) |

**Detail field by operation:**

| Verb | Detail |
|---|---|
| `LOGIN` | Username |
| `AUTH` | Protocol name (`gsi`) |
| `OPEN` | Access mode (`rd` or `wr`) |
| `READ` | `offset+length` (e.g. `0+4194304`) |
| `WRITE` | `offset+length` (e.g. `0+8388608`) |
| `CLOSE` | Average throughput (e.g. `582.54MB/s`), or `interrupted` if connection dropped |
| `DISCONNECT` | `rx=N.NNMiB/s tx=N.NNMiB/s` session summary |
| `DIRLIST` | `stat` if per-entry stat requested, else `-` |
| `STAT` | `vfs` for filesystem stat, else `-` |
| `SYNC` / `PING` | `-` |

### Example log lines

**Anonymous upload:**
```
127.0.0.1 anon "-" [14/Apr/2026:10:23:45 +0000] "LOGIN - alice" OK 0 0ms
127.0.0.1 anon "-" [14/Apr/2026:10:23:45 +0000] "STAT /upload.root -" ERR 0 0ms "file not found"
127.0.0.1 anon "-" [14/Apr/2026:10:23:45 +0000] "OPEN /data/upload/upload.root wr" OK 0 1ms
127.0.0.1 anon "-" [14/Apr/2026:10:23:45 +0000] "WRITE /data/upload/upload.root 0+8388608" OK 8388608 0ms
127.0.0.1 anon "-" [14/Apr/2026:10:23:45 +0000] "WRITE /data/upload/upload.root 8388608+8388608" OK 8388608 0ms
127.0.0.1 anon "-" [14/Apr/2026:10:23:46 +0000] "CLOSE /data/upload/upload.root 718.20MB/s" OK 52428800 0ms
127.0.0.1 anon "-" [14/Apr/2026:10:23:46 +0000] "DISCONNECT - rx=0.00MB/s tx=689.85MB/s" OK 52428800 76ms
```

**GSI/x509 read:**
```
192.168.1.1 gsi "-" [14/Apr/2026:10:23:44 +0000] "LOGIN - rcurrie" OK 0 0ms
192.168.1.1 gsi "/DC=test/DC=xrootd/CN=Test User/CN=12345" [14/Apr/2026:10:23:44 +0000] "AUTH - gsi" OK 0 48ms
192.168.1.1 gsi "/DC=test/DC=xrootd/CN=Test User/CN=12345" [14/Apr/2026:10:23:45 +0000] "OPEN /store/mc/data.root rd" OK 0 2ms
192.168.1.1 gsi "/DC=test/DC=xrootd/CN=Test User/CN=12345" [14/Apr/2026:10:23:45 +0000] "READ /store/mc/data.root 0+4194304" OK 4194304 18ms
192.168.1.1 gsi "/DC=test/DC=xrootd/CN=Test User/CN=12345" [14/Apr/2026:10:23:46 +0000] "CLOSE /store/mc/data.root 234.56MB/s" OK 4194304 0ms
192.168.1.1 gsi "/DC=test/DC=xrootd/CN=Test User/CN=12345" [14/Apr/2026:10:23:46 +0000] "DISCONNECT - rx=0.00MB/s tx=234.56MB/s" OK 4194304 1ms
```

### Log rotation

```bash
mv /var/log/nginx/xrootd_access.log /var/log/nginx/xrootd_access.log.1
kill -USR1 $(cat /var/run/nginx.pid)   # nginx master reopens all log files
```

---

## Security

**Path traversal** is prevented by calling `realpath(3)` on every client-supplied path and verifying the result is rooted under `xrootd_root`. For write-mode opens where the target file may not yet exist, the parent directory is verified instead. Symlinks that escape the root are rejected.

**Authentication** is supported in two modes — anonymous (any username accepted) and GSI/x509 proxy certificates (see below).

**Write access** is disabled by default. Set `xrootd_allow_write on` explicitly in server blocks that should accept uploads. Server blocks without this directive return `kXR_fsReadOnly` for any write request.

**TLS** is not handled at the XRootD protocol level (no `kXR_tlsLogin` / `kXR_haveTLS` negotiation). For encrypted transport, terminate TLS externally with `ssl_preread` or a separate stunnel/nginx SSL stream block in front.

---

## GSI / x509 Authentication

GSI (Grid Security Infrastructure) is the dominant authentication mechanism in High Energy Physics computing grids (CERN, SLAC, Fermilab). It is based on RFC 3820 proxy certificates and a Diffie-Hellman key exchange.

### Configuration

```nginx
stream {
    server {
        listen 1095;
        xrootd on;
        xrootd_auth gsi;
        xrootd_root /data/store;
        xrootd_certificate     /etc/grid-security/hostcert.pem;
        xrootd_certificate_key /etc/grid-security/hostkey.pem;
        xrootd_trusted_ca      /etc/grid-security/ca.pem;
    }
}
```

### Authentication flow

```
Client                                    Server
──────                                    ──────
kXR_protocol (secreqs=1)       ────────>
                                <──────── kXR_ok + SecurityInfo
                                          (secopt=force, "gsi " protocol)
kXR_login                      ────────>
                                <──────── kXR_ok + sessid
                                          + "&P=gsi,v:10000,c:ssl,ca:<hash>"

kXR_auth [kXGC_certreq=1000]   ────────>   ← "please send your cert"
  { kXRS_main{ kXRS_rtag } }
                                <──────── kXR_authmore [kXGS_cert=2001]
                                          { kXRS_puk (DH blob),
                                            kXRS_cipher_alg,
                                            kXRS_md_alg,
                                            kXRS_x509 (host cert PEM),
                                            kXRS_main{ kXRS_signed_rtag } }

kXR_auth [kXGC_cert=1001]      ────────>   ← "here is my proxy cert"
  { kXRS_puk (client DH blob),
    kXRS_cipher_alg, kXRS_md_alg,
    kXRS_main=AES( proxy_chain_PEM ) }
                                <──────── kXR_ok  ← auth complete
```

### Wire format: XrdSutBuffer

All GSI payloads are serialised as **XrdSutBuffer**:

```
[protocol_name\0]    null-terminated ("gsi\0")
[step : uint32 BE]   e.g. kXGC_certreq=1000, kXGS_cert=2001
[type : uint32 BE]   bucket type
[len  : uint32 BE]   data length
[data : len bytes]
... (repeat buckets) ...
[kXRS_none : uint32 BE]   terminator (type=0)
```

Key bucket types:

| Constant | Value | Meaning |
|---|---|---|
| `kXRS_none` | 0 | Terminator |
| `kXRS_main` | 2 | Inner payload (may be AES-encrypted) |
| `kXRS_puk` | 4 | DH public key blob |
| `kXRS_x509` | 22 | PEM certificate chain |
| `kXRS_cipher_alg` | 27 | Cipher name list (colon-separated) |
| `kXRS_md_alg` | 28 | Hash name list |
| `kXRS_rtag` | 33 | Client random challenge nonce |
| `kXRS_signed_rtag` | 34 | Server signature of client's rtag |

### DH session key derivation

```
shared_secret = EVP_PKEY_derive(server_dh_private, client_dh_public)
                  with EVP_PKEY_CTX_set_dh_pad(0)   ← no padding
session_key   = first N bytes of shared_secret
                  where N = EVP_CIPHER_key_length(chosen_cipher)
IV            = all zeros   (old protocol, HasPad=false)
```

---

## Protocol implementation notes

These are non-obvious issues discovered by reverse-engineering the XRootD C++ source. None are documented in the protocol specification.

---

### 1. XRootD v5 handshake uses standard 8-byte response header

v5 clients send the 20-byte handshake and `kXR_protocol` as a single 44-byte TCP segment, then expect each server reply as a standard `ServerResponseHdr` (8 bytes: `streamid[2] + status[2] + dlen[4]`) followed by the body.

The old 12-byte `ServerInitHandShake` framing (`msglen[4] + protover[4] + msgval[4]`) parses as `status=0x0008 / dlen=1312` — the client stalls waiting for 1312 bytes that never arrive.

**Fix:** respond to the handshake with `ServerResponseHdr{streamid={0,0}, status=kXR_ok, dlen=8}` followed by 8 bytes of `protover + msgval`.

---

### 2. `kXR_protocol` SecurityInfo required when `kXR_secreqs` is set

When the client's `kXR_protocol` request has `kXR_secreqs=0x01` set, the server's response body must include a 4-byte `SecurityInfo` header after `pval + flags`, followed by an 8-byte entry per supported authentication protocol. Without it, the client disconnects silently after the protocol exchange.

---

### 3. GSI login challenge must be `&P=` text, not binary XrdSutBuffer

The `kXR_login` response for GSI must append a plain-text challenge:
```
kXR_ok + sessid[16] + "&P=gsi,v:10000,c:ssl,ca:ABCD1234\0"
```
`ClientDoInit()` calls `GetOptions()` which only parses the `&P=key:val` text format. Sending a binary `XrdSutBuffer` causes the client to print *"No protocols left to try"* and disconnect.

---

### 4. `kXRS_puk` carries a DH blob, not an RSA PEM

The `kXRS_puk` bucket carries a DH public key in this custom text format:
```
<DH PARAMETERS PEM>---BPUB---<hex BIGNUM>---EPUB--
```
`---EPUB--` is 9 characters (not 10). Sending an RSA public key PEM causes *"could not instantiate session cipher"*.

---

### 5. DH derivation requires `EVP_PKEY_CTX_set_dh_pad(0)`

The old GSI protocol (v:10000) uses `HasPad=false`. OpenSSL's default DH derivation pads the shared secret with leading zeros to match the DH prime length; the XRootD client does not. Omitting the `set_dh_pad(0)` call produces the wrong session key and silently decrypts to garbage.

---

### 6. Server DH key must survive across two `kXR_auth` messages

The server's ephemeral DH private key is generated in the `kXGC_certreq` handler and must still be available when `kXGC_cert` derives the shared secret. The module stores it in `ctx->gsi_dh_key`.

---

### 7. Stat response field order: `id size flags mtime`

The `kXR_stat` wire format is `"<id> <size> <flags> <mtime>\0"` — **size comes before flags**. Swapping them causes the client to interpret `kXR_readable` (16) or `kXR_isDir` (2) as the file size.

The `kXR_open` retstat body uses the same order. Both match `XrdClXRootDResponses.cc` `ParseServerResponse()`: `chunks[0]=id, chunks[1]=size, chunks[2]=flags, chunks[3]=mtime`.

---

### 8. Proxy cert verification requires `X509_V_FLAG_ALLOW_PROXY_CERTS`

RFC 3820 proxy certificates are rejected by default in OpenSSL's `X509_verify_cert()`. The flag must be set on **both** the `X509_STORE` (at config time) and the `X509_STORE_CTX` (at verification time).

---

### 9. CGI parameters must be stripped from write-mode paths

xrdcp appends metadata as URL query parameters: `?oss.asize=N&xrdcl.requuid=...`. These must be stripped (truncate at the first `?`) before any filesystem operations. Passing `?oss.asize=29` to `open(2)` fails with `ENOENT`.

---

### 10. `kXR_pgwrite` requires a `kXR_status` response, not `kXR_ok`

xrdcp v5 uses `kXR_pgwrite` for all uploads. The client parses the response as `ServerResponseV2` — a 32-byte struct starting with a 24-byte `ServerResponseStatus`. Sending a plain 8-byte `kXR_ok` causes the client to read past the buffer and crash.

**Wire format for pgwrite success (32 bytes total):**

```
ServerResponseHdr (8B):
  streamid[2]   ← echo from request
  status        ← kXR_status (4007), NOT kXR_ok
  dlen          ← 24 (sizeof Status body + sizeof pgWrite body)

ServerResponseBody_Status (16B):
  crc32c[4]     ← CRC32c of bytes 12..31 (everything after this field)
  streamID[2]   ← echo from request
  requestid[1]  ← kXR_pgwrite - kXR_1stRequest  (= 26)
  resptype[1]   ← 0 (kXR_FinalResult)
  reserved[4]   ← zeros
  dlen[4]       ← 0 (no bad pages), big-endian

ServerResponseBody_pgWrite (8B):
  offset[8]     ← last written file offset, big-endian
```

CRC32c uses the Castagnoli polynomial (0x82F63B78, reflected). Initial value `0xFFFFFFFF`, final XOR `0xFFFFFFFF`. Test vector: `CRC32c("123456789") == 0xE3069283`.

---

### 11. `kXR_pgwrite` payload layout: CRC-first per page

xrdcp sends pgwrite payload as interleaved `[4-byte CRC32c][page data]` units per 4096-byte page — **CRC comes first**, not last. For a 41-byte file the payload is `[4 bytes CRC32c][41 bytes data]` = 45 bytes total. Consuming data bytes before skipping the CRC produces a file with 4 garbage bytes prepended.

---

### 12. Write payload size limit must be separate from path size limit

The module caps general payloads at `XROOTD_MAX_PATH + 64` (~4 KB) to prevent over-allocation for paths, auth tokens, and other small metadata. xrdcp uses 8 MB write chunks (default), so `kXR_pgwrite`/`kXR_write`/`kXR_writev` need a separate limit (`XROOTD_MAX_WRITE_PAYLOAD = 16 MB`). Without this, the connection drops silently immediately after OPEN for any file larger than ~4 KB.

---

### 13. `kXR_mv` payload uses a space separator, not a null

The `ClientMvRequest.arg1len` field encodes the **byte length of the source path, not including any terminator**. The payload is:

```
src[arg1len] + ' ' (0x20) + dst[...]
```

The separator between source and destination is a single ASCII space — not a null byte. `arg1len` is the source string length without any trailing zero. This is visible in `XrdClFileSystem.cc`:

```cpp
req->arg1len = fSource.length();              // no +1
*msg->GetBuffer(24 + fSource.length()) = ' '; // space separator
```

Parsing the source as null-terminated at `src[arg1len - 1]` fails for every path.

---

### 14. `kXR_new` requires `O_EXCL` only when `kXR_delete` is not also set

`kXR_new` means "create the file; fail if it already exists" — equivalent to `O_CREAT|O_EXCL`. However, xrdcp routinely sends `kXR_new|kXR_delete` together to mean "create or overwrite", which maps to `O_CREAT|O_TRUNC` (no `O_EXCL`). The correct mapping is:

| Flags | OS flags |
|---|---|
| `kXR_new` only | `O_CREAT \| O_EXCL` |
| `kXR_new \| kXR_delete` | `O_CREAT \| O_TRUNC` |
| `kXR_delete` only | `O_CREAT \| O_TRUNC` |

Omitting `O_EXCL` for `kXR_new` alone silently opens and truncates existing files instead of returning an error.

---

### 15. `kXR_mkdir` with `kXR_mkdirpath`: resolve path without requiring parent to exist

The write-path resolver (`xrootd_resolve_path_write`) calls `realpath(3)` on the parent directory to canonicalize it. For a recursive `mkdir -p a/b/c`, neither `a` nor `a/b` exists yet, so `realpath` fails and the request is rejected before any directory is created.

**Fix:** When `kXR_mkdirpath` is set (or `kXR_mkpath` on open), use a separate resolver (`xrootd_resolve_path_noexist`) that validates the path by scanning for `..` components rather than calling `realpath`. The root directory itself is always trusted (set via nginx config); any relative path with no `..` segment is safe.

---

### 16. Opening a directory path returns a valid fd on Linux

`open(dir_path, O_RDONLY)` succeeds on Linux and returns a directory file descriptor. The XRootD spec requires `kXR_open` to fail with `kXR_isDirectory` when the client tries to open a directory as a file. Without an explicit `stat()` check after path resolution, the module hands back a directory fd and subsequent `read(2)` calls return `EISDIR`.

**Fix:** After resolving a read-mode open path, `stat(2)` the result and return `kXR_isDirectory` if `S_ISDIR(st.st_mode)`.

---

### 17. `kXR_dirlist` dStat sentinel: `".\n0 0 0 0\n"`

When the client requests per-entry stat (`kXR_dstat` option flag), the response body **must** begin with the 10-byte lead-in string `".\n0 0 0 0\n"`. Without it the XRootD client library (`DirectoryList::HasStatInfo`) does not enter stat-pairing mode and instead treats every newline-delimited line as a separate filename — causing stat info strings to appear as extra directory entries.

The client checks for the 9-byte prefix `".\n0 0 0 0"` at position 0 of the response body. If found it skips those 9 bytes, then pairs up the remaining newline-delimited tokens as (filename, stat-string) alternating. The 10th byte of the lead-in (`\n`) is harmlessly consumed as an empty token because the client's string-splitter skips zero-length fields.

**Wire format (kXR_dstat):**
```
".\n0 0 0 0\n"                 ← 10-byte lead-in
"<name1>\n<id1> <sz1> <fl1> <mt1>\n"   ← entry + stat pair
"<name2>\n<id2> <sz2> <fl2> <mt2>\n"   ← entry + stat pair
...
```
The last `\n` is replaced by `\0` (NUL terminator) rather than appending `\0` after it. The client parses the body as a C string, so interior entries must not contain NUL bytes.

**Stat field order is `id size flags mtime`** (size before flags) — the same order used by `kXR_stat` and `kXR_open` retstat.

---

### 18. State machine: `XRD_ST_SENDING` guard in the write handler

A subtle concurrency hazard exists between the nginx write event handler and the AIO completion path. When `xrootd_queue_response_base` finds the send buffer full (`EAGAIN`) it stores the remaining data in `ctx->wbuf`, transitions to `XRD_ST_SENDING`, and arms the write event. The write handler is later called to drain `ctx->wbuf`.

Between arming the write event and the write handler firing, the AIO completion (`xrootd_read_aio_done` / `xrootd_write_aio_done`) may fire first via `ngx_post_event`, advance the state machine to `XRD_ST_AIO`, `XRD_ST_REQ_PAYLOAD`, or `XRD_ST_REQ_HEADER`, and dispatch a new request. If the write handler then unconditionally resets state to `XRD_ST_REQ_HEADER` and calls `ngx_stream_xrootd_recv`, a second concurrent AIO is dispatched. When both complete, the second overwrites `ctx->wbuf` before the first's bytes are sent, silently discarding part of a response and corrupting the TCP stream.

**Fix:** `ngx_stream_xrootd_send` checks `ctx->state` after flushing. If state is no longer `XRD_ST_SENDING`, the state machine has already advanced via the read-event path and the write handler returns immediately without calling `ngx_stream_xrootd_recv`.

---

## Protocol reference

The implementation was derived from three authoritative sources checked against each other:

- **[XRootD Protocol Specification v5.2.0](https://xrootd.web.cern.ch/doc/dev56/XRdv520.htm)** — official spec
- **[xrootd/xrootd](https://github.com/xrootd/xrootd)** `src/XProtocol/XProtocol.hh` — canonical C++ header with all wire constants
- **[dcache/xrootd4j](https://github.com/dCache/xrootd4j)** — dCache's Java re-implementation (useful cross-reference for message framing)

All multi-byte integers on the wire are big-endian. The packed structs in `src/xrootd_protocol.h` mirror `XProtocol.hh` exactly and are safe to cast directly against a receive buffer.

---

## Roadmap

Items deferred from this implementation, roughly in priority order:

- **SciToken / WLCG Bearer Token authentication** — complement GSI with token-based auth via `kXR_auth` / `kXR_authmore`
- **TLS** — negotiate `kXR_haveTLS` / `kXR_gotoTLS` so clients can use `roots://`
- **Streaming write I/O** — replace full-payload buffering in pgwrite with streaming pwrite() to avoid 8 MB per-connection allocation for large uploads
- **`kXR_locate`** — redirect clients to the optimal replica
- **RHEL 9 packaging** — RPM spec and `modulemd` for deployment via standard OS channels

---

## Repository layout

```
nginx-xrootd/
├── config                                   # nginx build system integration (stream + HTTP modules)
├── src/
│   ├── xrootd_protocol.h                    # XRootD wire constants and packed structs
│   ├── ngx_xrootd_metrics.h                 # shared counter structs and op index constants
│   ├── ngx_stream_xrootd_module.c           # nginx stream module (XRootD protocol handler)
│   └── ngx_http_xrootd_metrics_module.c     # nginx HTTP module (Prometheus /metrics endpoint)
└── tests/
    ├── test_xrootd.py             # functional tests (stat, read, dirlist, GSI auth)
    ├── test_write.py              # upload tests (pgwrite, integrity, GSI write)
    ├── test_fs_ops.py             # filesystem ops (mkdir, rmdir, rm, mv, chmod; anon + GSI)
    ├── test_file_api.py           # comprehensive File/FileSystem API tests (71 tests)
    ├── test_metrics.py            # Prometheus metrics endpoint tests (14 tests)
    ├── test_query.py              # kXR_query tests — checksum and space (14 tests)
    ├── test_conformance.py        # protocol conformance: nginx vs reference xrootd (30 tests)
    ├── test_throughput.py         # throughput benchmarks (anon vs GSI)
    └── test_concurrent.py         # concurrent transfer tests (n=1..8, anon + GSI)
```

Run all functional tests (201 tests, ~2 min):

```bash
pytest tests/ --ignore=tests/test_throughput.py -v
```

The conformance suite (`test_conformance.py`) starts a reference xrootd server on port 11096 pointing at the same data directory, then compares nginx responses against it for ping, stat, read, dirlist, checksum, write round-trip, open, and path-security operations.

---

## License

Same as nginx: [2-Clause BSD](https://opensource.org/licenses/BSD-2-Clause).
