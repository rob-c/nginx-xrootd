# Metrics and logging

The module provides two ways to observe what is happening: a Prometheus metrics endpoint and a per-request access log.

---

## Prometheus metrics

### Setup

Add an `http {}` block to `nginx.conf` with the `xrootd_metrics` directive:

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

Then scrape it:

```bash
curl http://localhost:9100/metrics
```

Or configure your Prometheus scrape config:

```yaml
scrape_configs:
  - job_name: xrootd
    static_configs:
      - targets: ['localhost:9100']
```

Metrics are shared across all nginx worker processes via shared memory and updated atomically. They survive `nginx -s reload` (counters are preserved across config reloads).

Client-controlled strings are not used as Prometheus label values. Exported labels come from server configuration (`port`, `auth`) and the fixed operation table (`op`, `status`). The current `auth` metric label is `gsi` for GSI-only listeners and `anon` for all non-GSI-only listeners, including token and mixed listeners.

---

### Available metrics

#### `xrootd_connections_total`

Total TCP connections accepted since the nginx process started. Never decreases.

Labels: `port`, `auth`

```
xrootd_connections_total{port="1094",auth="anon"} 1042
xrootd_connections_total{port="1095",auth="gsi"} 17
```

#### `xrootd_connections_active`

Number of XRootD connections currently open. Goes up when a client connects, down when it disconnects.

Labels: `port`, `auth`

```
xrootd_connections_active{port="1094",auth="anon"} 4
xrootd_connections_active{port="1095",auth="gsi"} 1
```

#### `xrootd_bytes_rx_total`

Total bytes received from clients (i.e. uploaded data). Counts only file data payloads, not protocol overhead.

Labels: `port`, `auth`

```
xrootd_bytes_rx_total{port="1094",auth="anon"} 5368709120
```

#### `xrootd_bytes_tx_total`

Total bytes sent to clients (i.e. downloaded data). Counts only file data, not protocol overhead.

Labels: `port`, `auth`

```
xrootd_bytes_tx_total{port="1094",auth="anon"} 107374182400
```

#### `xrootd_requests_total`

Total XRootD requests completed, broken down by operation type and outcome.

Labels: `port`, `auth`, `op`, `status`

```
xrootd_requests_total{port="1094",auth="anon",op="login",status="ok"} 1042
xrootd_requests_total{port="1094",auth="anon",op="open_rd",status="ok"} 8314
xrootd_requests_total{port="1094",auth="anon",op="read",status="ok"} 41570
xrootd_requests_total{port="1094",auth="anon",op="close",status="ok"} 8314
xrootd_requests_total{port="1094",auth="anon",op="open_rd",status="error"} 12
```

Operations tracked (`op` label values): `login`, `auth`, `stat`, `open_rd`, `open_wr`, `read`, `write`, `sync`, `close`, `dirlist`, `mkdir`, `rmdir`, `rm`, `mv`, `chmod`, `truncate`, `ping`, `query_cksum`, `query_space`, `readv`

Error series (`status="error"`) are omitted from the output when the count is zero — this keeps the scrape output short when errors are rare.

---

### Full example output

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

---

### Limits

Up to 16 stream server blocks are tracked simultaneously. This is a compile-time limit (`XROOTD_METRICS_MAX_SERVERS` in `ngx_xrootd_metrics.h`).

---

## Access logging

### Enable

```nginx
xrootd_access_log /var/log/nginx/xrootd_access.log;
```

One line is written per XRootD operation. The file is opened `O_APPEND` and is safe for multiple nginx worker processes to write concurrently.

### Log format

```
<ip> <auth> "<identity>" [<timestamp>] "<verb> <path> <detail>" <status> <bytes> <ms>ms ["<errmsg>"]
```

Before any client-controlled text is written, the logger escapes whitespace, control bytes, quotes, backslashes, and non-ASCII bytes as `\xNN`. This keeps every record single-line and prevents log injection.

| Field | Meaning |
|---|---|
| `ip` | Client IP address |
| `auth` | `gsi` for GSI-only listeners; `anon` for anonymous, token, and mixed listeners in the current implementation |
| `identity` | X.509 subject DN for GSI-only connections; `-` for anonymous, token, mixed, or before authentication completes. Unsafe bytes are escaped as `\xNN`. |
| `timestamp` | `DD/Mon/YYYY:HH:MM:SS +ZZZZ` |
| `verb` | Operation name — see table below |
| `path` | Resolved filesystem path, or `-` for session-level operations. Unsafe bytes are escaped as `\xNN`. |
| `detail` | Extra context — depends on the verb. Unsafe bytes are escaped as `\xNN`. |
| `status` | `OK` or `ERR` |
| `bytes` | File data bytes transferred; `0` for non-data operations |
| `ms` | Server-side processing time in milliseconds |
| `errmsg` | Error description — only appears on `ERR` lines |

**Verbs and their detail fields:**

| Verb | What happened | Detail field |
|---|---|---|
| `LOGIN` | Client logged in | Username |
| `AUTH` | GSI certificate verified | `gsi` |
| `STAT` | `kXR_stat` request | `vfs` for filesystem-level stat, `-` otherwise |
| `OPEN` | File opened | `rd` for read-only, `wr` for write |
| `READ` | Data read from file | `offset+length` e.g. `0+4194304` |
| `WRITE` | Data written to file | `offset+length` e.g. `8388608+8388608` |
| `SYNC` | `fsync` called | `-` |
| `CLOSE` | File handle closed | Throughput e.g. `582.54MB/s`, or `interrupted` if connection dropped |
| `DIRLIST` | Directory listed | `stat` if per-entry stat requested, else `-` |
| `MKDIR` | Directory created | `-` |
| `RMDIR` | Directory removed | `-` |
| `RM` | File deleted | `-` |
| `MV` | File renamed | `-` |
| `CHMOD` | Permissions changed | `-` |
| `PING` | Liveness check | `-` |
| `QUERY` | Checksum, space, or config query | `cksum`, `space`, or query-specific detail |
| `READV` | Vector read | Segment count, e.g. `3_segs` |
| `DISCONNECT` | Connection closed | Session summary: `rx=N.NNMiB/s tx=N.NNMiB/s` |

### Example log lines

**Anonymous upload:**
```
127.0.0.1 anon "-" [14/Apr/2026:10:23:45 +0000] "LOGIN - alice" OK 0 0ms
127.0.0.1 anon "-" [14/Apr/2026:10:23:45 +0000] "OPEN /data/upload/file.root wr" OK 0 1ms
127.0.0.1 anon "-" [14/Apr/2026:10:23:45 +0000] "WRITE /data/upload/file.root 0+8388608" OK 8388608 0ms
127.0.0.1 anon "-" [14/Apr/2026:10:23:45 +0000] "WRITE /data/upload/file.root 8388608+8388608" OK 8388608 0ms
127.0.0.1 anon "-" [14/Apr/2026:10:23:46 +0000] "CLOSE /data/upload/file.root 718.20MB/s" OK 52428800 0ms
127.0.0.1 anon "-" [14/Apr/2026:10:23:46 +0000] "DISCONNECT - rx=689.85MB/s tx=0.00MB/s" OK 52428800 76ms
```

**GSI read with failed stat:**
```
192.168.1.1 gsi "-" [14/Apr/2026:10:23:44 +0000] "LOGIN - rcurrie" OK 0 0ms
192.168.1.1 gsi "/DC=test/CN=Test\x20User" [14/Apr/2026:10:23:44 +0000] "AUTH - gsi" OK 0 48ms
192.168.1.1 gsi "/DC=test/CN=Test\x20User" [14/Apr/2026:10:23:45 +0000] "STAT /missing.root -" ERR 0 0ms "No\x20such\x20file\x20or\x20directory"
192.168.1.1 gsi "/DC=test/CN=Test\x20User" [14/Apr/2026:10:23:45 +0000] "OPEN /store/mc/data.root rd" OK 0 2ms
192.168.1.1 gsi "/DC=test/CN=Test\x20User" [14/Apr/2026:10:23:45 +0000] "READ /store/mc/data.root 0+4194304" OK 4194304 18ms
192.168.1.1 gsi "/DC=test/CN=Test\x20User" [14/Apr/2026:10:23:46 +0000] "CLOSE /store/mc/data.root 234.56MB/s" OK 4194304 0ms
192.168.1.1 gsi "/DC=test/CN=Test\x20User" [14/Apr/2026:10:23:46 +0000] "DISCONNECT - rx=0.00MB/s\x20tx=234.56MB/s" OK 4194304 1ms
```

### Log rotation

```bash
# Rename the old log, then signal nginx to reopen
mv /var/log/nginx/xrootd_access.log /var/log/nginx/xrootd_access.log.1
kill -USR1 $(cat /run/nginx.pid)
```

nginx reopens all log files without dropping connections.
