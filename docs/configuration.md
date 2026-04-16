# Configuration reference

All `xrootd_*` directives go inside a `server {}` block in the `stream {}` section of `nginx.conf`. Each `server {}` block is a separate XRootD endpoint and can have its own settings.

---

## Directives

### `xrootd on|off`

**Required.** Enables the XRootD protocol handler for this server block.

```nginx
stream {
    server {
        listen 1094;
        xrootd on;       # ← this activates the module
        xrootd_root /data;
    }
}
```

Without `xrootd on`, nginx ignores all other `xrootd_*` directives in the block.

---

### `xrootd_root <path>`

**Default:** `/`

The filesystem directory that clients see as their root (`/`). Every path a client requests is resolved relative to this directory. Paths that try to escape using `..` or symlinks are rejected.

```nginx
xrootd_root /data/store;   # clients see /data/store as "/"
```

A client requesting `/mc/sample.root` gets `/data/store/mc/sample.root` on disk.

---

### `xrootd_allow_write on|off`

**Default:** `off`

Whether clients may write, delete, rename, or create directories. Off by default so read-only servers are safe without any extra configuration.

Write operations that require this flag: `kXR_pgwrite`, `kXR_write`, `kXR_sync`, `kXR_truncate`, `kXR_mkdir`, `kXR_rmdir`, `kXR_rm`, `kXR_mv`, `kXR_chmod`. A write request to a server where this is `off` returns `kXR_fsReadOnly`.

```nginx
xrootd_allow_write on;   # allow uploads and deletes
```

---

### `xrootd_auth none|gsi`

**Default:** `none`

Authentication mode:

- `none` — accept any username, no credentials required
- `gsi` — require a valid x509 proxy certificate (see [Authentication](authentication.md))

```nginx
xrootd_auth gsi;
```

---

### `xrootd_certificate <path>`

Path to the server's PEM certificate file. Required when `xrootd_auth gsi`.

```nginx
xrootd_certificate /etc/grid-security/hostcert.pem;
```

---

### `xrootd_certificate_key <path>`

Path to the server's PEM private key file. Required when `xrootd_auth gsi`.

```nginx
xrootd_certificate_key /etc/grid-security/hostkey.pem;
```

---

### `xrootd_trusted_ca <path>`

Path to a PEM file containing the CA certificate (or bundle of CA certificates) that the server trusts for verifying client proxy certificates. Required when `xrootd_auth gsi`.

```nginx
xrootd_trusted_ca /etc/grid-security/certificates/ca.pem;
```

---

### `xrootd_access_log <path>|off`

**Default:** `off`

File path for the per-request access log. One line is written per operation. See [Metrics & logging](metrics-and-logging.md) for the log format and examples.

```nginx
xrootd_access_log /var/log/nginx/xrootd_access.log;
```

The file is opened `O_APPEND` so it is safe to share across multiple nginx worker processes. Rotate with `kill -USR1 $(cat /run/nginx.pid)`.

---

### `xrootd_thread_pool <name>`

**Default:** `default`

Name of the nginx thread pool used for async file I/O (reads and writes). Must match a `thread_pool` directive at the main config level (outside `stream {}`).

If the named pool does not exist, the module falls back to synchronous I/O and logs a notice. Synchronous I/O means a slow read blocks all other connections on the same worker process — fine for development, not for production.

```nginx
# At the top of nginx.conf, outside stream {}
thread_pool xrootd_io threads=8 max_queue=65536;

stream {
    server {
        listen 1094;
        xrootd on;
        xrootd_root /data;
        xrootd_thread_pool xrootd_io;
    }
}
```

How many threads to use: a good starting point is one thread per disk spindle, or 4–8 for NVMe/SSD. The `max_queue` value caps how many pending I/O tasks can queue up before new requests start returning errors.

---

## Complete examples

### Minimal read-only server

```nginx
worker_processes auto;
thread_pool default threads=4 max_queue=65536;

events { worker_connections 1024; }

stream {
    server {
        listen 1094;
        xrootd on;
        xrootd_root /data/public;
    }
}
```

### Read-write server with access log

```nginx
worker_processes auto;
thread_pool default threads=4 max_queue=65536;

events { worker_connections 1024; }

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

### Two ports: read-only anonymous + read-write GSI-authenticated

```nginx
worker_processes auto;
thread_pool default threads=4 max_queue=65536;

events { worker_connections 1024; }

stream {
    # Public read-only endpoint
    server {
        listen 1094;
        xrootd on;
        xrootd_root /data/public;
        xrootd_access_log /var/log/nginx/xrootd_public.log;
    }

    # Authenticated read-write endpoint
    server {
        listen 1095;
        xrootd on;
        xrootd_auth gsi;
        xrootd_allow_write on;
        xrootd_root /data/upload;
        xrootd_certificate     /etc/grid-security/hostcert.pem;
        xrootd_certificate_key /etc/grid-security/hostkey.pem;
        xrootd_trusted_ca      /etc/grid-security/ca.pem;
        xrootd_access_log /var/log/nginx/xrootd_gsi.log;
    }
}

# Prometheus metrics on a separate port
http {
    server {
        listen 9100;
        location /metrics {
            xrootd_metrics on;
        }
    }
}
```

---

## XRootD stream directive summary

| Directive | Context | Default | Required? |
|---|---|---|---|
| `xrootd on\|off` | `server` (stream) | `off` | Yes |
| `xrootd_root <path>` | `server` | `/` | Recommended |
| `xrootd_allow_write on\|off` | `server` | `off` | No |
| `xrootd_auth none\|gsi` | `server` | `none` | No |
| `xrootd_certificate <path>` | `server` | — | If `auth gsi` |
| `xrootd_certificate_key <path>` | `server` | — | If `auth gsi` |
| `xrootd_trusted_ca <path>` | `server` | — | If `auth gsi` |
| `xrootd_access_log <path>\|off` | `server` | `off` | No |
| `xrootd_thread_pool <name>` | `server` | `default` | No |
| `xrootd_metrics on\|off` | `location` (HTTP) | `off` | No |

---

## WebDAV directives

The WebDAV module (`ngx_http_xrootd_webdav_module`) handles `davs://` clients in nginx's `http {}` context. Full documentation and examples: [webdav.md](webdav.md).

| Directive | Context | Default | Notes |
|---|---|---|---|
| `xrootd_webdav on\|off` | `location` | `off` | Activates WebDAV handler |
| `xrootd_webdav_root <path>` | `location` | — | Filesystem root for clients |
| `xrootd_webdav_auth none\|optional\|required` | `location` | `none` | Client cert policy |
| `xrootd_webdav_cadir <path>` | `location` | — | Hashed CA directory |
| `xrootd_webdav_cafile <path>` | `location` | — | Single CA PEM file |
| `xrootd_webdav_allow_write on\|off` | `location` | `off` | Enable PUT/DELETE/MKCOL |
| `xrootd_webdav_proxy_certs on\|off` | `server` (HTTP) | `off` | Accept RFC 3820 proxy certs |
| `xrootd_webdav_verify_depth <n>` | `location` | `10` | Proxy chain depth limit |
