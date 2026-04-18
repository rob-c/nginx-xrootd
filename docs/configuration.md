# Configuration reference

Native XRootD stream directives go inside a `server {}` block in the `stream {}` section of `nginx.conf`. Each `server {}` block is a separate XRootD endpoint and can have its own settings. HTTP/WebDAV and metrics directives are summarized at the end of this page.

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

### `xrootd_auth none|gsi|token|both`

**Default:** `none`

Authentication mode:

- `none` — accept any username, no credentials required
- `gsi` — require a valid x509 proxy certificate (see [Authentication](authentication.md))
- `token` — require a valid WLCG/JWT bearer token using the `ztn` security protocol
- `both` — accept either GSI or bearer-token credentials on the same listener

```nginx
xrootd_auth gsi;
```

---

### `xrootd_certificate <path>`

Path to the server's PEM certificate file. Required when `xrootd_auth gsi` or `xrootd_auth both`.

```nginx
xrootd_certificate /etc/grid-security/hostcert.pem;
```

---

### `xrootd_certificate_key <path>`

Path to the server's PEM private key file. Required when `xrootd_auth gsi` or `xrootd_auth both`.

```nginx
xrootd_certificate_key /etc/grid-security/hostkey.pem;
```

---

### `xrootd_trusted_ca <path>`

Path to a PEM file containing the CA certificate (or bundle of CA certificates) that the server trusts for verifying client proxy certificates. Required when `xrootd_auth gsi` or `xrootd_auth both`.

```nginx
xrootd_trusted_ca /etc/grid-security/certificates/ca.pem;
```

---

### `xrootd_crl <path>`

Path to a PEM CRL file or a directory containing CRLs. Directory mode scans `*.pem` and grid-style `*.r0` through `*.r9` files. When configured, GSI verification enables OpenSSL CRL checks for the full certificate chain.

```nginx
xrootd_crl /etc/grid-security/certificates;
```

---

### `xrootd_crl_reload <seconds>`

**Default:** `0` (disabled)

How often each worker reloads `xrootd_crl` and rebuilds its GSI trust store. A failed reload keeps the previous store in place.

```nginx
xrootd_crl_reload 300;  # reload CRLs every five minutes
```

---

### `xrootd_token_jwks <path>`

Path to a JWKS file containing public keys trusted for JWT/WLCG bearer-token validation. Used when `xrootd_auth token` or `xrootd_auth both` is configured.

```nginx
xrootd_token_jwks /etc/tokens/jwks.json;
```

---

### `xrootd_token_issuer <string>`

Expected JWT `iss` claim. Tokens from other issuers are rejected.

```nginx
xrootd_token_issuer "https://idp.example.com";
```

---

### `xrootd_token_audience <string>`

Expected JWT `aud` claim. Tokens for other services are rejected.

```nginx
xrootd_token_audience "my-storage";
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

### `xrootd_vomsdir <path>`

Path to the directory containing VOMS server information (`.lsc` files), one per VO. Required when `xrootd_require_vo` is used. Requires `libvomsapi.so.1` at runtime (install `voms-libs` on EL9 or `libvomsapi1` on Debian/Ubuntu).

```nginx
xrootd_vomsdir /etc/voms;
```

---

### `xrootd_voms_cert_dir <path>`

Path to the hashed CA certificate directory used for verifying VOMS attribute certificates. Required when `xrootd_require_vo` is used.

```nginx
xrootd_voms_cert_dir /etc/grid-security/certificates;
```

---

### `xrootd_require_vo <path> <vo>`

Restricts access to `<path>` (and all descendants) to clients whose VO list includes `<vo>`. For GSI, the VO list comes from VOMS proxy attributes. For token authentication, `wlcg.groups` claims are mapped into the same VO list. Can be specified multiple times for different paths.

`xrootd_auth gsi`, `xrootd_auth token`, or `xrootd_auth both` must be enabled, and `libvomsapi.so.1` must be available at runtime. The directive also requires `xrootd_vomsdir` and `xrootd_voms_cert_dir` because the same ACL machinery is used for GSI and token groups.

```nginx
xrootd_require_vo /atlas atlas;   # only ATLAS members can access /atlas
xrootd_require_vo /cms   cms;     # only CMS members can access /cms
```

If a GSI client has no VOMS extensions, or a token client has no matching `wlcg.groups`, the VO list is empty and access to protected paths is denied.

---

### `xrootd_inherit_parent_group <path>`

When a file or directory is created under `<path>`, nginx automatically adjusts its GID and group permission bits to match the parent directory. This mimics the Linux `setgid` bit at the application layer, which is useful when the backing filesystem (e.g. CephFS) does not reliably propagate `setgid` across mounts.

```nginx
xrootd_inherit_parent_group /cms;   # keep /cms/* group-owned by cms group
```

What happens on each create:
- **File**: GID set to parent GID; group read/write bits copied from parent; group execute preserved if already set.
- **Directory**: GID set to parent GID; group rwx bits copied from parent; `S_ISGID` added if the parent has it.
- **Recursive mkdir (`kXR_mkdirpath`)**: policy applied to each newly created directory level.

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

### VO-restricted storage with group inheritance (CephFS-style)

```nginx
worker_processes auto;
thread_pool default threads=8 max_queue=65536;

events { worker_connections 1024; }

stream {
    server {
        listen 1095;
        xrootd on;
        xrootd_auth          gsi;
        xrootd_allow_write   on;
        xrootd_root          /ceph/store;

        xrootd_certificate     /etc/grid-security/hostcert.pem;
        xrootd_certificate_key /etc/grid-security/hostkey.pem;
        xrootd_trusted_ca      /etc/grid-security/ca.pem;

        # VOMS: where to find VO membership information
        xrootd_vomsdir         /etc/voms;
        xrootd_voms_cert_dir   /etc/grid-security/certificates;

        # Restrict /atlas and /cms sub-trees to their respective VOs
        xrootd_require_vo /atlas atlas;
        xrootd_require_vo /cms   cms;

        # Keep group ownership consistent for all new files/dirs
        xrootd_inherit_parent_group /atlas;
        xrootd_inherit_parent_group /cms;

        xrootd_access_log /var/log/nginx/xrootd_gsi.log;
        xrootd_thread_pool default;
    }
}
```

With `setgid` on the top-level directories (set once with `chmod g+s /ceph/store/atlas /ceph/store/cms`), all files written through nginx will automatically inherit the correct GID and group permissions.

---

### Token-authenticated stream listener

```nginx
worker_processes auto;
thread_pool default threads=4 max_queue=65536;

events { worker_connections 1024; }

stream {
    server {
        listen 1096;
        xrootd on;
        xrootd_root /data/token;
        xrootd_auth token;
        xrootd_allow_write on;

        xrootd_token_jwks     /etc/tokens/jwks.json;
        xrootd_token_issuer   "https://idp.example.com";
        xrootd_token_audience "my-storage";

        xrootd_access_log /var/log/nginx/xrootd_token.log;
    }
}
```

Native stream token auth validates the JWT and stores the `sub`, `scope`, and `wlcg.groups` claims. Native stream write access is still controlled by `xrootd_allow_write`; `storage.read` and `storage.write` scopes are not currently enforced per path on the stream protocol. Use `xrootd_require_vo` with `wlcg.groups` for path ACLs.

---

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
| `xrootd_auth none\|gsi\|token\|both` | `server` | `none` | No |
| `xrootd_certificate <path>` | `server` | — | If `auth gsi` or `auth both` |
| `xrootd_certificate_key <path>` | `server` | — | If `auth gsi` or `auth both` |
| `xrootd_trusted_ca <path>` | `server` | — | If `auth gsi` or `auth both` |
| `xrootd_crl <path>` | `server` | — | No |
| `xrootd_crl_reload <seconds>` | `server` | `0` | No |
| `xrootd_vomsdir <path>` | `server` | — | If `require_vo` |
| `xrootd_voms_cert_dir <path>` | `server` | — | If `require_vo` |
| `xrootd_require_vo <path> <vo>` | `server` | — | No |
| `xrootd_inherit_parent_group <path>` | `server` | — | No |
| `xrootd_token_jwks <path>` | `server` | — | If `auth token` or `auth both` |
| `xrootd_token_issuer <string>` | `server` | — | If token JWKS is configured |
| `xrootd_token_audience <string>` | `server` | — | If token JWKS is configured |
| `xrootd_access_log <path>\|off` | `server` | `off` | No |
| `xrootd_thread_pool <name>` | `server` | `default` | No |
| `xrootd_metrics on\|off` | `location` (HTTP) | `off` | No |

---

## WebDAV directives

The WebDAV module (`ngx_http_xrootd_webdav_module`) handles `davs://` clients in nginx's `http {}` context. Full documentation and examples: [webdav.md](webdav.md).

| Directive | Context | Default | Notes |
|---|---|---|---|
| `xrootd_webdav on\|off` | `location` | `off` | Activates WebDAV handler |
| `xrootd_webdav_root <path>` | `location` | `/` | Filesystem root for clients |
| `xrootd_webdav_auth none\|optional\|required` | `location` | `optional` | Proxy-cert or bearer-token auth policy |
| `xrootd_webdav_cadir <path>` | `location` | — | Hashed CA directory |
| `xrootd_webdav_cafile <path>` | `location` | — | Single CA PEM file |
| `xrootd_webdav_crl <path>` | `location` | — | PEM CRL file for proxy-cert revocation checks |
| `xrootd_webdav_allow_write on\|off` | `location` | `off` | Enable PUT/DELETE/MKCOL and TPC COPY writes |
| `xrootd_webdav_tpc on\|off` | `location` | `off` | Enable HTTP-TPC COPY pull support |
| `xrootd_webdav_tpc_curl <path>` | `location` | `/usr/bin/curl` | External curl helper for TPC pulls |
| `xrootd_webdav_tpc_cert <path>` | `location` | — | X.509 cert/proxy used for outbound TPC source fetches |
| `xrootd_webdav_tpc_key <path>` | `location` | `xrootd_webdav_tpc_cert` | Private key used with the TPC cert |
| `xrootd_webdav_tpc_cadir <path>` | `location` | `xrootd_webdav_cadir` | CA directory for outbound source TLS verification |
| `xrootd_webdav_tpc_cafile <path>` | `location` | `xrootd_webdav_cafile` | CA bundle for outbound source TLS verification |
| `xrootd_webdav_tpc_timeout <seconds>` | `location` | `0` | Optional curl max-time for TPC pulls |
| `xrootd_webdav_proxy_certs on\|off` | `server` or `location` (HTTP) | `off` | Accept RFC 3820 proxy certs |
| `xrootd_webdav_verify_depth <n>` | `location` | `10` | Proxy chain depth limit |
| `xrootd_webdav_token_jwks <path>` | `location` | — | JWKS for Bearer tokens |
| `xrootd_webdav_token_issuer <string>` | `location` | — | Expected token issuer |
| `xrootd_webdav_token_audience <string>` | `location` | — | Expected token audience |
