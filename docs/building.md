# Building from scratch

This guide covers building the nginx-xrootd module from a clean machine. It includes every dependency, compile-time option, and the full test harness setup.

---

## 1. System prerequisites

**RHEL 9 / AlmaLinux 9 / Rocky 9:**

```bash
sudo dnf install -y gcc make pcre2-devel zlib-devel openssl-devel \
    xrootd-client xrootd-server \
    voms-libs \
    python3 python3-pip
```

**Ubuntu 22.04+ / Debian 12+:**

```bash
sudo apt install -y build-essential libpcre2-dev zlib1g-dev libssl-dev \
    xrootd-client xrootd-server \
    libvomsapi1 \
    python3 python3-pip python3-venv
```

Key packages and why they are needed:

| Package | Purpose |
|---|---|
| `gcc`, `make` | C compiler and build system |
| `pcre2-devel` / `libpcre2-dev` | Regular expressions (nginx core) |
| `zlib-devel` / `zlib1g-dev` | gzip compression (nginx core) |
| `openssl-devel` / `libssl-dev` | TLS and x509 certificate handling (GSI auth, WebDAV) |
| `voms-libs` / `libvomsapi1` | `libvomsapi.so.1` runtime library (VO ACL enforcement via dlopen) |
| `xrootd-client` | `xrdcp`, `xrdfs` command-line tools for testing |
| `xrootd-server` | Reference `xrootd` daemon for interoperability tests |
| Python `cryptography` | Test PKI, proxy, CRL, and JWT token generation |

VOMS support is loaded at runtime via `dlopen("libvomsapi.so.1")` — no compile-time VOMS headers or link flags are needed. If the library is present at startup, VO ACL enforcement is available; if absent, the module starts normally but `xrootd_require_vo` directives will fail with an error telling you to install `voms-libs` (EL9) or `libvomsapi1` (Debian/Ubuntu).

Verify `libvomsapi` is installed:

```bash
ls /usr/lib64/libvomsapi.so.1   # EL9
# or
ldconfig -p | grep libvomsapi   # any distro
```

---

## 2. Get the nginx source

Use the current stable release. The module is tested against nginx 1.28.x:

```bash
cd /tmp
curl -O https://nginx.org/download/nginx-1.28.3.tar.gz
tar xzf nginx-1.28.3.tar.gz
cd nginx-1.28.3
```

---

## 3. Clone the module

```bash
git clone https://github.com/HEP-x/nginx-xrootd.git /opt/nginx-xrootd
```

Or, if you already have it checked out:

```bash
export XROOTD_MODULE=/home/you/nginx-xrootd
```

---

## 4. Configure nginx

```bash
cd /tmp/nginx-1.28.3

./configure \
    --with-stream \
    --with-stream_ssl_module \
    --with-http_ssl_module \
    --with-threads \
    --add-module=/opt/nginx-xrootd
```

What each flag does:

| Flag | Required? | Purpose |
|---|---|---|
| `--with-stream` | **Yes** | Enables nginx's raw TCP stream handling — this is how the XRootD protocol is served |
| `--with-stream_ssl_module` | Recommended | TLS for the stream (XRootD) protocol |
| `--with-http_ssl_module` | Recommended | TLS for the HTTP (WebDAV) protocol |
| `--with-threads` | **Strongly recommended** | Enables nginx thread pools for async file I/O. Without this, every disk read/write blocks the entire event loop. |
| `--add-module=<path>` | **Yes** | Points to the nginx-xrootd source directory |

The module's `config` script (at the root of this repository) runs automatically during `./configure`. It:
- Registers the **stream** module (`ngx_stream_xrootd_module`) for the XRootD protocol
- Registers two **HTTP** modules: `ngx_http_xrootd_metrics_module` (Prometheus) and `ngx_http_xrootd_webdav_module` (WebDAV)
- Links `-lssl -lcrypto` for OpenSSL/GSI support
- VOMS support requires no compile-time flags — `libvomsapi.so.1` is loaded at runtime via `dlopen`

### Verifying VOMS at runtime

After starting nginx, check the error log for the VOMS load message:

```bash
grep libvomsapi /tmp/xrd-test/logs/error.log
# Expected: xrootd: libvomsapi.so.1 loaded — VOMS VO ACL enforcement available
```

If you see `libvomsapi.so.1 not found — VOMS VO ACL enforcement disabled` instead, install `voms-libs` (EL9) or `libvomsapi1` (Debian/Ubuntu). The binary itself has no link-time dependency on VOMS — `ldd objs/nginx | grep voms` should return nothing.

---

## 5. Build

```bash
cd /tmp/nginx-1.28.3
make -j$(nproc)
```

The binary is at `/tmp/nginx-1.28.3/objs/nginx`. Verify the module compiled in:

```bash
/tmp/nginx-1.28.3/objs/nginx -V 2>&1 | grep -o 'add-module=[^ ]*'
# Expected: add-module=/opt/nginx-xrootd
```

---

## 6. Set up the test environment

The test suite expects a specific directory layout under `/tmp/xrd-test/`. This section creates it from scratch.

### 6.1 Directory structure

```bash
mkdir -p /tmp/xrd-test/{conf,data,logs,tmp}
mkdir -p /tmp/xrd-test/pki/{ca,server,user,voms,vomsdir}
mkdir -p /tmp/xrd-test/tokens
```

### 6.2 Generate the test PKI

See [docs/test-pki.md](test-pki.md) for a complete walkthrough of creating the CA, server cert, user cert, proxy certs, and VOMS infrastructure from scratch.

If you just want to get running quickly, the test fixtures in `tests/test_vo_acl.py` auto-generate VOMS signing certs and proxies on first run. But the CA, server cert, and user cert must exist first.

### 6.3 Create seed data

```bash
echo "hello xrootd" > /tmp/xrd-test/data/test.txt
for dir in cms atlas public; do
    mkdir -p /tmp/xrd-test/data/$dir
    echo "seed file for $dir" > /tmp/xrd-test/data/$dir/seed.txt
done
```

### 6.4 Create the token signing authority

The helper needs the Python `cryptography` package. If you are using a virtual environment, activate it before this step; otherwise install the dependencies from section 8.1 first.

```bash
cd /path/to/nginx-xrootd
python3 utils/make_token.py init /tmp/xrd-test/tokens
```

This writes `/tmp/xrd-test/tokens/signing_key.pem` and `/tmp/xrd-test/tokens/jwks.json`. See [docs/test-tokens.md](test-tokens.md) for the full walkthrough.

### 6.5 Write the test nginx.conf

Create `/tmp/xrd-test/conf/nginx.conf`:

```nginx
worker_processes 1;
error_log /tmp/xrd-test/logs/error.log info;
pid       /tmp/xrd-test/logs/nginx.pid;

thread_pool default threads=4 max_queue=65536;
events { worker_connections 64; }

stream {
    # Anonymous server (port 11094)
    server {
        listen 11094;
        xrootd on;
        xrootd_root /tmp/xrd-test/data;
        xrootd_auth none;
        xrootd_allow_write on;
        xrootd_access_log /tmp/xrd-test/logs/xrootd_access_anon.log;
    }

    # GSI/x509 server (port 11095)
    server {
        listen 11095;
        xrootd on;
        xrootd_root /tmp/xrd-test/data;
        xrootd_auth gsi;
        xrootd_allow_write on;
        xrootd_certificate     /tmp/xrd-test/pki/server/hostcert.pem;
        xrootd_certificate_key /tmp/xrd-test/pki/server/hostkey.pem;
        xrootd_trusted_ca      /tmp/xrd-test/pki/ca/ca.pem;
        xrootd_access_log /tmp/xrd-test/logs/xrootd_access_gsi.log;
    }

    # JWT/WLCG bearer-token server (port 11099)
    server {
        listen 11099;
        xrootd on;
        xrootd_root /tmp/xrd-test/data;
        xrootd_auth token;
        xrootd_allow_write on;
        xrootd_token_jwks     /tmp/xrd-test/tokens/jwks.json;
        xrootd_token_issuer   "https://test.example.com";
        xrootd_token_audience "nginx-xrootd";
        xrootd_access_log /tmp/xrd-test/logs/xrootd_access_token.log;
    }
}

http {
    access_log            /tmp/xrd-test/logs/http_access.log;
    client_body_temp_path /tmp/xrd-test/tmp;
    proxy_temp_path       /tmp/xrd-test/tmp;
    fastcgi_temp_path     /tmp/xrd-test/tmp;
    uwsgi_temp_path       /tmp/xrd-test/tmp;
    scgi_temp_path        /tmp/xrd-test/tmp;

    # Prometheus metrics
    server {
        listen 9100;
        location /metrics { xrootd_metrics on; }
    }

    # WebDAV over HTTPS (port 8443)
    server {
        listen 8443 ssl;
        server_name localhost;
        ssl_certificate     /tmp/xrd-test/pki/server/hostcert.pem;
        ssl_certificate_key /tmp/xrd-test/pki/server/hostkey.pem;
        xrootd_webdav_proxy_certs on;
        ssl_verify_client   optional_no_ca;
        ssl_verify_depth    10;
        client_max_body_size 1g;
        location / {
            xrootd_webdav         on;
            xrootd_webdav_root    /tmp/xrd-test/data;
            xrootd_webdav_cadir   /tmp/xrd-test/pki/ca;
            xrootd_webdav_auth    optional;
            xrootd_webdav_allow_write on;
            xrootd_webdav_token_jwks     /tmp/xrd-test/tokens/jwks.json;
            xrootd_webdav_token_issuer   "https://test.example.com";
            xrootd_webdav_token_audience "nginx-xrootd";
        }
    }
}
```

---

## 7. Start nginx

```bash
/tmp/nginx-1.28.3/objs/nginx -p /tmp/xrd-test -c conf/nginx.conf
```

Quick smoke test:

```bash
# Anonymous access
echo "hello" > /tmp/test.txt
xrdcp /tmp/test.txt root://localhost:11094//test_upload.txt
xrdfs localhost:11094 ls /

# GSI access (requires proxy cert — see test-pki.md)
export X509_USER_PROXY=/tmp/xrd-test/pki/user/proxy_std.pem
export X509_CERT_DIR=/tmp/xrd-test/pki/ca
xrdfs root://localhost:11095 ls /

# Token access (requires token signing authority — see test-tokens.md)
export BEARER_TOKEN=$(python3 /path/to/nginx-xrootd/utils/make_token.py gen \
    --scope "storage.read:/" /tmp/xrd-test/tokens)
xrdfs root://localhost:11099 ls /
```

---

## 8. Run the test suite

### 8.1 Install Python dependencies

```bash
cd /path/to/nginx-xrootd
python3 -m venv .venv
source .venv/bin/activate
pip install pytest xrootd pytest-timeout cryptography requests urllib3
```

### 8.2 Run tests

The test suite expects nginx to be running on the core ports configured above: 11094 for anonymous native XRootD, 11095 for GSI native XRootD, 11099 for token native XRootD, and 8443 for WebDAV.

```bash
# Core tests (protocol, file API, metrics)
pytest tests/test_xrootd.py tests/test_file_api.py tests/test_metrics.py -v

# Read and write handlers
pytest tests/test_write.py tests/test_readv.py -v

# GSI authentication and bridge transfers
pytest tests/test_gsi_bridge.py -v

# VO ACL enforcement (requires libvomsapi.so.1 at runtime)
pytest tests/test_vo_acl.py -v

# Token auth
pytest tests/test_token_auth.py -v

# CRL revocation checks
pytest tests/test_crl.py -v

# WebDAV / HTTPS
pytest tests/test_webdav.py -v

# Everything
pytest -v
```

The VO ACL tests (`test_vo_acl.py`) start their own nginx instance on port 11103 with `xrootd_require_vo` directives. They auto-generate VOMS proxies if expired or missing using the Python `voms_proxy_fake.py` utility in `utils/`. Token tests use the configured port 11099. CRL tests start a dedicated nginx instance on port 11100 plus WebDAV on 8444 so they do not disturb the main listener.

---

## 9. Rebuilding after code changes

After editing any `.c` or `.h` file:

```bash
cd /tmp/nginx-1.28.3
make -j$(nproc)

# Restart nginx (reload does NOT pick up a rebuilt binary)
/tmp/nginx-1.28.3/objs/nginx -p /tmp/xrd-test -c conf/nginx.conf -s stop
/tmp/nginx-1.28.3/objs/nginx -p /tmp/xrd-test -c conf/nginx.conf

# Re-run tests
cd /path/to/nginx-xrootd
pytest -v
```

---

## 10. Build options reference

### VOMS support (runtime, via dlopen)

VOMS support is always compiled in but loaded at runtime. The module calls `dlopen("libvomsapi.so.1")` during nginx startup and resolves the four API symbols it needs (`VOMS_Init`, `VOMS_Retrieve`, `VOMS_Destroy`, `VOMS_ErrorMessage`). No compile-time VOMS headers or link flags are required.

- **If `libvomsapi.so.1` is present** (e.g. from `voms-libs` on EL9): VO ACL enforcement is available. The startup log shows `xrootd: libvomsapi.so.1 loaded — VOMS VO ACL enforcement available`.
- **If `libvomsapi.so.1` is absent**: The module starts normally. `xrootd_vomsdir`, `xrootd_voms_cert_dir`, and `xrootd_require_vo` directives are still accepted by the config parser, but validation will fail at startup with a clear error message asking you to install the runtime library.

### Debug build

For development, use nginx's debug logging:

```bash
./configure \
    --with-stream \
    --with-http_ssl_module \
    --with-threads \
    --with-debug \
    --add-module=/opt/nginx-xrootd

make -j$(nproc)
```

Then set `error_log ... debug;` in `nginx.conf` for protocol-level trace output.

### Production install

```bash
./configure \
    --prefix=/usr/local/nginx \
    --with-stream \
    --with-stream_ssl_module \
    --with-http_ssl_module \
    --with-threads \
    --add-module=/opt/nginx-xrootd

make -j$(nproc)
sudo make install
```

The binary installs to `/usr/local/nginx/sbin/nginx` and configuration goes in `/usr/local/nginx/conf/`.
