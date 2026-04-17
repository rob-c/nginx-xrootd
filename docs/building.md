# Building from scratch

This guide covers building the nginx-xrootd module from a clean machine. It includes every dependency, compile-time option, and the full test harness setup.

---

## 1. System prerequisites

**RHEL 9 / AlmaLinux 9 / Rocky 9:**

```bash
sudo dnf install -y gcc make pcre2-devel zlib-devel openssl-devel \
    xrootd-client xrootd-server \
    voms voms-devel voms-clients-cpp voms-server \
    python3 python3-pip
```

**Ubuntu 22.04+ / Debian 12+:**

```bash
sudo apt install -y build-essential libpcre2-dev zlib1g-dev libssl-dev \
    xrootd-client xrootd-server \
    voms-dev voms-clients \
    python3 python3-pip python3-venv
```

Key packages and why they are needed:

| Package | Purpose |
|---|---|
| `gcc`, `make` | C compiler and build system |
| `pcre2-devel` / `libpcre2-dev` | Regular expressions (nginx core) |
| `zlib-devel` / `zlib1g-dev` | gzip compression (nginx core) |
| `openssl-devel` / `libssl-dev` | TLS and x509 certificate handling (GSI auth, WebDAV) |
| `voms-devel` / `voms-dev` | VOMS API headers and `libvomsapi` (VO ACL enforcement) |
| `voms-clients-cpp` / `voms-clients` | `voms-proxy-fake` for generating test VOMS proxies |
| `xrootd-client` | `xrdcp`, `xrdfs` command-line tools for testing |
| `xrootd-server` | Reference `xrootd` daemon for interoperability tests |

Verify VOMS development files are available:

```bash
pkg-config --cflags --libs voms-2.0
# Expected: -lvomsapi  (possibly with include paths)
```

If `pkg-config` cannot find `voms-2.0`, VOMS support will be silently disabled at compile time. You can still build and use the module — you just cannot use `xrootd_require_vo` directives.

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
- Auto-detects VOMS via `pkg-config voms-2.0` and adds `-DXROOTD_HAVE_VOMS=1` and `-lvomsapi` if found

### Verifying VOMS detection

After running `./configure`, check the output:

```bash
grep VOMS /tmp/nginx-1.28.3/objs/ngx_modules.c
# Not useful — check the Makefile instead:
grep -i voms /tmp/nginx-1.28.3/objs/Makefile
```

You should see `-DXROOTD_HAVE_VOMS=1` and `-lvomsapi` in the compile/link lines. If they are missing, VOMS was not detected. Check that `pkg-config --exists voms-2.0` returns 0.

### Known issue: VOMS CFLAGS propagation

In some nginx versions, `ngx_module_cflags` set during `./configure` does not propagate to the per-file compile rules in the generated Makefile. If your build compiles but VO ACL tests fail with config-parse errors like "xrootd_require_vo: unknown directive", the VOMS flag was lost.

Fix it manually after `./configure`:

```bash
sed -i 's/^CFLAGS =.*/& -DXROOTD_HAVE_VOMS=1/' /tmp/nginx-1.28.3/objs/Makefile
```

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

### 6.4 Write the test nginx.conf

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
```

---

## 8. Run the test suite

### 8.1 Install Python dependencies

```bash
cd /path/to/nginx-xrootd
python3 -m venv .venv
source .venv/bin/activate
pip install pytest xrootd pytest-timeout cryptography
```

### 8.2 Run tests

The test suite expects nginx to be running on ports 11094 and 11095 as configured above:

```bash
# Core tests (protocol, file API, metrics)
pytest tests/test_xrootd.py tests/test_file_api.py tests/test_metrics.py -v

# Read and write handlers
pytest tests/test_write.py tests/test_readv.py -v

# GSI authentication and bridge transfers
pytest tests/test_gsi_bridge.py -v

# VO ACL enforcement (requires voms-proxy-fake on PATH)
pytest tests/test_vo_acl.py -v

# WebDAV / HTTPS
pytest tests/test_webdav.py -v

# Everything
pytest -v
```

The VO ACL tests (`test_vo_acl.py`) start their own nginx instance on port 11096 with `xrootd_require_vo` directives. They auto-generate VOMS proxies if expired or missing, but require `voms-proxy-fake` on PATH.

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

### With VOMS support (default when detected)

VOMS support is auto-detected by the `config` script. If `pkg-config --exists voms-2.0` succeeds, these are added automatically:

- **CFLAGS:** `-DXROOTD_HAVE_VOMS=1` plus any include paths from `pkg-config --cflags voms-2.0`
- **LIBS:** `-lvomsapi` from `pkg-config --libs voms-2.0`

### Without VOMS support

If you do not install `voms-devel`, the module builds without VOMS support. The `xrootd_require_vo`, `xrootd_vomsdir`, and `xrootd_voms_cert_dir` directives will not be available in `nginx.conf`.

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
