# Getting started

This guide walks you from zero to a working XRootD server in nginx. It takes about 10 minutes.

## Prerequisites

- Linux (tested on RHEL 8/9, Ubuntu 22.04+)
- A C compiler (`gcc` or `clang`)
- nginx source (we build from source because we add a module)
- `xrdcp` installed for testing — install via `yum install xrootd-client` or `apt install xrootd-client`

> GSI authentication also needs an x509 host certificate. If you only want anonymous access (no certificates), you can skip that entirely.

---

## Step 1: Get the nginx source

We compile nginx from source to add this module. Use the current stable release:

```bash
curl -O https://nginx.org/download/nginx-1.28.3.tar.gz
tar xzf nginx-1.28.3.tar.gz
cd nginx-1.28.3
```

---

## Step 2: Configure and build

Clone this module alongside the nginx source tree, then configure:

```bash
git clone https://github.com/rob-c/nginx-xrootd.git /opt/nginx-xrootd

./configure \
    --with-stream \
    --with-threads \
    --add-module=/opt/nginx-xrootd
make -j$(nproc)
sudo make install
```

The key flags:
- `--with-stream` — enables nginx's raw TCP handling (required)
- `--with-threads` — enables async file I/O (strongly recommended; without this, slow disk I/O blocks all connections on the worker)
- `--add-module` — points to this repository

nginx is installed to `/usr/local/nginx` by default. The binary is at `/usr/local/nginx/sbin/nginx`.

**Verifying the build:**

```bash
/usr/local/nginx/sbin/nginx -V 2>&1 | grep xrootd
# Should show: --add-module=.../nginx-xrootd
```

---

## Step 3: Write a minimal nginx.conf

Create `/usr/local/nginx/conf/nginx.conf`:

```nginx
# Required: tell nginx how many workers to run
worker_processes auto;

# Required: enable async file I/O thread pool
# (match the thread count to your disk I/O capacity)
thread_pool default threads=4 max_queue=65536;

events {
    worker_connections 1024;
}

stream {
    server {
        listen 1094;           # standard XRootD port
        xrootd on;
        xrootd_root /data;     # serve files from /data
        xrootd_allow_write on; # allow uploads
        xrootd_access_log /var/log/nginx/xrootd_access.log;
    }
}
```

Make the data directory:

```bash
mkdir -p /data
```

---

## Step 4: Start nginx

```bash
sudo /usr/local/nginx/sbin/nginx
```

Check the error log if anything goes wrong:

```bash
tail -f /usr/local/nginx/logs/error.log
```

---

## Step 5: Test with xrdcp

```bash
# Upload a file
echo "hello xrootd" > /tmp/test.txt
xrdcp /tmp/test.txt root://localhost:1094//test.txt

# Download it back
xrdcp root://localhost:1094//test.txt /tmp/downloaded.txt
cat /tmp/downloaded.txt  # should print: hello xrootd

# List the directory
xrdfs localhost:1094 ls /

# Stat a file
xrdfs localhost:1094 stat /test.txt
```

If `xrdcp` exits with status 0 and prints no errors, you have a working XRootD server.

---

## Step 6: Test with the Python client (optional)

Install the Python XRootD client:

```bash
pip install xrootd
```

```python
from XRootD import client
from XRootD.client.flags import OpenFlags

fs = client.FileSystem("root://localhost:1094")

# List root directory
status, listing = fs.dirlist("/")
print([e.name for e in listing])

# Read back the file we uploaded
f = client.File()
f.open("root://localhost:1094//test.txt", OpenFlags.READ)
status, data = f.read()
print(data)
f.close()
```

---

## What's next?

- **Add GSI authentication** — [docs/authentication.md](authentication.md)
- **All configuration options** — [docs/configuration.md](configuration.md)
- **Prometheus metrics** — [docs/metrics-and-logging.md](metrics-and-logging.md)
- **Understand all supported operations** — [docs/operations.md](operations.md)

---

## Troubleshooting

**`xrdcp` hangs after connecting:**
Check the nginx error log. The most common cause is a firewall blocking port 1094.

**`xrdcp` prints "No space left on device":**
The upload landed in the right place but the filesystem is full.

**`xrdcp` prints "Permission denied":**
Either the nginx worker process does not have read/write permission to `xrootd_root`, or `xrootd_allow_write` is not set to `on`.

**`xrdcp` exits with status 1 and no useful message:**
Run with `--debug` for verbose output:
```bash
xrdcp --debug 2 /tmp/test.txt root://localhost:1094//test.txt
```

**Error log shows "xrootd: thread pool 'default' not found":**
Add `thread_pool default threads=4 max_queue=65536;` at the top level of `nginx.conf` (outside `stream {}`), or compile with `--with-threads`.
