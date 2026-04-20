# Background: what XRootD is and why this module exists

## What is XRootD?

XRootD is a file transfer protocol designed for High Energy Physics. It is the primary way physicists at CERN, SLAC, and Fermilab move data between storage systems and analysis jobs — files like ROOT ntuples and HEP datasets that can be tens of gigabytes each.

The protocol is similar in concept to FTP or HTTP, but optimised for physics workflows:

- **Addresses** look like `root://server//path/to/file.root` (note the double slash before the path)
- **Port 1094** is the default (also 1095 for authenticated access)
- **Tools** include `xrdcp` (like `scp`), `xrdfs` (like an FTP shell), and the XRootD Python and C++ client libraries
- **Authentication** commonly uses x509/GSI proxy certificates, and modern WLCG deployments are also moving toward JWT bearer tokens

A typical use looks like:

```bash
# Copy a file from an XRootD server
xrdcp root://server.cern.ch//store/mc/Run3/sample.root /tmp/local.root

# List a directory
xrdfs server.cern.ch ls /store/mc/Run3

# Or directly from Python / ROOT:
import XRootD.client as xrd
f = xrd.File()
f.open("root://server.cern.ch//store/mc/Run3/sample.root")
```

## What is an nginx stream module?

nginx is primarily an HTTP server, but its `stream {}` block handles raw TCP connections — any protocol, not just HTTP. A stream module intercepts the TCP connection right after nginx accepts it and drives a custom protocol.

This module is an nginx stream module: nginx accepts a TCP connection on port 1094, hands it to this module, and the module speaks XRootD directly — handshake, login, file operations, everything. nginx never sees HTTP; the whole connection is XRootD.

```
XRootD client (xrdcp, ROOT, Python)
        │  root://nginx-host//store/mc/sample.root
        │  TCP port 1094
        ▼
┌──────────────────────────────────────────┐
│ nginx                                    │
│  stream { xrootd on; xrootd_root /data; }│
│  (this module drives the XRootD protocol)│
└──────────────────┬───────────────────────┘
                   │  POSIX open/read/write/stat/readdir
                   ▼
             /data/store/mc/sample.root
```

## Why run XRootD inside nginx?

The standard XRootD server (`xrootd` daemon) is purpose-built and very capable, but it is a separate process with its own configuration, its own authentication infrastructure, and its own operational tooling.

If you already operate nginx, you get several things for free by using this module instead:

- **TLS policy and termination** — nginx's SSL stack provides the HTTPS and `roots://` transport layer, and the native stream module can also trigger the XRootD in-protocol TLS upgrade
- **IP-based access control** — use `allow`/`deny` in nginx config
- **Rate limiting** — `limit_conn` and `limit_req` from nginx
- **Load balancing** — put multiple nginx-xrootd backends behind an nginx upstream
- **Unified access logging** — same log format and log rotation as your other services
- **Prometheus metrics** — built-in `/metrics` endpoint, no extra exporters needed
- **Single binary** — one nginx process, one config file, one set of ops runbooks

The trade-off: this is an nginx module, not the full xrootd daemon. It implements the XRootD data server protocol (`kXR_DataServer`) but does not implement redirector/federation (`kXR_Manager`), clustered storage (HDFS/EOS backends), or some rarely-used v3 operations.

## What this module does and does not support

**Supported:**

- Full read and write access to local POSIX filesystems
- All standard file operations: open, read, write, stat, dirlist, rename, delete, chmod, mkdir, truncate
- Scatter-gather vector reads (`kXR_readv`)
- Checksum queries (adler32)
- Anonymous access, GSI/x509 proxy certificate authentication, and JWT/WLCG bearer-token authentication
- VO-style path ACLs from VOMS proxy attributes or token `wlcg.groups`
- Async file I/O via nginx thread pools (non-blocking reads and writes)
- Prometheus metrics

**Not supported:**

- `kXR_locate` (redirect to optimal replica)
- XRootD federation / redirector role (`kXR_Manager`)
- Remote storage backends (HDFS, EOS, etc.)
