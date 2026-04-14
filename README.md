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
| `kXR_login` | Accept username; anonymous or GSI auth depending on config |
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

**Authentication** is supported in two modes — anonymous (any username accepted) and GSI/x509 proxy certificates (see the section below).

**Write access** is permanently disabled. Any write-class request (`kXR_write`, `kXR_mkdir`, `kXR_rm`, `kXR_mv`, `kXR_chmod`, `kXR_truncate`, etc.) returns a `kXR_fsReadOnly` error.

**TLS** is not yet handled at the XRootD protocol level (the module does not negotiate `kXR_tlsLogin` / `kXR_haveTLS`). For encrypted transport, terminate TLS externally with `ssl_preread` or a separate stunnel/nginx SSL stream block in front.

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

All GSI payloads are serialised as **XrdSutBuffer** — a binary container:

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

The session cipher key for encrypting `kXRS_main` in `kXGC_cert` comes from a Diffie-Hellman exchange using the **ffdhe2048** well-known group (RFC 7919):

```
shared_secret = EVP_PKEY_derive(server_dh_private, client_dh_public)
                  with EVP_PKEY_CTX_set_dh_pad(0)   ← no padding
session_key   = first N bytes of shared_secret
                  where N = EVP_CIPHER_key_length(chosen_cipher)
IV            = all zeros   (old protocol, HasPad=false)
```

### Implementation gotchas

These are non-obvious issues discovered by reverse-engineering the XRootD C++ source (`XrdSecProtocolgsi.cc`, `XrdCryptosslCipher.cc`). None of them are documented in the protocol spec.

---

**1. Login challenge must be `&P=` text, not binary XrdSutBuffer**

The `kXR_login` response for GSI must append a plain-text challenge:
```
kXR_ok + sessid[16] + "&P=gsi,v:10000,c:ssl,ca:ABCD1234\0"
```
The XRootD client's `ClientDoInit()` calls `GetOptions()` on this string, which only parses the `&P=key:val,key:val` text format. Sending a binary `XrdSutBuffer` here causes the client to print *"No protocols left to try"* and disconnect silently.

---

**2. `kXRS_puk` is a DH blob, not an RSA PEM**

The `kXRS_puk` bucket carries a DH public key in this custom text format:
```
<DH PARAMETERS PEM>---BPUB---<hex BIGNUM>---EPUB--
```
where `---EPUB--` is 9 characters (no trailing dash). The hex BIGNUM is `BN_bn2hex()` of the DH public value. Sending an RSA public key PEM in `kXRS_puk` causes the client to print *"could not instantiate session cipher"*.

---

**3. Proxy cert is inside encrypted `kXRS_main`, not the outer buffer**

In `kXGC_cert`, the client's proxy certificate is inside the **encrypted** `kXRS_main` bucket. Scanning the outer buffer for `kXRS_x509` will always fail — it is only present after decrypting `kXRS_main` with the DH-derived session key.

---

**4. DH derivation requires `set_dh_pad(0)` (no padding)**

The old GSI protocol (v:10000) uses `HasPad=false`. OpenSSL's default DH derivation pads the shared secret with leading zeros to match the DH prime length. The XRootD client does not do this. If you omit `EVP_PKEY_CTX_set_dh_pad(pkctx, 0)`, the first N bytes of your shared secret will not match the client's, and decryption will fail silently (wrong plaintext, not a detectable error).

---

**5. Server DH key must survive across two `kXR_auth` messages**

The server's ephemeral DH private key is generated in the `kXGC_certreq` handler and must still be available when the `kXGC_cert` handler derives the shared secret. In the module this is stored in `ctx->gsi_dh_key` and freed immediately after `kXGC_cert` processing.

---

**6. `kXRS_puk` closing sentinel is `---EPUB--` (9 chars, not 10)**

The blob format uses `---BPUB---` (10 chars) to open and `---EPUB--` (9 chars) to close. Using `---EPUB---` (10 chars) as the closing sentinel means `memmem()` won't find it. Confirmed by reading `XrdCryptosslCipher.cc` which uses both lengths explicitly.

---

**7. Stat response field order: size before flags**

The `kXR_stat` wire format is `"<id> <size> <flags> <mtime>\0"` — **size comes before flags**. This is the opposite of what several online examples and older documentation show (`"<id> <flags> <size> <mtime>"`).

The XRootD client parser (`XrdClXRootDResponses.cc`, `ParseServerResponse()`) reads:
```
chunks[0] = id
chunks[1] = size    ← second field
chunks[2] = flags   ← third field
chunks[3] = mtime
```

Swapping size and flags causes the client to interpret `kXR_isDir` (value 2) or `kXR_readable` (value 16) as the file size, and the actual file size as flags — breaking all stat-based operations.

---

**8. Proxy cert verification requires `X509_V_FLAG_ALLOW_PROXY_CERTS`**

RFC 3820 proxy certificates are rejected by default in OpenSSL's `X509_verify_cert()`. The flag must be set on **both** the `X509_STORE` (at configuration time) and the `X509_STORE_CTX` (at verification time):

```c
X509_STORE_set_flags(store, X509_V_FLAG_ALLOW_PROXY_CERTS);
// ...
X509_STORE_CTX_set_flags(vctx, X509_V_FLAG_ALLOW_PROXY_CERTS);
```

---

**9. XRootD v5 handshake uses standard 8-byte response header**

XRootD v5 clients send the 20-byte handshake and the `kXR_protocol` request as a single 44-byte TCP segment, then expect each server reply as a standard `ServerResponseHdr` (8 bytes: streamid[2], status[2], dlen[4]) followed by the body.

The old 12-byte `ServerInitHandShake` framing (`msglen(4) + protover(4) + msgval(4)`) parses as `status=0x0008 / dlen=0x00000520=1312` — the client stalls waiting for 1312 bytes that never arrive.

Fix: respond to the handshake with `ServerResponseHdr{streamid={0,0}, status=kXR_ok, dlen=8}` followed by 8 bytes of `protover + msgval`.

---

**10. `kXR_protocol` SecurityInfo required when `kXR_secreqs` is set**

When the client's `kXR_protocol` request has flag `kXR_secreqs=0x01` set (security requirements requested), the server's response body must include a 4-byte `SecurityInfo` header after `pval + flags`:

```
secver  [1]  = 0
secopt  [1]  = 0x01 (kXR_secOFrce) if auth required, else 0
nProt   [1]  = number of protocol entries (1 for GSI, 0 for anonymous)
rsvd    [1]  = 0
```

Followed by an 8-byte entry per protocol:
```
name[4]  space-padded protocol name ("gsi ")
plvl[1]  security level (0 = kXR_secNone)
pargs[3] reserved, 0
```

Without `SecurityInfo`, the client disconnects silently after the protocol exchange.

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

- **SciToken / WLCG Bearer Token authentication** — complement GSI with token-based auth via `kXR_auth` / `kXR_authmore`
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
