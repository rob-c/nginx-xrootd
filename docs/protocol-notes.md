# Protocol implementation notes

This page documents non-obvious behaviour discovered by reverse-engineering the XRootD C++ source code. None of these are in the protocol specification — they were found by running the client against the server and reading the source when something did not work.

These notes are useful if you are:
- contributing to this module
- implementing your own XRootD server
- debugging unexpected client behaviour

If you just want to use the module, you can skip this page.

---

## 1. XRootD v5 handshake uses a different response format

**What the spec says:** The server should reply to the client handshake with a 12-byte `ServerInitHandShake` struct: `msglen[4] + protover[4] + msgval[4]`.

**What v5 clients actually do:** They send the 20-byte handshake and `kXR_protocol` as a single 44-byte TCP segment, then read each server reply as a standard 8-byte `ServerResponseHdr` (`streamid[2] + status[2] + dlen[4]`) followed by a body.

If you send the old 12-byte format, it parses as `status=0x0008` (some intermediate code) and `dlen=1312`. The client waits for 1312 bytes of body that never arrive and hangs.

**Fix:** Reply to the handshake with a standard `ServerResponseHdr{streamid={0,0}, status=kXR_ok, dlen=8}` followed by 8 bytes of `protover + msgval`. Then send the `kXR_protocol` response separately.

---

## 2. `kXR_protocol` response must include `SecurityInfo` when the client asks

When the client's `kXR_protocol` request has bit `kXR_secreqs=0x01` set (meaning "tell me what security you require"), the response body must include a 4-byte `SecurityInfo` header after `pval + flags`, plus one 8-byte entry per supported authentication protocol.

Without this, the client sees the protocol exchange as complete but then disconnects silently — no error message. The only symptom is the TCP connection closing immediately after the protocol exchange.

---

## 3. The GSI login challenge must be plain text, not a binary buffer

For GSI authentication, the `kXR_login` response must append a plain-text challenge string after the 16-byte session ID:

```
&P=gsi,v:10000,c:ssl,ca:ABCD1234\0
```

The client calls `GetOptions()` on this string, which only understands the `&P=key:val` text format. If you send a binary `XrdSutBuffer` instead, the client prints "No protocols left to try" and disconnects. This is not documented anywhere in the spec.

---

## 4. `kXRS_puk` carries a DH blob, not an RSA public key

The `kXRS_puk` bucket in the GSI certificate exchange carries a Diffie-Hellman public key in this specific text format:

```
<DH PARAMETERS PEM>---BPUB---<hex BIGNUM>---EPUB--
```

Note: `---EPUB--` is 9 characters, not 10. The client accepts this. If you send an RSA public key PEM instead (which looks superficially similar), the client responds with "could not instantiate session cipher".

The DH group must be `ffdhe2048` (RFC 7919 named group). Use OpenSSL `EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL)` with `OSSL_PARAM_utf8_string("group", "ffdhe2048", 0)`.

---

## 5. DH shared secret derivation requires no padding

The old GSI protocol (version v:10000, used by all current clients) sets `HasPad=false`. OpenSSL's default DH derivation pads the shared secret with leading zeros to fill the DH prime length. The XRootD client does not pad.

If you forget `EVP_PKEY_CTX_set_dh_pad(0)` when calling `EVP_PKEY_derive`, the session key bytes are wrong and the encrypted payload decrypts to garbage. The client accepts it without complaining and sends back a proxy certificate encrypted with the wrong key — which you then fail to decrypt.

Session key derivation:
```
shared_secret = EVP_PKEY_derive(server_dh_private, client_dh_public)
                  with EVP_PKEY_CTX_set_dh_pad(0)
session_key   = first N bytes of shared_secret
                  where N = EVP_CIPHER_key_length(cipher)  // e.g. 16 for aes-128-cbc
IV            = all zeros
```

---

## 6. The server DH key must persist between two `kXR_auth` round-trips

The GSI handshake requires two `kXR_auth` messages:
1. `kXGC_certreq` (step 1000): client sends a random nonce; server sends DH public key + signed nonce
2. `kXGC_cert` (step 1001): client sends proxy certificate encrypted with the DH session key

The server generates its ephemeral DH key pair during step 1 and needs the private key in step 2 to derive the shared secret. Store it in the per-connection context (`ctx->gsi_dh_key`) and free it after step 2.

---

## 7. `kXR_stat` wire format: size before flags

The `kXR_stat` response body is a null-terminated ASCII string:

```
"<id> <size> <flags> <mtime>\0"
```

Size comes **before** flags. This is also the format used in `kXR_open` retstat responses and `kXR_dirlist` dStat entries — they are all the same.

This is easily confused with the field order in `XProtocol.hh`'s `StatInfo` struct (which lists the fields in a different order for historical reasons). Getting it wrong causes the client to interpret the flags field (e.g. `16` for readable) as the file size.

---

## 8. Proxy certificate verification requires two flags

RFC 3820 proxy certificates are rejected by OpenSSL's `X509_verify_cert()` by default. You must set `X509_V_FLAG_ALLOW_PROXY_CERTS` on **both**:

- The `X509_STORE` object (at configuration time, using `X509_STORE_set_flags`)
- The `X509_STORE_CTX` object (at verification time, using `X509_STORE_CTX_set_flags`)

Setting it on only the store is not sufficient.

---

## 9. CGI parameters must be stripped from write-mode paths

`xrdcp` appends metadata as URL query parameters:

```
/store/mc/file.root?oss.asize=52428800&xrdcl.requuid=abc123
```

These parameters must be stripped (truncate at the first `?`) before any filesystem operations. Passing them to `open(2)` or `stat(2)` returns `ENOENT`.

---

## 10. `kXR_pgwrite` requires a 32-byte `kXR_status` response

xrdcp v5 uses `kXR_pgwrite` for all uploads. The client parses the response as `ServerResponseV2` — a 32-byte structure. Sending a plain 8-byte `kXR_ok` causes the client to read 24 bytes past the end of the response and either crash or hang.

Wire format for a successful pgwrite response (32 bytes total):

```
ServerResponseHdr (8 bytes):
  streamid[2]   ← echo from request
  status[2]     ← kXR_status (4007), NOT kXR_ok (4000)
  dlen[4]       ← 24 (body size)

ServerResponseBody_Status (16 bytes):
  crc32c[4]     ← CRC32c of the next 20 bytes
  streamID[2]   ← echo from request
  requestid[1]  ← kXR_pgwrite - kXR_1stRequest = 26
  resptype[1]   ← 0
  reserved[4]   ← zeros
  dlen[4]       ← 0 (no bad pages)

ServerResponseBody_pgWrite (8 bytes):
  offset[8]     ← last written file offset (big-endian)
```

CRC32c uses the Castagnoli polynomial (0x82F63B78). Initial value `0xFFFFFFFF`, final XOR `0xFFFFFFFF`. Test vector: `CRC32c("123456789") == 0xE3069283`.

---

## 11. `kXR_pgwrite` payload layout: CRC comes first per page

Each page in the `kXR_pgwrite` payload is structured as:

```
[4 bytes CRC32c] [up to 4096 bytes of file data]
```

The CRC comes **first**, not last. For a file smaller than one page, the entire payload is `[4 bytes CRC] [file data]`. For an 8 MB chunk, there are ~2000 CRC+data pairs interleaved.

The module strips the CRCs and writes only the file data to disk.

---

## 12. Write payload size needs a separate limit from path size

The module uses a small buffer (`XROOTD_MAX_PATH + 64` ≈ 4 KB) for most requests, since most XRootD requests carry only paths, handles, and small metadata. If this same limit applies to write payloads, `xrdcp` connects, opens the file, and then the connection drops silently when the first 8 MB write payload arrives.

The fix is a separate constant `XROOTD_MAX_WRITE_PAYLOAD = 16 MB` that applies only to `kXR_pgwrite`, `kXR_write`, and `kXR_writev`.

---

## 13. `kXR_mv` payload uses a space separator, not a null byte

The `ClientMvRequest.arg1len` field is the byte length of the source path **not including any terminator**. The payload is:

```
src[arg1len] + ' ' (0x20) + dst[...]
```

The separator is an ASCII space (0x20), not a null byte. Reading the source as a null-terminated C string at `src[arg1len-1]` fails for every path.

From the XRootD client source (`XrdClFileSystem.cc`):
```cpp
req->arg1len = fSource.length();              // no +1
*msg->GetBuffer(24 + fSource.length()) = ' '; // space separator
```

---

## 14. `kXR_new` flag requires `O_EXCL` only when `kXR_delete` is absent

`kXR_new` alone means "create; fail if the file already exists" → `O_CREAT|O_EXCL`.

`xrdcp` sends `kXR_new|kXR_delete` together to mean "create or overwrite" → `O_CREAT|O_TRUNC` (no `O_EXCL`).

| Client flags | OS open flags |
|---|---|
| `kXR_new` only | `O_CREAT \| O_EXCL` |
| `kXR_new \| kXR_delete` | `O_CREAT \| O_TRUNC` |
| `kXR_delete` only | `O_CREAT \| O_TRUNC` |

Omitting `O_EXCL` for `kXR_new` alone silently truncates existing files instead of returning an error.

---

## 15. `kXR_mkdir -p` requires resolving paths that do not yet exist

The path resolver normally calls `realpath(3)` on the parent directory to canonicalize it and check for `..` escape attempts. For a recursive `mkdir -p a/b/c`, neither `a/` nor `a/b/` exists yet, so `realpath` fails with `ENOENT` and the mkdir is rejected before any directory is created.

The fix: when `kXR_mkdirpath` is set (or `kXR_mkpath` on open), use a resolver that scans the path for `..` components rather than calling `realpath`. The `xrootd_root` directory is always trusted; any relative path with no `..` components is safe.

---

## 16. Opening a directory path on Linux returns a valid fd

On Linux, `open(dir_path, O_RDONLY)` succeeds and returns a file descriptor. The XRootD protocol requires `kXR_open` on a directory to fail with `kXR_isDirectory`.

Without an explicit `stat(2)` check, the module hands the client a directory fd. The first `kXR_read` then fails with `EISDIR`, which the client may not handle gracefully.

**Fix:** After resolving a read-mode open path, call `stat(2)` and return `kXR_isDirectory` if `S_ISDIR(st.st_mode)`.

---

## 17. `kXR_dirlist` dStat response must start with a specific 10-byte sentinel

When the client requests per-entry stat (`kXR_dstat` option flag), the response body must begin with the exact 10-byte string `".\n0 0 0 0\n"`.

The client library (`DirectoryList::HasStatInfo`) checks for the 9-byte prefix `".\n0 0 0 0"` at position 0 of the response body. If found, it enters stat-pairing mode and pairs up lines as `(name, stat_string)` alternating. Without the sentinel, every line — including stat strings — is treated as a filename.

Wire format with dStat:
```
".\n0 0 0 0\n"                          ← 10-byte lead-in (REQUIRED)
"<name1>\n<id> <size> <flags> <mtime>\n"  ← filename + stat, repeated
"<name2>\n<id> <size> <flags> <mtime>\n"
...
```
The final `\n` is replaced by `\0`. Intermediate chunks (`kXR_oksofar`) must not contain a `\0`.

Stat field order is `id size flags mtime` — size before flags. This matches `kXR_stat` and `kXR_open` retstat.

---

## 18. Write handler race condition: `XRD_ST_SENDING` guard

There is a concurrency hazard between the nginx write event handler and the AIO completion path.

**The scenario:**
1. A response cannot be sent immediately (OS send buffer full). The module stores the unsent bytes in `ctx->wbuf`, transitions to `XRD_ST_SENDING`, and arms the nginx write event.
2. Before the write event fires, an AIO completion (`xrootd_read_aio_done` etc.) runs via `ngx_post_event`, advances the state machine to `XRD_ST_AIO` or `XRD_ST_REQ_HEADER`, and dispatches the next request.
3. The write event fires. If it unconditionally resets state to `XRD_ST_REQ_HEADER` and calls the read handler, a second AIO is dispatched concurrently.
4. Both AIOs complete and race to overwrite `ctx->wbuf`. The first response's remaining bytes are silently discarded. The client receives a truncated response and hangs waiting for bytes that were never sent.

**Fix:** In `ngx_stream_xrootd_send`, after draining `ctx->wbuf`, check `ctx->state`. If it is no longer `XRD_ST_SENDING`, the pipeline has already advanced and the write handler returns without calling the read path.

This bug only manifests under a specific timing: a large response that requires a second `send()` call, combined with a very fast subsequent read completing before the write event fires. It does not show up in benchmarks but was observed with concurrent clients under load.

---

## 19. Real clients may include one trailing NUL inside path `dlen`

Several path-carrying requests are documented as “path payload follows”, and many client implementations do in fact send a C-string-like trailing `\0` inside the declared payload length.

In practice the safest rule is:

- allow exactly one trailing NUL at `payload[dlen - 1]`
- reject any embedded NUL before the last byte
- convert the result into an internal C string only after validation

Rejecting all NUL bytes outright breaks real clients. Accepting embedded NUL bytes is unsafe because it creates ambiguity between what the protocol length says and what libc file APIs will actually read.

---

## 20. Log sinks need the same kind of hardening as path sinks

The access log and nginx error/debug log receive several values that originate from the client or from client-controlled metadata:

- login usernames
- authenticated subject DNs
- request paths
- request detail strings derived from those paths
- error messages that may include client-originating context

Writing those values raw makes log injection possible: embedded newlines, tabs, quotes, backslashes, or other control bytes can split one logical record into many physical lines or make later parsing ambiguous.

The server now uses a dedicated escaping rule before logging client-controlled text:

- printable safe ASCII stays as-is
- whitespace, control bytes, quotes, backslashes, and non-ASCII bytes are rendered as `\xNN`

This is not a wire-protocol requirement, but it is an implementation requirement for any production-facing server.

---

## 21. Prometheus labels must stay low-cardinality and non-user-controlled

It is tempting to expose usernames, DNs, paths, or client addresses as metric labels. Do not do that here.

The current exporter is intentionally limited to stable, low-cardinality labels:

- `port`
- `auth`
- `op`
- `status`

Using client-controlled strings as labels would create an unbounded metric cardinality problem and would also reintroduce the same sanitization concerns that were removed from the logging path.

---

## 22. Rebuild vs reload matters when testing nginx modules

When iterating on a statically linked nginx module, there are two very different operations:

- rebuild the nginx binary after recompiling the module
- reload nginx configuration for an already-running master process

Only the first one changes code. A plain `nginx -s reload` keeps running the same executable image and just reparses config. If you rebuild `/tmp/nginx-1.28.3/objs/nginx` but only reload, you are still testing the old binary.

For this repo's test setup, the reliable sequence after code changes is:

1. rebuild `/tmp/nginx-1.28.3/objs/nginx`
2. stop the existing test nginx master
3. start the rebuilt binary again with `/tmp/xrd-test/conf/nginx.conf`

That operational detail is easy to forget and explains a lot of “the fix compiled but the behavior did not change” confusion.
