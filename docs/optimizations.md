# Optimizations in nginx-xrootd

This document focuses on code-level optimizations already implemented in the
module and why they help. It is intentionally about changes in the module
itself, not just "tune nginx harder".

---

## What has been optimized

The biggest improvements fall into five buckets:

1. reducing scheduler contention under many simultaneous transfers
2. reducing syscall count on hot paths
3. reducing userspace copies for large reads and uploads
4. moving blocking disk I/O off nginx event-loop threads
5. avoiding repeated expensive auth and path-resolution work

Some of these matter most for `root://`, some for `davs://`, and some for both.

---

## 1. Event-driven workers instead of one thread per connection

The biggest architectural advantage over a classic thread-per-connection server
is that nginx workers stay event-driven:

- idle sockets are cheap
- a worker only does work for connections that are actually ready
- large fan-out workloads do not create one kernel thread per client

That is why the concurrency numbers in the README improve sharply as connection
count rises: the scheduler is doing less thread wake/sleep work, and the nginx
workers spend more time moving data.

This is not a small micro-optimization. It is the reason the module scales much
better at 32, 64, or 128 parallel transfers.

---

## 2. Thread-pool offload for blocking disk I/O

Both the stream module and the WebDAV module can offload blocking disk work to
nginx thread pools:

- native XRootD:
  - async `pread()` for `kXR_readv`
  - async `pwrite()` for `kXR_write`
  - async flattened writes for `kXR_pgwrite`
- WebDAV:
  - async `PUT` writes when the request body is already in memory

Why it helps:

- the nginx event loop does not stall on slow storage
- one slow disk operation does not pause unrelated sockets on the same worker
- parallel transfers stay fairer under mixed workloads

Relevant directives:

- `xrootd_thread_pool`
- `xrootd_webdav_thread_pool`

Relevant code:

- `src/ngx_xrootd_read_handlers.c`
- `src/ngx_xrootd_write_handlers.c`
- `src/ngx_http_xrootd_webdav_module.c`

---

## 3. Native `kXR_read` uses file-backed chain buffers

For regular files on non-TLS stream connections, the native `kXR_read` path
does not copy the whole read into a second response buffer. Instead it builds:

- a small in-memory XRootD response header
- a file-backed nginx buffer pointing at the on-disk byte range

That lets nginx's `send_chain` path use the platform sendfile implementation
when available.

Why it helps:

- avoids an extra copy from kernel page cache into a large userspace response
  buffer
- reduces CPU time for large sequential reads
- lets nginx stream large responses in chunks without reformatting the file data

This is implemented in:

- `src/ngx_xrootd_read_handlers.c`
- `src/ngx_xrootd_aio.c`

### TLS caveat

The stream TLS path intentionally falls back to a memory-backed `pread()` path.
Without kernel TLS support, nginx's SSL send path is not a reliable place to
hand off file-backed XRootD chain buffers. So the optimization is "use sendfile
when it is correct, fall back when encryption changes the transport rules".

That trade-off keeps the implementation correct while still preserving the fast
path for raw `root://` reads.

---

## 4. `kXR_readv` avoids extra packing passes

`readv` is awkward because the XRootD wire format interleaves a 16-byte segment
descriptor with the data for each requested range. That means you cannot just
send a list of raw file slices the way plain `kXR_read` can.

The optimized `readv` path does three useful things:

1. lays out one reusable response buffer in the final wire format
2. reads each segment directly into its eventual output slice
3. queues the result as a header/data chain instead of copying everything into
   another giant response blob

Why it helps:

- fewer copy passes
- fewer temporary allocations
- better cache locality when many small ranges are returned together

The response workspace is also reused per connection, which stops the pool from
growing on every large `readv`.

---

## 5. Reusable scratch buffers for read-heavy sessions

The stream connection context keeps reusable scratch space for:

- read data bodies
- read response headers

Why it helps:

- avoids repeated pool growth and churn during sustained large reads
- reduces allocator overhead on long-lived high-throughput sessions
- keeps the hot-path working set more stable

Relevant code:

- `src/ngx_xrootd_aio.c`
- `src/ngx_xrootd_module.h`

---

## 6. Readahead hints before large reads

Both native XRootD reads and WebDAV downloads use `posix_fadvise(...,
POSIX_FADV_WILLNEED)` when appropriate.

Why it helps:

- the kernel can start populating page cache before the actual send path asks
  for the bytes
- reduces the chance that the worker blocks right when it reaches the send step
- helps especially for large sequential transfers and clustered `readv` ranges

For `readv` the module also coalesces nearby ranges before issuing the hint, so
it does not spam the kernel with one tiny readahead request per segment.

---

## 7. Posted-event send continuation for large responses

Large responses often make partial progress even when the socket is still
technically writable. The stream send path therefore:

- spins a small bounded number of times on `send_chain`
- then posts the write event back into nginx's posted-event queue

Why it helps:

- keeps a large transfer moving without waiting for another full poll cycle
- still yields often enough that other ready connections get CPU time
- reduces unnecessary wake/sleep churn on busy workers

Relevant code:

- `src/ngx_xrootd_connection.c`
- `src/ngx_xrootd_module.h` (`XROOTD_SEND_CHAIN_SPIN_MAX`)

---

## 8. `kXR_pgwrite` flattens once, then writes once

Modern XRootD clients prefer `kXR_pgwrite`, where each page arrives as:

```text
[CRC32c][page data][CRC32c][page data]...
```

The module strips the per-page CRC fields into one flat data buffer and then
writes that flattened payload with a single `pwrite()` path, either sync or via
the thread pool.

Why it helps:

- avoids issuing one write syscall per tiny sub-fragment
- gives the kernel a contiguous payload to write
- keeps the protocol-specific CRC framing from leaking into the storage path

The code deliberately skips CRC verification here; for the intended localhost
and trusted-LAN transfer path, that saves CPU and the transport already has its
own integrity checks.

---

## 9. WebDAV pre-resolves the export root once

The WebDAV module resolves `xrootd_webdav_root` to a canonical absolute path at
config time and stores it in `root_canon`.

Why it helps:

- eliminates one `realpath()` call from every request
- avoids the cascade of `lstat()` work that `realpath()` performs on each path
  component
- makes request-time path validation cheaper and more predictable

This matters more than it sounds because `GET`, `HEAD`, `PUT`, `DELETE`,
`MKCOL`, and `PROPFIND` all need path handling.

---

## 10. WebDAV GET keeps a per-connection fd table

The WebDAV path keeps a small fd cache on the HTTP connection, sized by
`WEBDAV_FD_TABLE_SIZE` (currently 16 entries).

Each cached entry records:

- the open fd
- canonical path
- URI hash
- inode/device
- open time

Why it helps:

- repeated keepalive `GET` and `HEAD` requests can reuse an already-open fd
- the hot path can skip `resolve_path()`, `open()`, and a separate `stat()`
- the cache validates entries with `fstat()` and evicts stale or unlinked files

On a cache hit the request can get by with one `fstat()` on an existing fd
instead of another full pathname walk.

The cache is explicitly evicted on writes and deletes so stale content is not
served after mutation.

---

## 11. WebDAV miss path changed from `stat()+open()` to `open()+fstat()`

When the fd cache misses, the WebDAV `GET` path now opens first and then uses
`fstat()` on that fd, rather than doing a separate `stat()` before `open()`.

Why it helps:

- one fewer pathname-based syscall on the miss path
- less duplicate VFS work
- one less race window between "checked the path" and "opened the path"

It is a small change, but on large transfer workloads the hot path is mostly
"death by a thousand small syscalls", so these reductions matter.

---

## 12. WebDAV GET uses file-backed output buffers

The WebDAV download path builds file-backed nginx buffers and hands them to the
normal HTTP output filter chain, including Range responses.

Why it helps:

- the data path stays streaming-oriented instead of assembling giant response
  buffers in user memory
- nginx can use its normal file-output optimizations where the platform and TLS
  stack allow it
- memory usage stays flatter for large files and long ranges

Combined with the fd cache and readahead hint, this is the main reason the
WebDAV read path is much less wasteful than a naive "read the whole file into a
malloc buffer and then `SSL_write()` it" implementation.

---

## 13. WebDAV PUT has a kernel-side temp-file fast path

Large HTTPS uploads often arrive in nginx as spooled temp files under
`client_body_temp_path`. The optimized WebDAV `PUT` path detects those file
buffers and copies them to the destination with:

- `copy_file_range()` on Linux when available
- a 1 MiB buffered fallback when the kernel fast path is unavailable

Why it helps:

- fewer syscalls for 1 GiB-class uploads
- less userspace bounce-buffer copying
- larger fallback copy chunks than the older small-loop approach

This is one of the most important fixes for the "too many syscalls per query"
problem on large WebDAV writes.

---

## 14. WebDAV PUT can offload in-memory request bodies

When nginx already has the full request body in memory, the WebDAV module can
coalesce it once and hand the actual blocking write to a thread pool.

Why it helps:

- the HTTP worker does not sit in a blocking write loop
- mixed read/write traffic stays smoother
- small and medium uploads avoid penalizing unrelated keepalive connections

This does not replace the spooled-file fast path above. It complements it for
the cases where nginx never needed to spill the request body to disk.

---

## 15. WebDAV x509 auth avoids repeating expensive verification work

The WebDAV TLS/x509 path has several implemented fast paths:

### Cached CA/CRL store

The CA store is built once at config load instead of rebuilding trust state on
every request.

### nginx-verified fast path

If nginx's SSL trust configuration matches the WebDAV module's trust inputs, a
request can reuse nginx's own successful certificate verification result.

### TLS connection and session caches

The verified subject DN is cached:

- on the live TLS connection
- on the `SSL_SESSION`

That means keepalive requests and resumed sessions can skip repeated
`X509_verify_cert()` work.

Why it helps:

- certificate verification is expensive relative to steady-state bulk I/O
- repeated GET/HEAD requests on one TLS session become much cheaper
- resumed HTTPS sessions avoid paying the full auth cost again

This is especially relevant for `xrdcp` and similar clients that perform more
than one request over the same HTTPS session.

---

## 16. Token auth is fully local

Both the stream and WebDAV token paths load JWKS keys from disk at startup and
verify bearer tokens locally.

Why it helps:

- no per-request network call to an identity provider
- predictable latency
- no dependency on external control-plane availability during transfers

This is not just a convenience feature. It removes an entire class of latency
and failure modes from the request path.

---

## 17. Handle-based native operations reuse open-file state

Once the native stream path has opened a file, later operations such as
handle-based `stat` and checksum queries use the open fd and cached canonical
path rather than resolving the pathname all over again.

Why it helps:

- fewer path-resolution syscalls on follow-up requests
- less repeated `realpath()`/`stat()` work
- logging can use the cached path while metadata comes from `fstat()`

This is one of those changes that is modest per request and very noticeable at
scale.

---

## What still costs real time

Even with these optimizations in place, some costs are intrinsic:

- TLS still adds encryption/decryption work
- WebDAV still carries HTTP framing and method handling on top of file I/O
- `readv` still needs some packing work because of the XRootD wire format
- revocation checks and proxy-chain verification still cost CPU when x509 auth
  is actually performed

So the goal of the module is not "make HTTPS identical to raw cleartext file
serving". The goal is "remove avoidable syscalls, copies, and event-loop
blocking so the remaining overhead is the one you actually asked for".

---

## Where to look in the tree

If you want to trace the implementation behind these optimizations, start here:

- `src/ngx_xrootd_connection.c`
- `src/ngx_xrootd_aio.c`
- `src/ngx_xrootd_read_handlers.c`
- `src/ngx_xrootd_write_handlers.c`
- `src/ngx_http_xrootd_webdav_module.c`
- `tests/test_gsi_tls.py`
- `tests/test_webdav_auth_cache.py`
- `tests/test_webdav_spooled_put.py`

The benchmark-oriented config and notes in [benchmarks.md](benchmarks.md) are a
good companion to this page.
