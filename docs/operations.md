# Supported operations

This page describes every XRootD operation the module supports, how to use it from the command line and Python client, and any constraints to be aware of.

If you want the higher-level "what does `xrdcp` usually do to the server?" view,
see [xrdcp-interactions.md](xrdcp-interactions.md). If you want the design
trade-offs behind some of the odd-looking behavior, see [quirks.md](quirks.md).

---

## Connection and session

These operations happen at the start of every connection, before any file access.

### Handshake + `kXR_protocol`

The XRootD client sends a 20-byte binary handshake when it first connects, then immediately sends a `kXR_protocol` request to negotiate capabilities. The module handles both automatically — clients and servers do this without any user-level configuration.

When `xrootd_manager_map` mappings are configured the server sets the `kXR_isManager` capability bit in the `kXR_protocol` response so clients know the server may return redirects.

### `kXR_login`

After the protocol handshake, the client sends its username. For anonymous servers, the module accepts any username. For GSI servers, the login response triggers the certificate exchange. For token servers, the login response advertises the `ztn` bearer-token security protocol.

### `kXR_ping`

A liveness check. Clients occasionally send pings to verify the server is still up. The module replies immediately with `kXR_ok`.

### `kXR_endsess`

The client signals it is done with the session. The module closes all open file handles and acknowledges. The client then closes the TCP connection.

---

## Reading files

### `kXR_stat` — file and directory information

Returns the inode number, size (bytes), flags (readable/writable/directory), and modification time for a path.

```bash
xrdfs localhost:1094 stat /store/mc/sample.root
# Path:   /store/mc/sample.root
# Id:     12345
# Flags:  16 (IsReadable)
# Size:   2147483648
# MTime:  2026-04-14 10:00:00
```

```python
from XRootD import client
fs = client.FileSystem("root://localhost:1094")
status, stat_info = fs.stat("/store/mc/sample.root")
print(stat_info.size)       # file size in bytes
print(stat_info.modtime)    # last modification time
```

You can also stat by open file handle (after `kXR_open`).

---

### `kXR_open` — open a file for reading

Opens a file and returns a file handle (a 4-byte opaque token used in subsequent read requests).

Up to 16 files can be open simultaneously per connection.

```python
from XRootD import client
from XRootD.client.flags import OpenFlags

f = client.File()
status, _ = f.open("root://localhost:1094//store/mc/sample.root", OpenFlags.READ)
# f is now open and ready for kXR_read
```

**Opening directories**: returns `kXR_isDirectory` — you cannot read a directory as a file.

---

### `kXR_read` — read data from an open file

Reads up to 4 MB in a single request. For larger reads, the client automatically retries at the new offset.

```python
status, data = f.read(offset=0, size=1048576)   # read 1 MB from offset 0
```

```bash
xrdcp root://localhost:1094//store/mc/sample.root /tmp/local.root
# xrdcp handles the chunking automatically
```

---

### `kXR_readv` — scatter-gather vector read

Reads multiple non-contiguous byte ranges in a single round-trip. This is significantly more efficient than issuing multiple individual `kXR_read` requests when you know which parts of a file you need — common in ROOT file access where the file index is read first to find the data.

Up to 1024 segments per request. Segments can span multiple open files.

```python
# Read three non-contiguous ranges from an open file
chunks = [(0, 100), (4096, 512), (1_048_576, 8192)]
status, result = f.vector_read(chunks)

for chunk in result:
    print(f"offset={chunk.offset} size={len(chunk.buffer)}")
```

---

### `kXR_dirlist` — list a directory

Lists all entries in a directory. Optionally returns stat information for each entry alongside its name (enabled with the `STAT` flag).

```bash
xrdfs localhost:1094 ls /store/mc
xrdfs localhost:1094 ls -l /store/mc   # with stat info
```

```python
from XRootD.client.flags import DirListFlags

status, listing = fs.dirlist("/store/mc", DirListFlags.STAT)
for entry in listing:
    print(entry.name, entry.statinfo.size)
```

---

### `kXR_locate` — file replica location query

`kXR_locate` asks the server for one or more replica locations for a given path. For a simple data server the module returns a single-entry location string in the format `"S<access><host:port>"` where `S` indicates the endpoint is a server and `<access>` is `r` (read-only) or `w` (read-write).

Manager-mode mapping: when `xrootd_manager_map` contains a matching prefix the server returns an XRootD `kXR_redirect` response (status `4004`) instead of a normal location list. The redirect body is encoded as a 4-byte big-endian port followed by the host name bytes (ASCII). Clients should parse the first four bytes as the port and the remaining bytes as the host string.

Both `locate` and `open` consult the configured manager map and will return a redirect when a mapping matches; mappings use longest-prefix matching so more-specific prefixes take precedence.

Configure static mappings using the `xrootd_manager_map /prefix host:port;` directive in the server block. See [Manager Mode](manager-mode.md) for details and examples.

### `kXR_close` — close a file handle

Releases an open file handle and logs throughput. All handles are automatically closed when the connection drops.

```python
f.close()
```

---

## Writing files

Write operations require `xrootd_allow_write on` in the server block. A server without this setting returns `kXR_fsReadOnly` for any write request.

### Opening a file for writing

```python
from XRootD.client.flags import OpenFlags

f = client.File()
# Create or truncate (overwrite if exists)
status, _ = f.open("root://localhost:1094//upload.root",
                   OpenFlags.NEW | OpenFlags.DELETE)
```

Open flags for writing:

| Flag | Meaning |
|---|---|
| `OpenFlags.NEW` | Create the file; fail if it already exists |
| `OpenFlags.DELETE` | Create or overwrite (truncate if exists) |
| `OpenFlags.NEW \| OpenFlags.DELETE` | Same as `DELETE` — create or overwrite |
| `OpenFlags.UPDATE` | Open an existing file for in-place writes |
| `OpenFlags.APPEND` | Open for writes at the end |

---

### `kXR_pgwrite` — paged write with CRC32c (used by xrdcp v5)

The primary write method used by `xrdcp` in XRootD v5. Data is sent in pages with CRC32c fields. The module strips those CRC fields and writes the raw data to disk; it does not currently verify the CRC32c values itself.

```bash
xrdcp /tmp/local_file.root root://localhost:1094//remote_file.root
# xrdcp uses kXR_pgwrite automatically — no user configuration needed
```

```python
# Python client also uses pgwrite automatically when writing
status, _ = f.write(data, offset=0)
```

---

### `kXR_write` — raw write (v3/v4 clients)

Older XRootD clients (v3, v4) use `kXR_write` instead of `kXR_pgwrite`. The module supports both. If you are using a current client, it will use `kXR_pgwrite`.

---

### `kXR_sync` — flush to disk

Ensures all data written to an open handle is flushed to the filesystem (calls `fsync(2)`).

```python
status, _ = f.sync()
```

---

### `kXR_truncate` — resize a file

Truncates a file to a specific size, either by path or by open file handle.

```python
status, _ = fs.truncate("/data/file.root", 1048576)  # truncate to 1 MB
```

---

## Filesystem management

These operations require `xrootd_allow_write on`.

### `kXR_mkdir` — create a directory

Creates a directory. With the recursive flag (`kXR_mkdirpath`), creates all intermediate directories as needed (like `mkdir -p`).

```bash
xrdfs localhost:1094 mkdir /store/mc/new_dataset
xrdfs localhost:1094 mkdir -p /store/mc/new_dataset/sub/dir
```

```python
from XRootD.client.flags import MkDirFlags
status, _ = fs.mkdir("/store/mc/new_dataset", MkDirFlags.MAKEPATH)
```

---

### `kXR_rmdir` — remove an empty directory

```bash
xrdfs localhost:1094 rmdir /store/mc/empty_dir
```

```python
status, _ = fs.rmdir("/store/mc/empty_dir")
```

---

### `kXR_rm` — delete a file

```bash
xrdfs localhost:1094 rm /store/mc/unwanted_file.root
```

```python
status, _ = fs.rm("/store/mc/unwanted_file.root")
```

---

### `kXR_mv` — rename or move

Renames a file or directory. Both source and destination must be on the same filesystem (this calls `rename(2)` internally, which is a single atomic syscall and does not copy data).

```bash
xrdfs localhost:1094 mv /store/mc/old_name.root /store/mc/new_name.root
```

```python
status, _ = fs.mv("/store/mc/old.root", "/store/mc/new.root")
```

---

### `kXR_chmod` — change permissions

Changes file or directory permission bits (Unix 9-bit mode: owner/group/other × read/write/execute).

```bash
xrdfs localhost:1094 chmod 0644 /store/mc/file.root
```

```python
from XRootD.client.flags import AccessMode
status, _ = fs.chmod("/store/mc/file.root", AccessMode.UR | AccessMode.UW | AccessMode.GR | AccessMode.OR)
```

---

## Queries

### `kXR_query` — server queries

#### Checksum (`QueryCode.CHECKSUM`)

Returns a checksum for a file. The server supports multiple algorithms; the
default is `adler32` (8 hex digits). You can explicitly request `md5`,
`sha1` or `sha256` by prefixing the path with the algorithm token using
either `"<alg>:<path>"` or `"<alg> <path>"` (for example
`sha256:/store/mc/sample.root`).

Examples:

```bash
xrdfs localhost:1094 query checksum /store/mc/sample.root
# adler32 1a2b3c4d

xrdfs localhost:1094 query checksum md5:/store/mc/sample.root
# md5 0123456789abcdef0123456789abcdef

xrdfs localhost:1094 query checksum sha256:/store/mc/sample.root
# sha256 0123456789abcdef... (64 hex digits)
```

```python
from XRootD.client.flags import QueryCode
status, resp = fs.query(QueryCode.CHECKSUM, "/store/mc/sample.root")
# resp → b"adler32 1a2b3c4d\x00"

status, resp = fs.query(QueryCode.CHECKSUM, "md5:/store/mc/sample.root")
# resp → b"md5 0123456789abcdef0123456789abcdef\x00"

status, resp = fs.query(QueryCode.CHECKSUM, "sha256:/store/mc/sample.root")
# resp → b"sha256 0123456789abcdef...\x00" (64-hex digits)
```

`xrdcp` continues to use the adler32 response when instructed with
`--cksum adler32:print`.

#### Space (`QueryCode.SPACE`)

Returns disk space statistics for the `xrootd_root` filesystem.

```bash
xrdfs localhost:1094 spaceinfo /
```

```python
status, resp = fs.query(QueryCode.SPACE, "/")
# resp contains oss.cgroup, oss.space, oss.free, oss.used, oss.quota
```

---

## Limits

| Limit | Value |
|---|---|
| Simultaneous open files per connection | 16 |
| Maximum read size per request | 4 MB |
| Maximum write chunk size | 16 MB |
| Maximum path length | 4 KB |
| Maximum `kXR_readv` segments per request | 1024 |
| Maximum total `kXR_readv` response | 256 MB |

---

## Authentication and authorisation notes

All data and namespace operations require a completed session login. When `xrootd_auth` is `gsi`, `token`, or `both`, the client must also complete the advertised security exchange before file operations are accepted.

Native stream write access is controlled by `xrootd_allow_write`. JWT/WLCG scopes are parsed during token authentication, but native stream operations do not currently enforce `storage.read` or `storage.write` scopes per path. Path-level restrictions use `xrootd_require_vo`; token `wlcg.groups` claims are mapped into the same VO list used by VOMS proxies.
