# Manager Mode (static path → backend mapping)

The manager-mode feature provides a simple static mapping from request path prefixes
to backend host:port endpoints. When a locate or open request matches a configured
prefix the server responds with an XRootD `kXR_redirect` response pointing the
client to the mapped backend.

Directive

- `xrootd_manager_map /prefix host:port;`

Behavior

- The `prefix` is normalized by the same path-normalization used by other
  policy directives (see the code comment for `xrootd_normalize_policy_path`).
- Lookups use longest-prefix matching — the most-specific configured mapping
  that matches the request path is selected.
- When a mapping matches, the server returns `kXR_redirect` (status 4004). The
  redirect body is formatted as a 4-byte big-endian port followed by the host
  bytes (ASCII). Clients should parse the first four bytes as the port and the
  remaining bytes as the host string.
- `locate` and `open` both consult the manager map. `locate` returns a redirect
  immediately when a map entry is found; `open` also redirects before attempting
  local resolution.

Handshake advertisement

- When `manager_map` contains at least one mapping the server advertises the
  `kXR_isManager` capability bit in the `kXR_protocol` response so clients are
  aware the server can behave as a manager/redirector.

Examples

```
stream {
    server {
        listen 127.0.0.1:11094;
        xrootd on;
        xrootd_manager_map /maps backend.example.org:54321;
        xrootd_manager_map /maps/prefix backend2.example.org:12345;
    }
}
```

Notes

- The redirect body contains no trailing NUL; parse the host using the body
  length minus four bytes.
- Manager-mode is intentionally simple: it is a static map useful for small
  deployments or as a building block for an external manager process that
  programs the mappings via configuration and restarts.
