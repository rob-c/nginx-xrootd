# Development

## Source layout

| File | Responsibility |
|---|---|
| `src/ngx_stream_xrootd_module.c` | Module entry point, directive registration |
| `src/ngx_xrootd_config.c` | Configuration parsing and validation |
| `src/ngx_xrootd_connection.c` | Session state machine, send/recv flow |
| `src/ngx_xrootd_handshake.c` | Handshake and opcode dispatch |
| `src/ngx_xrootd_session.c` | Login, protocol negotiation, ping, teardown |
| `src/ngx_xrootd_gsi.c` | GSI/x509 authentication exchange |
| `src/ngx_xrootd_voms.c` | Runtime VOMS support via `dlopen(\"libvomsapi.so.1\")` — VO extraction from proxy certs |
| `src/ngx_xrootd_token.c` / `src/ngx_xrootd_token.h` | JWT/JWKS validation and WLCG scope parsing |
| `src/ngx_xrootd_read_handlers.c` | Metadata and read-side operations |
| `src/ngx_xrootd_write_handlers.c` | Write-side and namespace-mutating operations |
| `src/ngx_xrootd_aio.c` | Async I/O via nginx thread pool |
| `src/ngx_xrootd_response.c` | Response framing helpers |
| `src/ngx_xrootd_path.c` | Path extraction, root confinement, log sanitization |
| `src/ngx_http_xrootd_metrics_module.c` | Prometheus metrics HTTP endpoint |
| `src/ngx_http_xrootd_webdav_module.c` | WebDAV over HTTPS content handler |

The `tests/` directory covers client interoperability, throughput, bridge transfers, GSI, token (JWT/WLCG), WebDAV, metrics, and security regressions.

The `utils/` directory contains standalone helper scripts used during development and testing. See [`utils/README.md`](../utils/README.md) for full usage details.

| Script | Purpose |
|---|---|
| `utils/make_proxy.py` | Generate RFC 3820 GSI proxy certificates — called by the test suite when proxies expire |
| `utils/make_token.py` | Generate WLCG JWT tokens and signing authority (RSA keypair + JWKS) for token auth testing |
| `utils/make_crl.py` | Generate PEM CRLs for local certificate revocation tests |
| `utils/inspect_token.py` | Decode JWT header/payload data and list JWKS key IDs for token debugging |
| `utils/token_examples.py` | Runnable examples for generating custom tokens with `TokenIssuer` |
| `utils/xrd_python_smoke.py` | Smoke-test an endpoint with the XRootD Python client |
| `utils/xrd_proxy.py` | TCP relay that hex-dumps XRootD protocol traffic for wire-level debugging |
| `utils/xrd_ref_server.py` | Minimal reference XRootD data server for calibrating client behaviour |
| `utils/xrd_sec_probe.py` | Adversarial security probe (44 tests): lockups, auth bypass, path traversal, resource exhaustion |

---

## Development workflow

Build and run nginx entirely from the source tree — no system install needed:

```bash
cd /tmp/nginx-1.28.3
make -j$(nproc)

# A reload only reloads config, not a rebuilt binary — always do a full restart
/tmp/nginx-1.28.3/objs/nginx -p /tmp/xrd-test -c conf/nginx.conf -s stop || true
/tmp/nginx-1.28.3/objs/nginx -p /tmp/xrd-test -c conf/nginx.conf

cd /path/to/nginx-xrootd
pytest -q
```

The main test harness in `tests/` expects nginx already running on the base anonymous/GSI/WebDAV ports. Some focused suites start their own sidecar nginx or reference services: conformance and bridge tests use a reference `xrootd`, VO ACL tests use a dedicated VOMS listener, privilege tests use a read-only listener, CRL tests use a revoked-cert listener, and token tests use the token-auth listener described in [building.md](building.md).

---

## Known client and runtime quirks

These came from interoperability debugging and are easy to forget:

- **Trailing NUL in path `dlen`:** Some XRootD clients include a single trailing NUL inside the path length field. The server must tolerate this terminator but still reject embedded NULs before it.
- **`xrdfs ping` not implemented:** In xrootd-client 5.9.2, `xrdfs ... ping` is not available. Use `xrdfs ... ls /` as the readiness probe instead.
- **Repeated upload tests:** Use `xrdcp -f` or remove the destination first; otherwise reruns fail because the file already exists rather than testing the server.
- **Log injection:** All client-controlled strings that reach log output must go through `xrootd_sanitize_log_string()` so control bytes are escaped as `\xNN`.
- **Token auth split:** Native XRootD token auth validates JWTs and parses scopes/groups, but native stream writes are still gated by `xrootd_allow_write`. WebDAV currently enforces token write scopes for `PUT`.
- **Protocol edge cases:** Many things that look obvious from the XRootD spec differ from what real clients actually send. Check [protocol-notes.md](protocol-notes.md) before simplifying any wire-level behavior.
- **nginx `O_EXCL` trap:** `ngx_open_file(path, mode, create, access)` ORs `create` into the flags argument. `NGX_FILE_DEFAULT_ACCESS` is `0644` (octal), and `0644` octal contains the bit for `O_EXCL` (`0200` octal). Always pass `NGX_FILE_DEFAULT_ACCESS` as the `access` (fourth) argument, never as `create`.

---

## Comment style

The code carries heavy inline comments in protocol-dense areas. The convention:

- explain wire-format quirks and client expectations
- explain ownership and lifetime of pool-allocated buffers
- explain why a loop or state transition is structured a particular way
- do not comment single-line syntax that is already self-evident

Protocol knowledge lives next to the code that depends on it so nothing is lost when reading or patching a single file.
