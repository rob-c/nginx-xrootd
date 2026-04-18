#include "ngx_xrootd_module.h"

/* ================================================================== */
/*  kXR_query handler                                                   */
/*                                                                      */
/*  This file handles the kXR_query opcode, which multiplexes several   */
/*  unrelated server-information requests behind a single request type. */
/*  The infotype field decides which sub-query is in use:               */
/*                                                                      */
/*    kXR_Qcksum  (3/8) — compute adler32 checksum for a file by       */
/*                         path or by open handle.                      */
/*    kXR_Qspace  (6)   — report available storage space.              */
/*    kXR_Qconfig (7)   — server configuration capability query.       */
/*                                                                      */
/*  Query is read-only — it never modifies data.  Each sub-query has   */
/*  its own payload expectations and response text format, documented   */
/*  inline below.                                                       */
/*                                                                      */
/*  The adler32 implementation is a simple iterative checksum over the  */
/*  file contents, not the adler32 from zlib.  It runs synchronously   */
/*  in the event loop because checksumming large files in a single     */
/*  thread would block the worker; a production deployment should use  */
/*  pre-computed checksum databases (not yet implemented).              */
/* ================================================================== */


/* ------------------------------------------------------------------ */
/* Helpers                                                              */
/* ------------------------------------------------------------------ */

/*
 * Compute adler32 of a file identified by an already-resolved path.
 *
 * Adler32 algorithm (RFC 1950 §9):
 *   A_0 = 1, B_0 = 0
 *   For each byte b: A += b; B += A;  (mod 65521, the largest prime < 2^16)
 *   Result = (B << 16) | A
 *
 * Returns the checksum value, or 0xFFFFFFFF on I/O error.
 */
static uint32_t
xrootd_adler32_file(const char *path, ngx_log_t *log)
{
    int          fd;
    ssize_t      n;
    uint32_t     A = 1, B = 0;
    const uint32_t MOD = 65521;
    u_char       buf[65536];
    char         safe_path[512];

    xrootd_sanitize_log_string(path, safe_path, sizeof(safe_path));

    fd = open(path, O_RDONLY);
    if (fd < 0) {
        ngx_log_error(NGX_LOG_ERR, log, errno,
                      "xrootd: adler32 open(\"%s\") failed", safe_path);
        return 0xFFFFFFFF;
    }

    for (;;) {
        /* Stream the file in fixed-size blocks so checksum cost is bounded in memory. */
        n = read(fd, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR) continue;
            ngx_log_error(NGX_LOG_ERR, log, errno,
                          "xrootd: adler32 read(\"%s\") failed", safe_path);
            close(fd);
            return 0xFFFFFFFF;
        }
        if (n == 0) break;

        /* Adler32 is inherently iterative, so fold each byte into A/B in order. */
        for (ssize_t i = 0; i < n; i++) {
            A = (A + buf[i]) % MOD;
            B = (B + A)      % MOD;
        }
    }

    close(fd);
    return (B << 16) | A;
}

/*
 * Append a formatted string to a kXR_Qconfig response buffer.
 * Returns 1 on success, 0 if the buffer is full.
 */
static ngx_flag_t
xrootd_qconfig_append(char *resp, size_t resp_sz, size_t *pos,
                      const char *fmt, ...)
{
    va_list ap;
    int     n;
    size_t  remaining;

    if (resp == NULL || pos == NULL || *pos >= resp_sz) {
        return 0;
    }

    remaining = resp_sz - *pos;

    va_start(ap, fmt);
    n = vsnprintf(resp + *pos, remaining, fmt, ap);
    va_end(ap);

    if (n < 0 || (size_t) n >= remaining) {
        resp[*pos] = '\0';
        return 0;
    }

    *pos += (size_t) n;
    return 1;
}


/* ------------------------------------------------------------------ */
/* kXR_query — query server information.                               */
/*                                                                     */
/* Supported infotypes:                                                */
/*   kXR_QChecksum (8) — compute adler32 checksum for a file by path  */
/*                       or by open handle.                            */
/*                       Response: "<algo> <hexval>\0"                 */
/*                       e.g.    "adler32 1a2b3c4d\0"                 */
/*                                                                     */
/*   kXR_QSpace (6)    — report available storage space for xrootd_root. */
/*                       Response: oss.* key-value string (text).      */
/*                       e.g. "oss.cgroup=default&oss.space=53687091200 */
/*                             &oss.free=42949672960&oss.maxf=42949672960 */
/*                             &oss.used=10737418240&oss.quota=-1\0"   */
/*                                                                     */
/*   kXR_Qconfig (7)   — server configuration capability query.       */
/*                       Payload: newline-separated list of config keys */
/*                       the client wants.                              */
/*                       Response: "key=value\n" pairs.                */
/*                       Unknown keys echo back as "key=0\n".          */
/*                                                                     */
/* All other infotypes return kXR_Unsupported.                         */
/* ------------------------------------------------------------------ */
ngx_int_t
xrootd_handle_query(xrootd_ctx_t *ctx, ngx_connection_t *c,
                    ngx_stream_xrootd_srv_conf_t *conf)
{
    ClientQueryRequest *req = (ClientQueryRequest *) ctx->hdr_buf;
    uint16_t infotype = ntohs(req->infotype);

    /*
     * kXR_query multiplexes several unrelated info requests behind one opcode.
     * The infotype field decides which sub-protocol is in use, so each branch
     * below has its own payload expectations and response text format.
     */

    /* ---- kXR_Qcksum (3): adler32 by path or open handle ---- */
    if (infotype == kXR_Qcksum) {
        char     resolved[PATH_MAX];
        char     pathbuf[XROOTD_MAX_PATH + 1];
        uint32_t cksum;
        char     resp[64];

        if (ctx->cur_dlen > 0 && ctx->payload != NULL) {
            /*
             * Path-based checksum follows the usual request-path pipeline:
             * normalize wire bytes, strip CGI hints, resolve under root, then
             * checksum the canonical target path.
             */
            if (!xrootd_extract_path(c->log, ctx->payload, ctx->cur_dlen,
                                     pathbuf, sizeof(pathbuf), 1)) {
                XROOTD_OP_ERR(ctx, XROOTD_OP_QUERY_CKSUM);
                return xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                         "invalid path payload");
            }

            if (!xrootd_resolve_path(c->log, &conf->root,
                                     pathbuf, resolved, sizeof(resolved))) {
                xrootd_log_access(ctx, c, "QUERY", pathbuf, "cksum",
                                  0, kXR_NotFound, "file not found", 0);
                XROOTD_OP_ERR(ctx, XROOTD_OP_QUERY_CKSUM);
                return xrootd_send_error(ctx, c, kXR_NotFound,
                                         "file not found");
            }

            if (xrootd_check_vo_acl(c->log, resolved, conf->vo_rules,
                                     ctx->vo_list) != NGX_OK) {
                xrootd_log_access(ctx, c, "QUERY", resolved, "cksum",
                                  0, kXR_NotAuthorized, "VO not authorized", 0);
                XROOTD_OP_ERR(ctx, XROOTD_OP_QUERY_CKSUM);
                return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                         "VO not authorized");
            }

            cksum = xrootd_adler32_file(resolved, c->log);
            if (cksum == 0xFFFFFFFF) {
                xrootd_log_access(ctx, c, "QUERY", resolved, "cksum",
                                  0, kXR_IOError, "read error", 0);
                XROOTD_OP_ERR(ctx, XROOTD_OP_QUERY_CKSUM);
                return xrootd_send_error(ctx, c, kXR_IOError,
                                         "checksum computation failed");
            }

        } else {
            /*
             * Handle-based checksum reuses the canonical path cached at open time
             * rather than trying to reconstruct a path from the opaque handle.
             */
            int idx = (int)(unsigned char) req->fhandle[0];
            if (idx < 0 || idx >= XROOTD_MAX_FILES
                        || ctx->files[idx].fd < 0) {
                XROOTD_OP_ERR(ctx, XROOTD_OP_QUERY_CKSUM);
                return xrootd_send_error(ctx, c, kXR_FileNotOpen,
                                         "invalid file handle");
            }
            ngx_cpystrn((u_char *) resolved,
                        (u_char *) ctx->files[idx].path,
                        sizeof(resolved));
            cksum = xrootd_adler32_file(resolved, c->log);
            if (cksum == 0xFFFFFFFF) {
                XROOTD_OP_ERR(ctx, XROOTD_OP_QUERY_CKSUM);
                return xrootd_send_error(ctx, c, kXR_IOError,
                                         "checksum computation failed");
            }
        }

        /* Response format is fixed text understood by XRootD clients verbatim. */
        /* The trailing NUL is required because clients treat the body as a C string. */
        snprintf(resp, sizeof(resp), "adler32 %08x", (unsigned int) cksum);

        xrootd_log_access(ctx, c, "QUERY", resolved, "cksum", 1, 0, NULL, 0);
        XROOTD_OP_OK(ctx, XROOTD_OP_QUERY_CKSUM);
        return xrootd_send_ok(ctx, c, resp, (uint32_t)(strlen(resp) + 1));
    }

    /* ---- kXR_Qspace (5): storage space for xrootd_root ---- */
    if (infotype == kXR_Qspace) {
        struct statvfs  vfs;
        char            resp[256];
        unsigned long long total, free_bytes, used_bytes;

        /*
         * Space queries are export-level rather than path-level: ask the host
         * filesystem backing xrootd_root and report the answer in oss.* form.
         */
        if (statvfs((const char *) conf->root.data, &vfs) != 0) {
            xrootd_log_access(ctx, c, "QUERY", (char *) conf->root.data,
                              "space", 0, kXR_IOError, strerror(errno), 0);
            XROOTD_OP_ERR(ctx, XROOTD_OP_QUERY_SPACE);
            return xrootd_send_error(ctx, c, kXR_IOError,
                                     "statvfs failed");
        }

        total      = (unsigned long long) vfs.f_blocks * vfs.f_frsize;
        free_bytes = (unsigned long long) vfs.f_bavail * vfs.f_frsize;
        used_bytes = total - (unsigned long long) vfs.f_bfree * vfs.f_frsize;

        /*
         * oss.* key-value format as used by XRootD's OSS layer:
         *   oss.cgroup  — storage group name (use "default")
         *   oss.space   — total filesystem bytes
         *   oss.free    — bytes available to unpriv processes (f_bavail)
         *   oss.maxf    — largest single free segment (approximate: == free)
         *   oss.used    — bytes used
         *   oss.quota   — -1 means no quota configured
         */
        snprintf(resp, sizeof(resp),
                 "oss.cgroup=default"
                 "&oss.space=%llu"
                 "&oss.free=%llu"
                 "&oss.maxf=%llu"
                 "&oss.used=%llu"
                 "&oss.quota=-1",
                 total, free_bytes, free_bytes, used_bytes);

        xrootd_log_access(ctx, c, "QUERY", (char *) conf->root.data,
                          "space", 1, 0, NULL, 0);
        XROOTD_OP_OK(ctx, XROOTD_OP_QUERY_SPACE);
        return xrootd_send_ok(ctx, c, resp, (uint32_t)(strlen(resp) + 1));
    }

    /* ---- kXR_Qconfig (7): configuration query ---- */
    if (infotype == kXR_Qconfig) {
        /*
         * The payload is a newline-separated list of config keys the client
         * wants.  We respond with "key=value\n" pairs; keys we don't know
         * echo back as "key=0\n".  xrdcp queries "chksum" and "readv" among
         * others; we advertise adler32 support.
         */
        char    resp[512];
        size_t  pos = 0;
        const char *p = (ctx->payload && ctx->cur_dlen > 0)
                        ? (const char *) ctx->payload : "";
        const char *nl;

        /*
         * The client may ask for many keys in one request. We intentionally do
         * not fail unknown keys because upstream servers also answer best-effort
         * capability queries one line at a time.
         */
        /* Walk one requested key per iteration until the newline-delimited list is exhausted. */
        while (*p) {
            nl = strchr(p, '\n');
            size_t keylen = nl ? (size_t)(nl - p) : strlen(p);
            char key[128];
            if (keylen >= sizeof(key)) keylen = sizeof(key) - 1;
            memcpy(key, p, keylen);
            key[keylen] = '\0';

            if (strcmp(key, "chksum") == 0) {
                if (!xrootd_qconfig_append(resp, sizeof(resp), &pos,
                                           "chksum=adler32\n")) {
                    break;
                }
            } else if (strcmp(key, "readv") == 0) {
                if (!xrootd_qconfig_append(resp, sizeof(resp), &pos,
                                           "readv=1\n")) {
                    break;
                }
            } else {
                if (!xrootd_qconfig_append(resp, sizeof(resp), &pos,
                                           "%s=0\n", key)) {
                    break;
                }
            }
            p = nl ? nl + 1 : p + keylen;
        }
        if (pos == 0) {
            /* No keys requested is still a valid query, just with an empty body. */
            return xrootd_send_ok(ctx, c, NULL, 0);
        }
        return xrootd_send_ok(ctx, c, resp, (uint32_t) pos);
    }

    /* All other query types: not implemented */
    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: kXR_query unsupported infotype=%d",
                   (int) infotype);
    return xrootd_send_error(ctx, c, kXR_Unsupported,
                             "query type not supported");
}
