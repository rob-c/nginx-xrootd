#include "ngx_xrootd_module.h"

/* ================================================================== */
/*  Read handlers                                                       */
/* ================================================================== */


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
/* All other infotypes return kXR_Unsupported.                         */
/*                                                                     */
/* Adler32 algorithm:                                                  */
/*   A_0 = 1, B_0 = 0                                                 */
/*   For each byte b: A += b; B += A;  (mod 65521)                    */
/*   Result = (B << 16) | A                                            */
/* ------------------------------------------------------------------ */

/*
 * Compute adler32 of a file identified by an already-resolved path.
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

    fd = open(path, O_RDONLY);
    if (fd < 0) {
        ngx_log_error(NGX_LOG_ERR, log, errno,
                      "xrootd: adler32 open(\"%s\") failed", path);
        return 0xFFFFFFFF;
    }

    for (;;) {
        n = read(fd, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR) continue;
            ngx_log_error(NGX_LOG_ERR, log, errno,
                          "xrootd: adler32 read(\"%s\") failed", path);
            close(fd);
            return 0xFFFFFFFF;
        }
        if (n == 0) break;

        for (ssize_t i = 0; i < n; i++) {
            A = (A + buf[i]) % MOD;
            B = (B + A)      % MOD;
        }
    }

    close(fd);
    return (B << 16) | A;
}

ngx_int_t
xrootd_handle_query(xrootd_ctx_t *ctx, ngx_connection_t *c,
                    ngx_stream_xrootd_srv_conf_t *conf)
{
    ClientQueryRequest *req = (ClientQueryRequest *) ctx->hdr_buf;
    uint16_t infotype = ntohs(req->infotype);

    /* ---- kXR_Qcksum (3): adler32 by path or open handle ---- */
    if (infotype == kXR_Qcksum) {
        char     resolved[PATH_MAX];
        uint32_t cksum;
        char     resp[64];

        if (ctx->cur_dlen > 0 && ctx->payload != NULL) {
            /* Path-based checksum */
            char pathbuf[XROOTD_MAX_PATH + 1];
            xrootd_strip_cgi((const char *) ctx->payload,
                             pathbuf, sizeof(pathbuf));

            if (!xrootd_resolve_path(c->log, &conf->root,
                                     pathbuf, resolved, sizeof(resolved))) {
                xrootd_log_access(ctx, c, "QUERY", pathbuf, "cksum",
                                  0, kXR_NotFound, "file not found", 0);
                XROOTD_OP_ERR(ctx, XROOTD_OP_QUERY_CKSUM);
                return xrootd_send_error(ctx, c, kXR_NotFound,
                                         "file not found");
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
            /* Handle-based checksum */
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

        /* Response format: "adler32 <8-hex-digits>\0" */
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

        /* statvfs on the configured root directory */
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

        while (*p) {
            nl = strchr(p, '\n');
            size_t keylen = nl ? (size_t)(nl - p) : strlen(p);
            char key[128];
            if (keylen >= sizeof(key)) keylen = sizeof(key) - 1;
            memcpy(key, p, keylen);
            key[keylen] = '\0';

            int n;
            if (strcmp(key, "chksum") == 0) {
                n = snprintf(resp + pos, sizeof(resp) - pos,
                             "chksum=adler32\n");
            } else if (strcmp(key, "readv") == 0) {
                n = snprintf(resp + pos, sizeof(resp) - pos, "readv=1\n");
            } else {
                n = snprintf(resp + pos, sizeof(resp) - pos, "%s=0\n", key);
            }
            if (n > 0) pos += (size_t) n;
            if (pos >= sizeof(resp) - 1) break;
            p = nl ? nl + 1 : p + keylen;
        }
        if (pos == 0) {
            /* no keys requested — return empty ok */
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


/* kXR_stat — stat by path or by open file handle */
ngx_int_t
xrootd_handle_stat(xrootd_ctx_t *ctx, ngx_connection_t *c,
                   ngx_stream_xrootd_srv_conf_t *conf)
{
    ClientStatRequest *req = (ClientStatRequest *) ctx->hdr_buf;
    struct stat        st;
    char               resolved[PATH_MAX];
    char               body[256];
    ngx_flag_t         is_vfs;
    const char        *reqpath = NULL;

    is_vfs = (req->options & kXR_vfs) ? 1 : 0;

    if (ctx->cur_dlen > 0 && ctx->payload != NULL) {
        /* Path-based stat */
        reqpath = (const char *) ctx->payload;

        if (!xrootd_resolve_path(c->log, &conf->root,
                                 reqpath, resolved, sizeof(resolved))) {
            xrootd_log_access(ctx, c, "STAT", reqpath, "-",
                              0, kXR_NotFound, "file not found", 0);
            XROOTD_OP_ERR(ctx, XROOTD_OP_STAT);
            return xrootd_send_error(ctx, c, kXR_NotFound,
                                     "file not found");
        }

        if (stat(resolved, &st) != 0) {
            xrootd_log_access(ctx, c, "STAT", reqpath, "-",
                              0, kXR_NotFound, strerror(errno), 0);
            XROOTD_OP_ERR(ctx, XROOTD_OP_STAT);
            return xrootd_send_error(ctx, c, kXR_NotFound,
                                     "file not found");
        }
    } else {
        /* Handle-based stat: fhandle[0] is our slot index */
        int idx = (int)(unsigned char) req->fhandle[0];

        if (idx < 0 || idx >= XROOTD_MAX_FILES
                || ctx->files[idx].fd < 0) {
            xrootd_log_access(ctx, c, "STAT", "-", "-",
                              0, kXR_FileNotOpen, "invalid file handle", 0);
            XROOTD_OP_ERR(ctx, XROOTD_OP_STAT);
            return xrootd_send_error(ctx, c, kXR_FileNotOpen,
                                     "invalid file handle");
        }

        resolved[0] = '\0';
        ngx_cpystrn((u_char *) resolved,
                    (u_char *) ctx->files[idx].path,
                    sizeof(resolved));

        if (fstat(ctx->files[idx].fd, &st) != 0) {
            xrootd_log_access(ctx, c, "STAT", resolved, "-",
                              0, kXR_IOError, strerror(errno), 0);
            XROOTD_OP_ERR(ctx, XROOTD_OP_STAT);
            return xrootd_send_error(ctx, c, kXR_IOError, strerror(errno));
        }
    }

    xrootd_make_stat_body(&st, is_vfs, body, sizeof(body));

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: kXR_stat ok: %s", body);

    /* Log the stat — use resolved path for handle-based stats */
    xrootd_log_access(ctx, c, "STAT",
                      (reqpath && reqpath[0]) ? reqpath : resolved,
                      is_vfs ? "vfs" : "-",
                      1, 0, NULL, 0);
    XROOTD_OP_OK(ctx, XROOTD_OP_STAT);

    return xrootd_send_ok(ctx, c, body, (uint32_t)(strlen(body) + 1));
}

/* kXR_open — open a file for reading or writing.
 *
 * Read flags (always accepted):
 *   kXR_open_read  — open for reading (default if no write flag set)
 *
 * Write flags (only when xrootd_allow_write is on):
 *   kXR_new        — create file; fail if it exists (O_CREAT|O_EXCL)
 *   kXR_delete     — create or truncate (O_CREAT|O_TRUNC)
 *   kXR_open_updt  — open existing for read+write (O_RDWR)
 *   kXR_open_apnd  — open for append (O_WRONLY|O_APPEND)
 *   kXR_open_wrto  — write-only (combine with kXR_new or kXR_delete)
 *   kXR_mkpath     — create parent directories before opening
 */
ngx_int_t
xrootd_handle_open(xrootd_ctx_t *ctx, ngx_connection_t *c,
                   ngx_stream_xrootd_srv_conf_t *conf)
{
    ClientOpenRequest *req = (ClientOpenRequest *) ctx->hdr_buf;
    uint16_t           options;
    uint16_t           mode_bits;
    char               resolved[PATH_MAX];
    char               clean_path[PATH_MAX];  /* path with CGI query stripped */
    int                idx, fd, oflags;
    int                is_write;
    ServerOpenBody     body;
    struct stat        st;
    char               statbuf[256];
    u_char            *buf;
    size_t             bodylen, total;
    ngx_flag_t         want_stat;

    options   = ntohs(req->options);
    mode_bits = ntohs(req->mode);
    want_stat = (options & kXR_retstat) ? 1 : 0;

    /* Determine whether this is a write-mode open */
    is_write = (options & (kXR_new | kXR_delete | kXR_open_updt |
                           kXR_open_wrto | kXR_open_apnd)) ? 1 : 0;

    if (is_write && !conf->allow_write) {
        xrootd_log_access(ctx, c, "OPEN",
                          ctx->payload ? (char *) ctx->payload : "-", "wr",
                          0, kXR_fsReadOnly, "read-only server", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_OPEN_WR);
        return xrootd_send_error(ctx, c, kXR_fsReadOnly,
                                 "this is a read-only server");
    }

    if (ctx->payload == NULL || ctx->cur_dlen == 0) {
        xrootd_log_access(ctx, c, "OPEN", "-",
                          is_write ? "wr" : "rd",
                          0, kXR_ArgMissing, "no path given", 0);
        XROOTD_OP_ERR(ctx, is_write ? XROOTD_OP_OPEN_WR : XROOTD_OP_OPEN_RD);
        return xrootd_send_error(ctx, c, kXR_ArgMissing, "no path given");
    }

    /* Strip XRootD CGI query string ("?oss.asize=N" etc.) from the path.
     * xrdcp and other clients append these for metadata; they are not part
     * of the filesystem path. */
    xrootd_strip_cgi((const char *) ctx->payload, clean_path, sizeof(clean_path));

    /* Resolve the path.
     * For read opens the file must already exist (realpath check).
     * For write opens with kXR_mkpath the parent dirs may not exist yet,
     * so use xrootd_resolve_path_noexist; otherwise use the write resolver
     * which requires the parent to exist. */
    if (!is_write) {
        if (!xrootd_resolve_path(c->log, &conf->root,
                                 clean_path, resolved, sizeof(resolved))) {
            xrootd_log_access(ctx, c, "OPEN", clean_path, "rd",
                              0, kXR_NotFound, "file not found", 0);
            XROOTD_OP_ERR(ctx, XROOTD_OP_OPEN_RD);
            return xrootd_send_error(ctx, c, kXR_NotFound, "file not found");
        }

        /* Reject opening a directory as a file */
        {
            struct stat st;
            if (stat(resolved, &st) == 0 && S_ISDIR(st.st_mode)) {
                xrootd_log_access(ctx, c, "OPEN", clean_path, "rd",
                                  0, kXR_isDirectory, "is a directory", 0);
                XROOTD_OP_ERR(ctx, XROOTD_OP_OPEN_RD);
                return xrootd_send_error(ctx, c, kXR_isDirectory,
                                         "is a directory");
            }
        }
    } else {
        int ok;
        if (options & kXR_mkpath) {
            /* Parent dirs may not exist yet — validate without realpath */
            ok = xrootd_resolve_path_noexist(c->log, &conf->root,
                                              clean_path, resolved,
                                              sizeof(resolved));
        } else {
            ok = xrootd_resolve_path_write(c->log, &conf->root,
                                           clean_path, resolved,
                                           sizeof(resolved));
        }
        if (!ok) {
            xrootd_log_access(ctx, c, "OPEN", clean_path, "wr",
                              0, kXR_NotFound, "invalid path", 0);
            XROOTD_OP_ERR(ctx, XROOTD_OP_OPEN_WR);
            return xrootd_send_error(ctx, c, kXR_NotFound, "invalid path");
        }

        /* Create parent directories if kXR_mkpath is set */
        if (options & kXR_mkpath) {
            char  parent[PATH_MAX];
            char *slash;
            ngx_cpystrn((u_char *) parent, (u_char *) resolved, sizeof(parent));
            slash = strrchr(parent, '/');
            if (slash && slash > parent) {
                *slash = '\0';
                /* mode 0755 for new directories */
                xrootd_mkdir_recursive(parent, 0755);
            }
        }
    }

    /* Build the OS open flags from XRootD options.
     *
     * XRootD separates the access mode from the creation/truncation action:
     *   kXR_open_updt  → O_RDWR (read+write access)
     *   kXR_open_apnd  → O_WRONLY|O_APPEND
     *   kXR_open_wrto  → O_WRONLY
     *   kXR_new        → O_CREAT (create if not exists)
     *   kXR_delete     → O_TRUNC (truncate to zero if exists)
     *
     * These flags are independent and can all be set simultaneously.
     * xrdcp typically sends kXR_new|kXR_delete|kXR_open_updt|kXR_mkpath
     * which means "create or overwrite, open for read+write".
     */
    if (!is_write) {
        oflags = O_RDONLY | O_NOCTTY;
    } else {
        /* Step 1: access mode */
        if (options & kXR_open_updt) {
            oflags = O_RDWR;
        } else if (options & kXR_open_apnd) {
            oflags = O_WRONLY | O_APPEND;
        } else {
            oflags = O_WRONLY;
        }

        /* Step 2: creation / truncation modifiers.
         *
         * kXR_new alone   → O_CREAT|O_EXCL  (fail if file exists)
         * kXR_new|kXR_delete → O_CREAT|O_TRUNC  (create or overwrite)
         * kXR_delete alone → O_CREAT|O_TRUNC
         */
        if (options & kXR_new) {
            oflags |= O_CREAT;
            if (!(options & kXR_delete)) {
                oflags |= O_EXCL;   /* fail if already exists */
            }
        }
        if (options & kXR_delete) {
            oflags |= O_CREAT | O_TRUNC;
        }

        oflags |= O_NOCTTY;
    }

    /* Convert XRootD mode bits (Unix permission bits in low 9 bits) */
    mode_t create_mode = (mode_bits & 0777);
    if (create_mode == 0) {
        create_mode = 0644;   /* sensible default if client sends 0 */
    }

    /* Allocate a file handle slot */
    idx = xrootd_alloc_fhandle(ctx);
    if (idx < 0) {
        xrootd_log_access(ctx, c, "OPEN", resolved,
                          is_write ? "wr" : "rd",
                          0, kXR_ServerError, "too many open files", 0);
        XROOTD_OP_ERR(ctx, is_write ? XROOTD_OP_OPEN_WR : XROOTD_OP_OPEN_RD);
        return xrootd_send_error(ctx, c, kXR_ServerError,
                                 "too many open files");
    }

    fd = open(resolved, oflags, create_mode);
    if (fd < 0) {
        int err = errno;
        const char *mode_str = is_write ? "wr" : "rd";
        if (err == ENOENT || err == ENOTDIR) {
            xrootd_log_access(ctx, c, "OPEN", resolved, mode_str,
                              0, kXR_NotFound, "file not found", 0);
            XROOTD_OP_ERR(ctx, is_write ? XROOTD_OP_OPEN_WR : XROOTD_OP_OPEN_RD);
            return xrootd_send_error(ctx, c, kXR_NotFound,
                                     "file not found");
        }
        if (err == EEXIST) {
            xrootd_log_access(ctx, c, "OPEN", resolved, mode_str,
                              0, kXR_FileLocked, "file already exists", 0);
            XROOTD_OP_ERR(ctx, is_write ? XROOTD_OP_OPEN_WR : XROOTD_OP_OPEN_RD);
            return xrootd_send_error(ctx, c, kXR_FileLocked,
                                     "file already exists");
        }
        if (err == EACCES) {
            xrootd_log_access(ctx, c, "OPEN", resolved, mode_str,
                              0, kXR_NotAuthorized, "permission denied", 0);
            XROOTD_OP_ERR(ctx, is_write ? XROOTD_OP_OPEN_WR : XROOTD_OP_OPEN_RD);
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "permission denied");
        }
        xrootd_log_access(ctx, c, "OPEN", resolved, mode_str,
                          0, kXR_IOError, strerror(err), 0);
        XROOTD_OP_ERR(ctx, is_write ? XROOTD_OP_OPEN_WR : XROOTD_OP_OPEN_RD);
        return xrootd_send_error(ctx, c, kXR_IOError, strerror(err));
    }

    ctx->files[idx].fd       = fd;
    ctx->files[idx].writable = is_write;
    ngx_cpystrn((u_char *) ctx->files[idx].path,
                (u_char *) resolved,
                sizeof(ctx->files[idx].path));

    /*
     * If the client set kXR_retstat, include a stat string in the open
     * response so the client doesn't need to issue a separate kXR_stat.
     *
     * Both kXR_open retstat and standalone kXR_stat use the same wire order:
     *   "<id> <size> <flags> <mtime>\0"
     *
     * The client's ServerOpenBody handler reads the stat string starting
     * immediately after the 12-byte ServerOpenBody, using the same parser
     * as standalone kXR_stat responses (StatInfo chunks[1]=size, [2]=flags).
     */
    statbuf[0] = '\0';
    if (want_stat) {
        if (fstat(fd, &st) == 0) {
            /* Format: "<id> <size> <flags> <mtime>\0" — size before flags. */
            int stat_flags = 0;
            if (st.st_mode & (S_IRUSR | S_IRGRP | S_IROTH)) {
                stat_flags |= kXR_readable;
            }
            if (st.st_mode & (S_IWUSR | S_IWGRP | S_IWOTH)) {
                stat_flags |= kXR_writable;
            }
            snprintf(statbuf, sizeof(statbuf), "%llu %lld %d %ld",
                     (unsigned long long) st.st_ino,
                     (long long) st.st_size,
                     stat_flags,
                     (long) st.st_mtime);
        } else {
            want_stat = 0;   /* couldn't stat; skip gracefully */
        }
    }

    ngx_log_debug4(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: kXR_open handle=%d path=%s mode=%s retstat=%d",
                   idx, resolved, is_write ? "wr" : "rd", (int) want_stat);

    /*
     * Build response: 8-byte header + 12-byte ServerOpenBody
     * + optional NUL-terminated stat string (when kXR_retstat set).
     */
    bodylen = sizeof(ServerOpenBody);
    if (want_stat) {
        bodylen += strlen(statbuf) + 1;   /* include the NUL */
    }

    total = XRD_RESPONSE_HDR_LEN + bodylen;
    buf   = ngx_palloc(c->pool, total);
    if (buf == NULL) {
        close(fd);
        ctx->files[idx].fd = -1;
        return NGX_ERROR;
    }

    xrootd_build_resp_hdr(ctx->cur_streamid, kXR_ok,
                           (uint32_t) bodylen,
                           (ServerResponseHdr *) buf);

    /*
     * fhandle[0] = our slot index; bytes 1-3 are zero.
     * The client will echo these 4 bytes in subsequent kXR_read/close.
     */
    ngx_memzero(&body, sizeof(body));
    body.fhandle[0] = (u_char) idx;
    body.cpsize     = 0;    /* no compression */
    ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN, &body, sizeof(body));

    if (want_stat) {
        size_t slen = strlen(statbuf) + 1;
        ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN + sizeof(ServerOpenBody),
                   statbuf, slen);
    }

    ctx->files[idx].bytes_read    = 0;
    ctx->files[idx].bytes_written = 0;
    ctx->files[idx].open_time     = ngx_current_msec;

    xrootd_log_access(ctx, c, "OPEN", resolved,
                      is_write ? "wr" : "rd", 1, 0, NULL, 0);
    XROOTD_OP_OK(ctx, is_write ? XROOTD_OP_OPEN_WR : XROOTD_OP_OPEN_RD);

    return xrootd_queue_response(ctx, c, buf, total);
}

/* ------------------------------------------------------------------ */
/* kXR_readv — scatter-gather / vector read                            */
/*                                                                     */
/* The payload is an array of readahead_list structs (16 bytes each).  */
/* Each struct specifies an open file handle, a byte offset, and the   */
/* number of bytes requested (rlen).  Segments may reference different  */
/* open handles.                                                        */
/*                                                                     */
/* Response: for each segment, a readahead_list header (fhandle +      */
/* actual rlen + offset) followed immediately by rlen bytes of data.   */
/* All segments are concatenated into one body.  Large responses are   */
/* split into kXR_oksofar chunks (same scheme as kXR_read).            */
/*                                                                     */
/* A short read (hit EOF) sets rlen to the actual bytes read in the    */
/* response header for that segment.  Zero-length segments are echoed  */
/* back with rlen=0.  An invalid file handle aborts the entire request. */
/* ------------------------------------------------------------------ */
ngx_int_t
xrootd_handle_readv(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    readahead_list               *segs;
    ngx_stream_xrootd_srv_conf_t *conf =
        ngx_stream_get_module_srv_conf((ngx_stream_session_t *)(c->data), ngx_stream_xrootd_module);
    size_t           n_segs, i;
    u_char          *databuf;
    size_t           max_rsp;

/* Hard cap for the total readv response (256 MiB). */
#define XROOTD_MAX_READV_TOTAL  (256u * 1024u * 1024u)

    /* Validate payload: must be a non-empty, whole multiple of segment size */
    if (ctx->payload == NULL || ctx->cur_dlen == 0 ||
        (ctx->cur_dlen % XROOTD_READV_SEGSIZE) != 0) {
        XROOTD_OP_ERR(ctx, XROOTD_OP_READV);
        return xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                 "malformed readv request");
    }

    segs   = (readahead_list *) ctx->payload;
    n_segs = ctx->cur_dlen / XROOTD_READV_SEGSIZE;

    /* --- First pass: validate all handles and compute max response size --- */
    max_rsp = 0;
    for (i = 0; i < n_segs; i++) {
        int      idx  = (int)(unsigned char) segs[i].fhandle[0];
        uint32_t rlen = (uint32_t) ntohl((uint32_t) segs[i].rlen);

        if (idx < 0 || idx >= XROOTD_MAX_FILES || ctx->files[idx].fd < 0) {
            XROOTD_OP_ERR(ctx, XROOTD_OP_READV);
            return xrootd_send_error(ctx, c, kXR_FileNotOpen,
                                     "invalid file handle in readv");
        }

        if (rlen > XROOTD_READ_MAX) { rlen = XROOTD_READ_MAX; }
        max_rsp += XROOTD_READV_SEGSIZE + rlen;

        if (max_rsp > XROOTD_MAX_READV_TOTAL) {
            XROOTD_OP_ERR(ctx, XROOTD_OP_READV);
            return xrootd_send_error(ctx, c, kXR_ArgTooLong,
                                     "readv total would exceed server limit");
        }
    }

    /* Allocate response body buffer (max size) and pre-fill headers */
    databuf = ngx_palloc(c->pool, max_rsp);
    if (databuf == NULL) { return NGX_ERROR; }

    /* Pre-fill readahead_list headers with fhandle and offset (BE).
     * rlen fields are left for the thread to patch after pread(). */
    {
        u_char *p = databuf;
        for (i = 0; i < n_segs; i++) {
            uint32_t rlen = (uint32_t) ntohl((uint32_t) segs[i].rlen);
            if (rlen > XROOTD_READ_MAX) { rlen = XROOTD_READ_MAX; }

            ngx_memcpy(p, segs[i].fhandle, 4);
            /* rlen field (p+4) will be patched by thread/sync path */
            uint32_t rlen_be = htonl(rlen);
            ngx_memcpy(p + 4, &rlen_be, 4);   /* requested rlen, thread patches actual */
            ngx_memcpy(p + 8, &segs[i].offset, 8);

            p += XROOTD_READV_SEGSIZE + rlen;  /* skip to next segment's header */
        }
    }

#if (NGX_THREADS)
    if (conf->thread_pool != NULL) {
        ngx_thread_task_t       *task;
        xrootd_readv_aio_t      *t;
        xrootd_readv_seg_desc_t *seg_descs;

        /* Allocate per-segment descriptors */
        seg_descs = ngx_palloc(c->pool,
                               n_segs * sizeof(xrootd_readv_seg_desc_t));
        if (seg_descs == NULL) { return NGX_ERROR; }

        /* Fill segment descriptors, pointing into databuf */
        {
            u_char *p = databuf;
            for (i = 0; i < n_segs; i++) {
                uint32_t rlen = (uint32_t) ntohl((uint32_t) segs[i].rlen);
                if (rlen > XROOTD_READ_MAX) { rlen = XROOTD_READ_MAX; }

                seg_descs[i].fd          = ctx->files[(int)(unsigned char)segs[i].fhandle[0]].fd;
                seg_descs[i].handle_idx  = (int)(unsigned char) segs[i].fhandle[0];
                seg_descs[i].offset      = (off_t)(int64_t) be64toh((uint64_t) segs[i].offset);
                seg_descs[i].rlen        = rlen;
                seg_descs[i].hdr_rlen_ptr = p + 4;   /* rlen field in header */
                seg_descs[i].data_ptr    = p + XROOTD_READV_SEGSIZE;

                p += XROOTD_READV_SEGSIZE + rlen;
            }
        }

        task = ngx_thread_task_alloc(c->pool, sizeof(xrootd_readv_aio_t));
        if (task == NULL) { return NGX_ERROR; }

        t = task->ctx;
        t->c           = c;
        t->ctx         = ctx;
        t->n_segs      = n_segs;
        t->segs        = seg_descs;
        t->databuf     = databuf;
        t->bytes_total = 0;
        t->rsp_total   = 0;
        t->io_error    = 0;
        t->streamid[0] = ctx->cur_streamid[0];
        t->streamid[1] = ctx->cur_streamid[1];

        task->handler       = xrootd_readv_aio_thread;
        task->event.handler = xrootd_readv_aio_done;
        task->event.data    = task;

        if (ngx_thread_task_post(conf->thread_pool, task) == NGX_OK) {
            ctx->state = XRD_ST_AIO;
            return NGX_OK;
        }
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "xrootd: thread_task_post failed, falling back to sync readv");
    }
#endif /* NGX_THREADS */

    /* --- Synchronous path: pread each segment in the event loop --- */
    {
        size_t  bytes_total = 0;
        size_t  rsp_total;
        u_char *p   = databuf;
        u_char *rspbuf;
        size_t  rsp_size;

        for (i = 0; i < n_segs; i++) {
            int      idx    = (int)(unsigned char) segs[i].fhandle[0];
            int64_t  offset = (int64_t) be64toh((uint64_t) segs[i].offset);
            uint32_t rlen   = (uint32_t) ntohl((uint32_t) segs[i].rlen);
            ssize_t  nread  = 0;

            if (rlen > XROOTD_READ_MAX) { rlen = XROOTD_READ_MAX; }

            u_char *rlen_field = p + 4;
            p += XROOTD_READV_SEGSIZE;

            if (rlen > 0) {
                nread = pread(ctx->files[idx].fd, p, (size_t) rlen, (off_t) offset);
                if (nread < 0) {
                    XROOTD_OP_ERR(ctx, XROOTD_OP_READV);
                    return xrootd_send_error(ctx, c, kXR_IOError, "readv I/O error");
                }
                if ((uint32_t) nread < rlen) {
                    XROOTD_OP_ERR(ctx, XROOTD_OP_READV);
                    return xrootd_send_error(ctx, c, kXR_IOError, "readv past EOF");
                }
            }

            uint32_t actual_rlen_be = htonl((uint32_t) nread);
            ngx_memcpy(rlen_field, &actual_rlen_be, 4);

            p           += (size_t) nread;
            bytes_total += (size_t) nread;
        }

        rsp_total = (size_t)(p - databuf);

        {
            char detail[64];
            snprintf(detail, sizeof(detail), "%zu_segs", n_segs);
            xrootd_log_access(ctx, c, "READV", "-", detail, 1, 0, NULL, bytes_total);
        }
        XROOTD_OP_OK(ctx, XROOTD_OP_READV);
        ctx->session_bytes += bytes_total;

        rspbuf = xrootd_build_readv_response(ctx, c, databuf, rsp_total, &rsp_size);
        if (rspbuf == NULL) { return NGX_ERROR; }

        return xrootd_queue_response(ctx, c, rspbuf, rsp_size);
    }
}


/* kXR_read — read file data
 *
 * Protocol semantics: a kXR_ok response with fewer bytes than rlen means
 * EOF — the client will NOT re-request the remainder.  kXR_oksofar means
 * "this chunk is part of the answer; more follows".
 *
 * When the requested rlen > XROOTD_READ_MAX we must chunk the response:
 * all but the final 8B+data chunk carry kXR_oksofar; the last carries
 * kXR_ok.  We build the entire interleaved response in one pool buffer and
 * issue a single xrootd_queue_response, avoiding state-machine re-entrancy.
 */
ngx_int_t
xrootd_handle_read(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    ClientReadRequest            *req  = (ClientReadRequest *) ctx->hdr_buf;
    ngx_stream_xrootd_srv_conf_t *conf =
        ngx_stream_get_module_srv_conf((ngx_stream_session_t *)(c->data), ngx_stream_xrootd_module);
    int      idx;
    int64_t  offset;
    size_t   rlen;
    u_char  *databuf;
    ssize_t  nread;
    size_t   data_total;
    size_t   rsp_total;
    u_char  *rspbuf;

    idx    = (int)(unsigned char) req->fhandle[0];
    offset = (int64_t) be64toh((uint64_t) req->offset);
    rlen   = (size_t)(uint32_t) ntohl((uint32_t) req->rlen);

    if (idx < 0 || idx >= XROOTD_MAX_FILES || ctx->files[idx].fd < 0) {
        xrootd_log_access(ctx, c, "READ", "-", "-",
                          0, kXR_FileNotOpen, "invalid file handle", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_READ);
        return xrootd_send_error(ctx, c, kXR_FileNotOpen,
                                 "invalid file handle");
    }

    if (rlen == 0) {
        XROOTD_OP_OK(ctx, XROOTD_OP_READ);
        return xrootd_send_ok(ctx, c, NULL, 0);
    }

    if (rlen > XROOTD_READ_MAX * 16) {
        rlen = XROOTD_READ_MAX * 16;   /* 64 MB hard cap */
    }

    databuf = ngx_palloc(c->pool, rlen);
    if (databuf == NULL) {
        return NGX_ERROR;
    }

#if (NGX_THREADS)
    /* Async path: post pread() to the thread pool */
    if (conf->thread_pool != NULL) {
        ngx_thread_task_t  *task;
        xrootd_read_aio_t  *t;

        task = ngx_thread_task_alloc(c->pool, sizeof(xrootd_read_aio_t));
        if (task == NULL) {
            return NGX_ERROR;
        }

        t = task->ctx;
        t->c          = c;
        t->ctx        = ctx;
        t->conf       = conf;
        t->fd         = ctx->files[idx].fd;
        t->handle_idx = idx;
        t->offset     = (off_t) offset;
        t->rlen       = rlen;
        t->databuf    = databuf;
        t->nread      = -1;
        t->io_errno   = 0;
        t->streamid[0] = ctx->cur_streamid[0];
        t->streamid[1] = ctx->cur_streamid[1];

        task->handler       = xrootd_read_aio_thread;
        task->event.handler = xrootd_read_aio_done;
        task->event.data    = task;

        if (ngx_thread_task_post(conf->thread_pool, task) != NGX_OK) {
            ngx_log_error(NGX_LOG_WARN, c->log, 0,
                          "xrootd: thread_task_post failed, falling back to sync read");
            goto sync_read;
        }

        ctx->state = XRD_ST_AIO;
        return NGX_OK;
    }

sync_read:
#endif /* NGX_THREADS */

    /* Synchronous path: pread() in the event loop worker */
    nread = pread(ctx->files[idx].fd, databuf, rlen, (off_t) offset);
    if (nread < 0) {
        ngx_pfree(c->pool, databuf);
        xrootd_log_access(ctx, c, "READ", ctx->files[idx].path, "-",
                          0, kXR_IOError, strerror(errno), 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_READ);
        return xrootd_send_error(ctx, c, kXR_IOError, strerror(errno));
    }

    data_total = (size_t) nread;

    ctx->files[idx].bytes_read += data_total;
    ctx->session_bytes         += data_total;

    {
        char read_detail[64];
        snprintf(read_detail, sizeof(read_detail), "%lld+%zu",
                 (long long) offset, rlen);
        xrootd_log_access(ctx, c, "READ", ctx->files[idx].path,
                          read_detail, 1, 0, NULL, data_total);
        XROOTD_OP_OK(ctx, XROOTD_OP_READ);
    }

    rspbuf = xrootd_build_read_response(ctx, c, databuf, data_total, &rsp_total);
    ngx_pfree(c->pool, databuf);   /* copied into rspbuf; no longer needed */

    if (rspbuf == NULL) {
        return NGX_ERROR;
    }

    {
        ngx_int_t rc = xrootd_queue_response_base(ctx, c, rspbuf, rsp_total, rspbuf);
        if (ctx->state != XRD_ST_SENDING) {
            ngx_pfree(c->pool, rspbuf);
        }
        return rc;
    }
}

/* kXR_close — close an open file handle */
ngx_int_t
xrootd_handle_close(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    ClientCloseRequest *req = (ClientCloseRequest *) ctx->hdr_buf;
    int idx = (int)(unsigned char) req->fhandle[0];

    if (idx < 0 || idx >= XROOTD_MAX_FILES || ctx->files[idx].fd < 0) {
        xrootd_log_access(ctx, c, "CLOSE", "-", "-",
                          0, kXR_FileNotOpen, "invalid file handle", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_CLOSE);
        return xrootd_send_error(ctx, c, kXR_FileNotOpen,
                                 "invalid file handle");
    }

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: kXR_close handle=%d", idx);

    /* Log before freeing so we still have the path and byte counters.
     * detail = average throughput for the transfer ("%.2fMB/s").
     * bytes  = total data bytes transferred (read or written). */
    {
        char       close_detail[64];
        size_t     br  = ctx->files[idx].bytes_read;
        size_t     bw  = ctx->files[idx].bytes_written;
        size_t     btotal = (bw > 0) ? bw : br;
        ngx_msec_t dur = ngx_current_msec - ctx->files[idx].open_time;

        if (btotal > 0 && dur > 0) {
            double mbps = (double) btotal / (double) dur / 1000.0;
            snprintf(close_detail, sizeof(close_detail), "%.2fMB/s", mbps);
        } else {
            snprintf(close_detail, sizeof(close_detail), "-");
        }

        xrootd_log_access(ctx, c, "CLOSE", ctx->files[idx].path, close_detail,
                          1, 0, NULL, btotal);
    }

    xrootd_free_fhandle(ctx, idx);
    XROOTD_OP_OK(ctx, XROOTD_OP_CLOSE);

    return xrootd_send_ok(ctx, c, NULL, 0);
}

/*
 * kXR_dirlist — list directory contents.
 *
 * Responses for large directories are split into chunks using
 * kXR_oksofar for intermediate chunks and kXR_ok for the last chunk.
 * Each chunk is built in a pool-allocated buffer.
 *
 * If the client set kXR_dstat (options byte 0x02) we append a second
 * line per entry with "id size flags mtime" (same order as kXR_stat /
 * kXR_open retstat — size BEFORE flags).
 */
ngx_int_t
xrootd_handle_dirlist(xrootd_ctx_t *ctx, ngx_connection_t *c,
                      ngx_stream_xrootd_srv_conf_t *conf)
{
    ClientDirlistRequest *req = (ClientDirlistRequest *) ctx->hdr_buf;
    u_char                options;
    char                  resolved[PATH_MAX];
    DIR                  *dp;
    struct dirent        *de;
    ngx_flag_t            want_stat;
    /* We buffer one directory chunk at a time */
    u_char               *chunk;
    size_t                chunk_cap = 65536;
    size_t                chunk_pos = 0;
    char                  statbuf[128];
    ngx_int_t             rc;

    options   = req->options;
    want_stat = (options & kXR_dstat) ? 1 : 0;

    if (ctx->payload == NULL || ctx->cur_dlen == 0) {
        xrootd_log_access(ctx, c, "DIRLIST", "-", "-",
                          0, kXR_ArgMissing, "no path given", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_DIRLIST);
        return xrootd_send_error(ctx, c, kXR_ArgMissing, "no path given");
    }

    if (!xrootd_resolve_path(c->log, &conf->root,
                             (const char *) ctx->payload,
                             resolved, sizeof(resolved))) {
        xrootd_log_access(ctx, c, "DIRLIST", (char *) ctx->payload, "-",
                          0, kXR_NotFound, "directory not found", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_DIRLIST);
        return xrootd_send_error(ctx, c, kXR_NotFound, "directory not found");
    }

    dp = opendir(resolved);
    if (dp == NULL) {
        int err = errno;
        if (err == ENOTDIR) {
            xrootd_log_access(ctx, c, "DIRLIST", resolved, "-",
                              0, kXR_NotFile, "path is not a directory", 0);
            XROOTD_OP_ERR(ctx, XROOTD_OP_DIRLIST);
            return xrootd_send_error(ctx, c, kXR_NotFile,
                                     "path is not a directory");
        }
        if (err == ENOENT) {
            xrootd_log_access(ctx, c, "DIRLIST", resolved, "-",
                              0, kXR_NotFound, "directory not found", 0);
            XROOTD_OP_ERR(ctx, XROOTD_OP_DIRLIST);
            return xrootd_send_error(ctx, c, kXR_NotFound,
                                     "directory not found");
        }
        xrootd_log_access(ctx, c, "DIRLIST", resolved, "-",
                          0, kXR_IOError, strerror(err), 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_DIRLIST);
        return xrootd_send_error(ctx, c, kXR_IOError, strerror(err));
    }

    chunk = ngx_palloc(c->pool, XRD_RESPONSE_HDR_LEN + chunk_cap);
    if (chunk == NULL) {
        closedir(dp);
        return NGX_ERROR;
    }

    /* We write entries starting after the response header (filled last) */
    u_char *data = chunk + XRD_RESPONSE_HDR_LEN;

    /*
     * dStat lead-in sentinel (kXR_dstat mode only)
     *
     * The XRootD client library (DirectoryList::HasStatInfo) looks for the
     * 9-byte prefix ".\n0 0 0 0" at byte 0 of the response body.  Only if
     * that prefix is present does the client enter stat-pairing mode, where
     * it alternates between treating a line as a filename and as a stat string.
     *
     * Without this sentinel every newline-delimited line is treated as a plain
     * filename, so the stat strings appear as extra directory entries.
     *
     * The reference xrootd server writes ".\n0 0 0 0\n" (10 bytes).  The
     * client strips only 9 bytes (the prefix without the trailing \n), leaving
     * the 10th byte (\n) as the first character of the remaining data.  The
     * client's splitString() skips zero-length tokens, so this leading \n is
     * harmlessly consumed.
     *
     * Wire layout after prepending the lead-in:
     *   ".\n0 0 0 0\n<name1>\n<stat1>\n<name2>\n<stat2>\n...\0"
     * where the final \n is replaced by \0 (see the NUL-terminator comment
     * near the final chunk send below).
     *
     * Each stat line is "<id> <size> <flags> <mtime>" — size before flags,
     * matching kXR_stat and kXR_open retstat order.
     */
    if (want_stat) {
        static const char dstat_leadin[] = ".\n0 0 0 0\n";
        ngx_memcpy(data, dstat_leadin, 10);
        chunk_pos = 10;
    }

    while ((de = readdir(dp)) != NULL) {
        const char *name = de->d_name;
        size_t      nlen = strlen(name);

        /* Skip . and .. — XRootD clients do not expect them */
        if (name[0] == '.' && (name[1] == '\0' ||
            (name[1] == '.' && name[2] == '\0'))) {
            continue;
        }

        /*
         * Estimate space needed for this entry.
         * name + '\n' + optional stat line ("<id> <f> <sz> <mt>\n") + '\0'
         */
        size_t need = nlen + 1;
        if (want_stat) {
            need += 80;   /* conservative room for stat line */
        }

        if (chunk_pos + need > chunk_cap) {
            /* Flush current chunk as kXR_oksofar (no NUL — raw data only) */
            xrootd_build_resp_hdr(ctx->cur_streamid, kXR_oksofar,
                                   (uint32_t)chunk_pos,
                                   (ServerResponseHdr *) chunk);

            rc = xrootd_queue_response(ctx, c, chunk,
                                       XRD_RESPONSE_HDR_LEN + chunk_pos);
            if (rc != NGX_OK) {
                closedir(dp);
                return rc;
            }

            chunk_pos = 0;
        }

        /* Append the entry name */
        ngx_memcpy(data + chunk_pos, name, nlen);
        chunk_pos += nlen;
        data[chunk_pos++] = '\n';

        /* Optionally append stat info — use fstatat to avoid path concat */
        if (want_stat) {
            struct stat entry_st;
            if (fstatat(dirfd(dp), name, &entry_st, AT_SYMLINK_NOFOLLOW)
                    == 0) {
                size_t slen;
                xrootd_make_stat_body(&entry_st, 0, statbuf, sizeof(statbuf));
                slen = strlen(statbuf);
                ngx_memcpy(data + chunk_pos, statbuf, slen);
                chunk_pos += slen;
                data[chunk_pos++] = '\n';
            }
        }
    }

    closedir(dp);

    /*
     * Send the final chunk as kXR_ok.
     *
     * NUL-terminator convention
     * ─────────────────────────
     * The XRootD client constructs a std::string from the response body via
     * a C-string (NUL-terminated) pointer.  The correct wire format places the
     * NUL at the position of the last '\n', not after it:
     *
     *   correct:  "file1\nfile2\0"          ← last \n → \0
     *   wrong:    "file1\nfile2\n\0"        ← extra \n before \0 creates
     *                                          a trailing empty token
     *
     * For dStat mode, splitString() is then applied to the body (after
     * stripping the 9-byte prefix).  An extra trailing empty string causes
     * entries.size() to be odd, which fails the size%2 sanity check and
     * discards the entire listing.
     *
     * Empty-directory edge cases
     * ──────────────────────────
     * No-stat, empty dir  (chunk_pos == 0): send kXR_ok with dlen=0.
     * dStat, empty dir    (chunk_pos == 10): the lead-in's trailing '\n'
     *   at data[9] becomes '\0', giving ".\n0 0 0 0\0".  After the client
     *   strips 9 bytes it sees "\0" → empty C-string → empty listing.
     */
    size_t final_len;
    if (chunk_pos == 0) {
        final_len = 0;                  /* empty dir, no stat */
    } else {
        data[chunk_pos - 1] = '\0';     /* replace trailing '\n' with NUL */
        final_len = chunk_pos;
    }

    xrootd_build_resp_hdr(ctx->cur_streamid, kXR_ok,
                           (uint32_t)final_len,
                           (ServerResponseHdr *) chunk);

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: kXR_dirlist final chunk %uz bytes", chunk_pos);

    xrootd_log_access(ctx, c, "DIRLIST", resolved,
                      want_stat ? "stat" : "-", 1, 0, NULL, 0);
    XROOTD_OP_OK(ctx, XROOTD_OP_DIRLIST);

    return xrootd_queue_response(ctx, c, chunk,
                                 XRD_RESPONSE_HDR_LEN + final_len);
}
