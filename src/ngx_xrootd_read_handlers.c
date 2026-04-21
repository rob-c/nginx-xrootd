#include "ngx_xrootd_module.h"

/* ================================================================== */
/*  File-handle lifecycle handlers                                      */
/* ================================================================== */

/*
 * This file owns the file-handle lifecycle in the XRootD protocol:
 *   - kXR_stat  — metadata lookup by path or open handle
 *   - kXR_open  — open a file for reading or writing
 *   - kXR_read  — single contiguous read
 *   - kXR_readv — scatter-gather / vector read
 *   - kXR_close — release a file handle
 *
 * Closely related handlers that were formerly in this file have been
 * extracted into dedicated files for navigability:
 *   - ngx_xrootd_query.c   — kXR_query (checksum, space, config)
 *   - ngx_xrootd_dirlist.c — kXR_dirlist (directory listing with dStat)
 *
 * The common pattern across all handlers here:
 *   1. validate handle-vs-path addressing from the fixed request header
 *   2. normalize/resolve any client path under xrootd_root
 *   3. translate POSIX results into the nearest XRootD status/error pair
 *   4. log/account the request before queueing the wire response
 *
 * XRootD wire quirks encoded here:
 *   - stat strings use "inode size flags mtime" ordering
 *   - read/readv may need kXR_oksofar chunking for large replies
 *   - handle-based requests reuse the canonical path cached at open time
 *     for logging; the fd remains the authoritative object for I/O
 */

#define XROOTD_READV_PREFETCH_GAP   (128 * 1024)
#define XROOTD_READV_PREFETCH_MAX   (16 * 1024 * 1024)

static void
xrootd_prefetch_fd_range(ngx_log_t *log, int fd, off_t offset, size_t len)
{
#if defined(POSIX_FADV_WILLNEED)
    int rc;

    if (fd < 0 || offset < 0 || len == 0) {
        return;
    }

    rc = posix_fadvise(fd, offset, (off_t) len, POSIX_FADV_WILLNEED);
    if (rc != 0) {
        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, log, rc,
                       "xrootd: POSIX_FADV_WILLNEED ignored: %s",
                       strerror(rc));
    }
#else
    (void) log;
    (void) fd;
    (void) offset;
    (void) len;
#endif
}

static void
xrootd_prefetch_flush(ngx_log_t *log, int fd, off_t start, off_t end)
{
    if (fd >= 0 && end > start) {
        xrootd_prefetch_fd_range(log, fd, start, (size_t) (end - start));
    }
}

static void
xrootd_prefetch_readv_segments(xrootd_ctx_t *ctx, ngx_connection_t *c,
    readahead_list *segs, size_t n_segs)
{
    int     cur_fd = -1;
    off_t   cur_start = 0;
    off_t   cur_end = 0;
    size_t  i;

    /*
     * XRootD clients commonly group adjacent readv ranges.  Coalesce nearby
     * ranges into one kernel readahead hint so storage backends can warm the
     * page cache before the worker thread starts issuing the exact pread calls.
     */
    for (i = 0; i < n_segs; i++) {
        int      idx = (int)(unsigned char) segs[i].fhandle[0];
        int      fd;
        int64_t  offset;
        uint32_t rlen;
        off_t    seg_start;
        off_t    seg_end;

        if (idx < 0 || idx >= XROOTD_MAX_FILES || ctx->files[idx].fd < 0) {
            continue;
        }

        rlen = (uint32_t) ntohl((uint32_t) segs[i].rlen);
        if (rlen > XROOTD_READ_MAX) { rlen = XROOTD_READ_MAX; }
        if (rlen == 0) { continue; }

        offset = (int64_t) be64toh((uint64_t) segs[i].offset);
        if (offset < 0) { continue; }

        fd = ctx->files[idx].fd;
        seg_start = (off_t) offset;
        seg_end = seg_start + (off_t) rlen;
        if (seg_end <= seg_start) { continue; }

        if (cur_fd == fd &&
            seg_start >= cur_start &&
            seg_start <= cur_end + (off_t) XROOTD_READV_PREFETCH_GAP &&
            seg_end - cur_start <= (off_t) XROOTD_READV_PREFETCH_MAX)
        {
            if (seg_end > cur_end) {
                cur_end = seg_end;
            }
            continue;
        }

        xrootd_prefetch_flush(c->log, cur_fd, cur_start, cur_end);
        cur_fd = fd;
        cur_start = seg_start;
        cur_end = seg_end;
    }

    xrootd_prefetch_flush(c->log, cur_fd, cur_start, cur_end);
}


/* kXR_stat — stat by path or by open file handle */
ngx_int_t
xrootd_handle_stat(xrootd_ctx_t *ctx, ngx_connection_t *c,
                   ngx_stream_xrootd_srv_conf_t *conf)
{
    ClientStatRequest *req = (ClientStatRequest *) ctx->hdr_buf;
    struct stat        st;
    char               resolved[PATH_MAX];
    char               reqpath_buf[XROOTD_MAX_PATH + 1];
    char               body[256];
    ngx_flag_t         is_vfs;
    const char        *reqpath = NULL;

    is_vfs = (req->options & kXR_vfs) ? 1 : 0;

    /*
     * kXR_stat is dual-mode like upstream XRootD:
     *   - dlen > 0 means the payload names a path to resolve and stat(2)
     *   - dlen == 0 means the opaque handle identifies an already-open fd
     *
     * The logging path and the syscall target are deliberately separated in the
     * handle case: logs use the cached canonical path, while fstat() uses the fd.
     */

    if (ctx->cur_dlen > 0 && ctx->payload != NULL) {
        /* Path-based stat */
        if (!xrootd_extract_path(c->log, ctx->payload, ctx->cur_dlen,
                                 reqpath_buf, sizeof(reqpath_buf), 0)) {
            xrootd_log_access(ctx, c, "STAT", "-", "-",
                              0, kXR_ArgInvalid, "invalid path payload", 0);
            XROOTD_OP_ERR(ctx, XROOTD_OP_STAT);
            return xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                     "invalid path payload");
        }
        reqpath = reqpath_buf;

        if (!xrootd_resolve_path(c->log, &conf->root,
                                 reqpath, resolved, sizeof(resolved))) {
            xrootd_log_access(ctx, c, "STAT", reqpath, "-",
                              0, kXR_NotFound, "file not found", 0);
            XROOTD_OP_ERR(ctx, XROOTD_OP_STAT);
            return xrootd_send_error(ctx, c, kXR_NotFound,
                                     "file not found");
        }

        if (xrootd_check_vo_acl(c->log, resolved, conf->vo_rules,
                                 ctx->vo_list) != NGX_OK) {
            xrootd_log_access(ctx, c, "STAT", resolved, "-",
                              0, kXR_NotAuthorized, "VO not authorized", 0);
            XROOTD_OP_ERR(ctx, XROOTD_OP_STAT);
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "VO not authorized");
        }

        if (stat(resolved, &st) != 0) {
            xrootd_log_access(ctx, c, "STAT", reqpath, "-",
                              0, kXR_NotFound, strerror(errno), 0);
            XROOTD_OP_ERR(ctx, XROOTD_OP_STAT);
            return xrootd_send_error(ctx, c, kXR_NotFound,
                                     "file not found");
        }
    } else {
        /* Handle-based stat: fhandle[0] is our slot index. */
        /* The cached path is only for logging; the real metadata comes from fstat(). */
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

    /* Convert the host stat struct into the exact ASCII body the client expects. */
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
    int                is_readable;
    ServerOpenBody     body;
    struct stat        st;
    char               statbuf[256];
    u_char            *buf;
    size_t             bodylen, total;
    ngx_flag_t         want_stat;

    options   = ntohs(req->options);
    mode_bits = ntohs(req->mode);
    want_stat = (options & kXR_retstat) ? 1 : 0;

    /*
     * open is the densest request in the read-side path because it bridges
     * protocol semantics (flags, mkpath, retstat) with POSIX open(2) details
     * and also seeds the per-handle bookkeeping reused by later read/close ops.
     */

    /* Determine whether this is a write-mode open */
    is_write = (options & (kXR_new | kXR_delete | kXR_open_updt |
                           kXR_open_wrto | kXR_open_apnd)) ? 1 : 0;

    /*
     * In XRootD the presence of any write-style option changes the semantics of
     * the open, even if the path lookup portion still looks read-like.
     */

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

    /*
     * clean_path is the protocol-facing pathname after stripping client-side
     * query metadata. resolved is the server's canonical or validated target.
     */
    /* Strip XRootD CGI query string ("?oss.asize=N" etc.) from the path.
     * xrdcp and other clients append these for metadata; they are not part
     * of the filesystem path. */
    if (!xrootd_extract_path(c->log, ctx->payload, ctx->cur_dlen,
                             clean_path, sizeof(clean_path), 1)) {
        xrootd_log_access(ctx, c, "OPEN", "-",
                          is_write ? "wr" : "rd",
                          0, kXR_ArgInvalid, "invalid path payload", 0);
        XROOTD_OP_ERR(ctx, is_write ? XROOTD_OP_OPEN_WR : XROOTD_OP_OPEN_RD);
        return xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                 "invalid path payload");
    }

    /* Manager-mode mapping: redirect opens for configured prefixes. */
    if (conf->manager_map != NULL) {
        const xrootd_manager_map_t *m = xrootd_find_manager_map(clean_path,
                                                                conf->manager_map);
        if (m != NULL) {
            xrootd_log_access(ctx, c, "OPEN", clean_path, "redirect",
                              1, 0, NULL, 0);
            XROOTD_OP_OK(ctx, is_write ? XROOTD_OP_OPEN_WR : XROOTD_OP_OPEN_RD);
            return xrootd_send_redirect(ctx, c, (const char *) m->host.data,
                                        m->port);
        }
    }

    /* Resolve the path.
     * For read opens the file must already exist (realpath check).
     * For write opens with kXR_mkpath the parent dirs may not exist yet,
     * so use xrootd_resolve_path_noexist; otherwise use the write resolver
     * which requires the parent to exist. */
    if (!is_write) {
        /* Read opens are strict: the final target must already exist and canonicalize. */
        if (!xrootd_resolve_path(c->log, &conf->root,
                                 clean_path, resolved, sizeof(resolved))) {
            /* No local file — query upstream redirector if configured */
            if (conf->upstream_host.len > 0) {
                xrootd_log_access(ctx, c, "OPEN", clean_path,
                                  "upstream", 1, 0, NULL, 0);
                XROOTD_OP_OK(ctx, XROOTD_OP_OPEN_RD);
                return xrootd_upstream_start(ctx, c, conf);
            }
            xrootd_log_access(ctx, c, "OPEN", clean_path, "rd",
                              0, kXR_NotFound, "file not found", 0);
            XROOTD_OP_ERR(ctx, XROOTD_OP_OPEN_RD);
            return xrootd_send_error(ctx, c, kXR_NotFound, "file not found");
        }

        if (xrootd_check_vo_acl(c->log, resolved, conf->vo_rules,
                                 ctx->vo_list) != NGX_OK) {
            xrootd_log_access(ctx, c, "OPEN", resolved, "rd",
                              0, kXR_NotAuthorized, "VO not authorized", 0);
            XROOTD_OP_ERR(ctx, XROOTD_OP_OPEN_RD);
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "VO not authorized");
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
        /*
         * Write opens are more permissive because the leaf may be created by
         * the open itself. The exact resolver depends on whether the client also
         * asked us to materialize missing parent directories.
         */
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

        if (xrootd_check_vo_acl(c->log, resolved, conf->vo_rules,
                                 ctx->vo_list) != NGX_OK) {
            xrootd_log_access(ctx, c, "OPEN", resolved, "wr",
                              0, kXR_NotAuthorized, "VO not authorized", 0);
            XROOTD_OP_ERR(ctx, XROOTD_OP_OPEN_WR);
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "VO not authorized");
        }

        /* Create parent directories if kXR_mkpath is set */
        if (options & kXR_mkpath) {
            char  parent[PATH_MAX];
            char *slash;
            ngx_cpystrn((u_char *) parent, (u_char *) resolved, sizeof(parent));
            slash = strrchr(parent, '/');
            if (slash && slash > parent) {
                *slash = '\0';
                /* mode 0755 for new directories; propagate group policy */
                xrootd_mkdir_recursive_policy(parent, 0755, c->log,
                                              conf->group_rules);
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
        is_readable = 1;
    } else {
        /* Step 1: access mode */
        if (options & kXR_open_updt) {
            oflags = O_RDWR;
            is_readable = 1;
        } else if (options & kXR_open_apnd) {
            oflags = O_WRONLY | O_APPEND;
            is_readable = 0;
        } else {
            oflags = O_WRONLY;
            is_readable = 0;
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

    /*
     * The handle slot is reserved before open(2) so we can reuse the same
     * cleanup path regardless of whether the file open succeeds or fails.
     */

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

        /* Translate common errno values into the closest XRootD protocol error. */
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
    ctx->files[idx].readable = is_readable;
    ctx->files[idx].writable = is_write;
    /* Cache the resolved path for later read/close/query logging and handle-based ops. */
    ngx_cpystrn((u_char *) ctx->files[idx].path,
                (u_char *) resolved,
                sizeof(ctx->files[idx].path));

    /* Apply parent-group ownership/permissions to newly created files. */
    if (is_write && conf->group_rules != NULL) {
        xrootd_apply_parent_group_policy_fd(c->log, fd, resolved,
                                            conf->group_rules);
    }

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

    if (c->log->log_level & NGX_LOG_DEBUG_STREAM) {
        char log_path[512];

        xrootd_sanitize_log_string(resolved, log_path, sizeof(log_path));
        ngx_log_debug4(NGX_LOG_DEBUG_STREAM, c->log, 0,
                       "xrootd: kXR_open handle=%d path=%s mode=%s retstat=%d",
                       idx, log_path, is_write ? "wr" : "rd", (int) want_stat);
    }

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
        ctx->files[idx].fd       = -1;
        ctx->files[idx].writable = 0;
        ctx->files[idx].readable = 0;
        ctx->files[idx].path[0]  = '\0';
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

    /* Reset per-handle transfer counters so close/disconnect summaries start fresh. */
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
    size_t           n_segs, i;
    u_char          *databuf;
    size_t           max_rsp;

/* Hard cap for the total readv response (256 MiB). */
#define XROOTD_MAX_READV_TOTAL  (256u * 1024u * 1024u)

    /*
     * readv is the most buffer-heavy read-side opcode:
     *   - the request payload is an array of fixed 16-byte segment descriptors
     *   - the response body repeats one descriptor per segment plus data bytes
     *   - segment headers are patched with the actual returned length
     *
     * This handler therefore runs in two conceptual passes:
     *   1. validate and size the whole response conservatively
     *   2. fill a pre-laid-out buffer synchronously or asynchronously
     */

    /* Validate payload: must be a non-empty, whole multiple of segment size */
    if (ctx->payload == NULL || ctx->cur_dlen == 0 ||
        (ctx->cur_dlen % XROOTD_READV_SEGSIZE) != 0) {
        XROOTD_OP_ERR(ctx, XROOTD_OP_READV);
        return xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                 "malformed readv request");
    }

    segs   = (readahead_list *) ctx->payload;
    n_segs = ctx->cur_dlen / XROOTD_READV_SEGSIZE;

    /* The wire payload contains only segment headers; all data bytes are produced server-side. */

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
        if (!ctx->files[idx].readable) {
            XROOTD_OP_ERR(ctx, XROOTD_OP_READV);
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "file not open for reading");
        }

        if (rlen > XROOTD_READ_MAX) { rlen = XROOTD_READ_MAX; }
        /* Reserve header + maximum data bytes this segment could contribute. */
        max_rsp += XROOTD_READV_SEGSIZE + rlen;

        if (max_rsp > XROOTD_MAX_READV_TOTAL) {
            /* Reject early rather than attempting an oversized pool allocation. */
            XROOTD_OP_ERR(ctx, XROOTD_OP_READV);
            return xrootd_send_error(ctx, c, kXR_ArgTooLong,
                                     "readv total would exceed server limit");
        }
    }

    xrootd_prefetch_readv_segments(ctx, c, segs, n_segs);

    /* Reuse one response body buffer per connection instead of growing the pool. */
    databuf = xrootd_get_read_scratch(ctx, c, max_rsp);
    if (databuf == NULL) { return NGX_ERROR; }

    /*
     * databuf is laid out exactly like the logical response body will look.
     * That lets the sync path read directly into place and the async path hand
     * each worker descriptor a pointer to its eventual output slice.
     */

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

            /* Skip over the data area this segment will eventually fill. */
            p += XROOTD_READV_SEGSIZE + rlen;  /* skip to next segment's header */
        }
    }

#if (NGX_THREADS)
    {
    ngx_stream_xrootd_srv_conf_t *conf =
        ngx_stream_get_module_srv_conf((ngx_stream_session_t *)(c->data), ngx_stream_xrootd_module);
    if (conf->thread_pool != NULL) {
        ngx_thread_task_t       *task;
        xrootd_readv_aio_t      *t;
        xrootd_readv_seg_desc_t *seg_descs;

        /* Allocate a sidecar descriptor array so the worker can iterate safely. */
        seg_descs = ngx_palloc(c->pool,
                               n_segs * sizeof(xrootd_readv_seg_desc_t));
        if (seg_descs == NULL) { return NGX_ERROR; }

        /* Fill segment descriptors, pointing into databuf */
        {
            u_char *p = databuf;
            for (i = 0; i < n_segs; i++) {
                uint32_t rlen = (uint32_t) ntohl((uint32_t) segs[i].rlen);
                if (rlen > XROOTD_READ_MAX) { rlen = XROOTD_READ_MAX; }

                /* Each descriptor points at the header field and data slice for one segment. */
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
            /* Completion callback owns the response from this point onward. */
            ctx->state = XRD_ST_AIO;
            return NGX_OK;
        }
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "xrootd: thread_task_post failed, falling back to sync readv");
    }
    } /* end NGX_THREADS block */
#endif /* NGX_THREADS */

    /* --- Synchronous path: pread each segment in the event loop --- */
    {
        size_t  bytes_total = 0;
        size_t  rsp_total;
        u_char *p   = databuf;
        ngx_chain_t *rsp_chain;

        /*
         * The synchronous fallback mirrors the worker-thread algorithm exactly
         * so both paths produce the same packed response layout and error rules.
         */

        for (i = 0; i < n_segs; i++) {
            int      idx    = (int)(unsigned char) segs[i].fhandle[0];
            int64_t  offset = (int64_t) be64toh((uint64_t) segs[i].offset);
            uint32_t rlen   = (uint32_t) ntohl((uint32_t) segs[i].rlen);
            ssize_t  nread  = 0;

            if (rlen > XROOTD_READ_MAX) { rlen = XROOTD_READ_MAX; }

            u_char *rlen_field = p + 4;
            p += XROOTD_READV_SEGSIZE;

            /* p now points at the start of this segment's response data area. */

            if (rlen > 0) {
                /* Read directly into the reserved data area behind this segment header. */
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

            /* Patch the header to the actual bytes returned for this segment. */
            uint32_t actual_rlen_be = htonl((uint32_t) nread);
            ngx_memcpy(rlen_field, &actual_rlen_be, 4);

            p           += (size_t) nread;
            bytes_total += (size_t) nread;
        }

        rsp_total = (size_t)(p - databuf);

        /* rsp_total may be smaller than max_rsp because the final data lengths are now known. */

        {
            char detail[64];
            snprintf(detail, sizeof(detail), "%zu_segs", n_segs);
            xrootd_log_access(ctx, c, "READV", "-", detail, 1, 0, NULL, bytes_total);
        }
        XROOTD_OP_OK(ctx, XROOTD_OP_READV);
        ctx->session_bytes += bytes_total;

        /* Queue header+data as an iovec-style chain instead of copying into a second buffer. */
        rsp_chain = xrootd_build_chunked_chain(ctx, c, databuf, rsp_total);
        if (rsp_chain == NULL) {
            xrootd_release_read_buffer(ctx, c, databuf);
            return NGX_ERROR;
        }

        {
            ngx_int_t rc = xrootd_queue_response_chain(ctx, c, rsp_chain, databuf);
            if (rc != NGX_OK || ctx->state != XRD_ST_SENDING) {
                xrootd_release_read_buffer(ctx, c, databuf);
            }
            return rc;
        }
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
 * kXR_ok.  Regular files are returned as header buffers plus file-backed nginx
 * chain links so the stream send path can use sendfile; only unusual
 * non-regular descriptors fall back to a memory-backed pread response.
 */
ngx_int_t
xrootd_handle_read(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    ClientReadRequest            *req  = (ClientReadRequest *) ctx->hdr_buf;
    int      idx;
    int64_t  offset;
    size_t   rlen;
    u_char  *databuf;
    ssize_t  nread;
    size_t   data_total;
    u_char  *send_base = NULL;
    ngx_chain_t *rsp_chain;
    struct stat st;
    int      fd;

    idx    = (int)(unsigned char) req->fhandle[0];
    offset = (int64_t) be64toh((uint64_t) req->offset);
    rlen   = (size_t)(uint32_t) ntohl((uint32_t) req->rlen);

    /*
     * Plain read has one contiguous byte range, which makes it the right place
     * to use file-backed chain buffers.  readv still needs a packed memory body
     * because the protocol interleaves per-segment descriptors and payloads.
     */

    if (idx < 0 || idx >= XROOTD_MAX_FILES || ctx->files[idx].fd < 0) {
        xrootd_log_access(ctx, c, "READ", "-", "-",
                          0, kXR_FileNotOpen, "invalid file handle", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_READ);
        return xrootd_send_error(ctx, c, kXR_FileNotOpen,
                                 "invalid file handle");
    }

    if (!ctx->files[idx].readable) {
        xrootd_log_access(ctx, c, "READ", ctx->files[idx].path, "-",
                          0, kXR_NotAuthorized, "file not open for reading", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_READ);
        return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                 "file not open for reading");
    }

    if (rlen == 0) {
        /* Zero-length reads are legal and return an immediate empty success body. */
        XROOTD_OP_OK(ctx, XROOTD_OP_READ);
        return xrootd_send_ok(ctx, c, NULL, 0);
    }

    if (rlen > XROOTD_READ_MAX * 16) {
        /* One single read request should not monopolize memory or socket bandwidth indefinitely. */
        rlen = XROOTD_READ_MAX * 16;   /* 64 MB hard cap */
    }

    fd = ctx->files[idx].fd;

    if (offset < 0) {
        xrootd_log_access(ctx, c, "READ", ctx->files[idx].path, "-",
                          0, kXR_IOError, "negative read offset", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_READ);
        return xrootd_send_error(ctx, c, kXR_IOError, "negative read offset");
    }

    if (fstat(fd, &st) != 0) {
        xrootd_log_access(ctx, c, "READ", ctx->files[idx].path, "-",
                          0, kXR_IOError, strerror(errno), 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_READ);
        return xrootd_send_error(ctx, c, kXR_IOError, strerror(errno));
    }

    if (S_ISREG(st.st_mode) && !c->ssl) {
        off_t avail;

        if ((off_t) offset >= st.st_size) {
            data_total = 0;
        } else {
            avail = st.st_size - (off_t) offset;
            data_total = (avail < (off_t) rlen) ? (size_t) avail : rlen;
        }

        xrootd_prefetch_fd_range(c->log, fd, (off_t) offset, data_total);

        /* Account bytes before building the protocol response so logs see the same totals. */
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

        rsp_chain = xrootd_build_sendfile_chain(ctx, c, fd,
                                                ctx->files[idx].path,
                                                (off_t) offset, data_total,
                                                &send_base);
        if (rsp_chain == NULL) {
            xrootd_release_read_buffer(ctx, c, send_base);
            return NGX_ERROR;
        }

        {
            ngx_int_t rc = xrootd_queue_response_chain(ctx, c, rsp_chain,
                                                       send_base);
            if (rc != NGX_OK || ctx->state != XRD_ST_SENDING) {
                xrootd_release_read_buffer(ctx, c, send_base);
            }
            return rc;
        }
    }

    /*
     * Memory-backed read path.  Used for non-regular descriptors where sendfile
     * is invalid, and for TLS connections where nginx's ngx_ssl_send_chain
     * silently drops file-backed chain buffers without kernel TLS support.
     */
    databuf = xrootd_get_read_scratch(ctx, c, rlen);
    if (databuf == NULL) {
        return NGX_ERROR;
    }

#if (NGX_THREADS)
    {
        ngx_stream_xrootd_srv_conf_t *rconf =
            ngx_stream_get_module_srv_conf(
                (ngx_stream_session_t *)(c->data), ngx_stream_xrootd_module);

        if (rconf->thread_pool != NULL) {
            ngx_thread_task_t *task;
            xrootd_read_aio_t *t;

            task = ngx_thread_task_alloc(c->pool, sizeof(xrootd_read_aio_t));
            if (task == NULL) {
                xrootd_release_read_buffer(ctx, c, databuf);
                return NGX_ERROR;
            }

            t = task->ctx;
            t->c           = c;
            t->ctx         = ctx;
            t->fd          = fd;
            t->handle_idx  = idx;
            t->offset      = (off_t) offset;
            t->rlen        = rlen;
            t->databuf     = databuf;
            t->streamid[0] = ctx->cur_streamid[0];
            t->streamid[1] = ctx->cur_streamid[1];

            task->handler       = xrootd_read_aio_thread;
            task->event.handler = xrootd_read_aio_done;
            task->event.data    = task;

            if (ngx_thread_task_post(rconf->thread_pool, task) == NGX_OK) {
                ctx->state = XRD_ST_AIO;
                return NGX_OK;
            }
            ngx_log_error(NGX_LOG_WARN, c->log, 0,
                          "xrootd: thread_task_post failed, sync read fallback");
        }
    }
#endif /* NGX_THREADS */

    nread = pread(fd, databuf, rlen, (off_t) offset);
    if (nread < 0) {
        xrootd_release_read_buffer(ctx, c, databuf);
        xrootd_log_access(ctx, c, "READ", ctx->files[idx].path, "-",
                          0, kXR_IOError, strerror(errno), 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_READ);
        return xrootd_send_error(ctx, c, kXR_IOError, strerror(errno));
    }

    data_total = (size_t) nread;

    /* A short successful pread is the normal EOF signal for XRootD clients. */

    /* Account bytes before building the protocol response so logs see the same totals. */
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

    rsp_chain = xrootd_build_chunked_chain(ctx, c, databuf, data_total);
    if (rsp_chain == NULL) {
        xrootd_release_read_buffer(ctx, c, databuf);
        return NGX_ERROR;
    }

    {
        /* queue_response_chain may keep databuf for later if the socket blocks mid-send. */
        ngx_int_t rc = xrootd_queue_response_chain(ctx, c, rsp_chain, databuf);
        if (rc != NGX_OK || ctx->state != XRD_ST_SENDING) {
            xrootd_release_read_buffer(ctx, c, databuf);
        }
        return rc;
    }
}

/* ------------------------------------------------------------------ */
/* kXR_pgread — paged read with per-page CRC32c checksums              */
/*                                                                     */
/* The response uses kXR_status framing (not kXR_ok).  Each 4096-byte */
/* page of data is immediately followed by a 4-byte big-endian CRC32c */
/* of that page.  The last page may be shorter than 4096 bytes but    */
/* still has a 4-byte CRC appended.                                    */
/* ------------------------------------------------------------------ */
ngx_int_t
xrootd_handle_pgread(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    ClientPgReadRequest *req = (ClientPgReadRequest *) ctx->hdr_buf;
    int      idx;
    int64_t  offset;
    size_t   rlen;
    int      fd;
    ssize_t  nread;
    size_t   n_pages, i;
    u_char  *flat_buf;   /* temporary: raw file data before CRC interleaving */
    u_char  *out_buf;    /* final: interleaved data + CRC, in scratch buffer  */
    size_t   out_size;
    ServerStatusResponse_pgRead *hdr_buf;
    ngx_chain_t *cl_hdr, *cl_data, *rsp_chain;
    char     detail[64];

    idx    = (int)(unsigned char) req->fhandle[0];
    offset = (int64_t) be64toh((uint64_t) req->offset);
    rlen   = (size_t)(uint32_t) ntohl((uint32_t) req->rlen);

    if (idx < 0 || idx >= XROOTD_MAX_FILES || ctx->files[idx].fd < 0) {
        XROOTD_OP_ERR(ctx, XROOTD_OP_PGREAD);
        return xrootd_send_error(ctx, c, kXR_FileNotOpen,
                                 "invalid file handle");
    }

    if (!ctx->files[idx].readable) {
        XROOTD_OP_ERR(ctx, XROOTD_OP_PGREAD);
        return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                 "file not open for reading");
    }

    if (offset < 0) {
        XROOTD_OP_ERR(ctx, XROOTD_OP_PGREAD);
        return xrootd_send_error(ctx, c, kXR_IOError, "negative read offset");
    }

    if (rlen == 0) {
        /* A zero-length pgread is an integrity no-op; return an empty kXR_status. */
        hdr_buf = ngx_palloc(c->pool, sizeof(*hdr_buf));
        if (hdr_buf == NULL) { return NGX_ERROR; }
        xrootd_build_pgread_status(ctx, offset, 0, hdr_buf);
        XROOTD_OP_OK(ctx, XROOTD_OP_PGREAD);
        return xrootd_queue_response(ctx, c, (u_char *) hdr_buf,
                                     sizeof(*hdr_buf));
    }

    if (rlen > (size_t) XROOTD_READ_MAX * 16) {
        rlen = (size_t) XROOTD_READ_MAX * 16;
    }

    fd = ctx->files[idx].fd;

#if (NGX_THREADS)
    {
        ngx_stream_xrootd_srv_conf_t *rconf =
            ngx_stream_get_module_srv_conf(
                (ngx_stream_session_t *)(c->data), ngx_stream_xrootd_module);

        if (rconf->thread_pool != NULL) {
            ngx_thread_task_t    *task;
            xrootd_pgread_aio_t  *t;
            size_t                n_pages_max, scratch_size;
            u_char               *scratch;

            n_pages_max  = (rlen + kXR_pgPageSZ - 1) / kXR_pgPageSZ;
            if (n_pages_max == 0) { n_pages_max = 1; }
            /* scratch holds flat data first, then interleaved data+CRC output */
            scratch_size = rlen + n_pages_max * kXR_pgUnitSZ;

            scratch = xrootd_get_read_scratch(ctx, c, scratch_size);
            if (scratch == NULL) { return NGX_ERROR; }

            task = ngx_thread_task_alloc(c->pool, sizeof(xrootd_pgread_aio_t));
            if (task == NULL) { return NGX_ERROR; }

            t = task->ctx;
            t->c           = c;
            t->ctx         = ctx;
            t->fd          = fd;
            t->handle_idx  = idx;
            t->offset      = (off_t) offset;
            t->rlen        = rlen;
            t->scratch     = scratch;
            t->out_size    = 0;
            t->streamid[0] = ctx->cur_streamid[0];
            t->streamid[1] = ctx->cur_streamid[1];

            task->handler       = xrootd_pgread_aio_thread;
            task->event.handler = xrootd_pgread_aio_done;
            task->event.data    = task;

            if (ngx_thread_task_post(rconf->thread_pool, task) == NGX_OK) {
                ctx->state = XRD_ST_AIO;
                return NGX_OK;
            }
            ngx_log_error(NGX_LOG_WARN, c->log, 0,
                          "xrootd: thread_task_post failed, sync pgread fallback");
        }
    }
#endif /* NGX_THREADS */

    /* Read raw data into a temporary flat buffer. */
    flat_buf = ngx_palloc(c->pool, rlen);
    if (flat_buf == NULL) { return NGX_ERROR; }

    nread = pread(fd, flat_buf, rlen, (off_t) offset);
    if (nread < 0) {
        xrootd_log_access(ctx, c, "PGREAD", ctx->files[idx].path, "-",
                          0, kXR_IOError, strerror(errno), 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_PGREAD);
        return xrootd_send_error(ctx, c, kXR_IOError, strerror(errno));
    }

    rlen = (size_t) nread;   /* actual bytes; may be short at EOF */

    /* Compute number of pages (last page may be partial). */
    n_pages = (rlen + kXR_pgPageSZ - 1) / kXR_pgPageSZ;
    if (n_pages == 0) { n_pages = 1; }

    out_size = n_pages * kXR_pgUnitSZ;   /* each page: kXR_pgPageSZ data + 4 CRC */

    /* The scratch buffer holds the interleaved data+CRC that follows the status header. */
    out_buf = xrootd_get_read_scratch(ctx, c, out_size);
    if (out_buf == NULL) { return NGX_ERROR; }

    /* Interleave: for each page copy data then append 4-byte BE CRC32c. */
    {
        u_char  *src = flat_buf;
        u_char  *dst = out_buf;
        size_t   remaining = rlen;

        for (i = 0; i < n_pages; i++) {
            size_t   page_data = (remaining >= (size_t) kXR_pgPageSZ)
                                 ? (size_t) kXR_pgPageSZ : remaining;
            uint32_t crc = xrootd_crc32c(src, page_data);
            uint32_t crc_be = htonl(crc);

            ngx_memcpy(dst, src, page_data);
            dst       += page_data;
            src       += page_data;
            remaining -= page_data;

            ngx_memcpy(dst, &crc_be, 4);
            dst += 4;
        }

        /* Actual output size: sum of (page_data + 4) per page. */
        out_size = (size_t)(dst - out_buf);
    }

    /* Build the 32-byte kXR_status header. */
    hdr_buf = ngx_palloc(c->pool, sizeof(*hdr_buf));
    if (hdr_buf == NULL) {
        xrootd_release_read_buffer(ctx, c, out_buf);
        return NGX_ERROR;
    }
    xrootd_build_pgread_status(ctx, offset, (uint32_t) out_size, hdr_buf);

    /* Chain: status header buffer → data+CRC buffer. */
    cl_hdr = ngx_alloc_chain_link(c->pool);
    if (cl_hdr == NULL) {
        xrootd_release_read_buffer(ctx, c, out_buf);
        return NGX_ERROR;
    }
    cl_hdr->buf = ngx_calloc_buf(c->pool);
    if (cl_hdr->buf == NULL) {
        xrootd_release_read_buffer(ctx, c, out_buf);
        return NGX_ERROR;
    }
    cl_hdr->buf->pos      = (u_char *) hdr_buf;
    cl_hdr->buf->last     = cl_hdr->buf->pos + sizeof(*hdr_buf);
    cl_hdr->buf->memory   = 1;
    cl_hdr->buf->last_buf = 0;

    cl_data = xrootd_build_chunked_chain(ctx, c, out_buf, out_size);
    if (cl_data == NULL) {
        xrootd_release_read_buffer(ctx, c, out_buf);
        return NGX_ERROR;
    }
    cl_hdr->next = cl_data;
    rsp_chain    = cl_hdr;

    ctx->files[idx].bytes_read += rlen;
    ctx->session_bytes         += rlen;

    snprintf(detail, sizeof(detail), "%lld+%zu", (long long) offset, rlen);
    xrootd_log_access(ctx, c, "PGREAD", ctx->files[idx].path,
                      detail, 1, 0, NULL, rlen);
    XROOTD_OP_OK(ctx, XROOTD_OP_PGREAD);

    {
        ngx_int_t rc = xrootd_queue_response_chain(ctx, c, rsp_chain, out_buf);
        if (rc != NGX_OK || ctx->state != XRD_ST_SENDING) {
            xrootd_release_read_buffer(ctx, c, out_buf);
        }
        return rc;
    }
}

/* ------------------------------------------------------------------ */
/* kXR_locate — file replica location query                            */
/*                                                                     */
/* For a data server we return a single-entry location string in the  */
/* format "XY<host:port>" where X=S (server online), Y=r|w.           */
/* ------------------------------------------------------------------ */
ngx_int_t
xrootd_handle_locate(xrootd_ctx_t *ctx, ngx_connection_t *c,
                     ngx_stream_xrootd_srv_conf_t *conf)
{
    ClientLocateRequest *req = (ClientLocateRequest *) ctx->hdr_buf;
    char     reqpath_buf[XROOTD_MAX_PATH + 1];
    char     resolved[PATH_MAX];
    struct   sockaddr_in *sin;
    char     loc_buf[256];
    char     addr_buf[INET6_ADDRSTRLEN + 8];
    int      loc_len;
    int      is_wildcard;
    uint16_t port;
    char     access_char;

    (void) req;   /* options field unused for data-server implementation */

    /* Validate and extract path from payload. */
    if (ctx->cur_dlen == 0 || ctx->payload == NULL) {
        XROOTD_OP_ERR(ctx, XROOTD_OP_LOCATE);
        return xrootd_send_error(ctx, c, kXR_ArgMissing, "no path given");
    }

    if (!xrootd_extract_path(c->log, ctx->payload, ctx->cur_dlen,
                             reqpath_buf, sizeof(reqpath_buf), 1)) {
        XROOTD_OP_ERR(ctx, XROOTD_OP_LOCATE);
        return xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                 "invalid path payload");
    }

    is_wildcard = (reqpath_buf[0] == '*' && reqpath_buf[1] == '\0');

    /* Manager-mode static mapping: check for a configured redirect before local resolution. */
    if (!is_wildcard && conf->manager_map != NULL) {
        const xrootd_manager_map_t *m = xrootd_find_manager_map(reqpath_buf,
                                                                conf->manager_map);
        if (m != NULL) {
            xrootd_log_access(ctx, c, "LOCATE", reqpath_buf, "redirect",
                              1, 0, NULL, 0);
            XROOTD_OP_OK(ctx, XROOTD_OP_LOCATE);
            return xrootd_send_redirect(ctx, c, (const char *) m->host.data,
                                        m->port);
        }
    }

    if (!is_wildcard) {
        /* Verify the path exists and is accessible. */
        if (!xrootd_resolve_path(c->log, &conf->root,
                                 reqpath_buf, resolved, sizeof(resolved))) {
            /* No local file — query upstream redirector if configured */
            if (conf->upstream_host.len > 0) {
                xrootd_log_access(ctx, c, "LOCATE", reqpath_buf,
                                  "upstream", 1, 0, NULL, 0);
                XROOTD_OP_OK(ctx, XROOTD_OP_LOCATE);
                return xrootd_upstream_start(ctx, c, conf);
            }
            xrootd_log_access(ctx, c, "LOCATE", reqpath_buf, "-",
                              0, kXR_NotFound, "file not found", 0);
            XROOTD_OP_ERR(ctx, XROOTD_OP_LOCATE);
            return xrootd_send_error(ctx, c, kXR_NotFound, "file not found");
        }

        if (xrootd_check_vo_acl(c->log, resolved, conf->vo_rules,
                                 ctx->vo_list) != NGX_OK) {
            XROOTD_OP_ERR(ctx, XROOTD_OP_LOCATE);
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "VO not authorized");
        }
    }

    /* Determine access level for this server. */
    access_char = conf->allow_write ? 'w' : 'r';

    /* Format the local endpoint as "host:port". */
    if (c->local_sockaddr != NULL
        && c->local_sockaddr->sa_family == AF_INET) {
        sin  = (struct sockaddr_in *) c->local_sockaddr;
        port = ntohs(sin->sin_port);
        snprintf(addr_buf, sizeof(addr_buf), "%s:%d",
                 inet_ntoa(sin->sin_addr), (int) port);
    } else {
        snprintf(addr_buf, sizeof(addr_buf), "localhost");
    }

    /* Build the single-entry response: "S<access><addr>\0" */
    loc_len = snprintf(loc_buf, sizeof(loc_buf), "S%c%s", access_char, addr_buf);

    xrootd_log_access(ctx, c, "LOCATE", reqpath_buf, loc_buf,
                      1, 0, NULL, 0);
    XROOTD_OP_OK(ctx, XROOTD_OP_LOCATE);

    return xrootd_send_ok(ctx, c, loc_buf, (uint32_t)(loc_len + 1));
}

/* ------------------------------------------------------------------ */
/* kXR_statx — multi-path stat                                         */
/*                                                                     */
/* Payload is one or more NUL-separated paths.  The response is a     */
/* concatenation of per-path stat strings, each on its own line.      */
/* Paths that cannot be resolved produce an error sentinel line.       */
/* ------------------------------------------------------------------ */
ngx_int_t
xrootd_handle_statx(xrootd_ctx_t *ctx, ngx_connection_t *c,
                    ngx_stream_xrootd_srv_conf_t *conf)
{
#define XROOTD_STATX_MAX_PATHS  256
#define XROOTD_STATX_LINE_MAX   256
#define XROOTD_STATX_BUF_MAX    (XROOTD_STATX_MAX_PATHS * XROOTD_STATX_LINE_MAX)
#define XROOTD_STATX_ERR_LINE   "0 0 0 0\n"

    const u_char *p, *end, *path_start;
    u_char       *rsp_buf, *rsp_ptr;
    char          reqpath_buf[XROOTD_MAX_PATH + 1];
    char          resolved[PATH_MAX];
    struct stat   st;
    char          stat_body[XROOTD_STATX_LINE_MAX];
    size_t        path_len, stat_len;
    int           n_paths = 0;

    if (ctx->cur_dlen == 0 || ctx->payload == NULL) {
        XROOTD_OP_ERR(ctx, XROOTD_OP_STATX);
        return xrootd_send_error(ctx, c, kXR_ArgMissing, "no paths given");
    }

    rsp_buf = ngx_palloc(c->pool, XROOTD_STATX_BUF_MAX);
    if (rsp_buf == NULL) { return NGX_ERROR; }

    rsp_ptr = rsp_buf;
    p       = ctx->payload;
    end     = ctx->payload + ctx->cur_dlen;

    while (p < end && n_paths < XROOTD_STATX_MAX_PATHS) {
        /* Find the next NUL-terminated path in the payload. */
        path_start = p;
        while (p < end && *p != '\0') { p++; }

        path_len = (size_t)(p - path_start);
        if (p < end) { p++; }   /* skip the NUL separator */

        if (path_len == 0) { continue; }
        if (path_len >= sizeof(reqpath_buf)) { continue; }

        ngx_memcpy(reqpath_buf, path_start, path_len);
        reqpath_buf[path_len] = '\0';

        n_paths++;

        /* Resolve and stat the path. */
        if (!xrootd_resolve_path(c->log, &conf->root,
                                 reqpath_buf, resolved, sizeof(resolved))
            || xrootd_check_vo_acl(c->log, resolved, conf->vo_rules,
                                    ctx->vo_list) != NGX_OK
            || stat(resolved, &st) != 0)
        {
            /* Inaccessible or missing — emit error sentinel. */
            size_t errlen = sizeof(XROOTD_STATX_ERR_LINE) - 1;
            if (rsp_ptr + errlen < rsp_buf + XROOTD_STATX_BUF_MAX) {
                ngx_memcpy(rsp_ptr, XROOTD_STATX_ERR_LINE, errlen);
                rsp_ptr += errlen;
            }
            continue;
        }

        xrootd_make_stat_body(&st, 0, stat_body, sizeof(stat_body));
        stat_len = strlen(stat_body);

        if (rsp_ptr + stat_len + 1 < rsp_buf + XROOTD_STATX_BUF_MAX) {
            ngx_memcpy(rsp_ptr, stat_body, stat_len);
            rsp_ptr += stat_len;
            *rsp_ptr++ = '\n';
        }
    }

    /* Replace the last '\n' with '\0' per the XRootD stat wire protocol. */
    if (rsp_ptr > rsp_buf && *(rsp_ptr - 1) == '\n') {
        *(rsp_ptr - 1) = '\0';
    } else {
        *rsp_ptr++ = '\0';
    }

    {
        char detail[32];
        snprintf(detail, sizeof(detail), "%d_paths", n_paths);
        xrootd_log_access(ctx, c, "STATX", "-", detail, 1, 0, NULL, 0);
    }
    XROOTD_OP_OK(ctx, XROOTD_OP_STATX);

    return xrootd_send_ok(ctx, c, rsp_buf,
                          (uint32_t)((size_t)(rsp_ptr - rsp_buf)));
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

        /* Prefer written-byte totals when uploads happened so write handles log correctly. */

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
