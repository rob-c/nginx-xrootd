#include "ngx_xrootd_module.h"

/* ================================================================== */
/*  Write handlers                                                      */
/* ================================================================== */



ngx_int_t
xrootd_handle_write(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    ClientWriteRequest           *req  = (ClientWriteRequest *) ctx->hdr_buf;
    int     idx    = (int)(unsigned char) req->fhandle[0];
    int64_t offset = (int64_t) be64toh((uint64_t) req->offset);
    size_t  wlen   = ctx->cur_dlen;
    ssize_t nwritten;
    char    write_detail[64];

    /* The first byte of the 4-byte opaque handle is our internal slot index. */
    if (idx < 0 || idx >= XROOTD_MAX_FILES || ctx->files[idx].fd < 0) {
        xrootd_log_access(ctx, c, "WRITE", "-", "-",
                          0, kXR_FileNotOpen, "invalid file handle", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_WRITE);
        return xrootd_send_error(ctx, c, kXR_FileNotOpen,
                                 "invalid file handle");
    }

    if (!ctx->files[idx].writable) {
        xrootd_log_access(ctx, c, "WRITE", ctx->files[idx].path, "-",
                          0, kXR_NotAuthorized, "file not open for writing", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_WRITE);
        return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                 "file not open for writing");
    }

    if (wlen == 0) {
        /* Zero-length writes are valid no-ops that still count as successful requests. */
        XROOTD_OP_OK(ctx, XROOTD_OP_WRITE);
        return xrootd_send_ok(ctx, c, NULL, 0);
    }

#if (NGX_THREADS)
    {
    ngx_stream_xrootd_srv_conf_t *conf =
        ngx_stream_get_module_srv_conf((ngx_stream_session_t *)(c->data), ngx_stream_xrootd_module);
    if (conf->thread_pool != NULL) {
        ngx_thread_task_t   *task;
        xrootd_write_aio_t  *t;

        task = ngx_thread_task_alloc(c->pool, sizeof(xrootd_write_aio_t));
        if (task == NULL) { return NGX_ERROR; }

        t = task->ctx;
        t->c               = c;
        t->ctx             = ctx;
        t->conf            = conf;
        t->fd              = ctx->files[idx].fd;
        t->handle_idx      = idx;
        t->offset          = (off_t) offset;
        t->data            = ctx->payload ? ctx->payload : (u_char *) "";
        t->len             = wlen;
        t->req_offset      = offset;
        t->is_pgwrite      = 0;
        t->nwritten        = -1;
        t->io_errno        = 0;
        /* Keep the request payload alive until the completion handler runs. */
        t->payload_to_free = ctx->payload;   /* freed in done handler */
        t->streamid[0]     = ctx->cur_streamid[0];
        t->streamid[1]     = ctx->cur_streamid[1];
        ngx_memcpy(t->path, ctx->files[idx].path, sizeof(t->path));

        task->handler       = xrootd_write_aio_thread;
        task->event.handler = xrootd_write_aio_done;
        task->event.data    = task;

        if (ngx_thread_task_post(conf->thread_pool, task) != NGX_OK) {
            ngx_log_error(NGX_LOG_WARN, c->log, 0,
                          "xrootd: thread_task_post failed, falling back to sync write");
            goto sync_write;
        }

        /* Completion callback will restore streamid/state and send the final reply. */
        ctx->state = XRD_ST_AIO;
        return NGX_OK;
    }
    } /* end NGX_THREADS block */

sync_write:
#endif /* NGX_THREADS */

    /* Synchronous fallback writes the request payload directly from the recv buffer. */
    nwritten = pwrite(ctx->files[idx].fd,
                      ctx->payload ? ctx->payload : (u_char *) "",
                      wlen, (off_t) offset);

    /* Access log detail format for writes is "<offset>+<requested-bytes>". */
    snprintf(write_detail, sizeof(write_detail), "%lld+%zu",
             (long long) offset, wlen);

    if (nwritten < 0) {
        xrootd_log_access(ctx, c, "WRITE", ctx->files[idx].path,
                          write_detail, 0, kXR_IOError, strerror(errno), 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_WRITE);
        return xrootd_send_error(ctx, c, kXR_IOError, strerror(errno));
    }

    if ((size_t) nwritten < wlen) {
        xrootd_log_access(ctx, c, "WRITE", ctx->files[idx].path,
                          write_detail, 0, kXR_IOError, "short write (disk full?)", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_WRITE);
        return xrootd_send_error(ctx, c, kXR_IOError, "short write (disk full?)");
    }

    ctx->files[idx].bytes_written  += (size_t) nwritten;
    ctx->session_bytes_written     += (size_t) nwritten;

    xrootd_log_access(ctx, c, "WRITE", ctx->files[idx].path,
                      write_detail, 1, 0, NULL, (size_t) nwritten);
    XROOTD_OP_OK(ctx, XROOTD_OP_WRITE);

    return xrootd_send_ok(ctx, c, NULL, 0);
}

/*
 * kXR_pgwrite — paged write with per-page CRC32c checksums.
 *
 * Used by modern xrdcp (XRootD v5+) in preference to kXR_write.
 *
 * Payload layout (CRC comes FIRST, not last):
 *   [4 bytes CRC32c][up to 4096 bytes data] per page, back-to-back.
 *   The last page may carry fewer than 4096 data bytes but still has 4 bytes CRC32c.
 *   CRC32c uses the Castagnoli polynomial (not generic CRC32).
 *
 * We strip the CRC32c fields to produce a flat data buffer, then write it
 * with a single pwrite() — either synchronously or via the thread pool.
 * CRC32c verification is intentionally skipped: the TCP checksum already
 * ensures integrity on loopback and LAN.
 *
 * Response format: kXR_status (NOT plain kXR_ok).
 *   The xrdcp v5 client parses pgwrite responses as ServerResponseV2
 *   (32 bytes: 8-byte header + 16-byte Status body + 8-byte pgWrite body).
 *   Sending a plain 8-byte kXR_ok causes the client to read 24 bytes past
 *   the end of the response buffer and crash.  See xrootd_send_pgwrite_status().
 */
ngx_int_t
xrootd_handle_pgwrite(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    ClientPgWriteRequest         *req  = (ClientPgWriteRequest *) ctx->hdr_buf;
    int     idx     = (int)(unsigned char) req->fhandle[0];
    int64_t offset  = (int64_t) be64toh((uint64_t) req->offset);
    size_t  dlen    = ctx->cur_dlen;
    u_char *payload = ctx->payload;
    int64_t write_offset;
    size_t  page_data, total_written;
    ssize_t nw;
    char    write_detail[64];

    if (idx < 0 || idx >= XROOTD_MAX_FILES || ctx->files[idx].fd < 0) {
        xrootd_log_access(ctx, c, "WRITE", "-", "-",
                          0, kXR_FileNotOpen, "invalid file handle", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_WRITE);
        return xrootd_send_error(ctx, c, kXR_FileNotOpen,
                                 "invalid file handle");
    }

    if (!ctx->files[idx].writable) {
        xrootd_log_access(ctx, c, "WRITE", ctx->files[idx].path, "-",
                          0, kXR_NotAuthorized, "file not open for writing", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_WRITE);
        return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                 "file not open for writing");
    }

    if (payload == NULL || dlen == 0) {
        /* Empty pgwrite is treated like a successful zero-byte write. */
        XROOTD_OP_OK(ctx, XROOTD_OP_WRITE);
        return xrootd_send_ok(ctx, c, NULL, 0);
    }

    /*
     * Strip interleaved 4-byte CRC32c fields from the pgwrite payload to
     * produce a flat data buffer for pwrite().
     *
     * Payload layout (CRC first):
     *   [XRD_PGWRITE_CKSZ=4 bytes CRC32c][up to XRD_PGWRITE_PAGESZ=4096 bytes data]
     * repeated for each page.  The last page may have fewer than 4096 data
     * bytes.  The CRC32c values are discarded.
     */
    {
        u_char *flat    = ngx_palloc(c->pool, dlen);   /* upper bound */
        u_char *src     = payload;
        u_char *dst;
        size_t  rem     = dlen;
        size_t  flat_sz = 0;

        if (flat == NULL) { return NGX_ERROR; }
        dst = flat;

        while (rem > XRD_PGWRITE_CKSZ) {
            /* Skip the per-page CRC field, then copy only the page data bytes forward. */
            src += XRD_PGWRITE_CKSZ;
            rem -= XRD_PGWRITE_CKSZ;
            page_data = (rem >= XRD_PGWRITE_PAGESZ) ? XRD_PGWRITE_PAGESZ : rem;
            ngx_memcpy(dst, src, page_data);
            dst     += page_data;
            src     += page_data;
            rem     -= page_data;
            flat_sz += page_data;
        }

#if (NGX_THREADS)
        {
        ngx_stream_xrootd_srv_conf_t *conf =
            ngx_stream_get_module_srv_conf((ngx_stream_session_t *)(c->data), ngx_stream_xrootd_module);
        if (conf->thread_pool != NULL) {
            ngx_thread_task_t   *task;
            xrootd_write_aio_t  *t;

            task = ngx_thread_task_alloc(c->pool, sizeof(xrootd_write_aio_t));
            if (task == NULL) { return NGX_ERROR; }

            t = task->ctx;
            t->c               = c;
            t->ctx             = ctx;
            t->conf            = conf;
            t->fd              = ctx->files[idx].fd;
            t->handle_idx      = idx;
            t->offset          = (off_t) offset;
            t->data            = flat;
            t->len             = flat_sz;
            t->req_offset      = offset;
            t->is_pgwrite      = 1;
            t->nwritten        = -1;
            t->io_errno        = 0;
            /* The flattened buffer belongs to the async write until completion. */
            t->payload_to_free = flat;   /* freed in done handler */
            t->streamid[0]     = ctx->cur_streamid[0];
            t->streamid[1]     = ctx->cur_streamid[1];
            ngx_memcpy(t->path, ctx->files[idx].path, sizeof(t->path));

            task->handler       = xrootd_write_aio_thread;
            task->event.handler = xrootd_write_aio_done;
            task->event.data    = task;

            if (ngx_thread_task_post(conf->thread_pool, task) == NGX_OK) {
                /* Async completion sends the mandatory kXR_status pgwrite reply. */
                ctx->state = XRD_ST_AIO;
                return NGX_OK;
            }
            ngx_log_error(NGX_LOG_WARN, c->log, 0,
                          "xrootd: thread_task_post failed, falling back to sync pgwrite");
        }
        } /* end NGX_THREADS block */
#endif /* NGX_THREADS */

        /* Synchronous path: write the flat buffer page by page */
        write_offset  = offset;
        total_written = 0;
        src = flat;
        rem = flat_sz;

        while (rem > 0) {
            /* Preserve page-sized progress so the final status can report the end offset. */
            page_data = (rem >= XRD_PGWRITE_PAGESZ) ? XRD_PGWRITE_PAGESZ : rem;
            nw = pwrite(ctx->files[idx].fd, src, page_data, (off_t) write_offset);
            if (nw < 0) {
                snprintf(write_detail, sizeof(write_detail), "%lld+%zu",
                         (long long) offset, total_written);
                xrootd_log_access(ctx, c, "WRITE", ctx->files[idx].path,
                                  write_detail, 0, kXR_IOError, strerror(errno), 0);
                XROOTD_OP_ERR(ctx, XROOTD_OP_WRITE);
                return xrootd_send_error(ctx, c, kXR_IOError, strerror(errno));
            }
            if ((size_t) nw < page_data) {
                snprintf(write_detail, sizeof(write_detail), "%lld+%zu",
                         (long long) offset, total_written);
                xrootd_log_access(ctx, c, "WRITE", ctx->files[idx].path,
                                  write_detail, 0, kXR_IOError, "short write (disk full?)", 0);
                XROOTD_OP_ERR(ctx, XROOTD_OP_WRITE);
                return xrootd_send_error(ctx, c, kXR_IOError, "short write (disk full?)");
            }
            total_written += (size_t) nw;
            write_offset  += (int64_t) nw;
            src           += page_data;
            rem           -= page_data;
        }

        /* pgwrite accounting uses the same write counters as plain kXR_write. */
        ctx->files[idx].bytes_written += total_written;
        ctx->session_bytes_written    += total_written;

        snprintf(write_detail, sizeof(write_detail), "%lld+%zu",
                 (long long) offset, total_written);
        xrootd_log_access(ctx, c, "WRITE", ctx->files[idx].path,
                          write_detail, 1, 0, NULL, total_written);
        XROOTD_OP_OK(ctx, XROOTD_OP_WRITE);

        return xrootd_send_pgwrite_status(ctx, c, write_offset);
    }
}

/*
 * kXR_sync — flush/fsync an open file handle.
 *
 * Ensures all previously written data is durable on the underlying
 * filesystem.  xrdcp issues kXR_sync before kXR_close on uploads.
 */
ngx_int_t
xrootd_handle_sync(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    ClientSyncRequest *req = (ClientSyncRequest *) ctx->hdr_buf;
    int idx = (int)(unsigned char) req->fhandle[0];

    if (idx < 0 || idx >= XROOTD_MAX_FILES || ctx->files[idx].fd < 0) {
        xrootd_log_access(ctx, c, "SYNC", "-", "-",
                          0, kXR_FileNotOpen, "invalid file handle", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_SYNC);
        return xrootd_send_error(ctx, c, kXR_FileNotOpen,
                                 "invalid file handle");
    }

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: kXR_sync handle=%d", idx);

    if (fsync(ctx->files[idx].fd) != 0) {
        xrootd_log_access(ctx, c, "SYNC", ctx->files[idx].path, "-",
                          0, kXR_IOError, strerror(errno), 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_SYNC);
        return xrootd_send_error(ctx, c, kXR_IOError, strerror(errno));
    }

    xrootd_log_access(ctx, c, "SYNC", ctx->files[idx].path, "-",
                      1, 0, NULL, 0);
    XROOTD_OP_OK(ctx, XROOTD_OP_SYNC);
    return xrootd_send_ok(ctx, c, NULL, 0);
}

/*
 * kXR_truncate — truncate a file by path or open handle.
 *
 * If dlen > 0: path-based truncate (payload is path).
 * If dlen == 0: handle-based truncate using fhandle[0].
 * The offset field carries the target file length.
 */
ngx_int_t
xrootd_handle_truncate(xrootd_ctx_t *ctx, ngx_connection_t *c,
                        ngx_stream_xrootd_srv_conf_t *conf)
{
    ClientTruncateRequest *req = (ClientTruncateRequest *) ctx->hdr_buf;
    int64_t  length = (int64_t) be64toh((uint64_t) req->offset);
    char     detail[64];
    int      rc;

    snprintf(detail, sizeof(detail), "%lld", (long long) length);

    if (ctx->cur_dlen > 0) {
        /* Path-based truncate */
        char resolved[PATH_MAX];
        char reqpath[XROOTD_MAX_PATH + 1];
        if (ctx->payload == NULL) {
            return xrootd_send_error(ctx, c, kXR_ArgMissing, "no path given");
        }
        if (!xrootd_extract_path(c->log, ctx->payload, ctx->cur_dlen,
                                 reqpath, sizeof(reqpath), 0)) {
            xrootd_log_access(ctx, c, "TRUNCATE", "-", detail,
                              0, kXR_ArgInvalid, "invalid path payload", 0);
            XROOTD_OP_ERR(ctx, XROOTD_OP_TRUNCATE);
            return xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                     "invalid path payload");
        }
        if (!xrootd_resolve_path_write(c->log, &conf->root,
                                       reqpath,
                                       resolved, sizeof(resolved))) {
              /*
               * write-style resolution handles the common "target may not exist" case.
               * If that fails, fall back to the normal resolver so existing files with
               * canonical paths still truncate correctly.
               */
            if (!xrootd_resolve_path(c->log, &conf->root,
                                     reqpath,
                                     resolved, sizeof(resolved))) {
                xrootd_log_access(ctx, c, "TRUNCATE", reqpath,
                                  detail, 0, kXR_NotFound, "file not found", 0);
                XROOTD_OP_ERR(ctx, XROOTD_OP_TRUNCATE);
                return xrootd_send_error(ctx, c, kXR_NotFound, "file not found");
            }
        }
        if (xrootd_check_vo_acl(c->log, resolved, conf->vo_rules,
                                 ctx->vo_list) != NGX_OK) {
            xrootd_log_access(ctx, c, "TRUNCATE", resolved, detail,
                              0, kXR_NotAuthorized, "VO not authorized", 0);
            XROOTD_OP_ERR(ctx, XROOTD_OP_TRUNCATE);
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "VO not authorized");
        }
        rc = truncate(resolved, (off_t) length);
        if (rc != 0) {
            xrootd_log_access(ctx, c, "TRUNCATE", resolved, detail,
                              0, kXR_IOError, strerror(errno), 0);
            XROOTD_OP_ERR(ctx, XROOTD_OP_TRUNCATE);
            return xrootd_send_error(ctx, c, kXR_IOError, strerror(errno));
        }
        xrootd_log_access(ctx, c, "TRUNCATE", resolved, detail,
                          1, 0, NULL, 0);
    } else {
        /* Handle-based truncate bypasses path resolution and uses the already-open fd. */
        int idx = (int)(unsigned char) req->fhandle[0];
        if (idx < 0 || idx >= XROOTD_MAX_FILES || ctx->files[idx].fd < 0) {
            xrootd_log_access(ctx, c, "TRUNCATE", "-", detail,
                              0, kXR_FileNotOpen, "invalid file handle", 0);
            XROOTD_OP_ERR(ctx, XROOTD_OP_TRUNCATE);
            return xrootd_send_error(ctx, c, kXR_FileNotOpen,
                                     "invalid file handle");
        }
        rc = ftruncate(ctx->files[idx].fd, (off_t) length);
        if (rc != 0) {
            xrootd_log_access(ctx, c, "TRUNCATE", ctx->files[idx].path, detail,
                              0, kXR_IOError, strerror(errno), 0);
            XROOTD_OP_ERR(ctx, XROOTD_OP_TRUNCATE);
            return xrootd_send_error(ctx, c, kXR_IOError, strerror(errno));
        }
        xrootd_log_access(ctx, c, "TRUNCATE", ctx->files[idx].path, detail,
                          1, 0, NULL, 0);
    }

    XROOTD_OP_OK(ctx, XROOTD_OP_TRUNCATE);
    return xrootd_send_ok(ctx, c, NULL, 0);
}

/*
 * kXR_mkdir — create a directory.
 *
 * options[0] bit kXR_mkdirpath (0x01): create parent directories too.
 * mode field: Unix permission bits.
 */
ngx_int_t
xrootd_handle_mkdir(xrootd_ctx_t *ctx, ngx_connection_t *c,
                     ngx_stream_xrootd_srv_conf_t *conf)
{
    ClientMkdirRequest *req = (ClientMkdirRequest *) ctx->hdr_buf;
    char     reqpath[XROOTD_MAX_PATH + 1];
    char     resolved[PATH_MAX];
    mode_t   mode;
    int      recursive;

    if (ctx->payload == NULL || ctx->cur_dlen == 0) {
        return xrootd_send_error(ctx, c, kXR_ArgMissing, "no path given");
    }

    recursive = (req->options[0] & kXR_mkdirpath) ? 1 : 0;
    mode      = ntohs(req->mode) & 0777;
    if (mode == 0) {
        mode = 0755;
    }

    /* kXR_mkdirpath changes only namespace creation strategy, not permission handling. */

    if (!xrootd_extract_path(c->log, ctx->payload, ctx->cur_dlen,
                             reqpath, sizeof(reqpath), 0)) {
        xrootd_log_access(ctx, c, "MKDIR", "-", "-",
                          0, kXR_ArgInvalid, "invalid path payload", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_MKDIR);
        return xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                 "invalid path payload");
    }

    /*
     * Resolve the target path.  For recursive mkdir intermediate directories
     * do not exist yet, so we use xrootd_resolve_path_noexist (no realpath).
     * For a single-level mkdir the parent must exist, so use the write resolver.
     */
    if (recursive) {
        if (!xrootd_resolve_path_noexist(c->log, &conf->root,
                                          reqpath,
                                          resolved, sizeof(resolved))) {
            xrootd_log_access(ctx, c, "MKDIR", reqpath, "-",
                              0, kXR_NotFound, "invalid path", 0);
            XROOTD_OP_ERR(ctx, XROOTD_OP_MKDIR);
            return xrootd_send_error(ctx, c, kXR_NotFound, "invalid path");
        }
    } else {
        if (!xrootd_resolve_path_write(c->log, &conf->root,
                                       reqpath,
                                       resolved, sizeof(resolved))) {
            xrootd_log_access(ctx, c, "MKDIR", reqpath, "-",
                              0, kXR_NotFound, "invalid path", 0);
            XROOTD_OP_ERR(ctx, XROOTD_OP_MKDIR);
            return xrootd_send_error(ctx, c, kXR_NotFound, "invalid path");
        }
    }

    if (xrootd_check_vo_acl(c->log, resolved, conf->vo_rules,
                             ctx->vo_list) != NGX_OK) {
        xrootd_log_access(ctx, c, "MKDIR", resolved, "-",
                          0, kXR_NotAuthorized, "VO not authorized", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_MKDIR);
        return xrootd_send_error(ctx, c, kXR_NotAuthorized, "VO not authorized");
    }

    if (recursive) {
        if (xrootd_mkdir_recursive_policy(resolved, mode, c->log,
                                          conf->group_rules) != 0
            && errno != EEXIST)
        {
            xrootd_log_access(ctx, c, "MKDIR", resolved, "-",
                              0, kXR_IOError, strerror(errno), 0);
            XROOTD_OP_ERR(ctx, XROOTD_OP_MKDIR);
            return xrootd_send_error(ctx, c, kXR_IOError, strerror(errno));
        }
    } else {
        /* Non-recursive mkdir maps directly to one mkdir(2) call on the resolved leaf. */
        if (mkdir(resolved, mode) != 0) {
            int err = errno;
            if (err == EEXIST) {
                /* Not an error — directory already exists */
            } else if (err == EACCES) {
                xrootd_log_access(ctx, c, "MKDIR", resolved, "-",
                                  0, kXR_NotAuthorized, "permission denied", 0);
                XROOTD_OP_ERR(ctx, XROOTD_OP_MKDIR);
                return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                         "permission denied");
            } else {
                xrootd_log_access(ctx, c, "MKDIR", resolved, "-",
                                  0, kXR_IOError, strerror(err), 0);
                XROOTD_OP_ERR(ctx, XROOTD_OP_MKDIR);
                return xrootd_send_error(ctx, c, kXR_IOError, strerror(err));
            }
        }
        /* Align ownership/group-bits of new directory with parent dir policy. */
        if (conf->group_rules != NULL) {
            xrootd_apply_parent_group_policy_path(c->log, resolved,
                                                  conf->group_rules);
        }
    }

    xrootd_log_access(ctx, c, "MKDIR", resolved, "-", 1, 0, NULL, 0);
    XROOTD_OP_OK(ctx, XROOTD_OP_MKDIR);
    return xrootd_send_ok(ctx, c, NULL, 0);
}

/*
 * kXR_rm — remove a file.
 *
 * Path is in the payload.  Does not remove directories (use kXR_rmdir).
 */
ngx_int_t
xrootd_handle_rm(xrootd_ctx_t *ctx, ngx_connection_t *c,
                  ngx_stream_xrootd_srv_conf_t *conf)
{
    char reqpath[XROOTD_MAX_PATH + 1];
    char resolved[PATH_MAX];

    if (ctx->payload == NULL || ctx->cur_dlen == 0) {
        return xrootd_send_error(ctx, c, kXR_ArgMissing, "no path given");
    }

    if (!xrootd_extract_path(c->log, ctx->payload, ctx->cur_dlen,
                             reqpath, sizeof(reqpath), 0)) {
        xrootd_log_access(ctx, c, "RM", "-", "-",
                          0, kXR_ArgInvalid, "invalid path payload", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_RM);
        return xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                 "invalid path payload");
    }

    /* File must exist for rm — use standard resolve */
    if (!xrootd_resolve_path(c->log, &conf->root,
                              reqpath,
                              resolved, sizeof(resolved))) {
        xrootd_log_access(ctx, c, "RM", reqpath, "-",
                          0, kXR_NotFound, "file not found", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_RM);
        return xrootd_send_error(ctx, c, kXR_NotFound, "file not found");
    }

    if (xrootd_check_vo_acl(c->log, resolved, conf->vo_rules,
                             ctx->vo_list) != NGX_OK) {
        xrootd_log_access(ctx, c, "RM", resolved, "-",
                          0, kXR_NotAuthorized, "VO not authorized", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_RM);
        return xrootd_send_error(ctx, c, kXR_NotAuthorized, "VO not authorized");
    }

    if (unlink(resolved) != 0) {
        int err = errno;
        if (err == EACCES || err == EPERM) {
            xrootd_log_access(ctx, c, "RM", resolved, "-",
                              0, kXR_NotAuthorized, "permission denied", 0);
            XROOTD_OP_ERR(ctx, XROOTD_OP_RM);
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "permission denied");
        }
        xrootd_log_access(ctx, c, "RM", resolved, "-",
                          0, kXR_IOError, strerror(err), 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_RM);
        return xrootd_send_error(ctx, c, kXR_IOError, strerror(err));
    }

    xrootd_log_access(ctx, c, "RM", resolved, "-", 1, 0, NULL, 0);
    XROOTD_OP_OK(ctx, XROOTD_OP_RM);
    return xrootd_send_ok(ctx, c, NULL, 0);
}

/*
 * kXR_rmdir — remove an empty directory.
 *
 * Path is in the payload.  Fails with kXR_NotFound if path doesn't exist,
 * kXR_FSError (ENOTEMPTY) if the directory is not empty.
 */
ngx_int_t
xrootd_handle_rmdir(xrootd_ctx_t *ctx, ngx_connection_t *c,
                    ngx_stream_xrootd_srv_conf_t *conf)
{
    char reqpath[XROOTD_MAX_PATH + 1];
    char resolved[PATH_MAX];

    if (ctx->payload == NULL || ctx->cur_dlen == 0) {
        return xrootd_send_error(ctx, c, kXR_ArgMissing, "no path given");
    }

    if (!xrootd_extract_path(c->log, ctx->payload, ctx->cur_dlen,
                             reqpath, sizeof(reqpath), 0)) {
        xrootd_log_access(ctx, c, "RMDIR", "-", "-",
                          0, kXR_ArgInvalid, "invalid path payload", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_RMDIR);
        return xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                 "invalid path payload");
    }

    if (!xrootd_resolve_path(c->log, &conf->root,
                              reqpath,
                              resolved, sizeof(resolved))) {
        xrootd_log_access(ctx, c, "RMDIR", reqpath, "-",
                          0, kXR_NotFound, "directory not found", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_RMDIR);
        return xrootd_send_error(ctx, c, kXR_NotFound, "directory not found");
    }

    if (xrootd_check_vo_acl(c->log, resolved, conf->vo_rules,
                             ctx->vo_list) != NGX_OK) {
        xrootd_log_access(ctx, c, "RMDIR", resolved, "-",
                          0, kXR_NotAuthorized, "VO not authorized", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_RMDIR);
        return xrootd_send_error(ctx, c, kXR_NotAuthorized, "VO not authorized");
    }

    if (rmdir(resolved) != 0) {
        int err = errno;

        /* Map common namespace errors to protocol-level directory semantics. */
        if (err == ENOTEMPTY || err == EEXIST) {
            xrootd_log_access(ctx, c, "RMDIR", resolved, "-",
                              0, kXR_FSError, "directory not empty", 0);
            XROOTD_OP_ERR(ctx, XROOTD_OP_RMDIR);
            return xrootd_send_error(ctx, c, kXR_FSError,
                                     "directory not empty");
        }
        if (err == EACCES || err == EPERM) {
            xrootd_log_access(ctx, c, "RMDIR", resolved, "-",
                              0, kXR_NotAuthorized, "permission denied", 0);
            XROOTD_OP_ERR(ctx, XROOTD_OP_RMDIR);
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "permission denied");
        }
        if (err == ENOTDIR) {
            xrootd_log_access(ctx, c, "RMDIR", resolved, "-",
                              0, kXR_NotFile, "not a directory", 0);
            XROOTD_OP_ERR(ctx, XROOTD_OP_RMDIR);
            return xrootd_send_error(ctx, c, kXR_NotFile, "not a directory");
        }
        xrootd_log_access(ctx, c, "RMDIR", resolved, "-",
                          0, kXR_IOError, strerror(err), 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_RMDIR);
        return xrootd_send_error(ctx, c, kXR_IOError, strerror(err));
    }

    xrootd_log_access(ctx, c, "RMDIR", resolved, "-", 1, 0, NULL, 0);
    XROOTD_OP_OK(ctx, XROOTD_OP_RMDIR);
    return xrootd_send_ok(ctx, c, NULL, 0);
}

/*
 * kXR_mv — rename/move a file or directory.
 *
 * Payload layout (from XrdClFileSystem.cc):
 *   header.arg1len = source.length()   ← byte count, no trailing NUL
 *   payload        = src[arg1len] + ' ' (0x20) + dst[...]
 *
 * The separator is a single ASCII space — NOT a null byte.  arg1len does
 * NOT include any terminator.  The destination runs to the end of dlen.
 *
 * Both paths must be inside the server root; rename(2) is used, so cross-
 * device moves return EXDEV.
 */
ngx_int_t
xrootd_handle_mv(xrootd_ctx_t *ctx, ngx_connection_t *c,
                 ngx_stream_xrootd_srv_conf_t *conf)
{
    ClientMvRequest *req = (ClientMvRequest *) ctx->hdr_buf;
    char src_resolved[PATH_MAX];
    char dst_resolved[PATH_MAX];
    char src_buf[XROOTD_MAX_PATH + 1];
    char dst_buf[XROOTD_MAX_PATH + 1];
    int16_t  src_len;
    size_t   dst_len;

    if (ctx->payload == NULL || ctx->cur_dlen == 0) {
        return xrootd_send_error(ctx, c, kXR_ArgMissing, "no paths given");
    }

    /*
     * Wire format (from XrdClFileSystem.cc):
     *   arg1len = source.length()       (NOT including any terminator)
     *   dlen    = src.length() + dst.length() + 1
     *   payload = src[arg1len] + ' ' + dst[...]
     * The separator between source and destination is a single space (0x20).
     */
    src_len = (int16_t) ntohs((uint16_t) req->arg1len);
    if (src_len <= 0 || (uint32_t)(src_len + 1) >= ctx->cur_dlen) {
        return xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                 "invalid arg1len for mv");
    }

    /* Separator byte at src_len must be a space */
    if (ctx->payload[src_len] != ' ') {
        return xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                 "mv payload separator not a space");
    }
    dst_len = (size_t) ctx->cur_dlen - (size_t) src_len - 1;
    if (dst_len == 0) {
        return xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                 "missing destination path");
    }

    /* Parse each half independently so embedded-NUL and traversal checks apply to both. */
    if (!xrootd_extract_path(c->log, ctx->payload, (size_t) src_len,
                             src_buf, sizeof(src_buf), 0)) {
        return xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                 "invalid source path payload");
    }

    if (!xrootd_extract_path(c->log, ctx->payload + src_len + 1, dst_len,
                             dst_buf, sizeof(dst_buf), 0)) {
        return xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                 "invalid destination path payload");
    }

    if (!xrootd_resolve_path(c->log, &conf->root, src_buf,
                              src_resolved, sizeof(src_resolved))) {
        xrootd_log_access(ctx, c, "MV", src_buf, "-",
                          0, kXR_NotFound, "source not found", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_MV);
        return xrootd_send_error(ctx, c, kXR_NotFound, "source not found");
    }

    if (xrootd_check_vo_acl(c->log, src_resolved, conf->vo_rules,
                             ctx->vo_list) != NGX_OK) {
        xrootd_log_access(ctx, c, "MV", src_resolved, "-",
                          0, kXR_NotAuthorized, "VO not authorized", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_MV);
        return xrootd_send_error(ctx, c, kXR_NotAuthorized, "VO not authorized");
    }

    if (!xrootd_resolve_path_write(c->log, &conf->root, dst_buf,
                                    dst_resolved, sizeof(dst_resolved))) {
        xrootd_log_access(ctx, c, "MV", src_buf, "-",
                          0, kXR_NotFound, "invalid destination path", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_MV);
        return xrootd_send_error(ctx, c, kXR_NotFound,
                                 "invalid destination path");
    }

    if (xrootd_check_vo_acl(c->log, dst_resolved, conf->vo_rules,
                             ctx->vo_list) != NGX_OK) {
        xrootd_log_access(ctx, c, "MV", dst_resolved, "-",
                          0, kXR_NotAuthorized, "VO not authorized for destination", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_MV);
        return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                 "VO not authorized for destination");
    }

    /* rename(2) performs the atomic namespace switch when source and dest share a filesystem. */
    if (rename(src_resolved, dst_resolved) != 0) {
        int err = errno;
        if (err == EACCES || err == EPERM) {
            xrootd_log_access(ctx, c, "MV", src_resolved, "-",
                              0, kXR_NotAuthorized, "permission denied", 0);
            XROOTD_OP_ERR(ctx, XROOTD_OP_MV);
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "permission denied");
        }
        xrootd_log_access(ctx, c, "MV", src_resolved, "-",
                          0, kXR_IOError, strerror(err), 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_MV);
        return xrootd_send_error(ctx, c, kXR_IOError, strerror(err));
    }

    xrootd_log_access(ctx, c, "MV", src_resolved, dst_resolved, 1, 0, NULL, 0);
    XROOTD_OP_OK(ctx, XROOTD_OP_MV);
    return xrootd_send_ok(ctx, c, NULL, 0);
}

/*
 * kXR_chmod — change the permission bits of a file or directory.
 *
 * The header's mode field carries the Unix permission bits (9 bits).
 * Path is in the payload.
 */
ngx_int_t
xrootd_handle_chmod(xrootd_ctx_t *ctx, ngx_connection_t *c,
                    ngx_stream_xrootd_srv_conf_t *conf)
{
    ClientChmodRequest *req = (ClientChmodRequest *) ctx->hdr_buf;
    char    reqpath[XROOTD_MAX_PATH + 1];
    char    resolved[PATH_MAX];
    mode_t  mode;

    if (ctx->payload == NULL || ctx->cur_dlen == 0) {
        return xrootd_send_error(ctx, c, kXR_ArgMissing, "no path given");
    }

    mode = ntohs(req->mode) & 0777;
    if (mode == 0) {
        mode = 0644;  /* sensible default if client sends 0 */
    }

    /* chmod uses only the low permission bits; file type bits are never client-controlled. */

    if (!xrootd_extract_path(c->log, ctx->payload, ctx->cur_dlen,
                             reqpath, sizeof(reqpath), 0)) {
        xrootd_log_access(ctx, c, "CHMOD", "-", "-",
                          0, kXR_ArgInvalid, "invalid path payload", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_CHMOD);
        return xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                 "invalid path payload");
    }

    if (!xrootd_resolve_path(c->log, &conf->root,
                              reqpath,
                              resolved, sizeof(resolved))) {
        xrootd_log_access(ctx, c, "CHMOD", reqpath, "-",
                          0, kXR_NotFound, "path not found", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_CHMOD);
        return xrootd_send_error(ctx, c, kXR_NotFound, "path not found");
    }

    if (xrootd_check_vo_acl(c->log, resolved, conf->vo_rules,
                             ctx->vo_list) != NGX_OK) {
        xrootd_log_access(ctx, c, "CHMOD", resolved, "-",
                          0, kXR_NotAuthorized, "VO not authorized", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_CHMOD);
        return xrootd_send_error(ctx, c, kXR_NotAuthorized, "VO not authorized");
    }

    if (chmod(resolved, mode) != 0) {
        int err = errno;
        if (err == EACCES || err == EPERM) {
            xrootd_log_access(ctx, c, "CHMOD", resolved, "-",
                              0, kXR_NotAuthorized, "permission denied", 0);
            XROOTD_OP_ERR(ctx, XROOTD_OP_CHMOD);
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "permission denied");
        }
        xrootd_log_access(ctx, c, "CHMOD", resolved, "-",
                          0, kXR_IOError, strerror(err), 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_CHMOD);
        return xrootd_send_error(ctx, c, kXR_IOError, strerror(err));
    }

    xrootd_log_access(ctx, c, "CHMOD", resolved, "-", 1, 0, NULL, 0);
    XROOTD_OP_OK(ctx, XROOTD_OP_CHMOD);
    return xrootd_send_ok(ctx, c, NULL, 0);
}
