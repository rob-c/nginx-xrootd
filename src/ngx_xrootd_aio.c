#include "ngx_xrootd_module.h"

/* ================================================================== */
/*  Response buffer builders (used by both sync and AIO paths)         */
/* ================================================================== */

/*
 * xrootd_build_read_response — build the chunked kXR_read response buffer.
 */
u_char *
xrootd_build_read_response(xrootd_ctx_t *ctx, ngx_connection_t *c,
    u_char *databuf, size_t data_total, size_t *rsp_total_out)
{
    size_t   n_chunks, last_size, rsp_total;
    u_char  *rspbuf;
    size_t   ri, di;

    n_chunks = (data_total + XROOTD_READ_MAX - 1) / XROOTD_READ_MAX;
    if (n_chunks == 0) { n_chunks = 1; }
    last_size = data_total % XROOTD_READ_MAX;
    if (last_size == 0 && data_total > 0) { last_size = XROOTD_READ_MAX; }

    rsp_total = n_chunks * XRD_RESPONSE_HDR_LEN + data_total;
    rspbuf    = ngx_palloc(c->pool, rsp_total);
    if (rspbuf == NULL) { return NULL; }

    ri = 0; di = 0;
    for (size_t chunk = 0; chunk < n_chunks; chunk++) {
        size_t   chunk_data = (chunk < n_chunks - 1) ? XROOTD_READ_MAX : last_size;
        uint16_t status     = (chunk == n_chunks - 1) ? kXR_ok : kXR_oksofar;

        xrootd_build_resp_hdr(ctx->cur_streamid, status,
                              (uint32_t) chunk_data,
                              (ServerResponseHdr *)(rspbuf + ri));
        ri += XRD_RESPONSE_HDR_LEN;
        ngx_memcpy(rspbuf + ri, databuf + di, chunk_data);
        ri += chunk_data;
        di += chunk_data;
    }

    *rsp_total_out = rsp_total;
    return rspbuf;
}

/*
 * xrootd_build_readv_response — build the chunked kXR_readv response buffer.
 */
u_char *
xrootd_build_readv_response(xrootd_ctx_t *ctx, ngx_connection_t *c,
    u_char *databuf, size_t rsp_total, size_t *out_size)
{
    size_t   n_chunks, last_size, buf_size;
    u_char  *rspbuf;
    size_t   ri, di;

    n_chunks = (rsp_total + XROOTD_READ_MAX - 1) / XROOTD_READ_MAX;
    if (n_chunks == 0) { n_chunks = 1; }
    last_size = rsp_total % XROOTD_READ_MAX;
    if (last_size == 0 && rsp_total > 0) { last_size = XROOTD_READ_MAX; }

    buf_size = n_chunks * XRD_RESPONSE_HDR_LEN + rsp_total;
    rspbuf   = ngx_palloc(c->pool, buf_size);
    if (rspbuf == NULL) { return NULL; }

    ri = 0; di = 0;
    for (size_t chunk = 0; chunk < n_chunks; chunk++) {
        size_t   chunk_data = (chunk < n_chunks - 1) ? XROOTD_READ_MAX : last_size;
        uint16_t status     = (chunk == n_chunks - 1) ? kXR_ok : kXR_oksofar;

        xrootd_build_resp_hdr(ctx->cur_streamid, status,
                              (uint32_t) chunk_data,
                              (ServerResponseHdr *)(rspbuf + ri));
        ri += XRD_RESPONSE_HDR_LEN;
        ngx_memcpy(rspbuf + ri, databuf + di, chunk_data);
        ri += chunk_data;
        di += chunk_data;
    }

    *out_size = buf_size;
    return rspbuf;
}

/* ================================================================== */
/*  Async I/O — thread pool support                                     */
/* ================================================================== */

#if (NGX_THREADS)

/* ------------------------------------------------------------------ */
/*  Thread handlers                                                     */
/* ------------------------------------------------------------------ */

void
xrootd_read_aio_thread(void *data, ngx_log_t *log)
{
    xrootd_read_aio_t *t = data;
    t->nread = pread(t->fd, t->databuf, t->rlen, t->offset);
    if (t->nread < 0) {
        t->io_errno = errno;
    }
}

void
xrootd_write_aio_thread(void *data, ngx_log_t *log)
{
    xrootd_write_aio_t *t = data;
    t->nwritten = pwrite(t->fd, t->data, t->len, t->offset);
    if (t->nwritten < 0) {
        t->io_errno = errno;
    }
}

void
xrootd_readv_aio_thread(void *data, ngx_log_t *log)
{
    xrootd_readv_aio_t *t = data;
    size_t i;

    t->bytes_total = 0;
    t->io_error    = 0;
    t->rsp_total   = 0;

    for (i = 0; i < t->n_segs; i++) {
        xrootd_readv_seg_desc_t *seg = &t->segs[i];
        ssize_t nread;

        nread = pread(seg->fd, seg->data_ptr, (size_t) seg->rlen, seg->offset);
        if (nread < 0) {
            t->io_error = 1;
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "readv I/O error at seg %d: %s", (int) i, strerror(errno));
            return;
        }
        if ((uint32_t) nread < seg->rlen) {
            t->io_error = 2;
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "readv past EOF at seg %d", (int) i);
            return;
        }
        uint32_t rlen_be = htonl((uint32_t) nread);
        ngx_memcpy(seg->hdr_rlen_ptr, &rlen_be, 4);

        t->bytes_total += (size_t) nread;
    }

    t->rsp_total = t->n_segs * XROOTD_READV_SEGSIZE + t->bytes_total;
}

/* ------------------------------------------------------------------ */
/*  Completion handlers                                                 */
/* ------------------------------------------------------------------ */

/*
 * xrootd_aio_resume — re-enter the XRootD read loop after AIO completion.
 */
void
xrootd_aio_resume(ngx_connection_t *c)
{
    ngx_event_t *rev = c->read;
    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                  "xrootd: aio_resume avail=%d ready=%d active=%d posted=%d",
                  rev->available, (int)rev->ready,
                  (int)rev->active, (int)rev->posted);
    if (!rev->active && !rev->ready) {
        if (ngx_handle_read_event(rev, 0) != NGX_OK) {
            ngx_stream_finalize_session(c->data, NGX_STREAM_INTERNAL_SERVER_ERROR);
        }
    }
    ngx_post_event(rev, &ngx_posted_events);
}

void
xrootd_read_aio_done(ngx_event_t *ev)
{
    ngx_thread_task_t  *task = ev->data;
    xrootd_read_aio_t  *t   = task->ctx;
    xrootd_ctx_t       *ctx = t->ctx;
    ngx_connection_t   *c   = t->c;
    size_t              rsp_total;
    u_char             *rspbuf;

    if (ctx->destroyed) {
        return;
    }

    ctx->cur_streamid[0] = t->streamid[0];
    ctx->cur_streamid[1] = t->streamid[1];

    if (t->nread < 0) {
        ctx->state = XRD_ST_REQ_HEADER;
        ctx->hdr_pos = 0;
        ngx_pfree(c->pool, t->databuf);
        XROOTD_OP_ERR(ctx, XROOTD_OP_READ);
        xrootd_send_error(ctx, c, kXR_IOError,
                          t->io_errno ? strerror(t->io_errno) : "async read error");
        xrootd_aio_resume(c);
        return;
    }

    ctx->files[t->handle_idx].bytes_read += (size_t) t->nread;
    ctx->session_bytes                   += (size_t) t->nread;
    XROOTD_OP_OK(ctx, XROOTD_OP_READ);

    rspbuf = xrootd_build_read_response(ctx, c,
                                        t->databuf, (size_t) t->nread,
                                        &rsp_total);
    ngx_pfree(c->pool, t->databuf);

    if (rspbuf == NULL) {
        ctx->state = XRD_ST_REQ_HEADER;
        xrootd_aio_resume(c);
        return;
    }

    ctx->state   = XRD_ST_REQ_HEADER;
    ctx->hdr_pos = 0;

    xrootd_queue_response_base(ctx, c, rspbuf, rsp_total, rspbuf);
    if (ctx->state != XRD_ST_SENDING) {
        ngx_pfree(c->pool, rspbuf);
    }
    xrootd_aio_resume(c);
}

void
xrootd_write_aio_done(ngx_event_t *ev)
{
    ngx_thread_task_t   *task = ev->data;
    xrootd_write_aio_t  *t   = task->ctx;
    xrootd_ctx_t        *ctx = t->ctx;
    ngx_connection_t    *c   = t->c;
    char                 detail[64];
    ngx_int_t            op  = t->is_pgwrite ? XROOTD_OP_WRITE : XROOTD_OP_WRITE;

    if (ctx->destroyed) { return; }

    ctx->cur_streamid[0] = t->streamid[0];
    ctx->cur_streamid[1] = t->streamid[1];
    ctx->state   = XRD_ST_REQ_HEADER;
    ctx->hdr_pos = 0;

    if (t->payload_to_free) {
        ngx_pfree(c->pool, t->payload_to_free);
    }

    snprintf(detail, sizeof(detail), "%lld+%zu",
             (long long) t->req_offset, t->len);

    if (t->nwritten < 0) {
        xrootd_log_access(ctx, c, "WRITE", t->path, detail,
                          0, kXR_IOError,
                          t->io_errno ? strerror(t->io_errno) : "async write error",
                          0);
        XROOTD_OP_ERR(ctx, op);
        xrootd_send_error(ctx, c, kXR_IOError,
                          t->io_errno ? strerror(t->io_errno) : "async write error");
        xrootd_aio_resume(c);
        return;
    }

    if ((size_t) t->nwritten < t->len) {
        xrootd_log_access(ctx, c, "WRITE", t->path, detail,
                          0, kXR_IOError, "short write (disk full?)", 0);
        XROOTD_OP_ERR(ctx, op);
        xrootd_send_error(ctx, c, kXR_IOError, "short write (disk full?)");
        xrootd_aio_resume(c);
        return;
    }

    ctx->files[t->handle_idx].bytes_written += (size_t) t->nwritten;
    ctx->session_bytes_written              += (size_t) t->nwritten;

    xrootd_log_access(ctx, c, "WRITE", t->path, detail,
                      1, 0, NULL, (size_t) t->nwritten);
    XROOTD_OP_OK(ctx, op);

    if (t->is_pgwrite) {
        xrootd_send_pgwrite_status(ctx, c, t->req_offset + (int64_t) t->nwritten);
    } else {
        xrootd_send_ok(ctx, c, NULL, 0);
    }

    xrootd_aio_resume(c);
}

void
xrootd_readv_aio_done(ngx_event_t *ev)
{
    ngx_thread_task_t   *task = ev->data;
    xrootd_readv_aio_t  *t   = task->ctx;
    xrootd_ctx_t        *ctx = t->ctx;
    ngx_connection_t    *c   = t->c;
    size_t               out_size;
    u_char              *rspbuf;

    if (ctx->destroyed) { return; }

    ctx->cur_streamid[0] = t->streamid[0];
    ctx->cur_streamid[1] = t->streamid[1];
    ctx->state   = XRD_ST_REQ_HEADER;
    ctx->hdr_pos = 0;

    if (t->io_error) {
        ngx_pfree(c->pool, t->databuf);
        XROOTD_OP_ERR(ctx, XROOTD_OP_READV);
        xrootd_send_error(ctx, c, kXR_IOError, t->err_msg);
        xrootd_aio_resume(c);
        return;
    }

    XROOTD_OP_OK(ctx, XROOTD_OP_READV);
    ctx->session_bytes += t->bytes_total;

    rspbuf = xrootd_build_readv_response(ctx, c,
                                         t->databuf, t->rsp_total,
                                         &out_size);
    ngx_pfree(c->pool, t->databuf);

    if (rspbuf == NULL) {
        xrootd_aio_resume(c);
        return;
    }

    xrootd_queue_response_base(ctx, c, rspbuf, out_size, rspbuf);
    if (ctx->state != XRD_ST_SENDING) {
        ngx_pfree(c->pool, rspbuf);
    }
    xrootd_aio_resume(c);
}

#endif /* NGX_THREADS */
