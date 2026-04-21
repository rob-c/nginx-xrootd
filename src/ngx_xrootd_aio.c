#include "ngx_xrootd_module.h"

/* ================================================================== */
/*  Response buffer builders (used by both sync and AIO paths)         */
/* ================================================================== */

/*
 * This file builds the wire-format response buffers for kXR_read and kXR_readv.
 * The same code serves two execution models:
 *
 *   Synchronous: the handler in read_handlers.c either builds file-backed
 *   chains for regular kXR_read responses, or fills a reusable memory buffer
 *   and calls the chunked-chain builder for readv/fallback responses.
 *
 *   Asynchronous (NGX_THREADS): the handler posts a task to nginx's
 *   thread pool.  The pread(2) calls run on a worker thread, and the
 *   completion callback calls the same chunked-chain builder here.
 *
 * For kXR_read, the normal response path builds nginx file-backed buffers so
 * send_chain can use the platform sendfile implementation.  The memory-backed
 * builders remain for readv and for non-regular-file fallbacks.
 *
 * For kXR_readv, the wire format uses a readv_element array where each
 * element pairs a (fhandle, length, offset) request with the corresponding
 * data payload.  The response interleaves 16-byte kXR_readv_iov headers
 * with the actual data segments.
 */

static u_char *
xrootd_get_pool_scratch(ngx_pool_t *pool, u_char **slot, size_t *slot_size,
    size_t need)
{
    u_char *p;

    if (need == 0) {
        need = 1;
    }

    if (*slot != NULL && *slot_size >= need) {
        return *slot;
    }

    p = ngx_palloc(pool, need);
    if (p == NULL) {
        return NULL;
    }

    if (*slot != NULL) {
        (void) ngx_pfree(pool, *slot);
    }

    *slot = p;
    *slot_size = need;
    return p;
}

u_char *
xrootd_get_read_scratch(xrootd_ctx_t *ctx, ngx_connection_t *c, size_t need)
{
    return xrootd_get_pool_scratch(c->pool, &ctx->read_scratch,
                                   &ctx->read_scratch_size, need);
}

u_char *
xrootd_get_read_header_scratch(xrootd_ctx_t *ctx, ngx_connection_t *c,
    size_t need)
{
    return xrootd_get_pool_scratch(c->pool, &ctx->read_hdr_scratch,
                                   &ctx->read_hdr_scratch_size, need);
}

void
xrootd_release_read_buffer(xrootd_ctx_t *ctx, ngx_connection_t *c, u_char *buf)
{
    if (buf == NULL) {
        return;
    }

    if (buf == ctx->read_scratch || buf == ctx->read_hdr_scratch) {
        return;
    }

    (void) ngx_pfree(c->pool, buf);
}

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

    /*
     * XRootD replies larger than XROOTD_READ_MAX are streamed as a sequence of
     * response-header + payload chunks. Every chunk except the last is marked
     * kXR_oksofar so the client keeps consuming until the final kXR_ok frame.
     * A zero-byte read still emits one empty kXR_ok frame so EOF is expressed
     * as a normal successful response, not as "no response at all".
     */
    n_chunks = (data_total + XROOTD_READ_MAX - 1) / XROOTD_READ_MAX;
    if (n_chunks == 0) { n_chunks = 1; }
    last_size = data_total % XROOTD_READ_MAX;
    if (last_size == 0 && data_total > 0) { last_size = XROOTD_READ_MAX; }

    rsp_total = n_chunks * XRD_RESPONSE_HDR_LEN + data_total;
    rspbuf    = ngx_palloc(c->pool, rsp_total);
    if (rspbuf == NULL) { return NULL; }

    ri = 0; di = 0;
    for (size_t chunk = 0; chunk < n_chunks; chunk++) {
        /* ri walks the response buffer, di walks the source data buffer. */
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

    /*
     * readv has already packed segment descriptors and data into databuf; the
     * only job here is to split that logical response into wire-sized chunks.
     * The same zero-length rule applies here: the client still expects a final
     * header even if the logical body happens to be empty.
     */
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

ngx_chain_t *
xrootd_build_chunked_chain(xrootd_ctx_t *ctx, ngx_connection_t *c,
    u_char *databuf, size_t data_total)
{
    size_t      n_chunks, last_size;
    u_char     *hdrbuf;
    ngx_chain_t *head = NULL, *tail = NULL;
    size_t      di = 0;
    size_t      chunk;

    n_chunks = (data_total + XROOTD_READ_MAX - 1) / XROOTD_READ_MAX;
    if (n_chunks == 0) { n_chunks = 1; }
    last_size = data_total % XROOTD_READ_MAX;
    if (last_size == 0 && data_total > 0) { last_size = XROOTD_READ_MAX; }

    hdrbuf = xrootd_get_read_header_scratch(ctx, c,
                                            n_chunks * XRD_RESPONSE_HDR_LEN);
    if (hdrbuf == NULL) {
        return NULL;
    }

    for (chunk = 0; chunk < n_chunks; chunk++) {
        size_t        chunk_data;
        uint16_t      status;
        ngx_chain_t  *clh;
        ngx_buf_t    *bh;
        u_char       *hptr;

        chunk_data = (chunk < n_chunks - 1) ? XROOTD_READ_MAX : last_size;
        status     = (chunk == n_chunks - 1) ? kXR_ok : kXR_oksofar;
        hptr       = hdrbuf + chunk * XRD_RESPONSE_HDR_LEN;

        xrootd_build_resp_hdr(ctx->cur_streamid, status,
                              (uint32_t) chunk_data,
                              (ServerResponseHdr *) hptr);

        clh = ngx_alloc_chain_link(c->pool);
        bh = ngx_calloc_buf(c->pool);
        if (clh == NULL || bh == NULL) {
            return NULL;
        }

        bh->pos = hptr;
        bh->last = hptr + XRD_RESPONSE_HDR_LEN;
        bh->memory = 1;
        bh->temporary = 1;
        clh->buf = bh;
        clh->next = NULL;

        if (head == NULL) {
            head = clh;
        } else {
            tail->next = clh;
        }
        tail = clh;

        if (chunk_data > 0) {
            ngx_chain_t *cld;
            ngx_buf_t   *bd;

            cld = ngx_alloc_chain_link(c->pool);
            bd = ngx_calloc_buf(c->pool);
            if (cld == NULL || bd == NULL) {
                return NULL;
            }

            bd->pos = databuf + di;
            bd->last = databuf + di + chunk_data;
            bd->memory = 1;
            bd->temporary = 1;
            cld->buf = bd;
            cld->next = NULL;

            tail->next = cld;
            tail = cld;
            di += chunk_data;
        }
    }

    if (tail != NULL) {
        tail->buf->last_buf = 1;
    }

    return head;
}

ngx_chain_t *
xrootd_build_sendfile_chain(xrootd_ctx_t *ctx, ngx_connection_t *c,
    int fd, const char *path, off_t offset, size_t data_total,
    u_char **base_out)
{
    size_t       n_chunks, last_size;
    u_char     *hdrbuf;
    ngx_chain_t *head = NULL, *tail = NULL;
    size_t       di = 0;
    size_t       chunk;

    if (base_out != NULL) {
        *base_out = NULL;
    }

    n_chunks = (data_total + XROOTD_READ_MAX - 1) / XROOTD_READ_MAX;
    if (n_chunks == 0) { n_chunks = 1; }
    last_size = data_total % XROOTD_READ_MAX;
    if (last_size == 0 && data_total > 0) { last_size = XROOTD_READ_MAX; }

    hdrbuf = xrootd_get_read_header_scratch(ctx, c,
                                            n_chunks * XRD_RESPONSE_HDR_LEN);
    if (hdrbuf == NULL) {
        return NULL;
    }
    if (base_out != NULL) {
        *base_out = hdrbuf;
    }

    for (chunk = 0; chunk < n_chunks; chunk++) {
        size_t        chunk_data;
        uint16_t      status;
        ngx_chain_t  *clh;
        ngx_buf_t    *bh;
        u_char       *hptr;

        chunk_data = (chunk < n_chunks - 1) ? XROOTD_READ_MAX : last_size;
        status     = (chunk == n_chunks - 1) ? kXR_ok : kXR_oksofar;
        hptr       = hdrbuf + chunk * XRD_RESPONSE_HDR_LEN;

        xrootd_build_resp_hdr(ctx->cur_streamid, status,
                              (uint32_t) chunk_data,
                              (ServerResponseHdr *) hptr);

        clh = ngx_alloc_chain_link(c->pool);
        bh = ngx_calloc_buf(c->pool);
        if (clh == NULL || bh == NULL) {
            return NULL;
        }

        bh->pos = hptr;
        bh->last = hptr + XRD_RESPONSE_HDR_LEN;
        bh->memory = 1;
        bh->temporary = 1;
        clh->buf = bh;
        clh->next = NULL;

        if (head == NULL) {
            head = clh;
        } else {
            tail->next = clh;
        }
        tail = clh;

        if (chunk_data > 0) {
            ngx_chain_t *clf;
            ngx_buf_t   *bf;
            ngx_file_t  *file;

            clf = ngx_alloc_chain_link(c->pool);
            bf = ngx_calloc_buf(c->pool);
            file = ngx_pcalloc(c->pool, sizeof(ngx_file_t));
            if (clf == NULL || bf == NULL || file == NULL) {
                return NULL;
            }

            file->fd = fd;
            file->name.data = (u_char *) path;
            file->name.len = path ? ngx_strlen(path) : 0;
            file->log = c->log;

            bf->file = file;
            bf->in_file = 1;
            bf->file_pos = offset + (off_t) di;
            bf->file_last = bf->file_pos + (off_t) chunk_data;
            clf->buf = bf;
            clf->next = NULL;

            tail->next = clf;
            tail = clf;
            di += chunk_data;
        }
    }

    if (tail != NULL) {
        tail->buf->last_buf = 1;
        tail->buf->last_in_chain = 1;
    }

    return head;
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

    /*
     * Worker threads do the blocking syscall only; all protocol state updates
     * stay on the event-loop side in the completion callback.
     */
    t->nread = pread(t->fd, t->databuf, t->rlen, t->offset);
    if (t->nread < 0) {
        t->io_errno = errno;
    }
}

void
xrootd_write_aio_thread(void *data, ngx_log_t *log)
{
    xrootd_write_aio_t *t = data;

    /*
     * The request payload stays owned by the connection pool while the worker
     * runs; completion code decides when it is safe to free it.
     */
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

    /* Start with a clean aggregate result before any segment I/O begins. */
    t->bytes_total = 0;
    t->io_error    = 0;
    t->rsp_total   = 0;

    for (i = 0; i < t->n_segs; i++) {
        xrootd_readv_seg_desc_t *seg = &t->segs[i];
        ssize_t nread;

        /* Each iteration reads one user-requested segment directly into place. */
        nread = pread(seg->fd, seg->data_ptr, (size_t) seg->rlen, seg->offset);
        if (nread < 0) {
            /* Any failed segment aborts the entire vector request. */
            t->io_error = 1;
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "readv I/O error at seg %d: %s", (int) i, strerror(errno));
            return;
        }
        if ((uint32_t) nread < seg->rlen) {
            /* Short reads are treated as protocol-visible EOF errors here. */
            t->io_error = 2;
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "readv past EOF at seg %d", (int) i);
            return;
        }

        /* Backfill the per-segment length field the client expects on the wire. */
        uint32_t rlen_be = htonl((uint32_t) nread);
        ngx_memcpy(seg->hdr_rlen_ptr, &rlen_be, 4);

        t->bytes_total += (size_t) nread;
    }

    /* Final response size is all segment headers plus the concatenated data. */
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
    ngx_stream_session_t *s;
    xrootd_ctx_t         *ctx;

    /*
     * AIO completion runs outside the normal recv path.  If the completion
     * queued a response that still has bytes pending, resume the write side
     * first; posting a read event in that state only wakes a handler that must
     * immediately return.  Once there is no pending response, post the read side
     * so already-arrived pipelined requests run before the next epoll_wait.
     */

    s = c->data;
    ctx = ngx_stream_get_module_ctx(s, ngx_stream_xrootd_module);
    if (ctx == NULL || ctx->destroyed) {
        return;
    }

    ngx_log_debug5(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: aio_resume state=%d ravail=%d rready=%d "
                   "wready=%d wposted=%d",
                   (int) ctx->state, c->read->available,
                   (int) c->read->ready, (int) c->write->ready,
                   (int) c->write->posted);

    if (ctx->state == XRD_ST_SENDING) {
        if (xrootd_schedule_write_resume(c) != NGX_OK) {
            ngx_stream_finalize_session(c->data, NGX_STREAM_INTERNAL_SERVER_ERROR);
        }
        return;
    }

    if (xrootd_schedule_read_resume(c) != NGX_OK) {
        ngx_stream_finalize_session(c->data, NGX_STREAM_INTERNAL_SERVER_ERROR);
    }
}

void
xrootd_read_aio_done(ngx_event_t *ev)
{
    ngx_thread_task_t  *task = ev->data;
    xrootd_read_aio_t  *t   = task->ctx;
    xrootd_ctx_t       *ctx = t->ctx;
    ngx_connection_t   *c   = t->c;
    ngx_chain_t        *rsp_chain;

    if (ctx->destroyed) {
        /* The session closed while the worker was running; drop the result. */
        return;
    }

    /* Restore the request streamid so the async response matches the caller. */
    ctx->cur_streamid[0] = t->streamid[0];
    ctx->cur_streamid[1] = t->streamid[1];

    if (t->nread < 0) {
        /* Reset parsing first so the connection is in a sane state on error. */
        ctx->state = XRD_ST_REQ_HEADER;
        ctx->hdr_pos = 0;
        xrootd_release_read_buffer(ctx, c, t->databuf);
        XROOTD_OP_ERR(ctx, XROOTD_OP_READ);
        xrootd_send_error(ctx, c, kXR_IOError,
                          t->io_errno ? strerror(t->io_errno) : "async read error");
        xrootd_aio_resume(c);
        return;
    }

    ctx->files[t->handle_idx].bytes_read += (size_t) t->nread;
    ctx->session_bytes                   += (size_t) t->nread;
    XROOTD_OP_OK(ctx, XROOTD_OP_READ);

    /* Build a header+data chain to avoid copying payload into a second buffer. */
    rsp_chain = xrootd_build_chunked_chain(ctx, c,
                                           t->databuf, (size_t) t->nread);
    if (rsp_chain == NULL) {
        xrootd_release_read_buffer(ctx, c, t->databuf);
        ctx->state = XRD_ST_REQ_HEADER;
        xrootd_aio_resume(c);
        return;
    }

    ctx->state   = XRD_ST_REQ_HEADER;
    ctx->hdr_pos = 0;

    xrootd_queue_response_chain(ctx, c, rsp_chain, t->databuf);
    if (ctx->state != XRD_ST_SENDING) {
        xrootd_release_read_buffer(ctx, c, t->databuf);
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

    /* Reconstruct the original request context before emitting any reply. */
    ctx->cur_streamid[0] = t->streamid[0];
    ctx->cur_streamid[1] = t->streamid[1];
    ctx->state   = XRD_ST_REQ_HEADER;
    ctx->hdr_pos = 0;

    if (t->payload_to_free) {
        /* Delayed free for request data kept alive while the worker was writing. */
        ngx_pfree(c->pool, t->payload_to_free);
    }

    /* Human-readable offset+length string used by the access logger. */
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
        /* pwrite() completed but did not consume the whole payload. */
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

    /* pgwrite expects the acknowledged end offset instead of a plain kXR_ok. */
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
    ngx_chain_t         *rsp_chain;

    if (ctx->destroyed) { return; }

    /* Mirror the synchronous path: restore request metadata, then reply. */
    ctx->cur_streamid[0] = t->streamid[0];
    ctx->cur_streamid[1] = t->streamid[1];
    ctx->state   = XRD_ST_REQ_HEADER;
    ctx->hdr_pos = 0;

    if (t->io_error) {
        xrootd_release_read_buffer(ctx, c, t->databuf);
        XROOTD_OP_ERR(ctx, XROOTD_OP_READV);
        xrootd_send_error(ctx, c, kXR_IOError, t->err_msg);
        xrootd_aio_resume(c);
        return;
    }

    XROOTD_OP_OK(ctx, XROOTD_OP_READV);
    ctx->session_bytes += t->bytes_total;

    /* datapack is already contiguous; send as chunked header+data chain. */
    rsp_chain = xrootd_build_chunked_chain(ctx, c,
                                           t->databuf, t->rsp_total);
    if (rsp_chain == NULL) {
        xrootd_release_read_buffer(ctx, c, t->databuf);
        xrootd_aio_resume(c);
        return;
    }

    xrootd_queue_response_chain(ctx, c, rsp_chain, t->databuf);
    if (ctx->state != XRD_ST_SENDING) {
        xrootd_release_read_buffer(ctx, c, t->databuf);
    }
    xrootd_aio_resume(c);
}

void
xrootd_pgread_aio_thread(void *data, ngx_log_t *log)
{
    xrootd_pgread_aio_t *t = data;
    size_t    n_pages, i;
    u_char   *src, *dst;
    size_t    remaining;
    uint32_t  crc, crc_be;
    size_t    page_data;

    /*
     * Phase 1: pread into the flat portion of scratch (scratch[0..rlen-1]).
     * Phase 2: interleave data + CRC32c into scratch[rlen..], page by page.
     * Both phases run on the worker thread to keep CRC off the event loop.
     */

    t->nread = pread(t->fd, t->scratch, t->rlen, t->offset);
    if (t->nread <= 0) {
        t->io_errno = (t->nread < 0) ? errno : 0;
        t->out_size = 0;
        return;
    }

    n_pages   = ((size_t) t->nread + kXR_pgPageSZ - 1) / kXR_pgPageSZ;
    src       = t->scratch;
    dst       = t->scratch + t->rlen;   /* interleaved output region */
    remaining = (size_t) t->nread;

    for (i = 0; i < n_pages; i++) {
        page_data = (remaining >= (size_t) kXR_pgPageSZ)
                    ? (size_t) kXR_pgPageSZ : remaining;
        crc    = xrootd_crc32c(src, page_data);
        crc_be = htonl(crc);

        ngx_memcpy(dst, src, page_data);
        dst       += page_data;
        src       += page_data;
        remaining -= page_data;

        ngx_memcpy(dst, &crc_be, 4);
        dst += 4;
    }

    t->out_size = (size_t)(dst - (t->scratch + t->rlen));
}

void
xrootd_pgread_aio_done(ngx_event_t *ev)
{
    ngx_thread_task_t    *task = ev->data;
    xrootd_pgread_aio_t  *t   = task->ctx;
    xrootd_ctx_t         *ctx = t->ctx;
    ngx_connection_t     *c   = t->c;
    ServerStatusResponse_pgRead *hdr_buf;
    ngx_chain_t *cl_hdr, *cl_data, *rsp_chain;
    char detail[64];

    if (ctx->destroyed) { return; }

    ctx->cur_streamid[0] = t->streamid[0];
    ctx->cur_streamid[1] = t->streamid[1];
    ctx->state   = XRD_ST_REQ_HEADER;
    ctx->hdr_pos = 0;

    if (t->nread < 0) {
        xrootd_release_read_buffer(ctx, c, t->scratch);
        XROOTD_OP_ERR(ctx, XROOTD_OP_PGREAD);
        xrootd_send_error(ctx, c, kXR_IOError,
                          t->io_errno ? strerror(t->io_errno) : "async pgread error");
        xrootd_aio_resume(c);
        return;
    }

    /* EOF at requested offset: return an empty kXR_status frame. */
    if (t->nread == 0 || t->out_size == 0) {
        hdr_buf = ngx_palloc(c->pool, sizeof(*hdr_buf));
        if (hdr_buf) {
            xrootd_build_pgread_status(ctx, t->offset, 0, hdr_buf);
            XROOTD_OP_OK(ctx, XROOTD_OP_PGREAD);
            xrootd_queue_response(ctx, c, (u_char *) hdr_buf, sizeof(*hdr_buf));
        }
        xrootd_release_read_buffer(ctx, c, t->scratch);
        xrootd_aio_resume(c);
        return;
    }

    /* Build the 32-byte kXR_status header. */
    hdr_buf = ngx_palloc(c->pool, sizeof(*hdr_buf));
    if (hdr_buf == NULL) {
        xrootd_release_read_buffer(ctx, c, t->scratch);
        xrootd_aio_resume(c);
        return;
    }
    xrootd_build_pgread_status(ctx, t->offset, (uint32_t) t->out_size, hdr_buf);

    /* Chain: status header → interleaved data (scratch + rlen). */
    cl_hdr = ngx_alloc_chain_link(c->pool);
    if (cl_hdr == NULL) {
        xrootd_release_read_buffer(ctx, c, t->scratch);
        xrootd_aio_resume(c);
        return;
    }
    cl_hdr->buf = ngx_calloc_buf(c->pool);
    if (cl_hdr->buf == NULL) {
        xrootd_release_read_buffer(ctx, c, t->scratch);
        xrootd_aio_resume(c);
        return;
    }
    cl_hdr->buf->pos      = (u_char *) hdr_buf;
    cl_hdr->buf->last     = cl_hdr->buf->pos + sizeof(*hdr_buf);
    cl_hdr->buf->memory   = 1;
    cl_hdr->buf->last_buf = 0;

    /* The interleaved output sits at scratch + rlen for out_size bytes. */
    cl_data = xrootd_build_chunked_chain(ctx, c,
                                         t->scratch + t->rlen, t->out_size);
    if (cl_data == NULL) {
        xrootd_release_read_buffer(ctx, c, t->scratch);
        xrootd_aio_resume(c);
        return;
    }
    cl_hdr->next = cl_data;
    rsp_chain    = cl_hdr;

    ctx->files[t->handle_idx].bytes_read += (size_t) t->nread;
    ctx->session_bytes                   += (size_t) t->nread;

    snprintf(detail, sizeof(detail), "%lld+%zu",
             (long long) t->offset, (size_t) t->nread);
    xrootd_log_access(ctx, c, "PGREAD", ctx->files[t->handle_idx].path,
                      detail, 1, 0, NULL, (size_t) t->nread);
    XROOTD_OP_OK(ctx, XROOTD_OP_PGREAD);

    xrootd_queue_response_chain(ctx, c, rsp_chain, t->scratch);
    if (ctx->state != XRD_ST_SENDING) {
        xrootd_release_read_buffer(ctx, c, t->scratch);
    }
    xrootd_aio_resume(c);
}

#endif /* NGX_THREADS */
