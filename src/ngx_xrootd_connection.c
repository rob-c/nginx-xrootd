#include "ngx_xrootd_module.h"

/* ================================================================== */
/*  Connection entry point                                              */
/* ================================================================== */

void
ngx_stream_xrootd_handler(ngx_stream_session_t *s)
{
    ngx_connection_t  *c = s->connection;
    xrootd_ctx_t      *ctx;
    int                i;

    ctx = ngx_pcalloc(c->pool, sizeof(xrootd_ctx_t));
    if (ctx == NULL) {
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ctx->session = s;
    ctx->state   = XRD_ST_HANDSHAKE;
    ctx->hdr_pos = 0;

    for (i = 0; i < XROOTD_MAX_FILES; i++) {
        ctx->files[i].fd = -1;
    }

    {
        uint32_t parts[4];
        parts[0] = (uint32_t) ngx_time();
        parts[1] = (uint32_t) ngx_pid;
        parts[2] = (uint32_t) (uintptr_t) c;
        parts[3] = (uint32_t) ngx_random();
        ngx_memcpy(ctx->sessid, parts, XROOTD_SESSION_ID_LEN);
    }

    ngx_stream_set_ctx(s, ctx, ngx_stream_xrootd_module);

    /* Bind metrics slot for this connection */
    {
        ngx_stream_xrootd_srv_conf_t *mconf;
        mconf = ngx_stream_get_module_srv_conf(s, ngx_stream_xrootd_module);
        if (mconf->metrics_slot >= 0 && ngx_xrootd_shm_zone != NULL
            && ngx_xrootd_shm_zone->data != NULL
            && ngx_xrootd_shm_zone->data != (void *) 1)
        {
            ngx_xrootd_metrics_t     *shm = ngx_xrootd_shm_zone->data;
            ngx_xrootd_srv_metrics_t *srv = &shm->servers[mconf->metrics_slot];
            ctx->metrics = srv;

            if (!srv->in_use) {
                srv->in_use = 1;
                ngx_cpystrn((u_char *) srv->auth,
                            (u_char *) (mconf->auth == 1 ? "gsi" : "anon"),
                            sizeof(srv->auth));
                if (c->local_sockaddr) {
                    sa_family_t fam = c->local_sockaddr->sa_family;
                    if (fam == AF_INET) {
                        struct sockaddr_in *sin =
                            (struct sockaddr_in *) c->local_sockaddr;
                        srv->port = ntohs(sin->sin_port);
                    } else if (fam == AF_INET6) {
                        struct sockaddr_in6 *sin6 =
                            (struct sockaddr_in6 *) c->local_sockaddr;
                        srv->port = ntohs(sin6->sin6_port);
                    }
                }
            }

            ngx_atomic_fetch_add(&srv->connections_total, 1);
            ngx_atomic_fetch_add(&srv->connections_active, 1);
        }
    }

    c->read->handler  = ngx_stream_xrootd_recv;
    c->write->handler = ngx_stream_xrootd_send;

    ngx_stream_xrootd_recv(c->read);
}

/* ================================================================== */
/*  Read event handler                                                  */
/* ================================================================== */

void
ngx_stream_xrootd_recv(ngx_event_t *rev)
{
    ngx_connection_t              *c;
    ngx_stream_session_t          *s;
    ngx_stream_xrootd_srv_conf_t  *conf;
    xrootd_ctx_t                  *ctx;
    ssize_t                        n;
    ngx_int_t                      rc;

    c    = rev->data;
    s    = c->data;
    ctx  = ngx_stream_get_module_ctx(s, ngx_stream_xrootd_module);
    conf = ngx_stream_get_module_srv_conf(s, ngx_stream_xrootd_module);

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                      "xrootd: client connection timed out");
        xrootd_on_disconnect(ctx, c);
        xrootd_close_all_files(ctx);
        ngx_stream_finalize_session(s, NGX_STREAM_OK);
        return;
    }

    for (;;) {

        if (ctx->state == XRD_ST_SENDING) {
            return;
        }

        if (ctx->state == XRD_ST_AIO) {
            if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                goto fatal;
            }
            return;
        }

        u_char *dest;
        size_t  need, avail;

        if (ctx->state == XRD_ST_HANDSHAKE) {
            dest  = ctx->hdr_buf + ctx->hdr_pos;
            need  = XRD_HANDSHAKE_LEN - ctx->hdr_pos;

        } else if (ctx->state == XRD_ST_REQ_HEADER) {
            dest  = ctx->hdr_buf + ctx->hdr_pos;
            need  = XRD_REQUEST_HDR_LEN - ctx->hdr_pos;

        } else {
            dest  = ctx->payload + ctx->payload_pos;
            need  = ctx->cur_dlen - ctx->payload_pos;
        }

        if (need == 0) {
            goto process;
        }

        rev->available = -1;
        n = c->recv(c, dest, need);

        if (n == NGX_AGAIN) {
            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "xrootd: recv AGAIN st=%d hdr_pos=%uz avail=%d"
                          " ready=%d active=%d",
                          (int)ctx->state, ctx->hdr_pos,
                          rev->available, (int)rev->ready, (int)rev->active);
            if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                goto fatal;
            }
            return;
        }

        if (n == NGX_ERROR || n == 0) {
            ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                           "xrootd: client disconnected");
            xrootd_on_disconnect(ctx, c);
            xrootd_close_all_files(ctx);
            ngx_stream_finalize_session(s, NGX_STREAM_OK);
            return;
        }

        avail = (size_t) n;

        if (ctx->state == XRD_ST_HANDSHAKE) {
            ctx->hdr_pos += avail;
        } else if (ctx->state == XRD_ST_REQ_HEADER) {
            ctx->hdr_pos += avail;
        } else {
            ctx->payload_pos += avail;
        }

        if (avail < need) {
            continue;
        }

process:
        if (ctx->state == XRD_ST_HANDSHAKE) {

            rc = xrootd_process_handshake(ctx, c);
            if (rc != NGX_OK) {
                goto fatal;
            }
            ctx->state   = XRD_ST_REQ_HEADER;
            ctx->hdr_pos = 0;

        } else if (ctx->state == XRD_ST_REQ_HEADER) {

            ClientRequestHdr *hdr = (ClientRequestHdr *) ctx->hdr_buf;

            ctx->cur_streamid[0] = hdr->streamid[0];
            ctx->cur_streamid[1] = hdr->streamid[1];
            ctx->cur_reqid       = ntohs(hdr->requestid);
            ngx_memcpy(ctx->cur_body, hdr->body, 16);
            ctx->cur_dlen        = (uint32_t) ntohl(hdr->dlen);

            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "xrootd: req sid=[%02xd%02xd] reqid=%04xd dlen=%uz"
                          " avail=%d ready=%d",
                          (int)ctx->cur_streamid[0], (int)ctx->cur_streamid[1],
                          (int)ctx->cur_reqid, (size_t)ctx->cur_dlen,
                          c->read->available, (int)c->read->ready);

            {
                uint32_t max_pl;
                if (ctx->cur_reqid == kXR_pgwrite ||
                    ctx->cur_reqid == kXR_write   ||
                    ctx->cur_reqid == kXR_writev) {
                    max_pl = XROOTD_MAX_WRITE_PAYLOAD;
                } else if (ctx->cur_reqid == kXR_readv) {
                    max_pl = XROOTD_READV_MAXSEGS * XROOTD_READV_SEGSIZE;
                } else {
                    max_pl = XROOTD_MAX_PATH + 64;
                }
                if (ctx->cur_dlen > max_pl) {
                    ngx_log_error(NGX_LOG_WARN, c->log, 0,
                                  "xrootd: payload too large (%uz), closing",
                                  (size_t) ctx->cur_dlen);
                    goto fatal;
                }
            }

            if (ctx->cur_dlen > 0) {
                ctx->payload = ngx_palloc(c->pool, ctx->cur_dlen + 1);
                if (ctx->payload == NULL) {
                    goto fatal;
                }
                ctx->payload[ctx->cur_dlen] = '\0';
                ctx->payload_pos = 0;
                ctx->state       = XRD_ST_REQ_PAYLOAD;
                ctx->hdr_pos     = 0;
                continue;
            }

            ctx->payload = NULL;
            rc = xrootd_dispatch(ctx, c, conf);
            if (rc == NGX_ERROR) {
                goto fatal;
            }

            if (ctx->state == XRD_ST_AIO) {
                if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                    goto fatal;
                }
                return;
            }
            if (ctx->state != XRD_ST_SENDING) {
                ctx->state   = XRD_ST_REQ_HEADER;
                ctx->hdr_pos = 0;
            }

        } else {
            ctx->state = XRD_ST_REQ_HEADER;
            ctx->hdr_pos = 0;

            rc = xrootd_dispatch(ctx, c, conf);
            if (rc == NGX_ERROR) {
                goto fatal;
            }

            if (ctx->state == XRD_ST_SENDING) {
                return;
            }
        }
    }

fatal:
    xrootd_on_disconnect(ctx, c);
    xrootd_close_all_files(ctx);
    ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
}

/* ================================================================== */
/*  Write event handler                                                 */
/* ================================================================== */

void
ngx_stream_xrootd_send(ngx_event_t *wev)
{
    ngx_connection_t     *c;
    ngx_stream_session_t *s;
    xrootd_ctx_t         *ctx;
    ngx_int_t             rc;

    c   = wev->data;
    s   = c->data;
    ctx = ngx_stream_get_module_ctx(s, ngx_stream_xrootd_module);

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                      "xrootd: write timed out");
        xrootd_on_disconnect(ctx, c);
        xrootd_close_all_files(ctx);
        ngx_stream_finalize_session(s, NGX_STREAM_OK);
        return;
    }

    rc = xrootd_flush_pending(ctx, c);
    if (rc == NGX_ERROR) {
        xrootd_on_disconnect(ctx, c);
        xrootd_close_all_files(ctx);
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    if (rc == NGX_AGAIN) {
        return;
    }

    if (ctx->state != XRD_ST_SENDING) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "xrootd: send_done (state=%d, no recv) avail=%d ready=%d active=%d",
                      (int)ctx->state,
                      c->read->available, (int)c->read->ready,
                      (int)c->read->active);
        return;
    }

    ctx->state   = XRD_ST_REQ_HEADER;
    ctx->hdr_pos = 0;
    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                  "xrootd: send_done avail=%d ready=%d active=%d",
                  c->read->available, (int)c->read->ready, (int)c->read->active);
    ngx_stream_xrootd_recv(c->read);
}

/* ================================================================== */
/*  Write helpers                                                       */
/* ================================================================== */

ngx_int_t
xrootd_queue_response_base(xrootd_ctx_t *ctx, ngx_connection_t *c,
                            u_char *buf, size_t len, u_char *base)
{
    ssize_t n;

    while (len > 0) {
        n = c->send(c, buf, len);
        if (n > 0) {
            buf += n;
            len -= (size_t) n;
            continue;
        }
        if (n == NGX_AGAIN) {
            ctx->wbuf      = buf;
            ctx->wbuf_len  = len;
            ctx->wbuf_pos  = 0;
            ctx->wbuf_base = base;
            ctx->state     = XRD_ST_SENDING;

            if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
                return NGX_ERROR;
            }
            return NGX_OK;
        }
        return NGX_ERROR;
    }
    return NGX_OK;
}

ngx_int_t
xrootd_queue_response(xrootd_ctx_t *ctx, ngx_connection_t *c,
                      u_char *buf, size_t len)
{
    return xrootd_queue_response_base(ctx, c, buf, len, NULL);
}

ngx_int_t
xrootd_flush_pending(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    ssize_t n;

    while (ctx->wbuf_pos < ctx->wbuf_len) {
        n = c->send(c, ctx->wbuf + ctx->wbuf_pos,
                    ctx->wbuf_len - ctx->wbuf_pos);
        if (n > 0) {
            ctx->wbuf_pos += (size_t) n;
            continue;
        }
        if (n == NGX_AGAIN) {
            if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
                return NGX_ERROR;
            }
            return NGX_AGAIN;
        }
        return NGX_ERROR;
    }

    if (ctx->wbuf_base) {
        ngx_pfree(c->pool, ctx->wbuf_base);
        ctx->wbuf_base = NULL;
    }
    ctx->wbuf     = NULL;
    ctx->wbuf_len = 0;
    ctx->wbuf_pos = 0;
    return NGX_OK;
}

/* ================================================================== */
/*  File handle helpers                                                 */
/* ================================================================== */

int
xrootd_alloc_fhandle(xrootd_ctx_t *ctx)
{
    int i;
    for (i = 0; i < XROOTD_MAX_FILES; i++) {
        if (ctx->files[i].fd < 0) {
            return i;
        }
    }
    return -1;
}

void
xrootd_free_fhandle(xrootd_ctx_t *ctx, int idx)
{
    if (idx >= 0 && idx < XROOTD_MAX_FILES && ctx->files[idx].fd >= 0) {
        close(ctx->files[idx].fd);
        ctx->files[idx].fd      = -1;
        ctx->files[idx].path[0] = '\0';
    }
}

void
xrootd_close_all_files(xrootd_ctx_t *ctx)
{
    int i;
    for (i = 0; i < XROOTD_MAX_FILES; i++) {
        xrootd_free_fhandle(ctx, i);
    }
}

/* ================================================================== */
/*  Disconnect handler                                                  */
/* ================================================================== */

void
xrootd_on_disconnect(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    int        i;
    ngx_msec_t now = ngx_current_msec;

    ctx->destroyed = 1;

    if (ctx->metrics) {
        ngx_atomic_fetch_add(&ctx->metrics->connections_active, (ngx_atomic_int_t) -1);
        ngx_atomic_fetch_add(&ctx->metrics->bytes_rx_total,
                             (ngx_atomic_int_t) ctx->session_bytes_written);
        ngx_atomic_fetch_add(&ctx->metrics->bytes_tx_total,
                             (ngx_atomic_int_t) ctx->session_bytes);
    }

    for (i = 0; i < XROOTD_MAX_FILES; i++) {
        if (ctx->files[i].fd < 0) {
            continue;
        }

        ctx->req_start = ctx->files[i].open_time;

        {
            char   detail[64];
            size_t btotal = ctx->files[i].bytes_written > 0
                            ? ctx->files[i].bytes_written
                            : ctx->files[i].bytes_read;
            ngx_msec_t dur = now - ctx->files[i].open_time;

            if (btotal > 0 && dur > 0) {
                double mbps = (double) btotal / (double) dur / 1000.0;
                snprintf(detail, sizeof(detail), "interrupted %.2fMB/s", mbps);
            } else {
                snprintf(detail, sizeof(detail), "interrupted");
            }

            xrootd_log_access(ctx, c, "CLOSE", ctx->files[i].path, detail,
                              0, kXR_Cancelled, "connection lost", btotal);
        }
    }

    if (!ctx->logged_in) {
        return;
    }

    {
        char       detail[128];
        ngx_msec_t sess_dur = now - ctx->session_start;
        size_t     total    = ctx->session_bytes + ctx->session_bytes_written;

        if (total > 0 && sess_dur > 0) {
            double mbps = (double) total / (double) sess_dur / 1000.0;
            if (ctx->session_bytes_written > 0) {
                snprintf(detail, sizeof(detail),
                         "rx=%.2fMB/s tx=%.2fMB/s",
                         (double) ctx->session_bytes / (double) sess_dur / 1000.0,
                         (double) ctx->session_bytes_written / (double) sess_dur / 1000.0);
            } else {
                snprintf(detail, sizeof(detail), "%.2fMB/s", mbps);
            }
        } else {
            snprintf(detail, sizeof(detail), "-");
        }

        ctx->req_start = ctx->session_start;

        xrootd_log_access(ctx, c, "DISCONNECT", "-", detail,
                          1, 0, NULL, total);
    }
}
