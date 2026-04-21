#include "ngx_xrootd_module.h"

/* forward declaration — defined in the TLS section below */
static void xrootd_start_tls(xrootd_ctx_t *ctx, ngx_connection_t *c,
                              ngx_stream_xrootd_srv_conf_t *conf);

/* ================================================================== */
/*  Connection entry point                                              */
/* ================================================================== */

static off_t
xrootd_chain_pending_bytes(ngx_chain_t *cl)
{
    off_t total = 0;

    for (; cl != NULL; cl = cl->next) {
        off_t n = ngx_buf_size(cl->buf);

        if (n > 0) {
            total += n;
        }
    }

    return total;
}

ngx_int_t
xrootd_schedule_read_resume(ngx_connection_t *c)
{
    ngx_event_t *rev = c->read;

    /*
     * Thread-pool completions and fully flushed responses often discover that
     * the peer already sent the next request while this connection was busy.
     * Posting the read event lets nginx run that parser pass from the current
     * posted-events drain instead of falling through to another epoll_wait.
     */
    if (!rev->active && !rev->ready) {
        if (ngx_handle_read_event(rev, 0) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if (!rev->posted) {
        ngx_post_event(rev, &ngx_posted_events);
    }

    return NGX_OK;
}

ngx_int_t
xrootd_schedule_write_resume(ngx_connection_t *c)
{
    ngx_event_t *wev = c->write;

    /*
     * A partial chain send can stop because nginx reached an internal chunk
     * boundary even though the socket is still writable.  Keep the descriptor
     * armed for the real EAGAIN case, but post the write event immediately when
     * nginx still considers it ready so we do not pay for an extra poll cycle.
     */
    if (ngx_handle_write_event(wev, 0) != NGX_OK) {
        return NGX_ERROR;
    }

    if (wev->ready && !wev->posted) {
        ngx_post_event(wev, &ngx_posted_events);
    }

    return NGX_OK;
}

void
ngx_stream_xrootd_handler(ngx_stream_session_t *s)
{
    ngx_connection_t  *c = s->connection;
    xrootd_ctx_t      *ctx;
    int                i;

    /* One per-connection context carries protocol state for the session lifetime. */
    ctx = ngx_pcalloc(c->pool, sizeof(xrootd_ctx_t));
    if (ctx == NULL) {
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ctx->session = s;
    /* Every connection begins before any protocol framing has been negotiated. */
    ctx->state   = XRD_ST_HANDSHAKE;
    ctx->hdr_pos = 0;

    /* Mark every handle slot free before the first open request arrives. */
    for (i = 0; i < XROOTD_MAX_FILES; i++) {
        ctx->files[i].fd = -1;
    }

    {
        uint32_t parts[4];
        /*
         * Session IDs only need to be unique per process lifetime, not secret.
         * Mix together coarse time, worker pid, connection address identity,
         * and nginx's PRNG so concurrent sessions are unlikely to collide.
         */
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

        /*
         * metrics_slot is assigned at config time; here we translate it to the
         * shared-memory row the connection will update for its lifetime.
         */
        if (mconf->metrics_slot >= 0 && ngx_xrootd_shm_zone != NULL
            && ngx_xrootd_shm_zone->data != NULL
            && ngx_xrootd_shm_zone->data != (void *) 1)
        {
            ngx_xrootd_metrics_t     *shm = ngx_xrootd_shm_zone->data;
            ngx_xrootd_srv_metrics_t *srv = &shm->servers[mconf->metrics_slot];
            ctx->metrics = srv;

            if (!srv->in_use) {
                /*
                 * Lazily stamp listener metadata the first time any connection
                 * lands on this slot. Later connections only update counters.
                 */
                srv->in_use = 1;
                ngx_cpystrn((u_char *) srv->auth,
                            /* Export auth mode as a stable low-cardinality label. */
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

            /* `total` is monotonic; `active` is the live connection gauge. */
            ngx_atomic_fetch_add(&srv->connections_total, 1);
            ngx_atomic_fetch_add(&srv->connections_active, 1);
        }
    }

    /* After setup, all future progress happens through the read/write event handlers. */
    c->read->handler  = ngx_stream_xrootd_recv;
    c->write->handler = ngx_stream_xrootd_send;

    /* Kick the state machine once immediately so already-buffered bytes are consumed. */
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
        /* Timeout teardown follows the same accounting path as any other loss. */
        xrootd_on_disconnect(ctx, c);
        xrootd_close_all_files(ctx);
        ngx_stream_finalize_session(s, NGX_STREAM_OK);
        return;
    }

    for (;;) {

        /*
         * Drain as much input as we can in one callback until we either block,
         * hand ownership to the write side, or park on an async file operation.
         * This keeps latency down for pipelined clients that already have the
         * next request waiting in the socket buffer.
         */

        if (ctx->state == XRD_ST_SENDING) {
            /* Stop parsing new requests until the current response is flushed. */
            return;
        }

        if (ctx->state == XRD_ST_AIO) {
            /* A worker thread owns the request; just keep the read event armed. */
            if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                break;
            }
            return;
        }

        if (ctx->state == XRD_ST_UPSTREAM) {
            /* Upstream query in flight; hold client reads until it completes. */
            if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                break;
            }
            return;
        }

        if (ctx->state == XRD_ST_TLS_HANDSHAKE) {
            /* ngx_ssl_handshake() owns the connection events during handshake. */
            return;
        }

        u_char *dest;
        size_t  need, avail;

        /* Recompute target buffer and remaining byte count from the current state. */

        if (ctx->state == XRD_ST_HANDSHAKE) {
            /* Initial 20-byte hello before any framed requests exist. */
            dest  = ctx->hdr_buf + ctx->hdr_pos;
            need  = XRD_HANDSHAKE_LEN - ctx->hdr_pos;

        } else if (ctx->state == XRD_ST_REQ_HEADER) {
            /* Every normal XRootD request starts with one fixed 24-byte header. */
            dest  = ctx->hdr_buf + ctx->hdr_pos;
            need  = XRD_REQUEST_HDR_LEN - ctx->hdr_pos;

        } else {
            /* Payload bytes are accumulated into the pool buffer allocated from dlen. */
            dest  = ctx->payload + ctx->payload_pos;
            need  = ctx->cur_dlen - ctx->payload_pos;
        }

        if (need > 0) {
            /*
             * Ask the socket for exactly the remaining bytes needed for the
             * current frame fragment.  The state machine tracks any short
             * read explicitly.
             */
            rev->available = -1;
            n = c->recv(c, dest, need);

            if (n == NGX_AGAIN) {
                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                              "xrootd: recv AGAIN st=%d hdr_pos=%uz avail=%d"
                              " ready=%d active=%d",
                              (int)ctx->state, ctx->hdr_pos,
                              rev->available, (int)rev->ready, (int)rev->active);
                if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                    break;
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

                /*
                 * Fast-reject non-XRootD clients (HTTP crawlers, port scanners).
                 *
                 * A valid XRootD handshake is 20 bytes whose first 12 are all
                 * zero.  HTTP requests always start with a printable ASCII byte
                 * ('G' for GET, 'P' for POST/PUT, 'H' for HEAD, etc.).  We can
                 * therefore reject any connection whose first byte is non-zero
                 * without waiting for the full 20-byte frame, avoiding pool
                 * allocations and all downstream processing that would normally
                 * happen before the magic-value check in xrootd_process_handshake.
                 */
                if (ctx->hdr_pos >= 1 && ctx->hdr_buf[0] != 0) {
                    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                                   "xrootd: non-XRootD client (first byte 0x%02xd)"
                                   " — closing immediately",
                                   (unsigned) ctx->hdr_buf[0]);
                    break;
                }
            } else if (ctx->state == XRD_ST_REQ_HEADER) {
                ctx->hdr_pos += avail;
            } else {
                ctx->payload_pos += avail;
            }

            if (avail < need) {
                continue;
            }
        }

        /* The current handshake/header/payload frame is complete; act on it now. */
        if (ctx->state == XRD_ST_HANDSHAKE) {

            rc = xrootd_process_handshake(ctx, c);
            if (rc != NGX_OK) {
                break;
            }
            /* Handshake succeeded; all further traffic is 24-byte request headers. */
            ctx->state   = XRD_ST_REQ_HEADER;
            ctx->hdr_pos = 0;

        } else if (ctx->state == XRD_ST_REQ_HEADER) {

            ClientRequestHdr *hdr = (ClientRequestHdr *) ctx->hdr_buf;

            /* Cache the parsed header in host order for the downstream handlers. */
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
                /*
                 * Bound allocations per opcode before any payload buffer is
                 * created. Small metadata requests get a tight path-sized cap,
                 * while the write-family opcodes are allowed much larger bodies.
                 */
                if (ctx->cur_reqid == kXR_pgwrite ||
                    ctx->cur_reqid == kXR_write   ||
                    ctx->cur_reqid == kXR_writev) {
                    max_pl = XROOTD_MAX_WRITE_PAYLOAD;
                } else if (ctx->cur_reqid == kXR_readv) {
                    max_pl = XROOTD_READV_MAXSEGS * XROOTD_READV_SEGSIZE;
                } else if (ctx->cur_reqid == kXR_auth) {
                    /* GSI cert chains with VOMS extensions can exceed 4 KB. */
                    max_pl = XROOTD_MAX_AUTH_PAYLOAD;
                } else if (ctx->cur_reqid == kXR_prepare) {
                    max_pl = XROOTD_MAX_PREPARE_PAYLOAD;
                } else {
                    max_pl = XROOTD_MAX_PATH + 64;
                }
                if (ctx->cur_dlen > max_pl) {
                    /* Oversized payloads are treated as fatal protocol abuse. */
                    ngx_log_error(NGX_LOG_WARN, c->log, 0,
                                  "xrootd: payload too large (%uz), closing",
                                  (size_t) ctx->cur_dlen);
                    break;
                }
            }

            if (ctx->cur_dlen > 0) {
                /*
                 * Allocate one extra byte so path-style handlers can safely treat
                 * the payload as a C string after validation. dlen remains the
                 * authoritative byte count for binary-safe parsing.
                 */
                ctx->payload = ngx_palloc(c->pool, ctx->cur_dlen + 1);
                if (ctx->payload == NULL) {
                    break;
                }
                /* The spare byte is for local convenience only, never sent back on the wire. */
                ctx->payload[ctx->cur_dlen] = '\0';
                ctx->payload_pos = 0;
                ctx->state       = XRD_ST_REQ_PAYLOAD;
                ctx->hdr_pos     = 0;
                /* Loop back immediately in case the payload bytes are already waiting. */
                continue;
            }

            /* Zero-length requests can be dispatched immediately from the header. */
            /* `payload = NULL` lets handlers distinguish header-only requests cheaply. */
            ctx->payload = NULL;
            rc = xrootd_dispatch(ctx, c, conf);
            if (rc == NGX_ERROR) {
                break;
            }

            if (ctx->state == XRD_ST_AIO) {
                /* The handler posted background work; the completion callback resumes. */
                if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                    break;
                }
                return;
            }
            if (ctx->state != XRD_ST_SENDING) {
                /* kXR_protocol may have set tls_pending while sending synchronously. */
                if (ctx->tls_pending) {
                    xrootd_start_tls(ctx, c, conf);
                    return;
                }
                /* Most handlers complete synchronously and return to header parsing. */
                ctx->state   = XRD_ST_REQ_HEADER;
                ctx->hdr_pos = 0;
            }

        } else {
            /* Full payload is buffered; hand off to the request-specific handler. */
            /* Default back to header parsing unless the handler deliberately overrides state. */
            ctx->state = XRD_ST_REQ_HEADER;
            ctx->hdr_pos = 0;

            rc = xrootd_dispatch(ctx, c, conf);
            if (rc == NGX_ERROR) {
                break;
            }

            if (ctx->state == XRD_ST_SENDING) {
                /* Large or EAGAIN-limited replies resume from the write handler. */
                return;
            }

            /* Otherwise the handler completed synchronously and the loop keeps draining. */
        }
    }

    /* Fatal error — tear down the connection. */
    xrootd_on_disconnect(ctx, c);
    xrootd_close_all_files(ctx);
    ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
}

/* ================================================================== */
/*  kXR_ableTLS in-protocol TLS upgrade                                */
/* ================================================================== */

void
xrootd_tls_handshake_done(ngx_connection_t *c)
{
    ngx_stream_session_t *s   = c->data;
    xrootd_ctx_t         *ctx = ngx_stream_get_module_ctx(s,
                                                          ngx_stream_xrootd_module);

    if (!c->ssl->handshaked) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "xrootd: kXR_ableTLS handshake failed");
        xrootd_on_disconnect(ctx, c);
        xrootd_close_all_files(ctx);
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                  "xrootd: kXR_ableTLS TLS handshake complete (%s)",
                  SSL_get_cipher(c->ssl->connection));

    ctx->tls_pending = 0;
    ctx->state       = XRD_ST_REQ_HEADER;
    ctx->hdr_pos     = 0;

    /* Restore the normal read/write event handlers that ngx_ssl_handshake()
     * replaced with its own internal handlers during the async handshake. */
    c->read->handler  = ngx_stream_xrootd_recv;
    c->write->handler = ngx_stream_xrootd_send;

    ngx_stream_xrootd_recv(c->read);
}

static void
xrootd_start_tls(xrootd_ctx_t *ctx, ngx_connection_t *c,
                 ngx_stream_xrootd_srv_conf_t *conf)
{
    ngx_stream_session_t *s  = c->data;
    ngx_int_t             rc;

    ctx->state = XRD_ST_TLS_HANDSHAKE;

    if (ngx_ssl_create_connection(conf->tls_ctx, c, NGX_SSL_BUFFER) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "xrootd: ngx_ssl_create_connection failed");
        xrootd_on_disconnect(ctx, c);
        xrootd_close_all_files(ctx);
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    c->ssl->handler = xrootd_tls_handshake_done;

    rc = ngx_ssl_handshake(c);
    if (rc == NGX_AGAIN) {
        /* Handshake is non-blocking; xrootd_tls_handshake_done fires on completion. */
        return;
    }

    if (rc == NGX_OK) {
        xrootd_tls_handshake_done(c);
        return;
    }

    ngx_log_error(NGX_LOG_ERR, c->log, 0,
                  "xrootd: kXR_ableTLS ngx_ssl_handshake error");
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
    ngx_connection_t              *c;
    ngx_stream_session_t          *s;
    ngx_stream_xrootd_srv_conf_t  *conf;
    xrootd_ctx_t                  *ctx;
    ngx_int_t                      rc;

    c    = wev->data;
    s    = c->data;
    ctx  = ngx_stream_get_module_ctx(s, ngx_stream_xrootd_module);
    conf = ngx_stream_get_module_srv_conf(s, ngx_stream_xrootd_module);

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                      "xrootd: write timed out");
        xrootd_on_disconnect(ctx, c);
        xrootd_close_all_files(ctx);
        ngx_stream_finalize_session(s, NGX_STREAM_OK);
        return;
    }

    /* Try to finish any queued response body before parsing more client input. */
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
        /* Stray writable event after the state already moved on; ignore it. */
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

    /* If the just-sent response was kXR_protocol with kXR_haveTLS, start the
     * TLS accept handshake now before processing any further XRootD requests. */
    if (ctx->tls_pending) {
        xrootd_start_tls(ctx, c, conf);
        return;
    }

    /* Continue draining any bytes the client already pipelined behind this reply. */
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

    /*
     * Try to satisfy the response synchronously first; only fall back to the
     * write event path when the socket refuses more bytes.
     */
    while (len > 0) {
        /* Optimistic fast path: write directly until the socket would block. */
        n = c->send(c, buf, len);
        if (n > 0) {
            /* Advance over the bytes the kernel accepted this round. */
            buf += n;
            len -= (size_t) n;
            continue;
        }
        if (n == NGX_AGAIN) {
            /*
             * Preserve the unsent suffix; buf may already point into the middle
             * of a larger allocation, so `base` remembers what must be freed.
             */
            ctx->wbuf      = buf;
            ctx->wbuf_len  = len;
            ctx->wbuf_pos  = 0;
            ctx->wbuf_base = base;
            ctx->state     = XRD_ST_SENDING;

            /* Wake via posted event if still ready; otherwise wait for epoll. */
            if (xrootd_schedule_write_resume(c) != NGX_OK) {
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
    /* Simple wrapper for the common case where `buf` is itself the pool base. */
    return xrootd_queue_response_base(ctx, c, buf, len, NULL);
}

/*
 * xrootd_tcp_push — release TCP_CORK (set by ngx_linux_sendfile_chain when
 * it sees a memory-header + in_file body) and restore TCP_NODELAY.
 *
 * Without this, the kernel holds the last sub-MSS segment for the 200 ms
 * TCP_CORK auto-flush timeout, causing exactly that delay per kXR_read chunk
 * on plain TCP.  TLS connections are unaffected because ngx_ssl_send_chain
 * never sets TCP_CORK.
 */
static void
xrootd_tcp_push(ngx_connection_t *c)
{
    if (c->tcp_nopush != NGX_TCP_NOPUSH_SET) {
        return;
    }
    (void) ngx_tcp_push(c->fd);
    c->tcp_nopush = NGX_TCP_NOPUSH_UNSET;

    if (c->tcp_nodelay == NGX_TCP_NODELAY_UNSET) {
        (void) ngx_tcp_nodelay(c);
        c->tcp_nodelay = NGX_TCP_NODELAY_SET;
    }
}

ngx_int_t
xrootd_queue_response_chain(xrootd_ctx_t *ctx, ngx_connection_t *c,
                            ngx_chain_t *cl, u_char *base)
{
    ngx_chain_t *out;
    ngx_uint_t   spins = 0;

    out = cl;

    for (;;) {
        off_t before, after;

        before = xrootd_chain_pending_bytes(out);
        out = c->send_chain(c, out, 0);

        if (out == NGX_CHAIN_ERROR) {
            return NGX_ERROR;
        }

        if (out == NULL) {
            xrootd_tcp_push(c);
            return NGX_OK;
        }

        after = xrootd_chain_pending_bytes(out);
        if (after < before && ++spins < XROOTD_SEND_CHAIN_SPIN_MAX) {
            continue;
        }

        ctx->wchain = out;
        ctx->wchain_base = base;
        ctx->state = XRD_ST_SENDING;

        if (xrootd_schedule_write_resume(c) != NGX_OK) {
            return NGX_ERROR;
        }

        return NGX_OK;
    }
}

ngx_int_t
xrootd_flush_pending(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    ssize_t n;
    ngx_chain_t *out;

    if (ctx->wchain != NULL) {
        ngx_uint_t spins = 0;

        for (;;) {
            off_t before, after;

            before = xrootd_chain_pending_bytes(ctx->wchain);
            out = c->send_chain(c, ctx->wchain, 0);
            if (out == NGX_CHAIN_ERROR) {
                return NGX_ERROR;
            }

            if (out == NULL) {
                break;
            }

            after = xrootd_chain_pending_bytes(out);
            ctx->wchain = out;

            if (after < before && ++spins < XROOTD_SEND_CHAIN_SPIN_MAX) {
                continue;
            }

            if (xrootd_schedule_write_resume(c) != NGX_OK) {
                return NGX_ERROR;
            }
            return NGX_AGAIN;
        }

        xrootd_tcp_push(c);

        if (ctx->wchain_base) {
            xrootd_release_read_buffer(ctx, c, ctx->wchain_base);
            ctx->wchain_base = NULL;
        }

        ctx->wchain = NULL;
        return NGX_OK;
    }

    while (ctx->wbuf_pos < ctx->wbuf_len) {
        /* Resume exactly where the previous short write stopped. */
        n = c->send(c, ctx->wbuf + ctx->wbuf_pos,
                    ctx->wbuf_len - ctx->wbuf_pos);
        if (n > 0) {
            /* Advance the cursor until either all bytes are sent or the socket blocks again. */
            ctx->wbuf_pos += (size_t) n;
            continue;
        }
        if (n == NGX_AGAIN) {
            /* Still blocked; keep the remaining suffix and wait for the next write event. */
            if (xrootd_schedule_write_resume(c) != NGX_OK) {
                return NGX_ERROR;
            }
            return NGX_AGAIN;
        }
        return NGX_ERROR;
    }

    if (ctx->wbuf_base) {
        /* Some callers keep a separate base pointer because wbuf may be advanced. */
        xrootd_release_read_buffer(ctx, c, ctx->wbuf_base);
        ctx->wbuf_base = NULL;
    }

    /* Clear the pending-send bookkeeping before returning control to recv(). */
    ctx->wbuf     = NULL;
    ctx->wbuf_len = 0;
    ctx->wbuf_pos = 0;
    ctx->wchain   = NULL;
    return NGX_OK;
}

/* ================================================================== */
/*  File handle helpers                                                 */
/* ================================================================== */

int
xrootd_alloc_fhandle(xrootd_ctx_t *ctx)
{
    int i;
    /*
     * Small fixed table: a linear scan is simpler than free-list bookkeeping,
     * and the returned index is later encoded into the 4-byte opaque handle.
     */
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
        /* Close first, then mark the slot reusable for future opens. */
        close(ctx->files[idx].fd);
        ctx->files[idx].fd       = -1;
        ctx->files[idx].readable = 0;
        ctx->files[idx].writable = 0;
        ctx->files[idx].path[0]  = '\0';
    }
}

void
xrootd_close_all_files(xrootd_ctx_t *ctx)
{
    int i;
    /* Called on teardown paths, so keep it idempotent and brute-force simple. */
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

    /* Async completion handlers consult this before touching session state. */
    ctx->destroyed = 1;

    /* Close any in-flight upstream connection before cleaning up session state. */
    if (ctx->upstream != NULL) {
        xrootd_upstream_cleanup(ctx->upstream);
    }

    if (ctx->metrics) {
        /*
         * Publish aggregate byte counters once when the session actually ends.
         * From the server's perspective, uploaded bytes are RX and downloaded
         * bytes are TX, hence the written/read counter mapping below.
         */
        ngx_atomic_fetch_add(&ctx->metrics->connections_active, (ngx_atomic_int_t) -1);
        ngx_atomic_fetch_add(&ctx->metrics->bytes_rx_total,
                             (ngx_atomic_int_t) ctx->session_bytes_written);
        ngx_atomic_fetch_add(&ctx->metrics->bytes_tx_total,
                             (ngx_atomic_int_t) ctx->session_bytes);
    }

    /* Walk every still-open handle because clients may drop the TCP session mid-transfer. */
    for (i = 0; i < XROOTD_MAX_FILES; i++) {
        if (ctx->files[i].fd < 0) {
            continue;
        }

        /* Reuse the standard CLOSE log format for any handles left open on loss. */
        ctx->req_start = ctx->files[i].open_time;

        {
            char   detail[64];
            size_t btotal = ctx->files[i].bytes_written > 0
                            ? ctx->files[i].bytes_written
                            : ctx->files[i].bytes_read;
            ngx_msec_t dur = now - ctx->files[i].open_time;

            /* Summarize interrupted handle throughput using the same close log shape. */
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
        /* Pre-login disconnects never established a session identity worth summarizing. */
        return;
    }

    {
        char       detail[128];
        ngx_msec_t sess_dur = now - ctx->session_start;
        size_t     total    = ctx->session_bytes + ctx->session_bytes_written;

        /* Derive a coarse end-of-session throughput summary for the access log. */
        if (total > 0 && sess_dur > 0) {
            double mbps = (double) total / (double) sess_dur / 1000.0;
            if (ctx->session_bytes_written > 0) {
                /* Log bidirectional throughput separately when uploads happened. */
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
