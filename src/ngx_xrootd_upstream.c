#include "ngx_xrootd_module.h"

#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* ================================================================== */
/*  Upstream XRootD redirector client                                  */
/* ================================================================== */

/*
 * Connects to a configured upstream XRootD redirector, performs
 * handshake + kXR_protocol + kXR_login (pipelined), forwards the
 * pending client request, and relays the upstream response back:
 *
 *   kXR_redirect  → forward host:port to client
 *   kXR_wait      → schedule retry timer; resend after N seconds
 *   kXR_waitresp  → forward to client; wait for unsolicited response
 *   kXR_ok        → forward response body to client
 *   kXR_error     → forward error to client
 *
 * Usage:
 *   Call xrootd_upstream_start() from a request handler (locate, open,
 *   stat) when no local match is found and an upstream is configured.
 *   The handler must return NGX_OK after this call; the upstream module
 *   resumes the client state machine when the upstream response arrives.
 */

#define XROOTD_UP_WAIT_MAX   60   /* cap kXR_wait retries at 60 seconds */

/* Bootstrap phases (which response we're currently accumulating) */
typedef enum {
    XRD_UP_BS_HANDSHAKE = 0,
    XRD_UP_BS_PROTOCOL,
    XRD_UP_BS_LOGIN,
    XRD_UP_BS_DONE,
} xrootd_up_bs_t;

/* Upstream connection state */
typedef enum {
    XRD_UP_CONNECTING = 0,
    XRD_UP_BOOTSTRAP,     /* reading handshake/protocol/login responses  */
    XRD_UP_REQUEST,       /* reading response to the forwarded request    */
    XRD_UP_ASYNC,         /* got kXR_waitresp; awaiting unsolicited reply */
} xrootd_up_state_t;

struct xrootd_upstream_s {
    ngx_connection_t   *conn;
    xrootd_up_state_t   state;
    xrootd_up_bs_t      bs_phase;

    /* Response accumulation from upstream */
    u_char   rhdr[XRD_RESPONSE_HDR_LEN];
    size_t   rhdr_pos;
    uint16_t resp_status;
    uint32_t resp_dlen;
    u_char  *resp_body;
    size_t   resp_body_pos;

    /* Send buffer */
    u_char  *wbuf;
    size_t   wbuf_len;
    size_t   wbuf_pos;

    /* kXR_wait retry timer */
    ngx_event_t timer;

    /* Back-link to client connection */
    xrootd_ctx_t     *client_ctx;
    ngx_connection_t *client_conn;

    /* Saved client request for forwarding / retry */
    uint16_t  req_opcode;
    u_char    req_streamid[2];
    char      req_path[XROOTD_MAX_PATH];
    uint16_t  req_options;     /* options field from ClientLocateRequest/ClientOpenRequest */
    uint16_t  req_open_mode;   /* mode field from ClientOpenRequest */
};

/* ------------------------------------------------------------------
 * Forward declarations
 * ------------------------------------------------------------------ */

static void       xrootd_upstream_write_handler(ngx_event_t *wev);
static void       xrootd_upstream_read_handler(ngx_event_t *rev);
static ngx_int_t  xrootd_upstream_flush(xrootd_upstream_t *up);
static ngx_int_t  xrootd_upstream_send_request(xrootd_upstream_t *up);
static void       xrootd_upstream_abort(xrootd_upstream_t *up,
                      const char *reason);
static void       xrootd_upstream_forward_response(xrootd_upstream_t *up);
static void       xrootd_upstream_wait_timer_handler(ngx_event_t *ev);

/* ------------------------------------------------------------------
 * xrootd_upstream_cleanup
 *
 * Close the upstream TCP connection and disarm the retry timer.
 * Clears ctx->upstream so callers can detect the cleaned-up state.
 * Safe to call multiple times.
 * ------------------------------------------------------------------ */

void
xrootd_upstream_cleanup(xrootd_upstream_t *up)
{
    if (up == NULL) {
        return;
    }

    if (up->timer.timer_set) {
        ngx_del_timer(&up->timer);
    }

    if (up->conn != NULL) {
        ngx_close_connection(up->conn);
        up->conn = NULL;
    }

    if (up->client_ctx != NULL) {
        up->client_ctx->upstream = NULL;
        up->client_ctx = NULL;
    }
}

/* ------------------------------------------------------------------
 * Build pipelined bootstrap: handshake (20B) + kXR_protocol (24B)
 * + kXR_login (24B) = 68 bytes total written into buf.
 * ------------------------------------------------------------------ */

static void
xrootd_upstream_build_bootstrap(u_char *buf)
{
    u_char *p = buf;

    /* Handshake: 20 bytes (first 12 zero, fourth=4, fifth=2012) */
    ngx_memzero(p, 12);
    p += 12;
    *(uint32_t *)(void *)p = htonl(4);
    p += 4;
    *(uint32_t *)(void *)p = htonl(ROOTD_PQ);
    p += 4;

    /* kXR_protocol: 24 bytes */
    {
        ClientProtocolRequest *pr = (ClientProtocolRequest *)(void *) p;
        ngx_memzero(pr, sizeof(*pr));
        pr->streamid[0] = 0;
        pr->streamid[1] = 1;
        pr->requestid   = htons(kXR_protocol);
        pr->clientpv    = htonl(kXR_PROTOCOLVERSION);
        pr->flags       = 0;    /* no TLS negotiation on outbound connection */
        pr->expect      = 0x03; /* kXR_ExpLogin */
        pr->dlen        = 0;
        p += sizeof(*pr);
    }

    /* kXR_login: 24 bytes, no auth token payload */
    {
        ClientLoginRequest *lr = (ClientLoginRequest *)(void *) p;
        ngx_memzero(lr, sizeof(*lr));
        lr->streamid[0] = 0;
        lr->streamid[1] = 1;
        lr->requestid   = htons(kXR_login);
        lr->pid         = htonl((kXR_int32) ngx_pid);
        lr->username[0] = 'x';
        lr->username[1] = 'r';
        lr->username[2] = 'd';
        lr->capver      = kXR_ver005;
        lr->dlen        = 0;
    }
}

/* ------------------------------------------------------------------
 * Build and send the saved client request to upstream.
 * Resets response accumulation state and transitions to REQUEST.
 * ------------------------------------------------------------------ */

static ngx_int_t
xrootd_upstream_send_request(xrootd_upstream_t *up)
{
    ngx_pool_t *pool    = up->conn->pool;
    size_t      pathlen = strlen(up->req_path);
    size_t      hdrlen  = XRD_REQUEST_HDR_LEN;
    size_t      total   = hdrlen + pathlen;
    u_char     *buf;

    buf = ngx_palloc(pool, total);
    if (buf == NULL) {
        return NGX_ERROR;
    }
    ngx_memzero(buf, total);

    switch (up->req_opcode) {

    case kXR_locate: {
        ClientLocateRequest *r = (ClientLocateRequest *)(void *) buf;
        r->streamid[0] = 0;
        r->streamid[1] = 1;
        r->requestid   = htons(kXR_locate);
        r->options     = htons(up->req_options);
        r->dlen        = htonl((kXR_int32) pathlen);
        ngx_memcpy(buf + hdrlen, up->req_path, pathlen);
        break;
    }

    case kXR_open: {
        ClientOpenRequest *r = (ClientOpenRequest *)(void *) buf;
        r->streamid[0] = 0;
        r->streamid[1] = 1;
        r->requestid   = htons(kXR_open);
        r->mode        = htons(up->req_open_mode);
        r->options     = htons(up->req_options);
        r->dlen        = htonl((kXR_int32) pathlen);
        ngx_memcpy(buf + hdrlen, up->req_path, pathlen);
        break;
    }

    case kXR_stat: {
        ClientStatRequest *r = (ClientStatRequest *)(void *) buf;
        r->streamid[0] = 0;
        r->streamid[1] = 1;
        r->requestid   = htons(kXR_stat);
        r->dlen        = htonl((kXR_int32) pathlen);
        ngx_memcpy(buf + hdrlen, up->req_path, pathlen);
        break;
    }

    default:
        ngx_log_error(NGX_LOG_ERR, up->client_conn->log, 0,
                      "xrootd: upstream: unsupported opcode %d",
                      (int) up->req_opcode);
        return NGX_ERROR;
    }

    up->wbuf     = buf;
    up->wbuf_len = total;
    up->wbuf_pos = 0;

    /* Reset response accumulation for the fresh request */
    up->rhdr_pos      = 0;
    up->resp_dlen     = 0;
    up->resp_body     = NULL;
    up->resp_body_pos = 0;
    up->state         = XRD_UP_REQUEST;

    return xrootd_upstream_flush(up);
}

/* ------------------------------------------------------------------
 * Flush wbuf to the upstream socket (non-blocking).
 * When all bytes are sent, arms the read event for the response.
 * ------------------------------------------------------------------ */

static ngx_int_t
xrootd_upstream_flush(xrootd_upstream_t *up)
{
    ngx_connection_t *uconn = up->conn;
    ssize_t           n;

    while (up->wbuf_pos < up->wbuf_len) {
        n = uconn->send(uconn, up->wbuf + up->wbuf_pos,
                        up->wbuf_len - up->wbuf_pos);
        if (n > 0) {
            up->wbuf_pos += (size_t) n;
            continue;
        }
        if (n == NGX_AGAIN) {
            if (ngx_handle_write_event(uconn->write, 0) != NGX_OK) {
                return NGX_ERROR;
            }
            return NGX_AGAIN;
        }
        return NGX_ERROR;
    }

    /* All sent; arm read for the response */
    if (ngx_handle_read_event(uconn->read, 0) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

/* ------------------------------------------------------------------
 * Forward a completed upstream response to the client.
 * Handles kXR_redirect, kXR_wait, kXR_waitresp, kXR_ok, kXR_error.
 * ------------------------------------------------------------------ */

static void
xrootd_upstream_forward_response(xrootd_upstream_t *up)
{
    xrootd_ctx_t     *ctx    = up->client_ctx;
    ngx_connection_t *c      = up->client_conn;
    uint16_t          status = up->resp_status;
    u_char           *body   = up->resp_body;
    uint32_t          dlen   = up->resp_dlen;

    /* Restore client stream ID before building any response */
    ctx->cur_streamid[0] = up->req_streamid[0];
    ctx->cur_streamid[1] = up->req_streamid[1];

    switch (status) {

    case kXR_redirect: {
        if (dlen < 4) {
            xrootd_upstream_abort(up, "malformed kXR_redirect from upstream");
            return;
        }

        /* Build the redirect response verbatim from upstream body */
        size_t  total = XRD_RESPONSE_HDR_LEN + dlen;
        u_char *buf   = ngx_palloc(c->pool, total);
        if (buf == NULL) {
            xrootd_upstream_abort(up, "pool alloc failed forwarding redirect");
            return;
        }
        xrootd_build_resp_hdr(ctx->cur_streamid, kXR_redirect, dlen,
                              (ServerResponseHdr *) buf);
        ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN, body, dlen);

        {
            uint32_t port_be;
            ngx_memcpy(&port_be, body, sizeof(port_be));
            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "xrootd: upstream redirect to %.*s:%u",
                          (int)(dlen - 4), body + 4, ntohl(port_be));
        }

        ctx->state = XRD_ST_REQ_HEADER;
        xrootd_upstream_cleanup(up);
        xrootd_queue_response(ctx, c, buf, total);
        xrootd_schedule_read_resume(c);
        return;
    }

    case kXR_wait: {
        /* body: 4-byte big-endian seconds + optional message */
        uint32_t secs = 5;
        if (dlen >= 4) {
            uint32_t sbe;
            ngx_memcpy(&sbe, body, sizeof(sbe));
            secs = ntohl(sbe);
        }
        if (secs > XROOTD_UP_WAIT_MAX) {
            secs = XROOTD_UP_WAIT_MAX;
        }

        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "xrootd: upstream kXR_wait %u s; scheduling retry", secs);

        /* Reset response state before the timer fires */
        up->rhdr_pos      = 0;
        up->resp_dlen     = 0;
        up->resp_body     = NULL;
        up->resp_body_pos = 0;

        up->timer.handler = xrootd_upstream_wait_timer_handler;
        up->timer.data    = up;
        up->timer.log     = c->log;
        ngx_add_timer(&up->timer, (ngx_msec_t) secs * 1000);
        return;
    }

    case kXR_waitresp: {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "xrootd: upstream kXR_waitresp; forwarding to client");

        /* Forward kXR_waitresp to client, then stay connected and wait for the
         * upstream's unsolicited follow-up response on the same connection. */
        up->state         = XRD_UP_ASYNC;
        up->rhdr_pos      = 0;
        up->resp_dlen     = 0;
        up->resp_body     = NULL;
        up->resp_body_pos = 0;

        if (ngx_handle_read_event(up->conn->read, 0) != NGX_OK) {
            xrootd_upstream_abort(up, "read arm failed after kXR_waitresp");
            return;
        }

        /* kXR_waitresp to client: dlen=0, no body */
        xrootd_send_waitresp(ctx, c);
        return;
    }

    case kXR_ok: {
        size_t  total = XRD_RESPONSE_HDR_LEN + dlen;
        u_char *buf   = ngx_palloc(c->pool, total);
        if (buf == NULL) {
            xrootd_upstream_abort(up, "pool alloc failed forwarding ok");
            return;
        }
        xrootd_build_resp_hdr(ctx->cur_streamid, kXR_ok, dlen,
                              (ServerResponseHdr *) buf);
        if (dlen > 0) {
            ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN, body, dlen);
        }

        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "xrootd: upstream ok (dlen=%u)", dlen);

        ctx->state = XRD_ST_REQ_HEADER;
        xrootd_upstream_cleanup(up);
        xrootd_queue_response(ctx, c, buf, total);
        xrootd_schedule_read_resume(c);
        return;
    }

    case kXR_error: {
        uint16_t   errcode = kXR_ServerError;
        const char *msg    = "upstream error";
        char        msgbuf[256];

        if (dlen >= 4) {
            uint32_t ebe;
            ngx_memcpy(&ebe, body, sizeof(ebe));
            errcode = (uint16_t) ntohl(ebe);
        }
        if (dlen > 4) {
            /* NUL-terminate the error message from upstream */
            size_t mlen = dlen - 4;
            if (mlen >= sizeof(msgbuf)) {
                mlen = sizeof(msgbuf) - 1;
            }
            ngx_memcpy(msgbuf, body + 4, mlen);
            msgbuf[mlen] = '\0';
            msg = msgbuf;
        }

        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "xrootd: upstream error %d: %s", (int) errcode, msg);

        ctx->state = XRD_ST_REQ_HEADER;
        xrootd_upstream_cleanup(up);
        xrootd_send_error(ctx, c, errcode, msg);
        xrootd_schedule_read_resume(c);
        return;
    }

    default:
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "xrootd: upstream unexpected status %d", (int) status);
        xrootd_upstream_abort(up, "unexpected status from upstream");
        return;
    }
}

/* ------------------------------------------------------------------
 * Abort the upstream query, send kXR_error to client, resume.
 * ------------------------------------------------------------------ */

static void
xrootd_upstream_abort(xrootd_upstream_t *up, const char *reason)
{
    xrootd_ctx_t     *ctx = up->client_ctx;
    ngx_connection_t *c   = up->client_conn;
    u_char            sid[2];

    sid[0] = up->req_streamid[0];
    sid[1] = up->req_streamid[1];

    ngx_log_error(NGX_LOG_ERR, c->log, 0,
                  "xrootd: upstream abort: %s", reason);

    xrootd_upstream_cleanup(up);

    ctx->cur_streamid[0] = sid[0];
    ctx->cur_streamid[1] = sid[1];
    ctx->state = XRD_ST_REQ_HEADER;

    xrootd_send_error(ctx, c, kXR_ServerError, reason);
    xrootd_schedule_read_resume(c);
}

/* ------------------------------------------------------------------
 * kXR_wait retry timer fires: re-send the request to upstream.
 * ------------------------------------------------------------------ */

static void
xrootd_upstream_wait_timer_handler(ngx_event_t *ev)
{
    xrootd_upstream_t *up  = ev->data;
    xrootd_ctx_t      *ctx = up->client_ctx;

    if (ctx == NULL || ctx->destroyed) {
        xrootd_upstream_cleanup(up);
        return;
    }

    ngx_log_error(NGX_LOG_INFO, up->client_conn->log, 0,
                  "xrootd: upstream kXR_wait expired; retrying");

    if (xrootd_upstream_send_request(up) != NGX_OK &&
        up->conn != NULL)   /* flush may go AGAIN without error */
    {
        xrootd_upstream_abort(up, "upstream retry failed");
    }
}

/* ------------------------------------------------------------------
 * Process one complete response in bootstrap phase.
 * ------------------------------------------------------------------ */

static void
xrootd_upstream_handle_bootstrap_response(xrootd_upstream_t *up)
{
    switch (up->bs_phase) {

    case XRD_UP_BS_HANDSHAKE:
        if (up->resp_status != kXR_ok) {
            xrootd_upstream_abort(up, "upstream: bad handshake response");
            return;
        }
        up->bs_phase = XRD_UP_BS_PROTOCOL;
        break;

    case XRD_UP_BS_PROTOCOL:
        if (up->resp_status != kXR_ok) {
            xrootd_upstream_abort(up, "upstream: protocol response not ok");
            return;
        }
        /* Refuse if upstream demands TLS upgrade (we don't support it here) */
        if (up->resp_dlen >= 8) {
            uint32_t flags_be;
            ngx_memcpy(&flags_be, up->resp_body + 4, sizeof(flags_be));
            if (ntohl(flags_be) & kXR_gotoTLS) {
                xrootd_upstream_abort(up,
                    "upstream requires TLS (not supported on outbound)");
                return;
            }
        }
        up->bs_phase = XRD_UP_BS_LOGIN;
        break;

    case XRD_UP_BS_LOGIN:
        if (up->resp_status == kXR_authmore) {
            xrootd_upstream_abort(up,
                "upstream requires authentication (not supported)");
            return;
        }
        if (up->resp_status != kXR_ok) {
            xrootd_upstream_abort(up, "upstream: login failed");
            return;
        }
        up->bs_phase = XRD_UP_BS_DONE;
        break;

    default:
        xrootd_upstream_abort(up, "upstream: invalid bootstrap phase");
        return;
    }

    /* Reset response accumulation for the next bootstrap response */
    up->rhdr_pos      = 0;
    up->resp_dlen     = 0;
    up->resp_body     = NULL;
    up->resp_body_pos = 0;

    if (up->bs_phase == XRD_UP_BS_DONE) {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                       "xrootd: upstream bootstrap done; sending request");
        if (xrootd_upstream_send_request(up) == NGX_ERROR) {
            xrootd_upstream_abort(up, "upstream: send request failed");
        }
        return;
    }

    /* Arm read for the next bootstrap response (data may already be waiting) */
    if (ngx_handle_read_event(up->conn->read, 0) != NGX_OK) {
        xrootd_upstream_abort(up, "upstream: read event arm failed");
    }
}

/* ------------------------------------------------------------------
 * Upstream write event handler.
 * Fires on connect completion and when the socket becomes writable
 * while we have data to send.
 * ------------------------------------------------------------------ */

static void
xrootd_upstream_write_handler(ngx_event_t *wev)
{
    ngx_connection_t  *uconn = wev->data;
    xrootd_upstream_t *up    = uconn->data;
    xrootd_ctx_t      *ctx   = up->client_ctx;

    if (ctx == NULL || ctx->destroyed) {
        xrootd_upstream_cleanup(up);
        return;
    }

    if (wev->timedout) {
        xrootd_upstream_abort(up, "upstream connect/write timeout");
        return;
    }

    /* First write event after a non-blocking connect() → check result */
    if (up->state == XRD_UP_CONNECTING) {
        int       err = 0;
        socklen_t len = sizeof(err);

        if (getsockopt(uconn->fd, SOL_SOCKET, SO_ERROR,
                       (char *) &err, &len) == -1 || err) {
            ngx_log_error(NGX_LOG_ERR, up->client_conn->log,
                          err ? err : ngx_socket_errno,
                          "xrootd: upstream connect to %s failed",
                          (char *) up->client_conn->log->action);
            xrootd_upstream_abort(up, "upstream TCP connect failed");
            return;
        }

        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, up->client_conn->log, 0,
                       "xrootd: upstream TCP connected");

        up->state    = XRD_UP_BOOTSTRAP;
        up->bs_phase = XRD_UP_BS_HANDSHAKE;
        up->rhdr_pos = 0;
        up->resp_dlen = 0;
        up->resp_body = NULL;
        up->resp_body_pos = 0;
    }

    /* Flush any pending send buffer */
    if (up->wbuf_pos < up->wbuf_len) {
        ngx_int_t rc = xrootd_upstream_flush(up);
        if (rc == NGX_ERROR) {
            xrootd_upstream_abort(up, "upstream write error");
        }
        return;
    }

    /* Nothing pending; make sure read event is armed */
    if (ngx_handle_read_event(uconn->read, 0) != NGX_OK) {
        xrootd_upstream_abort(up, "upstream read arm failed in write handler");
    }
}

/* ------------------------------------------------------------------
 * Upstream read event handler.
 * Accumulates the 8-byte ServerResponseHdr then dlen body bytes,
 * then dispatches to bootstrap or response handling.
 * ------------------------------------------------------------------ */

static void
xrootd_upstream_read_handler(ngx_event_t *rev)
{
    ngx_connection_t  *uconn = rev->data;
    xrootd_upstream_t *up    = uconn->data;
    xrootd_ctx_t      *ctx   = up->client_ctx;
    ssize_t            n;

    if (ctx == NULL || ctx->destroyed) {
        xrootd_upstream_cleanup(up);
        return;
    }

    if (rev->timedout) {
        xrootd_upstream_abort(up, "upstream read timeout");
        return;
    }

    for (;;) {
        /* Phase A: accumulate the 8-byte response header */
        if (up->rhdr_pos < XRD_RESPONSE_HDR_LEN) {
            size_t need = XRD_RESPONSE_HDR_LEN - up->rhdr_pos;

            n = uconn->recv(uconn, up->rhdr + up->rhdr_pos, need);
            if (n == NGX_AGAIN) {
                if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                    xrootd_upstream_abort(up, "upstream read arm failed (hdr)");
                }
                return;
            }
            if (n <= 0) {
                xrootd_upstream_abort(up, "upstream connection closed");
                return;
            }

            up->rhdr_pos += (size_t) n;
            if (up->rhdr_pos < XRD_RESPONSE_HDR_LEN) {
                continue;
            }

            /* Full header: parse status and dlen */
            {
                ServerResponseHdr *hdr = (ServerResponseHdr *)(void *) up->rhdr;
                up->resp_status = ntohs(hdr->status);
                up->resp_dlen   = ntohl(hdr->dlen);
            }

            /* Allocate body buffer — limit to a generous but bounded size */
            if (up->resp_dlen > 0) {
                if (up->resp_dlen > XROOTD_MAX_PATH + 256) {
                    xrootd_upstream_abort(up, "upstream response body too large");
                    return;
                }
                up->resp_body = ngx_palloc(uconn->pool, up->resp_dlen + 1);
                if (up->resp_body == NULL) {
                    xrootd_upstream_abort(up, "upstream pool alloc failed");
                    return;
                }
                up->resp_body[up->resp_dlen] = '\0';
                up->resp_body_pos = 0;
            }
        }

        /* Phase B: accumulate body bytes */
        if (up->resp_body_pos < up->resp_dlen) {
            size_t need = up->resp_dlen - up->resp_body_pos;

            n = uconn->recv(uconn, up->resp_body + up->resp_body_pos, need);
            if (n == NGX_AGAIN) {
                if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                    xrootd_upstream_abort(up, "upstream read arm failed (body)");
                }
                return;
            }
            if (n <= 0) {
                xrootd_upstream_abort(up, "upstream connection closed (body)");
                return;
            }

            up->resp_body_pos += (size_t) n;
            if (up->resp_body_pos < up->resp_dlen) {
                continue;
            }
        }

        /* Full response received; dispatch */
        if (up->state == XRD_UP_BOOTSTRAP) {
            xrootd_upstream_handle_bootstrap_response(up);
            return;
        }

        if (up->state == XRD_UP_REQUEST || up->state == XRD_UP_ASYNC) {
            xrootd_upstream_forward_response(up);
            return;
        }

        xrootd_upstream_abort(up, "upstream: unexpected state in read handler");
        return;
    }
}

/* ------------------------------------------------------------------
 * xrootd_upstream_start
 *
 * Entry point called from request handlers (locate, open, stat) when
 * no local match is found and an upstream is configured.
 *
 * Allocates the upstream context, saves the client request, initiates
 * a non-blocking TCP connect, and transitions the client to
 * XRD_ST_UPSTREAM so the connection state machine pauses.
 *
 * Returns NGX_OK on success (async path started) or NGX_ERROR.
 * ------------------------------------------------------------------ */

ngx_int_t
xrootd_upstream_start(xrootd_ctx_t *ctx, ngx_connection_t *c,
                      ngx_stream_xrootd_srv_conf_t *conf)
{
    xrootd_upstream_t *up;
    ngx_connection_t  *uconn;
    int                fd;
    struct sockaddr_in sin;
    ngx_int_t          rc;
    size_t             bslen;
    u_char            *bsbuf;

    up = ngx_pcalloc(c->pool, sizeof(xrootd_upstream_t));
    if (up == NULL) {
        return NGX_ERROR;
    }

    up->client_ctx  = ctx;
    up->client_conn = c;
    ctx->upstream   = up;

    /* Save request context */
    up->req_opcode      = ctx->cur_reqid;
    up->req_streamid[0] = ctx->cur_streamid[0];
    up->req_streamid[1] = ctx->cur_streamid[1];

    if (ctx->payload == NULL || ctx->cur_dlen == 0) {
        ctx->upstream = NULL;
        return NGX_ERROR;
    }

    if (!xrootd_extract_path(c->log, ctx->payload, ctx->cur_dlen,
                             up->req_path, sizeof(up->req_path), 1)) {
        ctx->upstream = NULL;
        return NGX_ERROR;
    }

    if (ctx->cur_reqid == kXR_locate) {
        ClientLocateRequest *lr = (ClientLocateRequest *)(void *) ctx->hdr_buf;
        up->req_options = ntohs(lr->options);
    } else if (ctx->cur_reqid == kXR_open) {
        ClientOpenRequest *oreq = (ClientOpenRequest *)(void *) ctx->hdr_buf;
        up->req_options   = ntohs(oreq->options);
        up->req_open_mode = ntohs(oreq->mode);
    }

    /* Resolve upstream address */
    ngx_memzero(&sin, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port   = htons(conf->upstream_port);

    {
        in_addr_t addr = inet_addr((char *) conf->upstream_host.data);
        if (addr != INADDR_NONE) {
            sin.sin_addr.s_addr = addr;
        } else {
            struct hostent *he = gethostbyname(
                                     (char *) conf->upstream_host.data);
            if (he == NULL || he->h_addr_list[0] == NULL) {
                ngx_log_error(NGX_LOG_ERR, c->log, 0,
                              "xrootd: upstream: cannot resolve \"%s\"",
                              (char *) conf->upstream_host.data);
                ctx->upstream = NULL;
                return NGX_ERROR;
            }
            ngx_memcpy(&sin.sin_addr, he->h_addr_list[0],
                       sizeof(sin.sin_addr));
        }
    }

    /* Create a non-blocking TCP socket */
    fd = ngx_socket(AF_INET, SOCK_STREAM, 0);
    if (fd == (int) NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ERR, c->log, ngx_socket_errno,
                      "xrootd: upstream socket() failed");
        ctx->upstream = NULL;
        return NGX_ERROR;
    }

    if (ngx_nonblocking(fd) == NGX_ERROR) {
        ngx_close_socket(fd);
        ctx->upstream = NULL;
        return NGX_ERROR;
    }

    uconn = ngx_get_connection(fd, c->log);
    if (uconn == NULL) {
        ngx_close_socket(fd);
        ctx->upstream = NULL;
        return NGX_ERROR;
    }

    uconn->pool = ngx_create_pool(512, c->log);
    if (uconn->pool == NULL) {
        ngx_free_connection(uconn);
        ngx_close_socket(fd);
        ctx->upstream = NULL;
        return NGX_ERROR;
    }

    uconn->data             = up;
    uconn->recv             = ngx_recv;
    uconn->send             = ngx_send;
    uconn->recv_chain       = ngx_recv_chain;
    uconn->send_chain       = ngx_send_chain;
    uconn->log              = c->log;
    uconn->read->handler    = xrootd_upstream_read_handler;
    uconn->write->handler   = xrootd_upstream_write_handler;
    uconn->read->log        = c->log;
    uconn->write->log       = c->log;

    up->conn  = uconn;
    up->state = XRD_UP_CONNECTING;

    /* Pre-build bootstrap bytes (68 bytes) into upstream pool */
    bslen = XRD_HANDSHAKE_LEN
            + sizeof(ClientProtocolRequest)
            + sizeof(ClientLoginRequest);
    bsbuf = ngx_palloc(uconn->pool, bslen);
    if (bsbuf == NULL) {
        xrootd_upstream_cleanup(up);
        return NGX_ERROR;
    }
    xrootd_upstream_build_bootstrap(bsbuf);
    up->wbuf     = bsbuf;
    up->wbuf_len = bslen;
    up->wbuf_pos = 0;

    /* Transition client to UPSTREAM state before connecting */
    ctx->state = XRD_ST_UPSTREAM;

    /* Non-blocking connect */
    rc = connect(fd, (struct sockaddr *)(void *) &sin, sizeof(sin));
    if (rc == -1 && ngx_socket_errno != NGX_EINPROGRESS) {
        ngx_log_error(NGX_LOG_ERR, c->log, ngx_socket_errno,
                      "xrootd: upstream connect to %s:%d failed",
                      (char *) conf->upstream_host.data,
                      (int) conf->upstream_port);
        xrootd_upstream_cleanup(up);
        ctx->state = XRD_ST_REQ_HEADER;
        return NGX_ERROR;
    }

    /* Arm write event (fires on connect completion or immediate writability) */
    if (ngx_handle_write_event(uconn->write, 0) != NGX_OK) {
        xrootd_upstream_cleanup(up);
        ctx->state = XRD_ST_REQ_HEADER;
        return NGX_ERROR;
    }

    if (rc == 0) {
        /* Connected immediately (unusual but possible on loopback) */
        up->state    = XRD_UP_BOOTSTRAP;
        up->bs_phase = XRD_UP_BS_HANDSHAKE;
        up->rhdr_pos = 0;

        ngx_int_t frc = xrootd_upstream_flush(up);
        if (frc == NGX_ERROR) {
            xrootd_upstream_cleanup(up);
            ctx->state = XRD_ST_REQ_HEADER;
            return NGX_ERROR;
        }
    }

    ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: upstream connecting to %s:%d",
                   (char *) conf->upstream_host.data,
                   (int) conf->upstream_port);

    return NGX_OK;
}
