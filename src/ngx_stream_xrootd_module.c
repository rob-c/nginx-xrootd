/*
 * ngx_stream_xrootd_module.c
 *
 * nginx stream module implementing the XRootD root:// protocol.
 * Acts as a read-only data server (kXR_DataServer) at the TCP level.
 *
 * Supports:
 *   handshake / protocol negotiation
 *   anonymous login (no auth)
 *   kXR_protocol   — negotiate capabilities
 *   kXR_login      — accept any username, return 16-byte session id
 *   kXR_ping       — liveness check
 *   kXR_stat       — path-based and handle-based stat
 *   kXR_open       — open files for reading
 *   kXR_read       — read file data (chunked with kXR_oksofar)
 *   kXR_close      — close an open handle
 *   kXR_dirlist    — list a directory (with optional per-entry stat)
 *   kXR_endsess    — graceful session termination
 *
 * nginx.conf example:
 *
 *   stream {
 *       server {
 *           listen 1094;
 *           xrootd on;
 *           xrootd_root /data/store;
 *       }
 *   }
 *
 * Build:
 *   ./configure --with-stream --add-module=/path/to/nginx-xrootd
 *   make && make install
 *
 * Protocol reference: XRootD Protocol Specification v5.2.0,
 *   xrootd/xrootd src/XProtocol/XProtocol.hh (canonical),
 *   dcache/xrootd4j (Java reference impl).
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <dirent.h>
#include <limits.h>
#include <arpa/inet.h>

#include "xrootd_protocol.h"

/* ------------------------------------------------------------------ */
/* Module forward declaration (defined at bottom of file)              */
/* ------------------------------------------------------------------ */

extern ngx_module_t ngx_stream_xrootd_module;

/* ------------------------------------------------------------------ */
/* Tunables                                                             */
/* ------------------------------------------------------------------ */

/*
 * Maximum file data returned per kXR_read response.
 * XRootD clients typically request ≤2 MB chunks; we cap at 4 MB.
 * If rlen > XROOTD_READ_MAX the client will get a short read and MUST
 * retry at offset + bytes_received (standard XRootD client behaviour).
 */
#define XROOTD_READ_MAX      (4 * 1024 * 1024)

/* Maximum simultaneously open files per connection */
#define XROOTD_MAX_FILES     16

/* Maximum path length accepted from a client */
#define XROOTD_MAX_PATH      4096

/* TCP receive buffer (sized to hold the largest expected request) */
#define XROOTD_RECV_BUF      (XROOTD_MAX_PATH + XRD_REQUEST_HDR_LEN + 64)

/* ------------------------------------------------------------------ */
/* Per-connection state machine                                         */
/* ------------------------------------------------------------------ */

typedef enum {
    XRD_ST_HANDSHAKE,   /* accumulating the 20-byte client hello  */
    XRD_ST_REQ_HEADER,  /* accumulating a 24-byte request header  */
    XRD_ST_REQ_PAYLOAD, /* accumulating dlen bytes of payload     */
    XRD_ST_SENDING,     /* draining a large pending write buffer  */
} xrootd_state_t;

/* ------------------------------------------------------------------ */
/* Per-open-file bookkeeping                                            */
/* ------------------------------------------------------------------ */

typedef struct {
    int   fd;                 /* OS file descriptor; -1 = slot unused */
    char  path[PATH_MAX];     /* resolved absolute path (for fhandle stat) */
} xrootd_file_t;

/* ------------------------------------------------------------------ */
/* Per-connection context                                               */
/* ------------------------------------------------------------------ */

typedef struct {
    ngx_stream_session_t  *session;
    xrootd_state_t         state;

    /* Input accumulation for handshake / request header */
    u_char     hdr_buf[24];
    size_t     hdr_pos;       /* bytes accumulated so far */

    /* Parsed fields from the most recent 24-byte request header */
    u_char     cur_streamid[2];
    uint16_t   cur_reqid;     /* host byte order */
    u_char     cur_body[16];  /* request-specific parameter bytes */
    uint32_t   cur_dlen;      /* payload length, host byte order */

    /* Payload buffer */
    u_char    *payload;       /* allocated from pool */
    size_t     payload_pos;   /* bytes accumulated so far */

    /* Session */
    u_char     sessid[XROOTD_SESSION_ID_LEN];
    ngx_flag_t logged_in;

    /* Open file table; index 0..XROOTD_MAX_FILES-1 is the handle number */
    xrootd_file_t  files[XROOTD_MAX_FILES];

    /* Pending write queue (one buffer at a time) */
    u_char    *wbuf;          /* allocated from pool */
    size_t     wbuf_len;
    size_t     wbuf_pos;

} xrootd_ctx_t;

/* ------------------------------------------------------------------ */
/* Module configuration                                                 */
/* ------------------------------------------------------------------ */

typedef struct {
    ngx_flag_t  enable;
    ngx_str_t   root;         /* local filesystem root directory */
} ngx_stream_xrootd_srv_conf_t;

/* ------------------------------------------------------------------ */
/* Forward declarations                                                 */
/* ------------------------------------------------------------------ */

static void *ngx_stream_xrootd_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_xrootd_merge_srv_conf(ngx_conf_t *cf,
    void *parent, void *child);
static char *ngx_stream_xrootd_enable(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);

static void ngx_stream_xrootd_handler(ngx_stream_session_t *s);
static void ngx_stream_xrootd_recv(ngx_event_t *rev);
static void ngx_stream_xrootd_send(ngx_event_t *wev);

static ngx_int_t xrootd_queue_response(xrootd_ctx_t *ctx,
    ngx_connection_t *c, u_char *buf, size_t len);
static ngx_int_t xrootd_flush_pending(xrootd_ctx_t *ctx,
    ngx_connection_t *c);

static ngx_int_t xrootd_process_handshake(xrootd_ctx_t *ctx,
    ngx_connection_t *c);
static ngx_int_t xrootd_dispatch(xrootd_ctx_t *ctx,
    ngx_connection_t *c, ngx_stream_xrootd_srv_conf_t *conf);

static ngx_int_t xrootd_handle_protocol(xrootd_ctx_t *ctx,
    ngx_connection_t *c);
static ngx_int_t xrootd_handle_login(xrootd_ctx_t *ctx,
    ngx_connection_t *c);
static ngx_int_t xrootd_handle_ping(xrootd_ctx_t *ctx,
    ngx_connection_t *c);
static ngx_int_t xrootd_handle_stat(xrootd_ctx_t *ctx,
    ngx_connection_t *c, ngx_stream_xrootd_srv_conf_t *conf);
static ngx_int_t xrootd_handle_open(xrootd_ctx_t *ctx,
    ngx_connection_t *c, ngx_stream_xrootd_srv_conf_t *conf);
static ngx_int_t xrootd_handle_read(xrootd_ctx_t *ctx,
    ngx_connection_t *c);
static ngx_int_t xrootd_handle_close(xrootd_ctx_t *ctx,
    ngx_connection_t *c);
static ngx_int_t xrootd_handle_dirlist(xrootd_ctx_t *ctx,
    ngx_connection_t *c, ngx_stream_xrootd_srv_conf_t *conf);
static ngx_int_t xrootd_handle_endsess(xrootd_ctx_t *ctx,
    ngx_connection_t *c);

static ngx_int_t xrootd_send_ok(xrootd_ctx_t *ctx, ngx_connection_t *c,
    const void *body, uint32_t bodylen);
static ngx_int_t xrootd_send_error(xrootd_ctx_t *ctx,
    ngx_connection_t *c, uint16_t errcode, const char *msg);

static void xrootd_build_resp_hdr(const u_char *streamid, uint16_t status,
    uint32_t dlen, ServerResponseHdr *out);

static int  xrootd_resolve_path(ngx_log_t *log,
    const ngx_str_t *root, const char *reqpath,
    char *resolved, size_t resolvsz);
static int  xrootd_alloc_fhandle(xrootd_ctx_t *ctx);
static void xrootd_free_fhandle(xrootd_ctx_t *ctx, int idx);
static void xrootd_close_all_files(xrootd_ctx_t *ctx);
static void xrootd_make_stat_body(const struct stat *st, ngx_flag_t is_vfs,
    char *out, size_t outsz);

/* ------------------------------------------------------------------ */
/* Module directives                                                    */
/* ------------------------------------------------------------------ */

static ngx_command_t ngx_stream_xrootd_commands[] = {

    { ngx_string("xrootd"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_stream_xrootd_enable,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, enable),
      NULL },

    { ngx_string("xrootd_root"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, root),
      NULL },

    ngx_null_command
};

/* ------------------------------------------------------------------ */
/* Module context                                                       */
/* ------------------------------------------------------------------ */

static ngx_stream_module_t ngx_stream_xrootd_module_ctx = {
    NULL,                                 /* preconfiguration  */
    NULL,                                 /* postconfiguration */
    NULL,                                 /* create main conf  */
    NULL,                                 /* init main conf    */
    ngx_stream_xrootd_create_srv_conf,    /* create srv conf   */
    ngx_stream_xrootd_merge_srv_conf,     /* merge srv conf    */
};

/* ------------------------------------------------------------------ */
/* Module definition                                                    */
/* ------------------------------------------------------------------ */

ngx_module_t ngx_stream_xrootd_module = {
    NGX_MODULE_V1,
    &ngx_stream_xrootd_module_ctx,
    ngx_stream_xrootd_commands,
    NGX_STREAM_MODULE,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NGX_MODULE_V1_PADDING
};

/* ================================================================== */
/*  Configuration management                                            */
/* ================================================================== */

static void *
ngx_stream_xrootd_create_srv_conf(ngx_conf_t *cf)
{
    ngx_stream_xrootd_srv_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_xrootd_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = NGX_CONF_UNSET;

    return conf;
}

static char *
ngx_stream_xrootd_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_stream_xrootd_srv_conf_t *prev = parent;
    ngx_stream_xrootd_srv_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_str_value(conf->root, prev->root, "/");

    return NGX_CONF_OK;
}

/*
 * ngx_stream_xrootd_enable — handler for the "xrootd on|off;" directive.
 * When enabled, installs ourselves as the stream content handler so we
 * take over the TCP connection after the session is established.
 */
static char *
ngx_stream_xrootd_enable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_xrootd_srv_conf_t *xcf = conf;
    ngx_stream_core_srv_conf_t   *cscf;
    char                         *rv;

    rv = ngx_conf_set_flag_slot(cf, cmd, conf);
    if (rv != NGX_CONF_OK) {
        return rv;
    }

    if (!xcf->enable) {
        return NGX_CONF_OK;
    }

    cscf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_core_module);
    cscf->handler = ngx_stream_xrootd_handler;

    return NGX_CONF_OK;
}

/* ================================================================== */
/*  Connection entry point                                              */
/* ================================================================== */

/*
 * ngx_stream_xrootd_handler
 *
 * Called by nginx after the TCP connection is accepted and any pre-
 * content phases (access, etc.) have passed.  From here we own the
 * connection and drive the XRootD state machine.
 */
static void
ngx_stream_xrootd_handler(ngx_stream_session_t *s)
{
    ngx_connection_t  *c = s->connection;
    xrootd_ctx_t      *ctx;
    int                i;

    /* Allocate zeroed per-connection context */
    ctx = ngx_pcalloc(c->pool, sizeof(xrootd_ctx_t));
    if (ctx == NULL) {
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ctx->session = s;
    ctx->state   = XRD_ST_HANDSHAKE;
    ctx->hdr_pos = 0;

    /* Mark all file slots as unused */
    for (i = 0; i < XROOTD_MAX_FILES; i++) {
        ctx->files[i].fd = -1;
    }

    /* Generate a pseudo-random 16-byte session id from time + pid + conn */
    {
        uint32_t parts[4];
        parts[0] = (uint32_t) ngx_time();
        parts[1] = (uint32_t) ngx_pid;
        parts[2] = (uint32_t) (uintptr_t) c;
        parts[3] = (uint32_t) ngx_random();
        ngx_memcpy(ctx->sessid, parts, XROOTD_SESSION_ID_LEN);
    }

    ngx_stream_set_ctx(s, ctx, ngx_stream_xrootd_module);

    /* Install event handlers */
    c->read->handler  = ngx_stream_xrootd_recv;
    c->write->handler = ngx_stream_xrootd_send;

    /* Start reading immediately */
    ngx_stream_xrootd_recv(c->read);
}

/* ================================================================== */
/*  Read event handler                                                  */
/* ================================================================== */

static void
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
        xrootd_close_all_files(ctx);
        ngx_stream_finalize_session(s, NGX_STREAM_OK);
        return;
    }

    /* Read loop: consume as much data as is available this wakeup */
    for (;;) {

        if (ctx->state == XRD_ST_SENDING) {
            /*
             * We have a pending write; don't try to process more input
             * until the write handler drains it and re-enters us.
             */
            return;
        }

        /* ---------------------------------------------------------- */
        /* Determine where to put incoming bytes and how many we need  */
        /* ---------------------------------------------------------- */

        u_char *dest;
        size_t  need, avail;

        if (ctx->state == XRD_ST_HANDSHAKE) {
            /* Expecting 20 bytes (ClientInitHandShake) */
            dest  = ctx->hdr_buf + ctx->hdr_pos;
            need  = XRD_HANDSHAKE_LEN - ctx->hdr_pos;

        } else if (ctx->state == XRD_ST_REQ_HEADER) {
            /* Expecting 24 bytes (ClientRequestHdr) */
            dest  = ctx->hdr_buf + ctx->hdr_pos;
            need  = XRD_REQUEST_HDR_LEN - ctx->hdr_pos;

        } else {
            /* XRD_ST_REQ_PAYLOAD: accumulate dlen bytes */
            dest  = ctx->payload + ctx->payload_pos;
            need  = ctx->cur_dlen - ctx->payload_pos;
        }

        if (need == 0) {
            goto process;
        }

        n = c->recv(c, dest, need);

        if (n == NGX_AGAIN) {
            /* No data right now; wait for the next read event */
            if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                goto fatal;
            }
            return;
        }

        if (n == NGX_ERROR || n == 0) {
            /* Connection closed or error */
            ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                           "xrootd: client disconnected");
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
            /* Got a partial buffer; come back when there's more data */
            continue;
        }

process:
        /* We have a full handshake / header / payload to process */

        if (ctx->state == XRD_ST_HANDSHAKE) {

            rc = xrootd_process_handshake(ctx, c);
            if (rc != NGX_OK) {
                goto fatal;
            }
            /* Transition: start expecting request headers */
            ctx->state   = XRD_ST_REQ_HEADER;
            ctx->hdr_pos = 0;

        } else if (ctx->state == XRD_ST_REQ_HEADER) {

            /* Parse the standard 24-byte request header */
            ClientRequestHdr *hdr = (ClientRequestHdr *) ctx->hdr_buf;

            ctx->cur_streamid[0] = hdr->streamid[0];
            ctx->cur_streamid[1] = hdr->streamid[1];
            ctx->cur_reqid       = ntohs(hdr->requestid);
            ngx_memcpy(ctx->cur_body, hdr->body, 16);
            ctx->cur_dlen        = (uint32_t) ntohl(hdr->dlen);

            if (ctx->cur_dlen > XROOTD_MAX_PATH + 64) {
                ngx_log_error(NGX_LOG_WARN, c->log, 0,
                              "xrootd: payload too large (%uz), closing",
                              (size_t) ctx->cur_dlen);
                goto fatal;
            }

            if (ctx->cur_dlen > 0) {
                /* Allocate a pool buffer and start collecting payload */
                ctx->payload = ngx_palloc(c->pool, ctx->cur_dlen + 1);
                if (ctx->payload == NULL) {
                    goto fatal;
                }
                ctx->payload[ctx->cur_dlen] = '\0'; /* convenient NUL */
                ctx->payload_pos = 0;
                ctx->state       = XRD_ST_REQ_PAYLOAD;
                ctx->hdr_pos     = 0;   /* reset for next header */
                continue;
            }

            /* No payload: dispatch immediately */
            ctx->payload = NULL;
            rc = xrootd_dispatch(ctx, c, conf);
            if (rc == NGX_ERROR) {
                goto fatal;
            }

            /* Reset for next request (dispatch may have set SENDING) */
            if (ctx->state != XRD_ST_SENDING) {
                ctx->state   = XRD_ST_REQ_HEADER;
                ctx->hdr_pos = 0;
            }

        } else {
            /* XRD_ST_REQ_PAYLOAD — payload is complete */
            ctx->state = XRD_ST_REQ_HEADER;   /* reset before dispatch */
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
    xrootd_close_all_files(ctx);
    ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
}

/* ================================================================== */
/*  Write event handler — drains the pending write buffer              */
/* ================================================================== */

static void
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
        xrootd_close_all_files(ctx);
        ngx_stream_finalize_session(s, NGX_STREAM_OK);
        return;
    }

    rc = xrootd_flush_pending(ctx, c);
    if (rc == NGX_ERROR) {
        xrootd_close_all_files(ctx);
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    if (rc == NGX_AGAIN) {
        /* Still more to write; write handler will be called again */
        return;
    }

    /* All data sent — resume reading */
    ctx->state   = XRD_ST_REQ_HEADER;
    ctx->hdr_pos = 0;
    ngx_stream_xrootd_recv(c->read);
}

/* ================================================================== */
/*  Write helpers                                                       */
/* ================================================================== */

/*
 * xrootd_queue_response
 *
 * Try to send `len` bytes from `buf` right now.  If the OS send buffer
 * is full (EAGAIN) stash the remainder and transition to SENDING state
 * so the write handler drains it asynchronously.
 *
 * Returns NGX_OK (all sent or queued), NGX_ERROR on failure.
 */
static ngx_int_t
xrootd_queue_response(xrootd_ctx_t *ctx, ngx_connection_t *c,
                      u_char *buf, size_t len)
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
            /* Store unsent remainder */
            ctx->wbuf     = buf;
            ctx->wbuf_len = len;
            ctx->wbuf_pos = 0;
            ctx->state    = XRD_ST_SENDING;

            if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
                return NGX_ERROR;
            }
            return NGX_OK;
        }
        return NGX_ERROR;
    }
    return NGX_OK;
}

/*
 * xrootd_flush_pending — called from the write handler to drain wbuf.
 */
static ngx_int_t
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

    ctx->wbuf     = NULL;
    ctx->wbuf_len = 0;
    ctx->wbuf_pos = 0;
    return NGX_OK;
}

/* ================================================================== */
/*  Handshake                                                           */
/* ================================================================== */

/*
 * xrootd_process_handshake
 *
 * Validates the 20-byte client handshake and sends the server reply.
 *
 * In XRootD v5 the client sends handshake + kXR_protocol together in a
 * single 44-byte TCP segment.  The client then reads EACH server reply as a
 * standard 8-byte ServerResponseHdr + body:
 *
 *   1. Handshake response  (16 bytes): header(8) + {protover,msgval}(8)
 *   2. kXR_protocol response (8+N bytes): header(8) + body(N)
 *
 * The old 12-byte ServerInitHandShake framing (msglen+protover+msgval) is
 * NOT compatible with this because its first 8 bytes parse as
 * status=0x0008 / dlen=0x00000520=1312, causing the client to stall.
 *
 * We therefore send a proper ServerResponseHdr (streamid={0,0}, status=ok,
 * dlen=8) followed by 8 bytes of protover+msgval.  The kXR_protocol handler
 * sends its own response immediately after.
 */
static ngx_int_t
xrootd_process_handshake(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    ClientInitHandShake  *hs;
    ServerResponseHdr    *hdr;
    u_char               *buf;
    size_t                total;

    /* protover(4) + msgval(4) */
    static const size_t BODY_LEN = 8;

    hs = (ClientInitHandShake *) ctx->hdr_buf;

    /* Validate the magic fields */
    if (ntohl(hs->fourth) != 4 || ntohl(hs->fifth) != ROOTD_PQ) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "xrootd: invalid handshake magic "
                      "(fourth=%u fifth=%u)",
                      ntohl(hs->fourth), ntohl(hs->fifth));
        return NGX_ERROR;
    }

    total = XRD_RESPONSE_HDR_LEN + BODY_LEN;
    buf   = ngx_palloc(c->pool, total);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    /* Standard response header: streamid={0,0} (no client streamid in
     * the handshake), status=kXR_ok, dlen=8. */
    hdr             = (ServerResponseHdr *) buf;
    hdr->streamid[0] = 0;
    hdr->streamid[1] = 0;
    hdr->status      = htons(kXR_ok);
    hdr->dlen        = htonl((kXR_unt32) BODY_LEN);

    /* Body: protocol version + server type */
    u_char *body = buf + XRD_RESPONSE_HDR_LEN;
    *(kXR_unt32 *)(body + 0) = htonl(kXR_PROTOCOLVERSION);
    *(kXR_unt32 *)(body + 4) = htonl(kXR_DataServer);

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: handshake ok, sending standard-format response");

    return xrootd_queue_response(ctx, c, buf, total);
}

/* ================================================================== */
/*  Request dispatcher                                                  */
/* ================================================================== */

static ngx_int_t
xrootd_dispatch(xrootd_ctx_t *ctx, ngx_connection_t *c,
                ngx_stream_xrootd_srv_conf_t *conf)
{
    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: dispatch reqid=%d", (int) ctx->cur_reqid);

    switch (ctx->cur_reqid) {

    case kXR_protocol:
        return xrootd_handle_protocol(ctx, c);

    case kXR_login:
        return xrootd_handle_login(ctx, c);

    case kXR_ping:
        return xrootd_handle_ping(ctx, c);

    case kXR_endsess:
        return xrootd_handle_endsess(ctx, c);

    /*
     * The following requests require a successful login first.
     * Sending kXR_NotAuthorized is the correct response per spec.
     */
    case kXR_stat:
        if (!ctx->logged_in) {
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "login required");
        }
        return xrootd_handle_stat(ctx, c, conf);

    case kXR_open:
        if (!ctx->logged_in) {
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "login required");
        }
        return xrootd_handle_open(ctx, c, conf);

    case kXR_read:
        if (!ctx->logged_in) {
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "login required");
        }
        return xrootd_handle_read(ctx, c);

    case kXR_close:
        if (!ctx->logged_in) {
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "login required");
        }
        return xrootd_handle_close(ctx, c);

    case kXR_dirlist:
        if (!ctx->logged_in) {
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "login required");
        }
        return xrootd_handle_dirlist(ctx, c, conf);

    /*
     * Write operations are not supported on a read-only data server.
     */
    case kXR_write:
    case kXR_writev:
    case kXR_pgwrite:
    case kXR_mkdir:
    case kXR_rm:
    case kXR_rmdir:
    case kXR_mv:
    case kXR_chmod:
    case kXR_truncate:
        return xrootd_send_error(ctx, c, kXR_fsReadOnly,
                                 "this is a read-only server");

    default:
        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                       "xrootd: unsupported request %d",
                       (int) ctx->cur_reqid);
        return xrootd_send_error(ctx, c, kXR_Unsupported,
                                 "request not supported");
    }
}

/* ================================================================== */
/*  Request handlers                                                    */
/* ================================================================== */

/*
 * kXR_protocol — negotiate protocol capabilities.
 *
 * Client flags byte (cur_body[4]):
 *   kXR_secreqs  0x01 — client wants the server's security requirements
 *   kXR_ableTLS  0x02 — client supports TLS
 *   kXR_bifreqs  0x08 — client wants back-information frames
 *
 * When kXR_secreqs is set we must append a 4-byte SecurityInfo structure
 * immediately after pval+flags.  Sending it with secopt=0 and nProt=0
 * signals "no authentication required" so the client proceeds straight
 * to kXR_login.  Omitting it causes v5 clients to stall waiting for data
 * that never arrives.
 *
 * SecurityInfo layout (4 bytes, big-endian):
 *   secver  [1]  version, always 0
 *   secopt  [1]  options: 0x01=kXR_secOFrce (force auth), 0=no auth forced
 *   nProt   [1]  number of protocol entries that follow (0 = none)
 *   rsvd    [1]  reserved, 0
 */
static ngx_int_t
xrootd_handle_protocol(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    ServerProtocolBody  body;
    u_char             *buf;
    size_t              bodylen, total;
    u_char              client_flags;

    /* flags byte is at offset 4 of the 16-byte body section */
    client_flags = ctx->cur_body[4];

    /* Body = pval(4) + flags(4) + optional SecurityInfo(4) */
    bodylen = sizeof(body);
    if (client_flags & 0x01) {   /* kXR_secreqs */
        bodylen += 4;            /* SecurityInfo */
    }

    total = XRD_RESPONSE_HDR_LEN + bodylen;
    buf   = ngx_palloc(c->pool, total);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    xrootd_build_resp_hdr(ctx->cur_streamid, kXR_ok,
                           (uint32_t) bodylen,
                           (ServerResponseHdr *) buf);

    body.pval  = htonl(kXR_PROTOCOLVERSION);
    body.flags = htonl(kXR_isServer);   /* read-only data server */
    ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN, &body, sizeof(body));

    if (client_flags & 0x01) {   /* kXR_secreqs: append SecurityInfo */
        u_char *si = buf + XRD_RESPONSE_HDR_LEN + sizeof(body);
        si[0] = 0;   /* secver = 0 */
        si[1] = 0;   /* secopt = 0: auth not forced */
        si[2] = 0;   /* nProt  = 0: no protocols listed */
        si[3] = 0;   /* rsvd   = 0 */
    }

    ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: kXR_protocol ok (client_flags=0x%02x bodylen=%uz)",
                   (int) client_flags, bodylen);

    return xrootd_queue_response(ctx, c, buf, total);
}

/* kXR_login — accept any username; no authentication required */
static ngx_int_t
xrootd_handle_login(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    ClientLoginRequest *req;
    u_char             *buf;
    size_t              total;
    char                user[9];

    req = (ClientLoginRequest *) ctx->hdr_buf;
    ngx_memcpy(user, req->username, 8);
    user[8] = '\0';

    ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: login user=\"%s\" pid=%d",
                   user, (int) ntohl(req->pid));

    /* Mark session as authenticated */
    ctx->logged_in = 1;

    /* Response: 8-byte header + 16-byte sessid; no auth handshake */
    total = XRD_RESPONSE_HDR_LEN + XROOTD_SESSION_ID_LEN;
    buf   = ngx_palloc(c->pool, total);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    xrootd_build_resp_hdr(ctx->cur_streamid, kXR_ok,
                           XROOTD_SESSION_ID_LEN,
                           (ServerResponseHdr *) buf);

    ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN, ctx->sessid,
               XROOTD_SESSION_ID_LEN);

    return xrootd_queue_response(ctx, c, buf, total);
}

/* kXR_ping — liveness check */
static ngx_int_t
xrootd_handle_ping(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    return xrootd_send_ok(ctx, c, NULL, 0);
}

/* kXR_endsess — client wants to end the session gracefully */
static ngx_int_t
xrootd_handle_endsess(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: kXR_endsess received");
    xrootd_close_all_files(ctx);
    /* Acknowledge, then the client will close the TCP connection */
    return xrootd_send_ok(ctx, c, NULL, 0);
}

/* kXR_stat — stat by path or by open file handle */
static ngx_int_t
xrootd_handle_stat(xrootd_ctx_t *ctx, ngx_connection_t *c,
                   ngx_stream_xrootd_srv_conf_t *conf)
{
    ClientStatRequest *req = (ClientStatRequest *) ctx->hdr_buf;
    struct stat        st;
    char               resolved[PATH_MAX];
    char               body[256];
    ngx_flag_t         is_vfs;
    const char        *reqpath;

    is_vfs = (req->options & kXR_vfs) ? 1 : 0;

    if (ctx->cur_dlen > 0 && ctx->payload != NULL) {
        /* Path-based stat */
        reqpath = (const char *) ctx->payload;

        if (!xrootd_resolve_path(c->log, &conf->root,
                                 reqpath, resolved, sizeof(resolved))) {
            return xrootd_send_error(ctx, c, kXR_NotFound,
                                     "file not found");
        }

        if (stat(resolved, &st) != 0) {
            return xrootd_send_error(ctx, c, kXR_NotFound,
                                     "file not found");
        }
    } else {
        /* Handle-based stat: fhandle[0] is our slot index */
        int idx = (int)(unsigned char) req->fhandle[0];

        if (idx < 0 || idx >= XROOTD_MAX_FILES
                || ctx->files[idx].fd < 0) {
            return xrootd_send_error(ctx, c, kXR_FileNotOpen,
                                     "invalid file handle");
        }

        if (fstat(ctx->files[idx].fd, &st) != 0) {
            return xrootd_send_error(ctx, c, kXR_IOError, strerror(errno));
        }
    }

    xrootd_make_stat_body(&st, is_vfs, body, sizeof(body));

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: kXR_stat ok: %s", body);

    return xrootd_send_ok(ctx, c, body, (uint32_t)(strlen(body) + 1));
}

/* kXR_open — open a file for reading */
static ngx_int_t
xrootd_handle_open(xrootd_ctx_t *ctx, ngx_connection_t *c,
                   ngx_stream_xrootd_srv_conf_t *conf)
{
    ClientOpenRequest *req = (ClientOpenRequest *) ctx->hdr_buf;
    uint16_t           options;
    char               resolved[PATH_MAX];
    int                idx, fd;
    ServerOpenBody     body;
    struct stat        st;
    char               statbuf[256];
    u_char            *buf;
    size_t             bodylen, total;
    ngx_flag_t         want_stat;

    options   = ntohs(req->options);
    want_stat = (options & kXR_retstat) ? 1 : 0;

    /* Reject write-mode opens — we are a read-only server */
    if (options & (kXR_delete | kXR_new | kXR_open_updt |
                   kXR_open_wrto | kXR_open_apnd)) {
        return xrootd_send_error(ctx, c, kXR_fsReadOnly,
                                 "this is a read-only server");
    }

    if (ctx->payload == NULL || ctx->cur_dlen == 0) {
        return xrootd_send_error(ctx, c, kXR_ArgMissing, "no path given");
    }

    if (!xrootd_resolve_path(c->log, &conf->root,
                             (const char *) ctx->payload,
                             resolved, sizeof(resolved))) {
        return xrootd_send_error(ctx, c, kXR_NotFound, "file not found");
    }

    /* Allocate a file handle slot */
    idx = xrootd_alloc_fhandle(ctx);
    if (idx < 0) {
        return xrootd_send_error(ctx, c, kXR_ServerError,
                                 "too many open files");
    }

    fd = open(resolved, O_RDONLY | O_NOCTTY);
    if (fd < 0) {
        int err = errno;
        if (err == ENOENT || err == ENOTDIR) {
            return xrootd_send_error(ctx, c, kXR_NotFound,
                                     "file not found");
        }
        if (err == EACCES) {
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "permission denied");
        }
        return xrootd_send_error(ctx, c, kXR_IOError, strerror(err));
    }

    ctx->files[idx].fd = fd;
    ngx_cpystrn((u_char *) ctx->files[idx].path,
                (u_char *) resolved,
                sizeof(ctx->files[idx].path));

    /* If kXR_retstat, fstat now so we can include it in the response.
     *
     * The stat string in a kXR_open response uses 3 fields (no inode id):
     *   "<flags> <size> <mtime>\0"
     * This differs from the standalone kXR_stat response which has 4 fields:
     *   "<id> <flags> <size> <mtime>\0"
     */
    statbuf[0] = '\0';
    if (want_stat) {
        if (fstat(fd, &st) == 0) {
            /*
             * kXR_open retstat format is "<id> <size> <flags> <mtime>\0".
             * NOTE: field order is (id, size, flags, mtime) — size before
             * flags — which is the opposite of the standalone kXR_stat
             * response format (id, flags, size, mtime).  The XRootD v5
             * client's StatInfo parser for open responses reads field[1]
             * as size and field[2] as flags.
             */
            int stat_flags = 0;
            if (st.st_mode & (S_IRUSR | S_IRGRP | S_IROTH)) {
                stat_flags |= kXR_readable;
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

    ngx_log_debug3(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: kXR_open handle=%d path=%s retstat=%d",
                   idx, resolved, (int) want_stat);

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

    return xrootd_queue_response(ctx, c, buf, total);
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
static ngx_int_t
xrootd_handle_read(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    ClientReadRequest *req = (ClientReadRequest *) ctx->hdr_buf;
    int                idx;
    int64_t            offset;
    size_t             rlen;
    off_t              seekpos;
    u_char            *databuf, *rspbuf;
    ssize_t            nread;
    size_t             data_total;     /* actual bytes read */
    size_t             n_chunks, last_size;
    size_t             rsp_total;      /* total response bytes */
    size_t             di, ri;         /* data / response cursor */

    idx    = (int)(unsigned char) req->fhandle[0];
    offset = (int64_t) be64toh((uint64_t) req->offset);
    rlen   = (size_t)(uint32_t) ntohl((uint32_t) req->rlen);

    if (idx < 0 || idx >= XROOTD_MAX_FILES || ctx->files[idx].fd < 0) {
        return xrootd_send_error(ctx, c, kXR_FileNotOpen,
                                 "invalid file handle");
    }

    if (rlen == 0) {
        return xrootd_send_ok(ctx, c, NULL, 0);
    }

    /* Cap to something large but bounded; nginx pool handles the alloc */
    if (rlen > XROOTD_READ_MAX * 16) {
        rlen = XROOTD_READ_MAX * 16;   /* 64 MB hard cap */
    }

    /* Seek to the requested offset */
    seekpos = lseek(ctx->files[idx].fd, (off_t) offset, SEEK_SET);
    if (seekpos == (off_t) -1) {
        return xrootd_send_error(ctx, c, kXR_IOError, strerror(errno));
    }

    /* Read all available data up to rlen in a single OS call.
     * A short read (nread < rlen) means we hit EOF. */
    databuf = ngx_palloc(c->pool, rlen);
    if (databuf == NULL) {
        return NGX_ERROR;
    }

    nread = read(ctx->files[idx].fd, databuf, rlen);
    if (nread < 0) {
        return xrootd_send_error(ctx, c, kXR_IOError, strerror(errno));
    }

    data_total = (size_t) nread;

    ngx_log_debug4(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: kXR_read handle=%d offset=%L req=%uz got=%uz",
                   idx, offset, rlen, data_total);

    /* Calculate chunking.
     * If data_total fits in one chunk (or it's a short read = EOF), send
     * a single kXR_ok response.  Otherwise send N-1 kXR_oksofar chunks
     * followed by one kXR_ok chunk. */
    n_chunks  = (data_total + XROOTD_READ_MAX - 1) / XROOTD_READ_MAX;
    if (n_chunks == 0) {
        n_chunks = 1;   /* zero-byte response still needs one header */
    }
    last_size = data_total % XROOTD_READ_MAX;
    if (last_size == 0 && data_total > 0) {
        last_size = XROOTD_READ_MAX;   /* exactly divisible */
    }

    /* Allocate single response buffer:
     *   n_chunks response headers  +  data_total bytes of payload */
    rsp_total = n_chunks * XRD_RESPONSE_HDR_LEN + data_total;
    rspbuf = ngx_palloc(c->pool, rsp_total);
    if (rspbuf == NULL) {
        return NGX_ERROR;
    }

    ri = 0;
    di = 0;
    for (size_t chunk = 0; chunk < n_chunks; chunk++) {
        size_t   chunk_data = (chunk < n_chunks - 1)
                              ? XROOTD_READ_MAX : last_size;
        uint16_t status     = (chunk == n_chunks - 1) ? kXR_ok : kXR_oksofar;

        xrootd_build_resp_hdr(ctx->cur_streamid, status,
                               (uint32_t) chunk_data,
                               (ServerResponseHdr *)(rspbuf + ri));
        ri += XRD_RESPONSE_HDR_LEN;

        ngx_memcpy(rspbuf + ri, databuf + di, chunk_data);
        ri += chunk_data;
        di += chunk_data;
    }

    return xrootd_queue_response(ctx, c, rspbuf, rsp_total);
}

/* kXR_close — close an open file handle */
static ngx_int_t
xrootd_handle_close(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    ClientCloseRequest *req = (ClientCloseRequest *) ctx->hdr_buf;
    int idx = (int)(unsigned char) req->fhandle[0];

    if (idx < 0 || idx >= XROOTD_MAX_FILES || ctx->files[idx].fd < 0) {
        return xrootd_send_error(ctx, c, kXR_FileNotOpen,
                                 "invalid file handle");
    }

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: kXR_close handle=%d", idx);

    xrootd_free_fhandle(ctx, idx);

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
 * line per entry with "id flags size mtime".
 */
static ngx_int_t
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
        return xrootd_send_error(ctx, c, kXR_ArgMissing, "no path given");
    }

    if (!xrootd_resolve_path(c->log, &conf->root,
                             (const char *) ctx->payload,
                             resolved, sizeof(resolved))) {
        return xrootd_send_error(ctx, c, kXR_NotFound, "directory not found");
    }

    dp = opendir(resolved);
    if (dp == NULL) {
        int err = errno;
        if (err == ENOTDIR) {
            return xrootd_send_error(ctx, c, kXR_NotFile,
                                     "path is not a directory");
        }
        if (err == ENOENT) {
            return xrootd_send_error(ctx, c, kXR_NotFound,
                                     "directory not found");
        }
        return xrootd_send_error(ctx, c, kXR_IOError, strerror(err));
    }

    chunk = ngx_palloc(c->pool, XRD_RESPONSE_HDR_LEN + chunk_cap);
    if (chunk == NULL) {
        closedir(dp);
        return NGX_ERROR;
    }

    /* We write entries starting after the response header (filled last) */
    u_char *data = chunk + XRD_RESPONSE_HDR_LEN;

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
            /* Flush current chunk as kXR_oksofar */
            data[chunk_pos] = '\0';

            xrootd_build_resp_hdr(ctx->cur_streamid, kXR_oksofar,
                                   (uint32_t)(chunk_pos + 1),
                                   (ServerResponseHdr *) chunk);

            rc = xrootd_queue_response(ctx, c, chunk,
                                       XRD_RESPONSE_HDR_LEN + chunk_pos + 1);
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

    /* Send the final chunk as kXR_ok */
    data[chunk_pos] = '\0';

    xrootd_build_resp_hdr(ctx->cur_streamid, kXR_ok,
                           (uint32_t)(chunk_pos + 1),
                           (ServerResponseHdr *) chunk);

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: kXR_dirlist final chunk %uz bytes", chunk_pos);

    return xrootd_queue_response(ctx, c, chunk,
                                 XRD_RESPONSE_HDR_LEN + chunk_pos + 1);
}

/* ================================================================== */
/*  Response builders                                                   */
/* ================================================================== */

/*
 * xrootd_build_resp_hdr — fill in an 8-byte ServerResponseHdr.
 */
static void
xrootd_build_resp_hdr(const u_char *streamid, uint16_t status,
                      uint32_t dlen, ServerResponseHdr *out)
{
    out->streamid[0] = streamid[0];
    out->streamid[1] = streamid[1];
    out->status      = htons(status);
    out->dlen        = htonl(dlen);
}

/*
 * xrootd_send_ok — build and queue a kXR_ok response.
 * body may be NULL (dlen == 0) for requests with no response payload.
 */
static ngx_int_t
xrootd_send_ok(xrootd_ctx_t *ctx, ngx_connection_t *c,
               const void *body, uint32_t bodylen)
{
    size_t    total = XRD_RESPONSE_HDR_LEN + bodylen;
    u_char   *buf   = ngx_palloc(c->pool, total);

    if (buf == NULL) {
        return NGX_ERROR;
    }

    xrootd_build_resp_hdr(ctx->cur_streamid, kXR_ok, bodylen,
                           (ServerResponseHdr *) buf);

    if (bodylen > 0 && body != NULL) {
        ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN, body, bodylen);
    }

    return xrootd_queue_response(ctx, c, buf, total);
}

/*
 * xrootd_send_error — build and queue a kXR_error response.
 *
 * Wire layout: 8-byte header | errnum(4) | errmsg(N+1)
 */
static ngx_int_t
xrootd_send_error(xrootd_ctx_t *ctx, ngx_connection_t *c,
                  uint16_t errcode, const char *msg)
{
    size_t   msglen, bodylen, total;
    u_char  *buf;

    msglen  = strlen(msg) + 1;          /* include NUL */
    bodylen = sizeof(kXR_int32) + msglen;
    total   = XRD_RESPONSE_HDR_LEN + bodylen;

    buf = ngx_palloc(c->pool, total);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    xrootd_build_resp_hdr(ctx->cur_streamid, kXR_error, (uint32_t) bodylen,
                           (ServerResponseHdr *) buf);

    /* errnum in network byte order */
    uint32_t ecode = htonl(errcode);
    ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN, &ecode, sizeof(ecode));
    ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN + sizeof(ecode), msg, msglen);

    ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: sending error %d: %s", (int) errcode, msg);

    return xrootd_queue_response(ctx, c, buf, total);
}

/* ================================================================== */
/*  Helpers                                                             */
/* ================================================================== */

/*
 * xrootd_resolve_path
 *
 * Combine `root` and `reqpath` into a canonical absolute path,
 * then verify the result is still inside `root` (path traversal guard).
 *
 * Returns 1 on success (resolved[] filled), 0 on failure (not found,
 * traversal attempt, or overflow).
 */
static int
xrootd_resolve_path(ngx_log_t *log, const ngx_str_t *root,
                    const char *reqpath, char *resolved, size_t resolvsz)
{
    char combined[PATH_MAX * 2];
    char canonical[PATH_MAX];
    int  n;

    /* Strip leading slashes from reqpath to avoid // in combined */
    while (*reqpath == '/') {
        reqpath++;
    }

    n = snprintf(combined, sizeof(combined), "%.*s/%s",
                 (int) root->len, (char *) root->data, reqpath);

    if (n < 0 || (size_t) n >= sizeof(combined)) {
        ngx_log_error(NGX_LOG_WARN, log, 0, "xrootd: path too long");
        return 0;
    }

    if (realpath(combined, canonical) == NULL) {
        /* File does not exist (or is a dangling symlink) */
        return 0;
    }

    /* Ensure the resolved path starts with root (+ '/' or end-of-string) */
    if (strncmp(canonical, (char *) root->data, root->len) != 0) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd: path traversal attempt: %s", canonical);
        return 0;
    }

    if (canonical[root->len] != '\0' && canonical[root->len] != '/') {
        /* The root matched a prefix but not a directory boundary */
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd: path traversal attempt: %s", canonical);
        return 0;
    }

    n = snprintf(resolved, resolvsz, "%s", canonical);
    if (n < 0 || (size_t) n >= resolvsz) {
        return 0;
    }

    return 1;
}

/*
 * xrootd_alloc_fhandle — find a free slot in the open file table.
 * Returns slot index (0..XROOTD_MAX_FILES-1) or -1 if none available.
 */
static int
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

/* xrootd_free_fhandle — close and release a file handle slot */
static void
xrootd_free_fhandle(xrootd_ctx_t *ctx, int idx)
{
    if (idx >= 0 && idx < XROOTD_MAX_FILES && ctx->files[idx].fd >= 0) {
        close(ctx->files[idx].fd);
        ctx->files[idx].fd      = -1;
        ctx->files[idx].path[0] = '\0';
    }
}

/* xrootd_close_all_files — called on connection teardown */
static void
xrootd_close_all_files(xrootd_ctx_t *ctx)
{
    int i;
    for (i = 0; i < XROOTD_MAX_FILES; i++) {
        xrootd_free_fhandle(ctx, i);
    }
}

/*
 * xrootd_make_stat_body — format a kXR_stat response body as ASCII.
 *
 * Format: "<id> <flags> <size> <modtime>\0"
 * where:
 *   id      = inode number (unique enough for our purposes)
 *   flags   = XStatRespFlags bitmask
 *   size    = file size in bytes
 *   modtime = Unix timestamp of last modification
 */
static void
xrootd_make_stat_body(const struct stat *st, ngx_flag_t is_vfs,
                      char *out, size_t outsz)
{
    int flags = 0;

    if (is_vfs) {
        /* VFS stat: just report readable with large size */
        snprintf(out, outsz, "0 %d %lld %ld",
                 kXR_readable,
                 (long long) st->st_blocks * 512,   /* "free" space */
                 (long) st->st_mtime);
        return;
    }

    if (S_ISDIR(st->st_mode)) {
        flags |= kXR_isDir;
    } else if (!S_ISREG(st->st_mode)) {
        flags |= kXR_other;
    }

    if (st->st_mode & (S_IRUSR | S_IRGRP | S_IROTH)) {
        flags |= kXR_readable;
    }

    /* We are a read-only server; never advertise writable */

    snprintf(out, outsz, "%llu %d %lld %ld",
             (unsigned long long) st->st_ino,
             flags,
             (long long) st->st_size,
             (long) st->st_mtime);
}
