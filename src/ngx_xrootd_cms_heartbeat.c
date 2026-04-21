#include "ngx_xrootd_cms_heartbeat.h"

#include <ngx_event_connect.h>
#include <unistd.h>


#define NGX_XROOTD_CMS_INITIAL_DELAY   1000
#define NGX_XROOTD_CMS_BACKOFF_INITIAL 6000
#define NGX_XROOTD_CMS_BACKOFF_MAX     60000
#define NGX_XROOTD_CMS_CONNECT_TIMEOUT 5000
#define NGX_XROOTD_CMS_HDR_LEN         8
#define NGX_XROOTD_CMS_MAX_FRAME       4096
#define NGX_XROOTD_CMS_MIN_FREE_MB     100

#define CMS_RR_LOGIN   0
#define CMS_RR_AVAIL   12
#define CMS_RR_LOAD    16
#define CMS_RR_PING    17
#define CMS_RR_PONG    18
#define CMS_RR_SPACE   19
#define CMS_RR_STATUS  22

#define CMS_PT_SHORT   0x80
#define CMS_PT_INT     0xa0

#define CMS_LOGIN_VERSION 3
#define CMS_LOGIN_MODE    0x00000008


struct ngx_xrootd_cms_ctx_s {
    ngx_cycle_t                    *cycle;
    ngx_stream_xrootd_srv_conf_t   *conf;
    ngx_peer_connection_t           peer;
    ngx_connection_t               *connection;
    ngx_event_t                     timer;
    ngx_msec_t                      backoff;
    ngx_uint_t                      logged_in;
    u_char                          inbuf[NGX_XROOTD_CMS_MAX_FRAME];
    size_t                          in_pos;
    size_t                          in_need;
};


static void ngx_xrootd_cms_timer(ngx_event_t *ev);
static void ngx_xrootd_cms_write_handler(ngx_event_t *ev);
static void ngx_xrootd_cms_read_handler(ngx_event_t *ev);
static void ngx_xrootd_cms_connect(ngx_xrootd_cms_ctx_t *ctx);
static void ngx_xrootd_cms_disconnect(ngx_xrootd_cms_ctx_t *ctx);
static void ngx_xrootd_cms_schedule(ngx_xrootd_cms_ctx_t *ctx,
    ngx_msec_t delay);
static void ngx_xrootd_cms_schedule_retry(ngx_xrootd_cms_ctx_t *ctx);
static ngx_int_t ngx_xrootd_cms_process_frame(ngx_xrootd_cms_ctx_t *ctx);
static ngx_int_t ngx_xrootd_cms_send_login(ngx_xrootd_cms_ctx_t *ctx);
static ngx_int_t ngx_xrootd_cms_send_load(ngx_xrootd_cms_ctx_t *ctx);
static ngx_int_t ngx_xrootd_cms_send_avail(ngx_xrootd_cms_ctx_t *ctx,
    uint32_t streamid);
static ngx_int_t ngx_xrootd_cms_send_pong(ngx_xrootd_cms_ctx_t *ctx,
    uint32_t streamid);


static uint16_t
ngx_xrootd_cms_get16(const u_char *p)
{
    return (uint16_t) (((uint16_t) p[0] << 8) | p[1]);
}


static uint32_t
ngx_xrootd_cms_get32(const u_char *p)
{
    return ((uint32_t) p[0] << 24)
         | ((uint32_t) p[1] << 16)
         | ((uint32_t) p[2] << 8)
         | (uint32_t) p[3];
}


static void
ngx_xrootd_cms_put16(u_char *p, uint16_t value)
{
    p[0] = (u_char) (value >> 8);
    p[1] = (u_char) value;
}


static void
ngx_xrootd_cms_put32(u_char *p, uint32_t value)
{
    p[0] = (u_char) (value >> 24);
    p[1] = (u_char) (value >> 16);
    p[2] = (u_char) (value >> 8);
    p[3] = (u_char) value;
}


static u_char *
ngx_xrootd_cms_put_short(u_char *p, uint16_t value)
{
    *p++ = CMS_PT_SHORT;
    ngx_xrootd_cms_put16(p, value);
    return p + 2;
}


static u_char *
ngx_xrootd_cms_put_int(u_char *p, uint32_t value)
{
    *p++ = CMS_PT_INT;
    ngx_xrootd_cms_put32(p, value);
    return p + 4;
}


static ngx_str_t
ngx_xrootd_cms_export_paths(ngx_stream_xrootd_srv_conf_t *conf)
{
    if (conf->cms_paths.len > 0) {
        return conf->cms_paths;
    }

    return conf->root;
}


static ngx_int_t
ngx_xrootd_cms_stat_space(ngx_stream_xrootd_srv_conf_t *conf,
    uint32_t *total_gb, uint32_t *free_mb, uint32_t *util_pct)
{
    struct statvfs  st;
    uint64_t        total;
    uint64_t        free_bytes;
    uint64_t        used_blocks;

    if (statvfs((char *) conf->root.data, &st) != 0 || st.f_blocks == 0) {
        return NGX_ERROR;
    }

    total = (uint64_t) st.f_blocks * st.f_frsize;
    free_bytes = (uint64_t) st.f_bavail * st.f_frsize;
    used_blocks = st.f_blocks - st.f_bfree;

    if (total_gb != NULL) {
        *total_gb = (uint32_t) (total / (1024ULL * 1024ULL * 1024ULL));
    }

    if (free_mb != NULL) {
        *free_mb = (uint32_t) (free_bytes / (1024ULL * 1024ULL));
    }

    if (util_pct != NULL) {
        *util_pct = (uint32_t) ((used_blocks * 100) / st.f_blocks);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_xrootd_cms_send_all(ngx_xrootd_cms_ctx_t *ctx, const u_char *buf,
    size_t len)
{
    ngx_connection_t  *c;
    ssize_t            n;
    size_t             sent;

    c = ctx->connection;
    sent = 0;

    while (sent < len) {
        n = c->send(c, (u_char *) buf + sent, len - sent);

        if (n == NGX_AGAIN || n == 0) {
            return NGX_AGAIN;
        }

        if (n == NGX_ERROR) {
            return NGX_ERROR;
        }

        sent += (size_t) n;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_xrootd_cms_send_frame(ngx_xrootd_cms_ctx_t *ctx, uint32_t streamid,
    u_char code, u_char modifier, const u_char *payload, size_t payload_len)
{
    u_char  hdr[NGX_XROOTD_CMS_HDR_LEN];

    if (ctx->connection == NULL || payload_len > 65535) {
        return NGX_ERROR;
    }

    ngx_xrootd_cms_put32(hdr, streamid);
    hdr[4] = code;
    hdr[5] = modifier;
    ngx_xrootd_cms_put16(hdr + 6, (uint16_t) payload_len);

    if (ngx_xrootd_cms_send_all(ctx, hdr, sizeof(hdr)) != NGX_OK) {
        return NGX_ERROR;
    }

    if (payload_len > 0
        && ngx_xrootd_cms_send_all(ctx, payload, payload_len) != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_OK;
}


void
ngx_xrootd_cms_start(ngx_cycle_t *cycle, ngx_stream_xrootd_srv_conf_t *conf)
{
    ngx_xrootd_cms_ctx_t  *ctx;

    if (conf->cms_addr == NULL || conf->cms_ctx != NULL) {
        return;
    }

    ctx = ngx_pcalloc(cycle->pool, sizeof(ngx_xrootd_cms_ctx_t));
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                      "xrootd: CMS heartbeat allocation failed");
        return;
    }

    ctx->cycle = cycle;
    ctx->conf = conf;
    ctx->backoff = NGX_XROOTD_CMS_BACKOFF_INITIAL;
    ctx->in_need = NGX_XROOTD_CMS_HDR_LEN;

    ctx->timer.handler = ngx_xrootd_cms_timer;
    ctx->timer.data = ctx;
    ctx->timer.log = cycle->log;

    conf->cms_ctx = ctx;

    ngx_xrootd_cms_schedule(ctx, NGX_XROOTD_CMS_INITIAL_DELAY);

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                  "xrootd: CMS heartbeat starting for manager %V",
                  &conf->cms_manager);
}


static void
ngx_xrootd_cms_schedule(ngx_xrootd_cms_ctx_t *ctx, ngx_msec_t delay)
{
    if (ctx->timer.timer_set) {
        ngx_del_timer(&ctx->timer);
    }

    ngx_add_timer(&ctx->timer, delay);
}


static void
ngx_xrootd_cms_schedule_retry(ngx_xrootd_cms_ctx_t *ctx)
{
    ngx_msec_t  delay;

    delay = ctx->backoff;
    if (ctx->backoff < NGX_XROOTD_CMS_BACKOFF_MAX) {
        ctx->backoff *= 2;
        if (ctx->backoff > NGX_XROOTD_CMS_BACKOFF_MAX) {
            ctx->backoff = NGX_XROOTD_CMS_BACKOFF_MAX;
        }
    }

    ngx_xrootd_cms_schedule(ctx, delay);
}


static void
ngx_xrootd_cms_timer(ngx_event_t *ev)
{
    ngx_xrootd_cms_ctx_t  *ctx;

    ctx = ev->data;

    if (ctx->connection == NULL) {
        ngx_xrootd_cms_connect(ctx);
        return;
    }

    if (ngx_xrootd_cms_send_load(ctx) != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, ev->log, 0,
                      "xrootd: CMS load heartbeat failed");
        ngx_xrootd_cms_disconnect(ctx);
        ngx_xrootd_cms_schedule_retry(ctx);
        return;
    }

    ngx_xrootd_cms_schedule(ctx, (ngx_msec_t) ctx->conf->cms_interval * 1000);
}


static void
ngx_xrootd_cms_connect(ngx_xrootd_cms_ctx_t *ctx)
{
    ngx_int_t          rc;
    ngx_connection_t  *c;

    ngx_memzero(&ctx->peer, sizeof(ctx->peer));
    ctx->peer.sockaddr = ctx->conf->cms_addr->sockaddr;
    ctx->peer.socklen = ctx->conf->cms_addr->socklen;
    ctx->peer.name = &ctx->conf->cms_addr->name;
    ctx->peer.get = ngx_event_get_peer;
    ctx->peer.log = ctx->cycle->log;
    ctx->peer.log_error = NGX_ERROR_ERR;

    rc = ngx_event_connect_peer(&ctx->peer);
    if (rc == NGX_ERROR || rc == NGX_DECLINED || ctx->peer.connection == NULL) {
        ngx_log_error(NGX_LOG_WARN, ctx->cycle->log, 0,
                      "xrootd: CMS connect to %V failed",
                      &ctx->conf->cms_manager);
        ngx_xrootd_cms_schedule_retry(ctx);
        return;
    }

    c = ctx->peer.connection;
    ctx->connection = c;
    ctx->logged_in = 0;
    ctx->in_pos = 0;
    ctx->in_need = NGX_XROOTD_CMS_HDR_LEN;

    c->data = ctx;
    c->read->handler = ngx_xrootd_cms_read_handler;
    c->write->handler = ngx_xrootd_cms_write_handler;

    if (rc == NGX_AGAIN) {
        ngx_add_timer(c->write, NGX_XROOTD_CMS_CONNECT_TIMEOUT);
        return;
    }

    ngx_xrootd_cms_write_handler(c->write);
}


static void
ngx_xrootd_cms_disconnect(ngx_xrootd_cms_ctx_t *ctx)
{
    ngx_connection_t  *c;

    c = ctx->connection;
    if (c == NULL) {
        return;
    }

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    ngx_close_connection(c);

    ctx->connection = NULL;
    ctx->logged_in = 0;
    ctx->in_pos = 0;
    ctx->in_need = NGX_XROOTD_CMS_HDR_LEN;
}


static void
ngx_xrootd_cms_write_handler(ngx_event_t *ev)
{
    ngx_connection_t       *c;
    ngx_xrootd_cms_ctx_t   *ctx;

    c = ev->data;
    ctx = c->data;

    if (ev->timedout) {
        ngx_log_error(NGX_LOG_WARN, ev->log, 0,
                      "xrootd: CMS connect/write timed out");
        ngx_xrootd_cms_disconnect(ctx);
        ngx_xrootd_cms_schedule_retry(ctx);
        return;
    }

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    if (!ctx->logged_in) {
        if (ngx_xrootd_cms_send_login(ctx) != NGX_OK) {
            ngx_xrootd_cms_disconnect(ctx);
            ngx_xrootd_cms_schedule_retry(ctx);
            return;
        }

        ctx->logged_in = 1;
        ctx->backoff = NGX_XROOTD_CMS_BACKOFF_INITIAL;

        ngx_log_error(NGX_LOG_NOTICE, ev->log, 0,
                      "xrootd: CMS login sent to %V",
                      &ctx->conf->cms_manager);
    }

    if (ngx_xrootd_cms_send_load(ctx) != NGX_OK) {
        ngx_xrootd_cms_disconnect(ctx);
        ngx_xrootd_cms_schedule_retry(ctx);
        return;
    }

    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        ngx_xrootd_cms_disconnect(ctx);
        ngx_xrootd_cms_schedule_retry(ctx);
        return;
    }

    ngx_xrootd_cms_schedule(ctx, (ngx_msec_t) ctx->conf->cms_interval * 1000);
}


static void
ngx_xrootd_cms_read_handler(ngx_event_t *ev)
{
    ngx_connection_t      *c;
    ngx_xrootd_cms_ctx_t  *ctx;
    ssize_t                n;
    uint16_t               dlen;

    c = ev->data;
    ctx = c->data;

    if (ev->timedout) {
        ngx_xrootd_cms_disconnect(ctx);
        ngx_xrootd_cms_schedule_retry(ctx);
        return;
    }

    for ( ;; ) {
        n = c->recv(c, ctx->inbuf + ctx->in_pos,
                    ctx->in_need - ctx->in_pos);

        if (n == NGX_AGAIN) {
            break;
        }

        if (n == NGX_ERROR || n == 0) {
            ngx_xrootd_cms_disconnect(ctx);
            ngx_xrootd_cms_schedule_retry(ctx);
            return;
        }

        ctx->in_pos += (size_t) n;

        if (ctx->in_pos < ctx->in_need) {
            continue;
        }

        if (ctx->in_need == NGX_XROOTD_CMS_HDR_LEN) {
            dlen = ngx_xrootd_cms_get16(ctx->inbuf + 6);
            if ((size_t) dlen + NGX_XROOTD_CMS_HDR_LEN
                > NGX_XROOTD_CMS_MAX_FRAME)
            {
                ngx_log_error(NGX_LOG_WARN, ev->log, 0,
                              "xrootd: CMS frame too large: %ui",
                              (ngx_uint_t) dlen);
                ngx_xrootd_cms_disconnect(ctx);
                ngx_xrootd_cms_schedule_retry(ctx);
                return;
            }

            ctx->in_need = NGX_XROOTD_CMS_HDR_LEN + dlen;
            if (ctx->in_pos < ctx->in_need) {
                continue;
            }
        }

        if (ngx_xrootd_cms_process_frame(ctx) != NGX_OK) {
            ngx_xrootd_cms_disconnect(ctx);
            ngx_xrootd_cms_schedule_retry(ctx);
            return;
        }

        ctx->in_pos = 0;
        ctx->in_need = NGX_XROOTD_CMS_HDR_LEN;
    }

    if (ctx->connection != NULL
        && ngx_handle_read_event(c->read, 0) != NGX_OK)
    {
        ngx_xrootd_cms_disconnect(ctx);
        ngx_xrootd_cms_schedule_retry(ctx);
    }
}


static ngx_int_t
ngx_xrootd_cms_process_frame(ngx_xrootd_cms_ctx_t *ctx)
{
    uint32_t  streamid;
    u_char    code;

    streamid = ngx_xrootd_cms_get32(ctx->inbuf);
    code = ctx->inbuf[4];

    switch (code) {
    case CMS_RR_PING:
        return ngx_xrootd_cms_send_pong(ctx, streamid);

    case CMS_RR_SPACE:
        return ngx_xrootd_cms_send_avail(ctx, streamid);

    case CMS_RR_STATUS:
        ngx_log_error(NGX_LOG_INFO, ctx->cycle->log, 0,
                      "xrootd: CMS status update received");
        return NGX_OK;

    default:
        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ctx->cycle->log, 0,
                       "xrootd: ignoring CMS rrCode=%ui", (ngx_uint_t) code);
        return NGX_OK;
    }
}


static ngx_int_t
ngx_xrootd_cms_send_login(ngx_xrootd_cms_ctx_t *ctx)
{
    u_char     payload[1024];
    u_char    *p;
    ngx_str_t  paths;
    size_t     path_len;
    uint32_t   total_gb;
    uint32_t   free_mb;
    uint32_t   util_pct;

    p = payload;
    paths = ngx_xrootd_cms_export_paths(ctx->conf);
    path_len = paths.len;
    if (path_len > 512) {
        path_len = 512;
    }

    total_gb = 0;
    free_mb = 0;
    util_pct = 0;
    (void) ngx_xrootd_cms_stat_space(ctx->conf, &total_gb, &free_mb,
                                     &util_pct);

    p = ngx_xrootd_cms_put_short(p, CMS_LOGIN_VERSION);
    p = ngx_xrootd_cms_put_int(p, CMS_LOGIN_MODE);
    p = ngx_xrootd_cms_put_int(p, (uint32_t) getpid());
    p = ngx_xrootd_cms_put_int(p, total_gb);
    p = ngx_xrootd_cms_put_int(p, free_mb);
    p = ngx_xrootd_cms_put_int(p, NGX_XROOTD_CMS_MIN_FREE_MB);
    p = ngx_xrootd_cms_put_short(p, 1);
    p = ngx_xrootd_cms_put_short(p, (uint16_t) util_pct);
    p = ngx_xrootd_cms_put_short(p, XROOTD_DEFAULT_PORT);
    p = ngx_xrootd_cms_put_short(p, 0);
    p = ngx_xrootd_cms_put_short(p, 0);
    p = ngx_xrootd_cms_put_short(p, (uint16_t) path_len);

    if (path_len > 0) {
        ngx_memcpy(p, paths.data, path_len);
        p += path_len;
    }

    p = ngx_xrootd_cms_put_short(p, 0);
    p = ngx_xrootd_cms_put_short(p, 0);

    return ngx_xrootd_cms_send_frame(ctx, 0, CMS_RR_LOGIN, 0, payload,
                                     (size_t) (p - payload));
}


static ngx_int_t
ngx_xrootd_cms_send_load(ngx_xrootd_cms_ctx_t *ctx)
{
    u_char    payload[32];
    u_char   *p;
    uint32_t  free_mb;

    free_mb = 0;
    (void) ngx_xrootd_cms_stat_space(ctx->conf, NULL, &free_mb, NULL);

    p = payload;
    p = ngx_xrootd_cms_put_short(p, 6);
    *p++ = 0;
    *p++ = 0;
    *p++ = 0;
    *p++ = 0;
    *p++ = 0;
    *p++ = 0;
    p = ngx_xrootd_cms_put_int(p, free_mb);

    return ngx_xrootd_cms_send_frame(ctx, 0, CMS_RR_LOAD, 0, payload,
                                     (size_t) (p - payload));
}


static ngx_int_t
ngx_xrootd_cms_send_avail(ngx_xrootd_cms_ctx_t *ctx, uint32_t streamid)
{
    u_char    payload[16];
    u_char   *p;
    uint32_t  free_mb;
    uint32_t  util_pct;

    free_mb = 0;
    util_pct = 0;
    (void) ngx_xrootd_cms_stat_space(ctx->conf, NULL, &free_mb, &util_pct);

    p = payload;
    p = ngx_xrootd_cms_put_int(p, free_mb);
    p = ngx_xrootd_cms_put_int(p, util_pct);

    return ngx_xrootd_cms_send_frame(ctx, streamid, CMS_RR_AVAIL, 0, payload,
                                     (size_t) (p - payload));
}


static ngx_int_t
ngx_xrootd_cms_send_pong(ngx_xrootd_cms_ctx_t *ctx, uint32_t streamid)
{
    return ngx_xrootd_cms_send_frame(ctx, streamid, CMS_RR_PONG, 0, NULL, 0);
}
