/*
 * ngx_http_xrootd_metrics_module.c
 *
 * Exposes nginx-xrootd counters in the Prometheus text exposition format.
 * Enable with:
 *
 *   http {
 *       server {
 *           listen 9100;
 *           location /metrics {
 *               xrootd_metrics on;
 *           }
 *       }
 *   }
 *
 * Scrape with:
 *   curl http://localhost:9100/metrics
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_xrootd_metrics.h"

/* Forward declared in ngx_xrootd_metrics.h; defined in the stream module */
ngx_shm_zone_t *ngx_xrootd_shm_zone = NULL;

/* Human-readable operation names (must match XROOTD_OP_* indices) */
static const char *xrootd_op_names[XROOTD_NOPS] = {
    "login",        /* XROOTD_OP_LOGIN        */
    "auth",         /* XROOTD_OP_AUTH         */
    "stat",         /* XROOTD_OP_STAT         */
    "open_rd",      /* XROOTD_OP_OPEN_RD      */
    "open_wr",      /* XROOTD_OP_OPEN_WR      */
    "read",         /* XROOTD_OP_READ         */
    "write",        /* XROOTD_OP_WRITE        */
    "sync",         /* XROOTD_OP_SYNC         */
    "close",        /* XROOTD_OP_CLOSE        */
    "dirlist",      /* XROOTD_OP_DIRLIST      */
    "mkdir",        /* XROOTD_OP_MKDIR        */
    "rmdir",        /* XROOTD_OP_RMDIR        */
    "rm",           /* XROOTD_OP_RM           */
    "mv",           /* XROOTD_OP_MV           */
    "chmod",        /* XROOTD_OP_CHMOD        */
    "truncate",     /* XROOTD_OP_TRUNCATE     */
    "ping",         /* XROOTD_OP_PING         */
    "query_cksum",  /* XROOTD_OP_QUERY_CKSUM  */
    "query_space",  /* XROOTD_OP_QUERY_SPACE  */
    "readv",        /* XROOTD_OP_READV        */
};

/* ------------------------------------------------------------------ */
/* Location config                                                      */
/* ------------------------------------------------------------------ */

typedef struct {
    ngx_flag_t  enable;
} ngx_http_xrootd_metrics_loc_conf_t;

/* ------------------------------------------------------------------ */
/* Forward declarations                                                 */
/* ------------------------------------------------------------------ */

static ngx_int_t ngx_http_xrootd_metrics_handler(ngx_http_request_t *r);
static void     *ngx_http_xrootd_metrics_create_loc_conf(ngx_conf_t *cf);
static char     *ngx_http_xrootd_metrics_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static char     *ngx_http_xrootd_metrics_set(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);

/* ------------------------------------------------------------------ */
/* Directives                                                           */
/* ------------------------------------------------------------------ */

static ngx_command_t ngx_http_xrootd_metrics_commands[] = {

    { ngx_string("xrootd_metrics"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_http_xrootd_metrics_set,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_metrics_loc_conf_t, enable),
      NULL },

    ngx_null_command
};

/* ------------------------------------------------------------------ */
/* Module context                                                       */
/* ------------------------------------------------------------------ */

static ngx_http_module_t ngx_http_xrootd_metrics_module_ctx = {
    NULL,                                      /* preconfiguration    */
    NULL,                                      /* postconfiguration   */
    NULL,                                      /* create main conf    */
    NULL,                                      /* init main conf      */
    NULL,                                      /* create srv conf     */
    NULL,                                      /* merge srv conf      */
    ngx_http_xrootd_metrics_create_loc_conf,   /* create loc conf     */
    ngx_http_xrootd_metrics_merge_loc_conf     /* merge loc conf      */
};

/* ------------------------------------------------------------------ */
/* Module definition                                                    */
/* ------------------------------------------------------------------ */

ngx_module_t ngx_http_xrootd_metrics_module = {
    NGX_MODULE_V1,
    &ngx_http_xrootd_metrics_module_ctx,
    ngx_http_xrootd_metrics_commands,
    NGX_HTTP_MODULE,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NGX_MODULE_V1_PADDING
};

/* ------------------------------------------------------------------ */
/* Config callbacks                                                     */
/* ------------------------------------------------------------------ */

static void *
ngx_http_xrootd_metrics_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_xrootd_metrics_loc_conf_t *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(*conf));
    if (conf == NULL) { return NULL; }
    conf->enable = NGX_CONF_UNSET;
    return conf;
}

static char *
ngx_http_xrootd_metrics_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child)
{
    ngx_http_xrootd_metrics_loc_conf_t *prev = parent;
    ngx_http_xrootd_metrics_loc_conf_t *conf = child;
    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    return NGX_CONF_OK;
}

static char *
ngx_http_xrootd_metrics_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf;
    char *rv;

    rv = ngx_conf_set_flag_slot(cf, cmd, conf);
    if (rv != NGX_CONF_OK) { return rv; }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_xrootd_metrics_handler;
    return NGX_CONF_OK;
}

/* ------------------------------------------------------------------ */
/* Helper: append a formatted string to an ngx_buf_t chain             */
/* ------------------------------------------------------------------ */

#define METRICS_BUF_SIZE  65536

typedef struct {
    ngx_pool_t   *pool;
    ngx_chain_t  *head;
    ngx_chain_t  *tail;
    u_char       *pos;
    u_char       *last;
    size_t        total;
} metrics_writer_t;

static ngx_int_t
mw_init(metrics_writer_t *mw, ngx_pool_t *pool)
{
    ngx_buf_t   *b;
    ngx_chain_t *cl;

    b = ngx_create_temp_buf(pool, METRICS_BUF_SIZE);
    if (b == NULL) { return NGX_ERROR; }

    cl = ngx_alloc_chain_link(pool);
    if (cl == NULL) { return NGX_ERROR; }

    cl->buf  = b;
    cl->next = NULL;

    mw->pool  = pool;
    mw->head  = cl;
    mw->tail  = cl;
    mw->pos   = b->pos;
    mw->last  = b->last + METRICS_BUF_SIZE;
    mw->total = 0;
    return NGX_OK;
}

static ngx_int_t
mw_printf(metrics_writer_t *mw, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

static ngx_int_t
mw_printf(metrics_writer_t *mw, const char *fmt, ...)
{
    va_list   args;
    int       n;
    size_t    avail;
    ngx_buf_t   *b;
    ngx_chain_t *cl;

    avail = mw->last - mw->pos;

    va_start(args, fmt);
    n = vsnprintf((char *) mw->pos, avail, fmt, args);
    va_end(args);

    if (n < 0) { return NGX_ERROR; }

    if ((size_t) n >= avail) {
        /* Current buffer full — allocate another */
        mw->tail->buf->last = mw->pos;

        b = ngx_create_temp_buf(mw->pool, METRICS_BUF_SIZE);
        if (b == NULL) { return NGX_ERROR; }

        cl = ngx_alloc_chain_link(mw->pool);
        if (cl == NULL) { return NGX_ERROR; }

        cl->buf  = b;
        cl->next = NULL;
        mw->tail->next = cl;
        mw->tail       = cl;
        mw->pos        = b->pos;
        mw->last       = b->last + METRICS_BUF_SIZE;

        avail = METRICS_BUF_SIZE;
        va_start(args, fmt);
        n = vsnprintf((char *) mw->pos, avail, fmt, args);
        va_end(args);

        if (n < 0 || (size_t) n >= avail) { return NGX_ERROR; }
    }

    mw->pos   += n;
    mw->total += n;
    return NGX_OK;
}

static void
mw_finish(metrics_writer_t *mw)
{
    mw->tail->buf->last    = mw->pos;
    mw->tail->buf->last_buf = 1;
}

/* ------------------------------------------------------------------ */
/* Request handler                                                      */
/* ------------------------------------------------------------------ */

static ngx_int_t
ngx_http_xrootd_metrics_handler(ngx_http_request_t *r)
{
    ngx_http_xrootd_metrics_loc_conf_t *lcf;
    ngx_xrootd_metrics_t               *shm;
    ngx_xrootd_srv_metrics_t           *srv;
    metrics_writer_t                    mw;
    ngx_uint_t                          i, op;
    ngx_int_t                           rc;
    char                                port_str[16];

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_metrics_module);
    if (!lcf->enable) {
        return NGX_DECLINED;
    }

    if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_HEAD) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) { return rc; }

    if (mw_init(&mw, r->pool) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* If the shared zone isn't initialised yet (e.g. no stream {} block),
     * return empty metrics rather than crashing. */
    if (ngx_xrootd_shm_zone == NULL || ngx_xrootd_shm_zone->data == NULL) {
        mw_printf(&mw, "# nginx-xrootd: no stream servers configured\n");
        goto done;
    }

    shm = ngx_xrootd_shm_zone->data;

    /* ---- xrootd_connections_total ---- */
    mw_printf(&mw,
        "# HELP xrootd_connections_total "
            "Total TCP connections accepted since process start.\n"
        "# TYPE xrootd_connections_total counter\n");
    for (i = 0; i < XROOTD_METRICS_MAX_SERVERS; i++) {
        srv = &shm->servers[i];
        if (!srv->in_use) { continue; }
        ngx_snprintf((u_char *) port_str, sizeof(port_str),
                     "%ui%Z", srv->port);
        mw_printf(&mw,
            "xrootd_connections_total{port=\"%s\",auth=\"%s\"} %lu\n",
            port_str, srv->auth,
            (unsigned long) ngx_atomic_fetch_add(&srv->connections_total, 0));
    }

    /* ---- xrootd_connections_active ---- */
    mw_printf(&mw,
        "# HELP xrootd_connections_active "
            "Currently open XRootD connections.\n"
        "# TYPE xrootd_connections_active gauge\n");
    for (i = 0; i < XROOTD_METRICS_MAX_SERVERS; i++) {
        srv = &shm->servers[i];
        if (!srv->in_use) { continue; }
        ngx_snprintf((u_char *) port_str, sizeof(port_str),
                     "%ui%Z", srv->port);
        mw_printf(&mw,
            "xrootd_connections_active{port=\"%s\",auth=\"%s\"} %lu\n",
            port_str, srv->auth,
            (unsigned long) ngx_atomic_fetch_add(&srv->connections_active, 0));
    }

    /* ---- xrootd_bytes_rx_total ---- */
    mw_printf(&mw,
        "# HELP xrootd_bytes_rx_total "
            "Bytes received from clients (write payloads).\n"
        "# TYPE xrootd_bytes_rx_total counter\n");
    for (i = 0; i < XROOTD_METRICS_MAX_SERVERS; i++) {
        srv = &shm->servers[i];
        if (!srv->in_use) { continue; }
        ngx_snprintf((u_char *) port_str, sizeof(port_str),
                     "%ui%Z", srv->port);
        mw_printf(&mw,
            "xrootd_bytes_rx_total{port=\"%s\",auth=\"%s\"} %lu\n",
            port_str, srv->auth,
            (unsigned long) ngx_atomic_fetch_add(&srv->bytes_rx_total, 0));
    }

    /* ---- xrootd_bytes_tx_total ---- */
    mw_printf(&mw,
        "# HELP xrootd_bytes_tx_total "
            "Bytes sent to clients (read data).\n"
        "# TYPE xrootd_bytes_tx_total counter\n");
    for (i = 0; i < XROOTD_METRICS_MAX_SERVERS; i++) {
        srv = &shm->servers[i];
        if (!srv->in_use) { continue; }
        ngx_snprintf((u_char *) port_str, sizeof(port_str),
                     "%ui%Z", srv->port);
        mw_printf(&mw,
            "xrootd_bytes_tx_total{port=\"%s\",auth=\"%s\"} %lu\n",
            port_str, srv->auth,
            (unsigned long) ngx_atomic_fetch_add(&srv->bytes_tx_total, 0));
    }

    /* ---- xrootd_requests_total ---- */
    mw_printf(&mw,
        "# HELP xrootd_requests_total "
            "XRootD requests completed, by operation and status.\n"
        "# TYPE xrootd_requests_total counter\n");
    for (op = 0; op < XROOTD_NOPS; op++) {
        for (i = 0; i < XROOTD_METRICS_MAX_SERVERS; i++) {
            srv = &shm->servers[i];
            if (!srv->in_use) { continue; }
            ngx_snprintf((u_char *) port_str, sizeof(port_str),
                         "%ui%Z", srv->port);
            mw_printf(&mw,
                "xrootd_requests_total"
                    "{port=\"%s\",auth=\"%s\",op=\"%s\",status=\"ok\"}"
                    " %lu\n",
                port_str, srv->auth, xrootd_op_names[op],
                (unsigned long) ngx_atomic_fetch_add(&srv->op_ok[op], 0));
            /* Only emit error series when non-zero to keep output terse */
            ngx_atomic_t errs = ngx_atomic_fetch_add(&srv->op_err[op], 0);
            if (errs > 0) {
                mw_printf(&mw,
                    "xrootd_requests_total"
                        "{port=\"%s\",auth=\"%s\",op=\"%s\",status=\"error\"}"
                        " %lu\n",
                    port_str, srv->auth, xrootd_op_names[op],
                    (unsigned long) errs);
            }
        }
    }

done:
    mw_finish(&mw);

    r->headers_out.status           = NGX_HTTP_OK;
    r->headers_out.content_length_n = (off_t) mw.total;

    {
        ngx_str_t ct = ngx_string(
            "text/plain; version=0.0.4; charset=utf-8");
        r->headers_out.content_type      = ct;
        r->headers_out.content_type_len  = ct.len;
        r->headers_out.content_type_lowcase = NULL;
    }

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, mw.head);
}
