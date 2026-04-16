/*
 * ngx_http_xrootd_webdav_module.c
 *
 * nginx HTTP module: WebDAV over HTTPS with GSI (x509 proxy certificate)
 * authentication, designed for xrdcp compatibility on port 8443.
 *
 * xrdcp's HTTP plugin (XrdClHttp / libcurl) speaks HTTP/WebDAV over TLS and
 * presents an x509 proxy certificate for authentication.  This module:
 *
 *   1.  Hooks the SSL context (postconfiguration) to enable
 *       X509_V_FLAG_ALLOW_PROXY_CERTS so that nginx's built-in TLS can accept
 *       RFC 3820 proxy certificates used by Grid/HEP clients.
 *
 *   2.  Verifies the proxy certificate chain in the request handler using a
 *       configurable CA directory (hash-named PEM files as distributed by
 *       ca-certificates or IGTF).
 *
 *   3.  Handles the WebDAV methods xrdcp requires:
 *         OPTIONS   – capability advertisement (PROPFIND in Allow header)
 *         HEAD      – file metadata without body
 *         GET       – ranged / full file download (RFC 7233 Range)
 *         PUT       – file upload
 *         DELETE    – remove file or empty directory
 *         MKCOL     – create directory
 *         PROPFIND  – WebDAV stat (Depth:0) and directory listing (Depth:1)
 *
 * nginx configuration:
 *
 *   server {
 *       listen 8443 ssl;
 *       ssl_certificate     /etc/grid-security/hostcert.pem;
 *       ssl_certificate_key /etc/grid-security/hostkey.pem;
 *       ssl_verify_client optional_no_ca;   # we verify proxy certs ourselves
 *       ssl_verify_depth    10;
 *
 *       location / {
 *           xrootd_webdav         on;
 *           xrootd_webdav_root    /data/xrootd;
 *           xrootd_webdav_cadir   /etc/grid-security/certificates;
 *           xrootd_webdav_auth    required;   # or "optional" or "none"
 *       }
 *   }
 *
 * To allow nginx's native ssl_verify_client verification to also accept proxy
 * certificates (in addition to the manual check above) add:
 *
 *       xrootd_webdav_proxy_certs on;
 *
 * This sets X509_V_FLAG_ALLOW_PROXY_CERTS on the server's SSL_CTX during
 * postconfiguration so you can use `ssl_verify_client on` instead.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_ssl_module.h>

#include <ctype.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/x509_vfy.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <time.h>

/* Maximum path length we'll construct */
#define WEBDAV_MAX_PATH   4096
/* Maximum PUT body size (16 MiB) */
#define WEBDAV_MAX_PUT    (16 * 1024 * 1024)
/* PROPFIND response buffer initial size */
#define WEBDAV_XML_CHUNK  4096

/* ------------------------------------------------------------------ */
/* Module config structs                                                */
/* ------------------------------------------------------------------ */

typedef enum {
    WEBDAV_AUTH_NONE,
    WEBDAV_AUTH_OPTIONAL,
    WEBDAV_AUTH_REQUIRED,
} webdav_auth_t;

typedef struct {
    ngx_flag_t     enable;
    ngx_str_t      root;
    ngx_str_t      cadir;
    ngx_str_t      cafile;
    ngx_uint_t     verify_depth;
    ngx_uint_t     auth;          /* webdav_auth_t */
    ngx_flag_t     proxy_certs;  /* set X509_V_FLAG_ALLOW_PROXY_CERTS on SSL CTX */
    ngx_flag_t     allow_write;
} ngx_http_xrootd_webdav_loc_conf_t;

/* Per-request auth result: cached across sub-handlers */
typedef struct {
    int            verified;      /* 1 = chain passed, 0 = failed/absent */
    char           dn[1024];
} ngx_http_xrootd_webdav_req_ctx_t;

/* ------------------------------------------------------------------ */
/* Forward declarations                                                */
/* ------------------------------------------------------------------ */

static ngx_int_t ngx_http_xrootd_webdav_handler(ngx_http_request_t *r);
static ngx_int_t webdav_handle_options(ngx_http_request_t *r);
static ngx_int_t webdav_handle_head(ngx_http_request_t *r, int send_body);
static ngx_int_t webdav_handle_get(ngx_http_request_t *r);
static void      webdav_handle_put_body(ngx_http_request_t *r);
static ngx_int_t webdav_handle_delete(ngx_http_request_t *r);
static ngx_int_t webdav_handle_mkcol(ngx_http_request_t *r);
static ngx_int_t webdav_handle_propfind(ngx_http_request_t *r);

static ngx_int_t webdav_resolve_path(ngx_http_request_t *r,
                                     const ngx_str_t *root,
                                     char *out, size_t outsz);
static ngx_int_t webdav_verify_proxy_cert(ngx_http_request_t *r,
                                          ngx_http_xrootd_webdav_loc_conf_t *cf);

static void     *ngx_http_xrootd_webdav_create_loc_conf(ngx_conf_t *cf);
static char     *ngx_http_xrootd_webdav_merge_loc_conf(ngx_conf_t *cf,
                                                        void *parent,
                                                        void *child);
static ngx_int_t ngx_http_xrootd_webdav_postconfiguration(ngx_conf_t *cf);

/* ------------------------------------------------------------------ */
/* Config directives                                                    */
/* ------------------------------------------------------------------ */

static ngx_conf_enum_t  webdav_auth_values[] = {
    { ngx_string("none"),     WEBDAV_AUTH_NONE     },
    { ngx_string("optional"), WEBDAV_AUTH_OPTIONAL },
    { ngx_string("required"), WEBDAV_AUTH_REQUIRED },
    { ngx_null_string, 0 }
};

static ngx_command_t ngx_http_xrootd_webdav_commands[] = {

    { ngx_string("xrootd_webdav"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, enable),
      NULL },

    { ngx_string("xrootd_webdav_root"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, root),
      NULL },

    { ngx_string("xrootd_webdav_cadir"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, cadir),
      NULL },

    { ngx_string("xrootd_webdav_cafile"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, cafile),
      NULL },

    { ngx_string("xrootd_webdav_verify_depth"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, verify_depth),
      NULL },

    { ngx_string("xrootd_webdav_auth"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, auth),
      &webdav_auth_values },

    { ngx_string("xrootd_webdav_proxy_certs"),
      NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, proxy_certs),
      NULL },

    { ngx_string("xrootd_webdav_allow_write"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, allow_write),
      NULL },

    ngx_null_command
};

/* ------------------------------------------------------------------ */
/* Module context and module object                                     */
/* ------------------------------------------------------------------ */

static ngx_http_module_t ngx_http_xrootd_webdav_module_ctx = {
    NULL,                                     /* preconfiguration */
    ngx_http_xrootd_webdav_postconfiguration, /* postconfiguration */
    NULL,                                     /* create main configuration */
    NULL,                                     /* init main configuration */
    NULL,                                     /* create server configuration */
    NULL,                                     /* merge server configuration */
    ngx_http_xrootd_webdav_create_loc_conf,   /* create location configuration */
    ngx_http_xrootd_webdav_merge_loc_conf,    /* merge location configuration */
};

ngx_module_t ngx_http_xrootd_webdav_module = {
    NGX_MODULE_V1,
    &ngx_http_xrootd_webdav_module_ctx,
    ngx_http_xrootd_webdav_commands,
    NGX_HTTP_MODULE,
    NULL,  /* init_master */
    NULL,  /* init_module */
    NULL,  /* init_process */
    NULL,  /* init_thread */
    NULL,  /* exit_thread */
    NULL,  /* exit_process */
    NULL,  /* exit_master */
    NGX_MODULE_V1_PADDING
};

/* ------------------------------------------------------------------ */
/* Config lifecycle                                                     */
/* ------------------------------------------------------------------ */

static void *
ngx_http_xrootd_webdav_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_xrootd_webdav_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(*conf));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable      = NGX_CONF_UNSET;
    conf->verify_depth = NGX_CONF_UNSET_UINT;
    conf->auth        = NGX_CONF_UNSET_UINT;
    conf->proxy_certs = NGX_CONF_UNSET;
    conf->allow_write = NGX_CONF_UNSET;

    return conf;
}

static char *
ngx_http_xrootd_webdav_merge_loc_conf(ngx_conf_t *cf,
                                       void *parent, void *child)
{
    ngx_http_xrootd_webdav_loc_conf_t *prev = parent;
    ngx_http_xrootd_webdav_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable,       prev->enable,       0);
    ngx_conf_merge_str_value(conf->root,     prev->root,         "/");
    ngx_conf_merge_str_value(conf->cadir,    prev->cadir,        "");
    ngx_conf_merge_str_value(conf->cafile,   prev->cafile,       "");
    ngx_conf_merge_uint_value(conf->verify_depth, prev->verify_depth, 10);
    ngx_conf_merge_uint_value(conf->auth,    prev->auth,
                              WEBDAV_AUTH_OPTIONAL);
    ngx_conf_merge_value(conf->proxy_certs,  prev->proxy_certs,  0);
    ngx_conf_merge_value(conf->allow_write,  prev->allow_write,  0);

    return NGX_CONF_OK;
}

/*
 * postconfiguration: register the content handler, and optionally patch every
 * SSL context to accept RFC 3820 proxy certificates.
 *
 * We do the SSL patching here because the SSL contexts have been fully
 * initialised by ngx_http_ssl_module's postconfiguration (which runs before
 * ours since it was added first).
 */
static ngx_int_t
ngx_http_xrootd_webdav_postconfiguration(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;
    ngx_http_core_srv_conf_t  **cscfp;
    ngx_http_ssl_srv_conf_t    *sslcf;
    ngx_http_xrootd_webdav_loc_conf_t *wdcf;
    ngx_uint_t                  s;
    X509_VERIFY_PARAM           *param;

    /* Register as a content-phase handler */
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_xrootd_webdav_handler;

    /*
     * Walk all virtual servers.  For any that have both SSL and
     * xrootd_webdav_proxy_certs enabled, patch their SSL_CTX so that
     * X509_V_FLAG_ALLOW_PROXY_CERTS is set.  This makes nginx's built-in
     * ssl_verify_client accept RFC 3820 proxy certificates.
     */
    cscfp = cmcf->servers.elts;
    for (s = 0; s < cmcf->servers.nelts; s++) {
        ngx_http_conf_ctx_t *ctx = cscfp[s]->ctx;

        /* Get this server's root location conf for our module */
        wdcf = ctx->loc_conf[ngx_http_xrootd_webdav_module.ctx_index];
        if (wdcf == NULL || !wdcf->proxy_certs) {
            continue;
        }

        /* Get the SSL server config to access the SSL_CTX */
        sslcf = ctx->srv_conf[ngx_http_ssl_module.ctx_index];
        if (sslcf == NULL || sslcf->ssl.ctx == NULL) {
            continue;
        }

        param = SSL_CTX_get0_param(sslcf->ssl.ctx);
        if (param) {
            X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_ALLOW_PROXY_CERTS);
            ngx_log_error(NGX_LOG_INFO, cf->log, 0,
                          "xrootd_webdav: enabled X509_V_FLAG_ALLOW_PROXY_CERTS"
                          " on SSL context for server %V",
                          &cscfp[s]->server_name);
        }
    }

    return NGX_OK;
}

/* ------------------------------------------------------------------ */
/* Utility: URL-decode a path segment into a fixed buffer              */
/* ------------------------------------------------------------------ */

static ngx_int_t
webdav_urldecode(const u_char *src, size_t src_len, char *dst, size_t dst_sz)
{
    size_t      i = 0, j = 0;
    unsigned    hi, lo;

    while (i < src_len && j + 1 < dst_sz) {
        if (src[i] == '%' && i + 2 < src_len) {
            hi = src[i+1];
            lo = src[i+2];
            if (isxdigit(hi) && isxdigit(lo)) {
                hi = hi >= 'a' ? hi - 'a' + 10 :
                     hi >= 'A' ? hi - 'A' + 10 : hi - '0';
                lo = lo >= 'a' ? lo - 'a' + 10 :
                     lo >= 'A' ? lo - 'A' + 10 : lo - '0';
                dst[j++] = (char)((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        dst[j++] = (char) src[i++];
    }
    dst[j] = '\0';
    return (i == src_len) ? NGX_OK : NGX_ERROR;
}

/* ------------------------------------------------------------------ */
/* Utility: resolve request URI path under the configured root          */
/* Returns NGX_OK and fills out[] on success, NGX_HTTP_* error code    */
/* on traversal attack or other error.                                  */
/* ------------------------------------------------------------------ */

static ngx_int_t
webdav_resolve_path(ngx_http_request_t *r, const ngx_str_t *root,
                    char *out, size_t outsz)
{
    char   root_buf[PATH_MAX];
    char   root_canon[PATH_MAX];
    char   uri_decoded[WEBDAV_MAX_PATH];
    char   combined[PATH_MAX];
    char   resolved[PATH_MAX];
    size_t rlen;

    /* Canonicalize the configured root */
    if (root->len == 0 || root->len >= sizeof(root_buf)) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "xrootd_webdav: root path missing or too long");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_memcpy(root_buf, root->data, root->len);
    root_buf[root->len] = '\0';

    if (realpath(root_buf, root_canon) == NULL) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, errno,
                      "xrootd_webdav: cannot resolve root \"%s\"", root_buf);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* URL-decode the URI path */
    if (webdav_urldecode(r->uri.data, r->uri.len,
                         uri_decoded, sizeof(uri_decoded)) != NGX_OK) {
        return NGX_HTTP_BAD_REQUEST;
    }

    /* Strip trailing slashes (MKCOL /dir/ should resolve same as /dir) */
    {
        size_t uri_dlen = strlen(uri_decoded);
        while (uri_dlen > 1 && uri_decoded[uri_dlen - 1] == '/') {
            uri_decoded[--uri_dlen] = '\0';
        }
    }

    /* Reject embedded NULs early */
    if (strlen(uri_decoded) != ngx_strnlen((u_char *) uri_decoded,
                                            sizeof(uri_decoded))) {
        return NGX_HTTP_BAD_REQUEST;
    }

    /* Construct: root_canon + "/" + uri_decoded */
    rlen = strlen(root_canon);
    if ((size_t) snprintf(combined, sizeof(combined), "%s%s",
                          root_canon, uri_decoded) >= sizeof(combined)) {
        return NGX_HTTP_REQUEST_URI_TOO_LARGE;
    }

    /*
     * For paths that do not yet exist (e.g. PUT target, MKCOL) realpath()
     * fails with ENOENT.  In that case canonicalize the parent directory and
     * append the (single-component) filename.
     */
    if (realpath(combined, resolved) == NULL) {
        if (errno == ENOENT) {
            char *slash = strrchr(combined, '/');
            if (slash == NULL) {
                return NGX_HTTP_BAD_REQUEST;
            }
            char  parent[PATH_MAX];
            char  parent_canon[PATH_MAX];
            char  filename[NAME_MAX + 1];

            size_t parent_len = (size_t)(slash - combined);
            if (parent_len >= sizeof(parent)) {
                return NGX_HTTP_REQUEST_URI_TOO_LARGE;
            }
            ngx_memcpy(parent, combined, parent_len);
            parent[parent_len] = '\0';

            size_t fname_len = strlen(slash + 1);
            if (fname_len == 0 || fname_len >= sizeof(filename)) {
                return NGX_HTTP_BAD_REQUEST;
            }
            ngx_memcpy(filename, slash + 1, fname_len + 1);

            if (realpath(parent, parent_canon) == NULL) {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, errno,
                              "xrootd_webdav: cannot resolve parent of \"%s\"",
                              combined);
                return NGX_HTTP_NOT_FOUND;
            }

            if ((size_t) snprintf(resolved, sizeof(resolved), "%s/%s",
                                  parent_canon, filename) >= sizeof(resolved)) {
                return NGX_HTTP_REQUEST_URI_TOO_LARGE;
            }
        } else {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, errno,
                          "xrootd_webdav: cannot resolve \"%s\"", combined);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    /* Traverse-attack check: resolved path must remain under root */
    if (strncmp(resolved, root_canon, rlen) != 0 ||
        (resolved[rlen] != '/' && resolved[rlen] != '\0'))
    {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "xrootd_webdav: path traversal blocked: \"%s\"",
                      resolved);
        return NGX_HTTP_FORBIDDEN;
    }

    {
        size_t rlen2 = strlen(resolved);
        if (rlen2 >= outsz) return NGX_HTTP_REQUEST_URI_TOO_LARGE;
        ngx_memcpy(out, resolved, rlen2 + 1);
    }

    return NGX_OK;
}

/* ------------------------------------------------------------------ */
/* Proxy certificate verification                                        */
/* ------------------------------------------------------------------ */

static ngx_int_t
webdav_verify_proxy_cert(ngx_http_request_t *r,
                         ngx_http_xrootd_webdav_loc_conf_t *conf)
{
    ngx_http_xrootd_webdav_req_ctx_t *ctx;
    SSL              *ssl;
    X509             *leaf = NULL;
    STACK_OF(X509)   *chain = NULL;
    X509_STORE       *store = NULL;
    X509_STORE_CTX   *vctx  = NULL;
    char             *dn    = NULL;
    int               ok    = 0;
    char              cadir_buf[PATH_MAX];
    char              cafile_buf[PATH_MAX];

    /* Check for cached result from a previous sub-request phase */
    ctx = ngx_http_get_module_ctx(r, ngx_http_xrootd_webdav_module);
    if (ctx != NULL) {
        return ctx->verified ? NGX_OK : NGX_HTTP_FORBIDDEN;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(*ctx));
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_http_set_ctx(r, ctx, ngx_http_xrootd_webdav_module);

    /* No TLS on this connection - cannot authenticate */
    if (r->connection->ssl == NULL) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "xrootd_webdav: non-TLS connection, cannot verify GSI");
        goto done;
    }

    ssl  = r->connection->ssl->connection;
    leaf = SSL_get_peer_certificate(ssl);
    if (leaf == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "xrootd_webdav: no client certificate presented");
        goto done;
    }

    /* chain includes the leaf at index 0 plus any intermediate certs */
    chain = SSL_get_peer_cert_chain(ssl);

    /* Build a CA store from the configured cadir / cafile */
    store = X509_STORE_new();
    if (store == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "xrootd_webdav: X509_STORE_new failed");
        goto done;
    }

    if (conf->cadir.len > 0) {
        if (conf->cadir.len >= sizeof(cadir_buf)) {
            goto done;
        }
        ngx_memcpy(cadir_buf, conf->cadir.data, conf->cadir.len);
        cadir_buf[conf->cadir.len] = '\0';
        if (!X509_STORE_load_path(store, cadir_buf)) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "xrootd_webdav: failed to load CA directory \"%s\"",
                          cadir_buf);
        }
    }

    if (conf->cafile.len > 0) {
        if (conf->cafile.len >= sizeof(cafile_buf)) {
            goto done;
        }
        ngx_memcpy(cafile_buf, conf->cafile.data, conf->cafile.len);
        cafile_buf[conf->cafile.len] = '\0';
        if (!X509_STORE_load_file(store, cafile_buf)) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "xrootd_webdav: failed to load CA file \"%s\"",
                          cafile_buf);
        }
    }

    /* Fall back to system default CAs if nothing was configured */
    if (conf->cadir.len == 0 && conf->cafile.len == 0) {
        X509_STORE_set_default_paths(store);
    }

    vctx = X509_STORE_CTX_new();
    if (vctx == NULL) {
        goto done;
    }

    /*
     * The peer cert chain from TLS includes the leaf at index 0.  X509_STORE_CTX
     * expects leaf + chain separately, but SSL_get_peer_cert_chain includes the
     * leaf so we can pass it directly as the untrusted set.
     */
    if (!X509_STORE_CTX_init(vctx, store, leaf, chain)) {
        goto done;
    }

    /* Allow RFC 3820 proxy certificates */
    X509_STORE_CTX_set_flags(vctx, X509_V_FLAG_ALLOW_PROXY_CERTS);

    if ((ngx_uint_t) conf->verify_depth > 0) {
        X509_STORE_CTX_set_depth(vctx, (int) conf->verify_depth);
    }

    ok = X509_verify_cert(vctx);

    if (!ok) {
        int verr = X509_STORE_CTX_get_error(vctx);
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "xrootd_webdav: proxy cert verification failed: %s",
                      X509_verify_cert_error_string(verr));
        goto done;
    }

    /* Extract the subject DN for logging / downstream use */
    dn = X509_NAME_oneline(X509_get_subject_name(leaf), NULL, 0);
    if (dn != NULL) {
        ngx_cpystrn((u_char *) ctx->dn, (u_char *) dn, sizeof(ctx->dn));
        OPENSSL_free(dn);
    }

    ctx->verified = 1;

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "xrootd_webdav: GSI auth OK dn=\"%s\"", ctx->dn);

done:
    if (vctx)  X509_STORE_CTX_free(vctx);
    if (store) X509_STORE_free(store);
    if (leaf)  X509_free(leaf);
    /* chain is owned by the SSL session — do not free */

    return ctx->verified ? NGX_OK : NGX_HTTP_FORBIDDEN;
}

/* ------------------------------------------------------------------ */
/* HTTP date formatting helper                                          */
/* ------------------------------------------------------------------ */

static void
webdav_http_date(time_t t, char *buf, size_t sz)
{
    struct tm tm;
    static const char *wday[] = {"Sun","Mon","Tue","Wed","Thu","Fri","Sat"};
    static const char *mon[]  = {"Jan","Feb","Mar","Apr","May","Jun",
                                  "Jul","Aug","Sep","Oct","Nov","Dec"};
    gmtime_r(&t, &tm);
    snprintf(buf, sz, "%s, %02d %s %04d %02d:%02d:%02d GMT",
             wday[tm.tm_wday], tm.tm_mday, mon[tm.tm_mon],
             tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec);
}

/* ------------------------------------------------------------------ */
/* Top-level request dispatcher                                         */
/* ------------------------------------------------------------------ */

static ngx_int_t
ngx_http_xrootd_webdav_handler(ngx_http_request_t *r)
{
    ngx_http_xrootd_webdav_loc_conf_t *conf;
    ngx_int_t                          auth_rc;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);
    if (!conf->enable) {
        return NGX_DECLINED;
    }

    /* ----- Authentication ------------------------------------------ */
    if (conf->auth != WEBDAV_AUTH_NONE) {
        auth_rc = webdav_verify_proxy_cert(r, conf);
        if (auth_rc != NGX_OK && conf->auth == WEBDAV_AUTH_REQUIRED) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "xrootd_webdav: unauthenticated request rejected"
                          " (auth=required)");
            return NGX_HTTP_FORBIDDEN;
        }
    }

    /* ----- Method dispatch ----------------------------------------- */
    if (r->method == NGX_HTTP_OPTIONS) {
        return webdav_handle_options(r);
    }
    if (r->method == NGX_HTTP_HEAD) {
        return webdav_handle_head(r, 0);
    }
    if (r->method == NGX_HTTP_GET) {
        return webdav_handle_get(r);
    }
    if (r->method == NGX_HTTP_PUT) {
        /* Write methods require explicit opt-in */
        if (!conf->allow_write) {
            return NGX_HTTP_FORBIDDEN;
        }
        /* Delegate body reading; the handler finishes asynchronously */
        r->request_body_in_single_buf = 1;
        ngx_int_t rc = ngx_http_read_client_request_body(
                           r, webdav_handle_put_body);
        if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            return rc;
        }
        return NGX_DONE;
    }
    if (r->method == NGX_HTTP_DELETE) {
        if (!conf->allow_write) {
            return NGX_HTTP_FORBIDDEN;
        }
        return webdav_handle_delete(r);
    }
    /* MKCOL - nginx doesn't define NGX_HTTP_MKCOL; match by string */
    if (r->method_name.len == 5 &&
        ngx_strncmp(r->method_name.data, "MKCOL", 5) == 0)
    {
        if (!conf->allow_write) {
            return NGX_HTTP_FORBIDDEN;
        }
        return webdav_handle_mkcol(r);
    }
    /* PROPFIND */
    if (r->method_name.len == 8 &&
        ngx_strncmp(r->method_name.data, "PROPFIND", 8) == 0)
    {
        return webdav_handle_propfind(r);
    }

    return NGX_HTTP_NOT_ALLOWED;
}

/* ------------------------------------------------------------------ */
/* OPTIONS                                                              */
/* ------------------------------------------------------------------ */

static ngx_int_t
webdav_handle_options(ngx_http_request_t *r)
{
    ngx_http_xrootd_webdav_loc_conf_t *conf;
    ngx_table_elt_t *h;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = 0;

    /* DAV: 1 – we implement class 1 WebDAV */
    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    h->hash = 1;
    ngx_str_set(&h->key, "DAV");
    ngx_str_set(&h->value, "1");

    /* Allow header enumerates supported methods */
    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    h->hash = 1;
    ngx_str_set(&h->key, "Allow");
    if (conf->allow_write) {
        ngx_str_set(&h->value,
            "OPTIONS, GET, HEAD, PUT, DELETE, MKCOL, PROPFIND");
    } else {
        ngx_str_set(&h->value, "OPTIONS, GET, HEAD, PROPFIND");
    }

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    h->hash = 1;
    ngx_str_set(&h->key, "MS-Author-Via");
    ngx_str_set(&h->value, "DAV");

    ngx_http_send_header(r);
    return ngx_http_send_special(r, NGX_HTTP_LAST);
}

/* ------------------------------------------------------------------ */
/* HEAD (and the header phase of GET)                                  */
/* ------------------------------------------------------------------ */

static ngx_int_t
webdav_handle_head(ngx_http_request_t *r, int send_body)
{
    ngx_http_xrootd_webdav_loc_conf_t *conf;
    char        path[WEBDAV_MAX_PATH];
    struct stat sb;
    ngx_int_t   rc;
    ngx_table_elt_t *h;
    char        date_buf[64];

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);

    rc = webdav_resolve_path(r, &conf->root, path, sizeof(path));
    if (rc != NGX_OK) return (ngx_int_t) rc;

    if (stat(path, &sb) != 0) {
        return (errno == ENOENT) ? NGX_HTTP_NOT_FOUND
                                 : NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->headers_out.status            = NGX_HTTP_OK;
    r->headers_out.content_length_n  = S_ISDIR(sb.st_mode) ? 0 : sb.st_size;
    r->headers_out.last_modified_time = sb.st_mtime;

    /* Content-Type */
    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    h->hash = 1;
    ngx_str_set(&h->key, "Content-Type");
    if (S_ISDIR(sb.st_mode)) {
        ngx_str_set(&h->value, "httpd/unix-directory");
    } else {
        ngx_str_set(&h->value, "application/octet-stream");
    }

    /* Last-Modified */
    webdav_http_date(sb.st_mtime, date_buf, sizeof(date_buf));
    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    h->hash = 1;
    ngx_str_set(&h->key, "Last-Modified");
    h->value.data = ngx_pstrdup(r->pool, &(ngx_str_t){strlen(date_buf),
                                                        (u_char*)date_buf});
    h->value.len  = strlen(date_buf);

    ngx_http_send_header(r);

    if (!send_body || r->header_only) {
        return ngx_http_send_special(r, NGX_HTTP_LAST);
    }
    return NGX_OK; /* caller will send body */
}

/* ------------------------------------------------------------------ */
/* GET (with Range support)                                             */
/* ------------------------------------------------------------------ */

static ngx_int_t
webdav_handle_get(ngx_http_request_t *r)
{
    ngx_http_xrootd_webdav_loc_conf_t *conf;
    char          path[WEBDAV_MAX_PATH];
    struct stat   sb;
    ngx_int_t     rc;
    ngx_fd_t      fd;
    off_t         range_start = 0, range_end;
    off_t         send_len;
    int           has_range = 0;
    ngx_buf_t    *b;
    ngx_chain_t   out;
    ngx_table_elt_t *h;
    char          cr_buf[64];
    char          date_buf[64];

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);

    rc = webdav_resolve_path(r, &conf->root, path, sizeof(path));
    if (rc != NGX_OK) return (ngx_int_t) rc;

    if (stat(path, &sb) != 0) {
        return (errno == ENOENT) ? NGX_HTTP_NOT_FOUND
                                 : NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (S_ISDIR(sb.st_mode)) {
        return NGX_HTTP_FORBIDDEN;
    }

    /* Parse Range header if present */
    if (r->headers_in.range != NULL) {
        ngx_str_t rv = r->headers_in.range->value;
        /* Expect "bytes=START-END" or "bytes=START-" */
        if (rv.len > 6 &&
            ngx_strncmp(rv.data, "bytes=", 6) == 0)
        {
            u_char *p    = rv.data + 6;
            u_char *end  = rv.data + rv.len;
            u_char *dash = ngx_strlchr(p, end, '-');
            if (dash != NULL) {
                if (dash == p) {
                    /* Suffix range: bytes=-N  (no start digit before '-') */
                    off_t suffix = 0;
                    for (u_char *q = dash + 1; q < end; q++) {
                        suffix = suffix * 10 + (*q - '0');
                    }
                    range_start = (suffix >= sb.st_size) ? 0
                                                         : sb.st_size - suffix;
                    range_end   = sb.st_size - 1;
                } else {
                    range_start = 0;
                    for (u_char *q = p; q < dash; q++) {
                        range_start = range_start * 10 + (*q - '0');
                    }
                    if (dash + 1 < end && *(dash + 1) != '\0') {
                        range_end = 0;
                        for (u_char *q = dash + 1; q < end; q++) {
                            range_end = range_end * 10 + (*q - '0');
                        }
                    } else {
                        range_end = sb.st_size - 1;
                    }
                }
                has_range = 1;
            }
        }
    }

    if (!has_range) {
        range_start = 0;
        range_end   = sb.st_size - 1;
    }

    /* Clamp to file size */
    if (range_end >= sb.st_size) {
        range_end = sb.st_size - 1;
    }
    if (range_start > range_end) {
        /* Unsatisfiable range */
        r->headers_out.status           = NGX_HTTP_RANGE_NOT_SATISFIABLE;
        r->headers_out.content_length_n = 0;
        ngx_http_send_header(r);
        return ngx_http_send_special(r, NGX_HTTP_LAST);
    }
    send_len = range_end - range_start + 1;

    fd = ngx_open_file(path, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                      "xrootd_webdav: open(\"%s\") failed", path);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Build response headers */
    r->headers_out.status           = has_range ? NGX_HTTP_PARTIAL_CONTENT
                                                 : NGX_HTTP_OK;
    r->headers_out.content_length_n = send_len;
    r->headers_out.last_modified_time = sb.st_mtime;

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) { ngx_close_file(fd); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    h->hash = 1;
    ngx_str_set(&h->key, "Content-Type");
    ngx_str_set(&h->value, "application/octet-stream");

    webdav_http_date(sb.st_mtime, date_buf, sizeof(date_buf));
    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) { ngx_close_file(fd); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    h->hash = 1;
    ngx_str_set(&h->key, "Last-Modified");
    h->value.data = ngx_pstrdup(r->pool, &(ngx_str_t){strlen(date_buf),
                                                        (u_char*)date_buf});
    h->value.len  = strlen(date_buf);

    if (has_range) {
        snprintf(cr_buf, sizeof(cr_buf),
                 "bytes %lld-%lld/%lld",
                 (long long) range_start,
                 (long long) range_end,
                 (long long) sb.st_size);
        h = ngx_list_push(&r->headers_out.headers);
        if (h == NULL) { ngx_close_file(fd); return NGX_HTTP_INTERNAL_SERVER_ERROR; }
        h->hash = 1;
        ngx_str_set(&h->key, "Content-Range");
        h->value.data = ngx_pstrdup(r->pool, &(ngx_str_t){strlen(cr_buf),
                                                            (u_char*)cr_buf});
        h->value.len  = strlen(cr_buf);
    }

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || r->header_only) {
        ngx_close_file(fd);
        return rc;
    }

    /* Build sendfile buf */
    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) { ngx_close_file(fd); return NGX_HTTP_INTERNAL_SERVER_ERROR; }

    b->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
    if (b->file == NULL) { ngx_close_file(fd); return NGX_HTTP_INTERNAL_SERVER_ERROR; }

    b->in_file           = 1;
    b->last_buf          = 1;
    b->last_in_chain     = 1;
    b->file->fd          = fd;
    b->file->name.data   = (u_char *) path;
    b->file->name.len    = strlen(path);
    b->file->log         = r->connection->log;
    b->file_pos          = range_start;
    b->file_last         = range_start + send_len;

    out.buf  = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}

/* ------------------------------------------------------------------ */
/* PUT body callback                                                    */
/* ------------------------------------------------------------------ */

static void
webdav_handle_put_body(ngx_http_request_t *r)
{
    ngx_http_xrootd_webdav_loc_conf_t *conf;
    char            path[WEBDAV_MAX_PATH];
    ngx_int_t       rc;
    ngx_fd_t        fd;
    ngx_buf_t      *buf;
    ngx_chain_t    *chain;
    ssize_t         n;
    int             created = 0;
    struct stat     sb;
    ngx_int_t       status;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);

    rc = webdav_resolve_path(r, &conf->root, path, sizeof(path));
    if (rc != NGX_OK) {
        ngx_http_finalize_request(r, (ngx_int_t) rc);
        return;
    }

    /* Check if target exists so we can return 201 vs 204 */
    created = (stat(path, &sb) != 0);

    fd = ngx_open_file(path,
                       NGX_FILE_WRONLY,
                       NGX_FILE_CREATE_OR_OPEN | NGX_FILE_TRUNCATE,
                       NGX_FILE_DEFAULT_ACCESS);
    if (fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                      "xrootd_webdav: open(\"%s\") for write failed", path);
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    /* Write all body buffers */
    if (r->request_body != NULL) {
        for (chain = r->request_body->bufs; chain != NULL; chain = chain->next) {
            buf = chain->buf;
            if (buf->in_file) {
                /* Body was spooled to disk by nginx */
                off_t off  = buf->file_pos;
                size_t len = (size_t)(buf->file_last - buf->file_pos);
                u_char *tmp = ngx_palloc(r->pool, 65536);
                if (!tmp) { ngx_close_file(fd); ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR); return; }
                while (len > 0) {
                    size_t chunk = len > 65536 ? 65536 : len;
                    ssize_t rd = pread(buf->file->fd, tmp, chunk, off);
                    if (rd <= 0) break;
                    if (write(fd, tmp, (size_t) rd) != rd) {
                        ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                                      "xrootd_webdav: write to \"%s\" failed", path);
                        ngx_close_file(fd);
                        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                        return;
                    }
                    off += rd;
                    len -= (size_t) rd;
                }
            } else if (buf->pos < buf->last) {
                n = write(fd, buf->pos, (size_t)(buf->last - buf->pos));
                if (n < 0) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                                  "xrootd_webdav: write to \"%s\" failed", path);
                    ngx_close_file(fd);
                    ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                    return;
                }
            }
        }
    }
    ngx_close_file(fd);

    status = created ? NGX_HTTP_CREATED : NGX_HTTP_NO_CONTENT;
    r->headers_out.status           = status;
    r->headers_out.content_length_n = 0;
    ngx_http_send_header(r);
    ngx_http_finalize_request(r, ngx_http_send_special(r, NGX_HTTP_LAST));
}

/* ------------------------------------------------------------------ */
/* DELETE                                                               */
/* ------------------------------------------------------------------ */

static ngx_int_t
webdav_handle_delete(ngx_http_request_t *r)
{
    ngx_http_xrootd_webdav_loc_conf_t *conf;
    char       path[WEBDAV_MAX_PATH];
    struct stat sb;
    ngx_int_t  rc;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);

    rc = webdav_resolve_path(r, &conf->root, path, sizeof(path));
    if (rc != NGX_OK) return (ngx_int_t) rc;

    if (stat(path, &sb) != 0) {
        return (errno == ENOENT) ? NGX_HTTP_NOT_FOUND
                                 : NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (S_ISDIR(sb.st_mode)) {
        if (rmdir(path) != 0) {
            return (errno == ENOTEMPTY) ? NGX_HTTP_CONFLICT
                                        : NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    } else {
        if (unlink(path) != 0) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    r->headers_out.status           = NGX_HTTP_NO_CONTENT;
    r->headers_out.content_length_n = 0;
    ngx_http_send_header(r);
    return ngx_http_send_special(r, NGX_HTTP_LAST);
}

/* ------------------------------------------------------------------ */
/* MKCOL                                                                */
/* ------------------------------------------------------------------ */

static ngx_int_t
webdav_handle_mkcol(ngx_http_request_t *r)
{
    ngx_http_xrootd_webdav_loc_conf_t *conf;
    char       path[WEBDAV_MAX_PATH];
    ngx_int_t  rc;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);

    rc = webdav_resolve_path(r, &conf->root, path, sizeof(path));
    /* 404 from resolve means the parent directory doesn't exist → 409 Conflict */
    if (rc == (ngx_int_t) NGX_HTTP_NOT_FOUND) return NGX_HTTP_CONFLICT;
    if (rc != NGX_OK) return (ngx_int_t) rc;

    if (mkdir(path, 0755) != 0) {
        if (errno == EEXIST) return NGX_HTTP_NOT_ALLOWED;
        if (errno == ENOENT) return NGX_HTTP_CONFLICT;
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->headers_out.status           = NGX_HTTP_CREATED;
    r->headers_out.content_length_n = 0;
    ngx_http_send_header(r);
    return ngx_http_send_special(r, NGX_HTTP_LAST);
}

/* ------------------------------------------------------------------ */
/* PROPFIND XML helpers                                                 */
/* ------------------------------------------------------------------ */

/*
 * Append formatted text to a dynamic ngx_buf chain, growing as needed.
 * Returns the current buffer (tail), or NULL on allocation error.
 */
static ngx_buf_t *
propfind_append(ngx_pool_t *pool, ngx_chain_t **head, ngx_chain_t **tail,
                const char *fmt, ...)
{
    va_list   ap;
    char      tmp[2048];
    size_t    n;
    ngx_buf_t    *b;
    ngx_chain_t  *lc;

    va_start(ap, fmt);
    n = (size_t) vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);

    if (n >= sizeof(tmp)) n = sizeof(tmp) - 1;
    if (n == 0) return (*tail ? (*tail)->buf : NULL);

    b = ngx_create_temp_buf(pool, n);
    if (b == NULL) return NULL;
    ngx_memcpy(b->pos, tmp, n);
    b->last = b->pos + n;

    lc = ngx_alloc_chain_link(pool);
    if (lc == NULL) return NULL;
    lc->buf  = b;
    lc->next = NULL;

    if (*tail == NULL) {
        *head = lc;
        *tail = lc;
    } else {
        (*tail)->next = lc;
        *tail = lc;
    }

    return b;
}

static ngx_int_t
propfind_entry(ngx_pool_t *pool, ngx_chain_t **head, ngx_chain_t **tail,
               const char *href, struct stat *sb)
{
    char date_buf[64];
    webdav_http_date(sb->st_mtime, date_buf, sizeof(date_buf));

    if (propfind_append(pool, head, tail,
            "<D:response>"
            "<D:href>%s</D:href>"
            "<D:propstat>"
            "<D:prop>", href) == NULL) return NGX_ERROR;

    if (S_ISDIR(sb->st_mode)) {
        if (propfind_append(pool, head, tail,
                "<D:resourcetype><D:collection/></D:resourcetype>"
                "<D:getcontentlength>0</D:getcontentlength>") == NULL)
            return NGX_ERROR;
    } else {
        if (propfind_append(pool, head, tail,
                "<D:resourcetype/>"
                "<D:getcontentlength>%lld</D:getcontentlength>",
                (long long) sb->st_size) == NULL)
            return NGX_ERROR;
    }

    if (propfind_append(pool, head, tail,
            "<D:getlastmodified>%s</D:getlastmodified>"
            "</D:prop>"
            "<D:status>HTTP/1.1 200 OK</D:status>"
            "</D:propstat>"
            "</D:response>", date_buf) == NULL) return NGX_ERROR;

    return NGX_OK;
}

/* ------------------------------------------------------------------ */
/* PROPFIND handler                                                     */
/* ------------------------------------------------------------------ */

static ngx_int_t
webdav_handle_propfind(ngx_http_request_t *r)
{
    ngx_http_xrootd_webdav_loc_conf_t *conf;
    char           path[WEBDAV_MAX_PATH];
    struct stat    sb;
    ngx_int_t      rc;
    int            depth = 0;          /* default: Depth: 0 */
    ngx_chain_t   *head = NULL, *tail = NULL;
    off_t          total_len = 0;
    ngx_chain_t   *lc;
    ngx_table_elt_t *h;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);

    rc = webdav_resolve_path(r, &conf->root, path, sizeof(path));
    if (rc != NGX_OK) return (ngx_int_t) rc;

    if (stat(path, &sb) != 0) {
        return (errno == ENOENT) ? NGX_HTTP_NOT_FOUND
                                 : NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Parse Depth header */
    {
        ngx_list_part_t  *part = &r->headers_in.headers.part;
        ngx_table_elt_t  *hdr  = part->elts;
        ngx_uint_t        i;

        for (;;) {
            for (i = 0; i < part->nelts; i++) {
                if (hdr[i].key.len == 5 &&
                    ngx_strncasecmp(hdr[i].key.data,
                                    (u_char *) "Depth", 5) == 0)
                {
                    if (hdr[i].value.len == 1 &&
                        hdr[i].value.data[0] == '1') {
                        depth = 1;
                    }
                }
            }
            if (part->next == NULL) break;
            part = part->next;
            hdr  = part->elts;
        }
    }

    /* Build XML response */
    if (propfind_append(r->pool, &head, &tail,
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            "<D:multistatus xmlns:D=\"DAV:\">") == NULL)
        return NGX_HTTP_INTERNAL_SERVER_ERROR;

    /* The self entry: URL path is the href */
    {
        char href[WEBDAV_MAX_PATH + 2];
        size_t uri_len = r->uri.len;
        if (uri_len >= sizeof(href) - 1) uri_len = sizeof(href) - 2;
        ngx_memcpy(href, r->uri.data, uri_len);
        href[uri_len] = '\0';

        if (propfind_entry(r->pool, &head, &tail, href, &sb) != NGX_OK)
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Depth:1 – enumerate directory contents */
    if (depth == 1 && S_ISDIR(sb.st_mode)) {
        DIR *dp = opendir(path);
        if (dp != NULL) {
            struct dirent *de;
            while ((de = readdir(dp)) != NULL) {
                if (de->d_name[0] == '.') continue; /* skip . and .. */

                char child_path[WEBDAV_MAX_PATH];
                if ((size_t) snprintf(child_path, sizeof(child_path),
                             "%s/%s", path, de->d_name) >= sizeof(child_path))
                    continue;

                struct stat csb;
                if (stat(child_path, &csb) != 0) continue;

                /* Build href for child: parent URI + "/" + name */
                char href[WEBDAV_MAX_PATH + 2];
                {
                    const char *base = (const char *) r->uri.data;
                    size_t blen = r->uri.len;
                    /* Ensure trailing slash on directory href */
                    if (blen == 0 || base[blen - 1] != '/') {
                        snprintf(href, sizeof(href), "%.*s/%s",
                                 (int) blen, base, de->d_name);
                    } else {
                        snprintf(href, sizeof(href), "%.*s%s",
                                 (int) blen, base, de->d_name);
                    }
                }

                if (propfind_entry(r->pool, &head, &tail, href, &csb) != NGX_OK) {
                    closedir(dp);
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
            }
            closedir(dp);
        }
    }

    if (propfind_append(r->pool, &head, &tail,
                        "</D:multistatus>") == NULL)
        return NGX_HTTP_INTERNAL_SERVER_ERROR;

    /* Mark the last buffer */
    if (tail != NULL) {
        tail->buf->last_buf      = 1;
        tail->buf->last_in_chain = 1;
    }

    /* Compute total content length */
    for (lc = head; lc != NULL; lc = lc->next) {
        total_len += lc->buf->last - lc->buf->pos;
    }

    /* 207 Multi-Status */
    r->headers_out.status           = 207;
    r->headers_out.content_length_n = total_len;

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    h->hash = 1;
    ngx_str_set(&h->key, "Content-Type");
    ngx_str_set(&h->value, "application/xml; charset=\"utf-8\"");

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, head);
}
