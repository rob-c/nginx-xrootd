/*
 * Shared declarations for the nginx HTTP WebDAV/XRootD module.
 *
 * Keep this header as the narrow contract between "vanilla" WebDAV
 * (ngx_http_xrootd_webdav_module.c) and optional HTTP-TPC COPY support
 * (ngx_http_xrootd_webdav_tpc.c).  Protocol parsing details belong in the
 * .c files; this header should mostly describe shared nginx configuration,
 * request auth state, and the few helpers needed across files.
 */

#ifndef NGX_HTTP_XROOTD_WEBDAV_MODULE_H
#define NGX_HTTP_XROOTD_WEBDAV_MODULE_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_xrootd_token.h"

/* Maximum path length we'll construct */
#define WEBDAV_MAX_PATH   4096

typedef enum {
    WEBDAV_AUTH_NONE,
    WEBDAV_AUTH_OPTIONAL,
    WEBDAV_AUTH_REQUIRED,
} webdav_auth_t;

typedef struct {
    ngx_flag_t     enable;
    ngx_str_t      root;

    /*
     * Certificate trust inputs used by manual x509/proxy validation.
     * nginx's TLS layer can ask for a client certificate, but this module does
     * the grid/proxy-specific verification itself so deployments can accept
     * RFC 3820 proxy certificates consistently.
     */
    ngx_str_t      cadir;
    ngx_str_t      cafile;
    ngx_str_t      crl;           /* xrootd_webdav_crl /path/to/crl.pem */
    ngx_uint_t     verify_depth;
    ngx_uint_t     auth;          /* webdav_auth_t */
    ngx_flag_t     proxy_certs;   /* set X509_V_FLAG_ALLOW_PROXY_CERTS on SSL CTX */

    /*
     * Generic write opt-in plus HTTP-TPC-specific settings.  COPY handling is
     * in ngx_http_xrootd_webdav_tpc.c, but nginx still stores all location
     * config in one per-location struct.
     */
    ngx_flag_t     allow_write;
    ngx_flag_t     tpc;           /* HTTP-TPC COPY pull support */
    ngx_str_t      tpc_curl;
    ngx_str_t      tpc_cert;
    ngx_str_t      tpc_key;
    ngx_str_t      tpc_cadir;
    ngx_str_t      tpc_cafile;
    ngx_uint_t     tpc_timeout;

    /* Token (JWT/WLCG) authentication */
    ngx_str_t      token_jwks;
    ngx_str_t      token_issuer;
    ngx_str_t      token_audience;

    /* Loaded JWKS keys (populated at postconfiguration) */
    xrootd_jwks_key_t  jwks_keys[XROOTD_MAX_JWKS_KEYS];
    int                 jwks_key_count;
} ngx_http_xrootd_webdav_loc_conf_t;

/* Per-request auth result: cached across sub-handlers */
typedef struct {
    int            verified;      /* 1 = chain passed, 0 = failed/absent */
    char           dn[1024];
    int            token_auth;    /* 1 = authenticated via bearer token */
    int            token_scope_count;
    xrootd_token_scope_t  token_scopes[XROOTD_MAX_TOKEN_SCOPES];
} ngx_http_xrootd_webdav_req_ctx_t;

extern ngx_module_t ngx_http_xrootd_webdav_module;

ngx_int_t ngx_http_xrootd_webdav_resolve_path(ngx_http_request_t *r,
    const ngx_str_t *root, char *out, size_t outsz);
void ngx_http_xrootd_webdav_log_safe_path(ngx_log_t *log, ngx_uint_t level,
    ngx_err_t err, const char *prefix, const char *path);

void ngx_http_xrootd_webdav_tpc_create_loc_conf(
    ngx_http_xrootd_webdav_loc_conf_t *conf);
void ngx_http_xrootd_webdav_tpc_merge_loc_conf(
    ngx_http_xrootd_webdav_loc_conf_t *conf,
    ngx_http_xrootd_webdav_loc_conf_t *prev);
ngx_int_t ngx_http_xrootd_webdav_tpc_handle_copy(ngx_http_request_t *r);

#endif /* NGX_HTTP_XROOTD_WEBDAV_MODULE_H */
