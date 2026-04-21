/*
 * Shared declarations for the nginx HTTP WebDAV/XRootD module.
 *
 * This header is the contract between the WebDAV module files:
 *   ngx_http_xrootd_webdav_module.c   — config, lifecycle, dispatcher, fd cache
 *   ngx_http_xrootd_webdav_auth.c     — GSI/x509 and bearer-token authentication
 *   ngx_http_xrootd_webdav_path.c     — URL decoding, path security, resolve
 *   ngx_http_xrootd_webdav_handlers.c — HTTP method handlers (GET/PUT/…)
 *   ngx_http_xrootd_webdav_tpc.c      — HTTP-TPC COPY pull support
 */

#ifndef NGX_HTTP_XROOTD_WEBDAV_MODULE_H
#define NGX_HTTP_XROOTD_WEBDAV_MODULE_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#if (NGX_THREADS)
#include <ngx_thread_pool.h>
#endif

#include "ngx_xrootd_token.h"

typedef struct x509_store_st X509_STORE;

/* Maximum path length we'll construct */
#define WEBDAV_MAX_PATH   4096

/* Maximum simultaneously cached fds per connection (keepalive fd table) */
#define WEBDAV_FD_TABLE_SIZE  16

/* Buffered PUT fallback copy size when copy_file_range is unavailable */
#define WEBDAV_PUT_COPY_BUFSZ   (1024 * 1024)

/* Large copy_file_range requests reduce syscall count on spooled uploads */
#define WEBDAV_PUT_COPY_CHUNK   (16 * 1024 * 1024)

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
    X509_STORE    *ca_store;      /* cached CA/CRL store for manual validation */

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

    /* Thread pool for async I/O (resolved at postconfiguration) */
    ngx_str_t           thread_pool_name;
#if (NGX_THREADS)
    ngx_thread_pool_t  *thread_pool;
#endif

    /* Pre-resolved canonical root path (eliminates per-request realpath) */
    char                root_canon[WEBDAV_MAX_PATH];
} ngx_http_xrootd_webdav_loc_conf_t;

/* Per-request auth result: cached across sub-handlers */
typedef struct {
    int            verified;      /* 1 = chain passed, 0 = failed/absent */
    char           dn[1024];
    const char    *auth_source;   /* manual, nginx, tls-connection, tls-session, token */
    int            token_auth;    /* 1 = authenticated via bearer token */
    int            token_scope_count;
    xrootd_token_scope_t  token_scopes[XROOTD_MAX_TOKEN_SCOPES];
} ngx_http_xrootd_webdav_req_ctx_t;

/* Per-connection fd cache entry (survives HTTP keepalive) */
typedef struct {
    ngx_fd_t    fd;                      /* OS fd; NGX_INVALID_FILE = unused */
    char        path[WEBDAV_MAX_PATH];   /* resolved canonical path          */
    uint64_t    uri_hash;                /* FNV-1a of decoded URI for fast GET */
    ino_t       ino;                     /* inode at open time for staleness  */
    dev_t       dev;                     /* device at open time              */
    ngx_msec_t  open_time;               /* monotonic time when cached       */
} webdav_fd_entry_t;

/* Per-connection context attached to c->pool (survives keepalive) */
typedef struct {
    webdav_fd_entry_t  fds[WEBDAV_FD_TABLE_SIZE];
    int                count;            /* populated slot count             */
} webdav_fd_table_t;

/* ---- Module object ------------------------------------------------- */

extern ngx_module_t ngx_http_xrootd_webdav_module;

/* ---- Shared utility (from ngx_xrootd_module) ---------------------- */

size_t xrootd_sanitize_log_string(const char *in, char *out, size_t outsz);

/* ---- Path utilities (ngx_http_xrootd_webdav_path.c) ---------------- */

ngx_int_t ngx_http_xrootd_webdav_resolve_path(ngx_http_request_t *r,
    const char *root_canon, char *out, size_t outsz);
void ngx_http_xrootd_webdav_log_safe_path(ngx_log_t *log, ngx_uint_t level,
    ngx_err_t err, const char *prefix, const char *path);
ngx_int_t webdav_urldecode(const u_char *src, size_t src_len,
    char *dst, size_t dst_sz);
char *webdav_escape_xml_text(ngx_pool_t *pool, const char *src);

/* ---- Auth (ngx_http_xrootd_webdav_auth.c) -------------------------- */

ngx_int_t webdav_auth_init_ssl_indices(ngx_log_t *log);
X509_STORE *webdav_build_ca_store(ngx_log_t *log,
    ngx_http_xrootd_webdav_loc_conf_t *conf, int *crl_count_out);
ngx_int_t webdav_verify_proxy_cert(ngx_http_request_t *r,
    ngx_http_xrootd_webdav_loc_conf_t *conf);
ngx_int_t webdav_verify_bearer_token(ngx_http_request_t *r,
    ngx_http_xrootd_webdav_loc_conf_t *conf);
ngx_int_t webdav_check_token_write_scope(ngx_http_request_t *r,
    const char *method_name);
/* PKI consistency checks invoked at postconfiguration/startup */
ngx_int_t webdav_check_pki_consistency(ngx_log_t *log,
    ngx_http_xrootd_webdav_loc_conf_t *conf);

/* ---- HTTP method handlers (ngx_http_xrootd_webdav_handlers.c) ------ */

ngx_int_t webdav_handle_options(ngx_http_request_t *r);
ngx_int_t webdav_handle_head(ngx_http_request_t *r, int send_body);
ngx_int_t webdav_handle_get(ngx_http_request_t *r);
void      webdav_handle_put_body(ngx_http_request_t *r);
ngx_int_t webdav_handle_delete(ngx_http_request_t *r);
ngx_int_t webdav_handle_mkcol(ngx_http_request_t *r);
ngx_int_t webdav_handle_propfind(ngx_http_request_t *r);

/* ---- FD cache (ngx_http_xrootd_webdav_module.c) -------------------- */

webdav_fd_table_t *webdav_get_fd_table(ngx_connection_t *c);
ngx_fd_t webdav_fd_table_get(webdav_fd_table_t *t, const char *path,
    const struct stat *sb);
void webdav_fd_table_put(webdav_fd_table_t *t, const char *path,
    const struct stat *sb, ngx_fd_t fd, uint64_t uri_hash);
void webdav_fd_table_evict(webdav_fd_table_t *t, const char *path);
uint64_t webdav_uri_hash(const char *s);
ngx_fd_t webdav_fd_table_get_by_uri(webdav_fd_table_t *t, uint64_t uri_hash,
    struct stat *sb_out);
void webdav_fadvise_willneed(ngx_log_t *log, ngx_fd_t fd, off_t offset,
    size_t len);

/* ---- I/O utilities (ngx_http_xrootd_webdav_module.c) --------------- */

ngx_int_t webdav_write_full(ngx_fd_t fd, u_char *buf, size_t len);
ngx_int_t webdav_copy_spooled_file(ngx_http_request_t *r, ngx_fd_t dst_fd,
    ngx_buf_t *buf, const char *path, u_char **scratch);

/* ---- HTTP-TPC (ngx_http_xrootd_webdav_tpc.c) ---------------------- */

void ngx_http_xrootd_webdav_tpc_create_loc_conf(
    ngx_http_xrootd_webdav_loc_conf_t *conf);
void ngx_http_xrootd_webdav_tpc_merge_loc_conf(
    ngx_http_xrootd_webdav_loc_conf_t *conf,
    ngx_http_xrootd_webdav_loc_conf_t *prev);
ngx_int_t ngx_http_xrootd_webdav_tpc_handle_copy(ngx_http_request_t *r);

#endif /* NGX_HTTP_XROOTD_WEBDAV_MODULE_H */
