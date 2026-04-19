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
 *       COPY / HTTP-TPC is deliberately kept in ngx_http_xrootd_webdav_tpc.c.
 *       The dispatcher below still performs the generic WebDAV checks
 *       (auth, writes enabled, token scope) before delegating to that file.
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

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/x509_vfy.h>

#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <dirent.h>
#include <limits.h>
#include <time.h>
#include <unistd.h>

#include "ngx_http_xrootd_webdav_module.h"

size_t xrootd_sanitize_log_string(const char *in, char *out, size_t outsz);

/* Maximum PUT body size (16 MiB) */
#define WEBDAV_MAX_PUT    (16 * 1024 * 1024)
/* PROPFIND response buffer initial size */
#define WEBDAV_XML_CHUNK  4096
/* Buffered PUT fallback copy size when copy_file_range is unavailable */
#define WEBDAV_PUT_COPY_BUFSZ   (1024 * 1024)
/* Large copy_file_range requests reduce syscall count on spooled uploads */
#define WEBDAV_PUT_COPY_CHUNK   (16 * 1024 * 1024)

typedef struct {
    ngx_http_xrootd_webdav_loc_conf_t *conf;
    X509_STORE                        *store;
    ngx_uint_t                         verify_depth;
    char                               dn[1024];
} ngx_http_xrootd_webdav_tls_auth_cache_t;

static int webdav_ssl_auth_cache_index = -1;
static int webdav_ssl_session_auth_cache_index = -1;

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

static ngx_int_t webdav_verify_proxy_cert(ngx_http_request_t *r,
                                          ngx_http_xrootd_webdav_loc_conf_t *cf);
static ngx_int_t webdav_check_token_write_scope(ngx_http_request_t *r,
                                                const char *method_name);
static ngx_int_t webdav_write_full(ngx_fd_t fd, u_char *buf, size_t len);
static ngx_int_t webdav_copy_spooled_file(ngx_http_request_t *r, ngx_fd_t dst_fd,
                                          ngx_buf_t *buf, const char *path,
                                          u_char **scratch);

static void     *ngx_http_xrootd_webdav_create_loc_conf(ngx_conf_t *cf);
static char     *ngx_http_xrootd_webdav_merge_loc_conf(ngx_conf_t *cf,
                                                        void *parent,
                                                        void *child);
static ngx_int_t ngx_http_xrootd_webdav_postconfiguration(ngx_conf_t *cf);

static void webdav_x509_store_cleanup(void *data);
static void webdav_tls_auth_cache_free(void *parent, void *ptr,
    CRYPTO_EX_DATA *ad, int idx, long argl, void *argp);
static X509_STORE *webdav_build_ca_store(ngx_log_t *log,
    ngx_http_xrootd_webdav_loc_conf_t *conf, int *crl_count_out);

typedef enum {
    WEBDAV_PATH_REGULAR_FILE,
    WEBDAV_PATH_DIRECTORY,
    WEBDAV_PATH_FILE_OR_DIRECTORY
} webdav_path_kind_t;

static ngx_int_t
webdav_validate_path(ngx_conf_t *cf, const char *label, const ngx_str_t *path,
                     webdav_path_kind_t kind, int access_mode)
{
    struct stat st;

    if (path == NULL || path->len == 0 || path->data == NULL) {
        return NGX_OK;
    }

    if (stat((char *) path->data, &st) != 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           "xrootd_webdav: %s path \"%s\" is not accessible",
                           label, path->data);
        return NGX_ERROR;
    }

    switch (kind) {
    case WEBDAV_PATH_REGULAR_FILE:
        if (!S_ISREG(st.st_mode)) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "xrootd_webdav: %s path \"%s\" must be a regular file",
                               label, path->data);
            return NGX_ERROR;
        }
        break;

    case WEBDAV_PATH_DIRECTORY:
        if (!S_ISDIR(st.st_mode)) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "xrootd_webdav: %s path \"%s\" must be a directory",
                               label, path->data);
            return NGX_ERROR;
        }
        break;

    case WEBDAV_PATH_FILE_OR_DIRECTORY:
        if (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode)) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "xrootd_webdav: %s path \"%s\" must be a file or directory",
                               label, path->data);
            return NGX_ERROR;
        }
        break;
    }

    if (access_mode != 0 && access((char *) path->data, access_mode) != 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           "xrootd_webdav: %s path \"%s\" failed permission check",
                           label, path->data);
        return NGX_ERROR;
    }

    return NGX_OK;
}

static void
webdav_x509_store_cleanup(void *data)
{
    X509_STORE *store = data;

    if (store != NULL) {
        X509_STORE_free(store);
    }
}

static void
webdav_tls_auth_cache_free(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
                           int idx, long argl, void *argp)
{
    (void) parent;
    (void) ad;
    (void) idx;
    (void) argl;
    (void) argp;

    if (ptr != NULL) {
        OPENSSL_free(ptr);
    }
}

static ngx_int_t
webdav_str_equal(const ngx_str_t *a, const ngx_str_t *b)
{
    if (a->len != b->len) {
        return 0;
    }

    if (a->len == 0) {
        return 1;
    }

    return ngx_memcmp(a->data, b->data, a->len) == 0;
}

static ngx_int_t
webdav_write_full(ngx_fd_t fd, u_char *buf, size_t len)
{
    while (len > 0) {
        ssize_t nwritten;

        nwritten = write(fd, buf, len);
        if (nwritten < 0) {
            if (errno == EINTR) {
                continue;
            }
            return NGX_ERROR;
        }

        if (nwritten == 0) {
            errno = EIO;
            return NGX_ERROR;
        }

        buf += (size_t) nwritten;
        len -= (size_t) nwritten;
    }

    return NGX_OK;
}

static ngx_int_t
webdav_copy_spooled_file(ngx_http_request_t *r, ngx_fd_t dst_fd, ngx_buf_t *buf,
                         const char *path, u_char **scratch)
{
    off_t   src_off;
    size_t  remaining;

    if (buf->file == NULL || buf->file->fd == NGX_INVALID_FILE) {
        errno = EINVAL;
        return NGX_ERROR;
    }

    src_off = buf->file_pos;
    remaining = (size_t) (buf->file_last - buf->file_pos);

#if defined(__linux__) && defined(SYS_copy_file_range)
    while (remaining > 0) {
        size_t  want;
        ssize_t copied;

        want = remaining > WEBDAV_PUT_COPY_CHUNK
                   ? WEBDAV_PUT_COPY_CHUNK
                   : remaining;

        copied = syscall(SYS_copy_file_range, buf->file->fd, &src_off,
                         dst_fd, NULL, want, 0);
        if (copied > 0) {
            remaining -= (size_t) copied;
            continue;
        }

        if (copied == 0) {
            errno = EIO;
            ngx_http_xrootd_webdav_log_safe_path(
                r->connection->log, NGX_LOG_ERR, errno,
                "xrootd_webdav: copy_file_range() hit unexpected EOF for",
                path);
            return NGX_ERROR;
        }

        if (errno == EINTR) {
            continue;
        }

        if (errno != ENOSYS
            && errno != EOPNOTSUPP
            && errno != EINVAL
            && errno != EXDEV
            && errno != EPERM)
        {
            ngx_http_xrootd_webdav_log_safe_path(
                r->connection->log, NGX_LOG_ERR, errno,
                "xrootd_webdav: copy_file_range() failed for",
                path);
            return NGX_ERROR;
        }

        break;
    }

    if (remaining == 0) {
        return NGX_OK;
    }
#endif

    if (*scratch == NULL) {
        *scratch = ngx_palloc(r->pool, WEBDAV_PUT_COPY_BUFSZ);
        if (*scratch == NULL) {
            return NGX_ERROR;
        }
    }

    while (remaining > 0) {
        size_t  chunk;
        ssize_t nread;

        chunk = remaining > WEBDAV_PUT_COPY_BUFSZ
                    ? WEBDAV_PUT_COPY_BUFSZ
                    : remaining;

        nread = pread(buf->file->fd, *scratch, chunk, src_off);
        if (nread < 0) {
            if (errno == EINTR) {
                continue;
            }

            ngx_http_xrootd_webdav_log_safe_path(
                r->connection->log, NGX_LOG_ERR, errno,
                "xrootd_webdav: pread() failed for",
                path);
            return NGX_ERROR;
        }

        if (nread == 0) {
            errno = EIO;
            ngx_http_xrootd_webdav_log_safe_path(
                r->connection->log, NGX_LOG_ERR, errno,
                "xrootd_webdav: short temp-file body read for",
                path);
            return NGX_ERROR;
        }

        if (webdav_write_full(dst_fd, *scratch, (size_t) nread) != NGX_OK) {
            ngx_http_xrootd_webdav_log_safe_path(
                r->connection->log, NGX_LOG_ERR, ngx_errno,
                "xrootd_webdav: write() failed for",
                path);
            return NGX_ERROR;
        }

        src_off += (off_t) nread;
        remaining -= (size_t) nread;
    }

    return NGX_OK;
}

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

    { ngx_string("xrootd_webdav_crl"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, crl),
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

    /*
     * HTTP-TPC directives are declared here because nginx requires all
     * directives for a module to live in that module's command table.  Their
     * defaulting and request handling live in ngx_http_xrootd_webdav_tpc.c.
     */
    { ngx_string("xrootd_webdav_tpc"),
      NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, tpc),
      NULL },

    { ngx_string("xrootd_webdav_tpc_curl"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, tpc_curl),
      NULL },

    { ngx_string("xrootd_webdav_tpc_cert"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, tpc_cert),
      NULL },

    { ngx_string("xrootd_webdav_tpc_key"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, tpc_key),
      NULL },

    { ngx_string("xrootd_webdav_tpc_cadir"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, tpc_cadir),
      NULL },

    { ngx_string("xrootd_webdav_tpc_cafile"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, tpc_cafile),
      NULL },

    { ngx_string("xrootd_webdav_tpc_timeout"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, tpc_timeout),
      NULL },

    { ngx_string("xrootd_webdav_token_jwks"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, token_jwks),
      NULL },

    { ngx_string("xrootd_webdav_token_issuer"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, token_issuer),
      NULL },

    { ngx_string("xrootd_webdav_token_audience"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, token_audience),
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
    conf->ca_store    = NULL;
    ngx_http_xrootd_webdav_tpc_create_loc_conf(conf);

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
    ngx_conf_merge_str_value(conf->crl,      prev->crl,          "");
    ngx_conf_merge_uint_value(conf->verify_depth, prev->verify_depth, 10);
    ngx_conf_merge_uint_value(conf->auth,    prev->auth,
                              WEBDAV_AUTH_OPTIONAL);
    ngx_conf_merge_value(conf->proxy_certs,  prev->proxy_certs,  0);
    ngx_conf_merge_value(conf->allow_write,  prev->allow_write,  0);
    ngx_http_xrootd_webdav_tpc_merge_loc_conf(conf, prev);

    ngx_conf_merge_str_value(conf->token_jwks,     prev->token_jwks,     "");
    ngx_conf_merge_str_value(conf->token_issuer,   prev->token_issuer,   "");
    ngx_conf_merge_str_value(conf->token_audience,  prev->token_audience, "");

    if (conf->enable) {
        if (webdav_validate_path(cf, "xrootd_webdav_root", &conf->root,
                                 WEBDAV_PATH_DIRECTORY,
                                 conf->allow_write ? (R_OK | W_OK | X_OK)
                                                   : (R_OK | X_OK))
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }

        if (conf->auth == WEBDAV_AUTH_OPTIONAL || conf->auth == WEBDAV_AUTH_REQUIRED) {
            if (conf->cadir.len == 0 && conf->cafile.len == 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "xrootd_webdav: auth optional/required needs xrootd_webdav_cadir or xrootd_webdav_cafile");
                return NGX_CONF_ERROR;
            }
        }

        if (webdav_validate_path(cf, "xrootd_webdav_cadir", &conf->cadir,
                                 WEBDAV_PATH_DIRECTORY, R_OK | X_OK)
            != NGX_OK
            || webdav_validate_path(cf, "xrootd_webdav_cafile", &conf->cafile,
                                    WEBDAV_PATH_REGULAR_FILE, R_OK) != NGX_OK
            || webdav_validate_path(cf, "xrootd_webdav_crl", &conf->crl,
                                    WEBDAV_PATH_FILE_OR_DIRECTORY, R_OK) != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }

        if (conf->auth == WEBDAV_AUTH_OPTIONAL
            || conf->auth == WEBDAV_AUTH_REQUIRED)
        {
            X509_STORE         *store;
            ngx_pool_cleanup_t *cln;
            int                 crl_count = 0;

            store = webdav_build_ca_store(cf->log, conf, &crl_count);
            if (store == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "xrootd_webdav: failed to build cached CA store");
                return NGX_CONF_ERROR;
            }

            cln = ngx_pool_cleanup_add(cf->pool, 0);
            if (cln == NULL) {
                X509_STORE_free(store);
                return NGX_CONF_ERROR;
            }

            cln->handler = webdav_x509_store_cleanup;
            cln->data = store;
            conf->ca_store = store;

            ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                               "xrootd_webdav: cached CA store built"
                               " for root=\"%V\" crls=%d",
                               &conf->root, crl_count);
        }

        if (conf->token_jwks.len > 0) {
            if (conf->token_issuer.len == 0 || conf->token_audience.len == 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "xrootd_webdav: xrootd_webdav_token_jwks requires xrootd_webdav_token_issuer and xrootd_webdav_token_audience");
                return NGX_CONF_ERROR;
            }

            if (webdav_validate_path(cf, "xrootd_webdav_token_jwks",
                                     &conf->token_jwks,
                                     WEBDAV_PATH_REGULAR_FILE, R_OK)
                != NGX_OK)
            {
                return NGX_CONF_ERROR;
            }
        }

        if (conf->tpc) {
            if (webdav_validate_path(cf, "xrootd_webdav_tpc_curl",
                                     &conf->tpc_curl,
                                     WEBDAV_PATH_REGULAR_FILE, X_OK)
                != NGX_OK
                || webdav_validate_path(cf, "xrootd_webdav_tpc_cert",
                                        &conf->tpc_cert,
                                        WEBDAV_PATH_REGULAR_FILE, R_OK)
                   != NGX_OK
                || webdav_validate_path(cf, "xrootd_webdav_tpc_key",
                                        &conf->tpc_key,
                                        WEBDAV_PATH_REGULAR_FILE, R_OK)
                   != NGX_OK
                || webdav_validate_path(cf, "xrootd_webdav_tpc_cadir",
                                        &conf->tpc_cadir,
                                        WEBDAV_PATH_DIRECTORY, R_OK | X_OK)
                   != NGX_OK
                || webdav_validate_path(cf, "xrootd_webdav_tpc_cafile",
                                        &conf->tpc_cafile,
                                        WEBDAV_PATH_REGULAR_FILE, R_OK)
                   != NGX_OK)
            {
                return NGX_CONF_ERROR;
            }
        }
    }

    /* Load JWKS keys if token is configured. */
    if (conf->token_jwks.len > 0) {
        int rc = xrootd_jwks_load(cf->log,
                                  (const char *) conf->token_jwks.data,
                                  conf->jwks_keys, XROOTD_MAX_JWKS_KEYS);
        if (rc < 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "xrootd_webdav: failed to load JWKS from \"%V\"",
                               &conf->token_jwks);
            return NGX_CONF_ERROR;
        }
        conf->jwks_key_count = rc;
    }

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

    if (webdav_ssl_auth_cache_index < 0) {
        webdav_ssl_auth_cache_index = SSL_get_ex_new_index(0, NULL, NULL,
                                                           NULL, NULL);
        if (webdav_ssl_auth_cache_index < 0) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "xrootd_webdav: SSL_get_ex_new_index() failed");
            return NGX_ERROR;
        }
    }

    if (webdav_ssl_session_auth_cache_index < 0) {
        webdav_ssl_session_auth_cache_index =
            SSL_SESSION_get_ex_new_index(0, NULL, NULL, NULL,
                                         webdav_tls_auth_cache_free);
        if (webdav_ssl_session_auth_cache_index < 0) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "xrootd_webdav: SSL_SESSION_get_ex_new_index() failed");
            return NGX_ERROR;
        }
    }

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
webdav_hex_value(u_char ch, u_char *value)
{
    if (ch >= '0' && ch <= '9') {
        *value = (u_char) (ch - '0');
        return NGX_OK;
    }

    if (ch >= 'a' && ch <= 'f') {
        *value = (u_char) (ch - 'a' + 10);
        return NGX_OK;
    }

    if (ch >= 'A' && ch <= 'F') {
        *value = (u_char) (ch - 'A' + 10);
        return NGX_OK;
    }

    return NGX_ERROR;
}

static ngx_inline u_char
webdav_hex_digit(u_char value)
{
    return (value < 10) ? (u_char) ('0' + value)
                        : (u_char) ('A' + (value - 10));
}

void
ngx_http_xrootd_webdav_log_safe_path(ngx_log_t *log, ngx_uint_t level,
                                     ngx_err_t err, const char *prefix,
                                     const char *path)
{
    char safe_path[512];

    xrootd_sanitize_log_string(path, safe_path, sizeof(safe_path));
    ngx_log_error(level, log, err, "%s: \"%s\"", prefix, safe_path);
}

static int
webdav_path_within_root(const char *root_canon, const char *path_canon)
{
    size_t root_len = strlen(root_canon);

    if (strncmp(path_canon, root_canon, root_len) != 0) {
        return 0;
    }

    return path_canon[root_len] == '\0' || path_canon[root_len] == '/';
}

static int
webdav_path_component_forbidden(const char *comp, size_t comp_len)
{
    return (comp_len == 1 && comp[0] == '.')
        || (comp_len == 2 && comp[0] == '.' && comp[1] == '.');
}

static int
webdav_path_has_forbidden_components(const char *path)
{
    const char *scan = path;

    while (*scan == '/') {
        scan++;
    }

    while (*scan != '\0') {
        const char *seg_end;
        size_t      seg_len;

        while (*scan == '/') {
            scan++;
        }
        if (*scan == '\0') {
            break;
        }

        seg_end = strchr(scan, '/');
        seg_len = seg_end ? (size_t) (seg_end - scan) : strlen(scan);

        if (webdav_path_component_forbidden(scan, seg_len)) {
            return 1;
        }

        if (seg_end == NULL) {
            break;
        }

        scan = seg_end + 1;
    }

    return 0;
}

static ngx_int_t
webdav_urldecode(const u_char *src, size_t src_len, char *dst, size_t dst_sz)
{
    size_t i = 0;
    size_t j = 0;
    u_char hi;
    u_char lo;
    u_char decoded;

    if (dst == NULL || dst_sz < 2) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    while (i < src_len) {
        if (j + 1 >= dst_sz) {
            return NGX_HTTP_REQUEST_URI_TOO_LARGE;
        }

        if (src[i] == '%' && i + 2 < src_len
            && webdav_hex_value(src[i + 1], &hi) == NGX_OK
            && webdav_hex_value(src[i + 2], &lo) == NGX_OK)
        {
            decoded = (u_char) ((hi << 4) | lo);
            if (decoded == '\0') {
                return NGX_HTTP_BAD_REQUEST;
            }

            dst[j++] = (char) decoded;
            i += 3;
            continue;
        }

        dst[j++] = (char) src[i++];
    }

    dst[j] = '\0';
    return NGX_OK;
}

static char *
webdav_escape_xml_text(ngx_pool_t *pool, const char *src)
{
    const u_char *in;
    u_char       *out;
    u_char       *escaped;
    size_t        src_len;

    if (pool == NULL || src == NULL) {
        return NULL;
    }

    src_len = strlen(src);
    escaped = ngx_pnalloc(pool, src_len * 6 + 1);
    if (escaped == NULL) {
        return NULL;
    }

    in = (const u_char *) src;
    out = escaped;

    while (*in != '\0') {
        switch (*in) {
        case '&':
            out = ngx_cpymem(out, "&amp;", sizeof("&amp;") - 1);
            break;
        case '<':
            out = ngx_cpymem(out, "&lt;", sizeof("&lt;") - 1);
            break;
        case '>':
            out = ngx_cpymem(out, "&gt;", sizeof("&gt;") - 1);
            break;
        case '"':
            out = ngx_cpymem(out, "&quot;", sizeof("&quot;") - 1);
            break;
        case '\'':
            out = ngx_cpymem(out, "&#39;", sizeof("&#39;") - 1);
            break;
        default:
            if (*in < 0x20 || *in == 0x7f) {
                *out++ = '%';
                *out++ = webdav_hex_digit((u_char) (*in >> 4));
                *out++ = webdav_hex_digit((u_char) (*in & 0x0f));
            } else {
                *out++ = *in;
            }
            break;
        }

        in++;
    }

    *out = '\0';
    return (char *) escaped;
}

/* ------------------------------------------------------------------ */
/* Utility: resolve request URI path under the configured root          */
/* Returns NGX_OK and fills out[] on success, NGX_HTTP_* error code    */
/* on traversal attack or other error.                                  */
/* ------------------------------------------------------------------ */

ngx_int_t
ngx_http_xrootd_webdav_resolve_path(ngx_http_request_t *r,
                                    const ngx_str_t *root,
                                    char *out, size_t outsz)
{
    char   root_buf[PATH_MAX];
    char   root_canon[PATH_MAX];
    char   uri_decoded[WEBDAV_MAX_PATH];
    char   combined[PATH_MAX];
    char   resolved[PATH_MAX];
    ngx_int_t rc;

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
    rc = webdav_urldecode(r->uri.data, r->uri.len,
                          uri_decoded, sizeof(uri_decoded));
    if (rc != NGX_OK) {
        if (rc == NGX_HTTP_BAD_REQUEST) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "xrootd_webdav: rejecting URI with decoded NUL");
        }
        return rc;
    }

    /* Strip trailing slashes (MKCOL /dir/ should resolve same as /dir) */
    {
        size_t uri_dlen = strlen(uri_decoded);
        while (uri_dlen > 1 && uri_decoded[uri_dlen - 1] == '/') {
            uri_decoded[--uri_dlen] = '\0';
        }
    }

    if (webdav_path_has_forbidden_components(uri_decoded)) {
        ngx_http_xrootd_webdav_log_safe_path(r->connection->log,
                                             NGX_LOG_WARN, 0,
                                             "xrootd_webdav: path traversal "
                                             "attempt",
                                             uri_decoded);
        return NGX_HTTP_FORBIDDEN;
    }

    /* Construct the on-disk target by appending the decoded URI to the root. */
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
                ngx_http_xrootd_webdav_log_safe_path(r->connection->log,
                                                     NGX_LOG_WARN, errno,
                                                     "xrootd_webdav: cannot "
                                                     "resolve parent of",
                                                     combined);
                return NGX_HTTP_NOT_FOUND;
            }

            if (!webdav_path_within_root(root_canon, parent_canon)) {
                ngx_http_xrootd_webdav_log_safe_path(r->connection->log,
                                                     NGX_LOG_WARN, 0,
                                                     "xrootd_webdav: path "
                                                     "traversal blocked",
                                                     parent_canon);
                return NGX_HTTP_FORBIDDEN;
            }

            if ((size_t) snprintf(resolved, sizeof(resolved), "%s/%s",
                                  parent_canon, filename) >= sizeof(resolved)) {
                return NGX_HTTP_REQUEST_URI_TOO_LARGE;
            }
        } else {
            ngx_http_xrootd_webdav_log_safe_path(r->connection->log,
                                                 NGX_LOG_WARN, errno,
                                                 "xrootd_webdav: cannot "
                                                 "resolve",
                                                 combined);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    /* Traverse-attack check: resolved path must remain under root */
    if (!webdav_path_within_root(root_canon, resolved)) {
        ngx_http_xrootd_webdav_log_safe_path(r->connection->log,
                                             NGX_LOG_WARN, 0,
                                             "xrootd_webdav: path traversal "
                                             "blocked",
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

static void
webdav_free_verify_resources(X509_STORE_CTX *vctx, X509 *leaf)
{
    if (vctx)  X509_STORE_CTX_free(vctx);
    if (leaf)  X509_free(leaf);
    /* chain is owned by the SSL session — do not free */
}

/*
 * Build an X509_STORE from the configured CA directory and/or file.
 * Returns NULL on allocation failure or over-length paths.
 */
static X509_STORE *
webdav_build_ca_store(ngx_log_t *log,
                      ngx_http_xrootd_webdav_loc_conf_t *conf,
                      int *crl_count_out)
{
    X509_STORE *store;
    char        cadir_buf[PATH_MAX];
    char        cafile_buf[PATH_MAX];

    if (crl_count_out != NULL) {
        *crl_count_out = 0;
    }

    store = X509_STORE_new();
    if (store == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "xrootd_webdav: X509_STORE_new failed");
        return NULL;
    }

    if (conf->cadir.len > 0) {
        if (conf->cadir.len >= sizeof(cadir_buf)) {
            X509_STORE_free(store);
            return NULL;
        }
        ngx_memcpy(cadir_buf, conf->cadir.data, conf->cadir.len);
        cadir_buf[conf->cadir.len] = '\0';
        if (!X509_STORE_load_path(store, cadir_buf)) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "xrootd_webdav: failed to load CA directory \"%s\"",
                          cadir_buf);
        }
    }

    if (conf->cafile.len > 0) {
        if (conf->cafile.len >= sizeof(cafile_buf)) {
            X509_STORE_free(store);
            return NULL;
        }
        ngx_memcpy(cafile_buf, conf->cafile.data, conf->cafile.len);
        cafile_buf[conf->cafile.len] = '\0';
        if (!X509_STORE_load_file(store, cafile_buf)) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "xrootd_webdav: failed to load CA file \"%s\"",
                          cafile_buf);
        }
    }

    if (conf->cadir.len == 0 && conf->cafile.len == 0) {
        X509_STORE_set_default_paths(store);
    }

    /* Load CRL(s) if configured (file or directory) */
    if (conf->crl.len > 0) {
        char       crl_buf[PATH_MAX];
        struct stat crl_st;
        int        crl_count = 0;

        if (conf->crl.len >= sizeof(crl_buf)) {
            X509_STORE_free(store);
            return NULL;
        }
        ngx_memcpy(crl_buf, conf->crl.data, conf->crl.len);
        crl_buf[conf->crl.len] = '\0';

        if (stat(crl_buf, &crl_st) != 0) {
            ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                          "xrootd_webdav: cannot stat CRL path \"%s\"",
                          crl_buf);
            X509_STORE_free(store);
            return NULL;
        }

        if (S_ISREG(crl_st.st_mode)) {
            /* Single file */
            FILE      *fp;
            X509_CRL  *crl_obj;

            fp = fopen(crl_buf, "r");
            if (fp == NULL) {
                ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                              "xrootd_webdav: cannot open CRL \"%s\"",
                              crl_buf);
                X509_STORE_free(store);
                return NULL;
            }

            while ((crl_obj = PEM_read_X509_CRL(fp, NULL, NULL, NULL))
                   != NULL)
            {
                if (!X509_STORE_add_crl(store, crl_obj)) {
                    ngx_log_error(NGX_LOG_WARN, log, 0,
                                  "xrootd_webdav: failed to add CRL from "
                                  "\"%s\"", crl_buf);
                }
                crl_count++;
                X509_CRL_free(crl_obj);
            }
            fclose(fp);
        } else if (S_ISDIR(crl_st.st_mode)) {
            /* Directory — scan *.pem and *.r0-*.r9 */
            DIR           *dir;
            struct dirent *ent;

            dir = opendir(crl_buf);
            if (dir == NULL) {
                ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                              "xrootd_webdav: cannot open CRL directory "
                              "\"%s\"", crl_buf);
                X509_STORE_free(store);
                return NULL;
            }

            while ((ent = readdir(dir)) != NULL) {
                const char *name = ent->d_name;
                size_t      nlen = strlen(name);
                char        fpath[PATH_MAX];
                int         match = 0;
                FILE       *fp;
                X509_CRL   *crl_obj;

                if (nlen > 4
                    && strcmp(name + nlen - 4, ".pem") == 0)
                {
                    match = 1;
                }
                if (nlen > 3 && name[nlen - 3] == '.'
                    && name[nlen - 2] == 'r'
                    && name[nlen - 1] >= '0' && name[nlen - 1] <= '9')
                {
                    match = 1;
                }
                if (!match) {
                    continue;
                }

                if (snprintf(fpath, sizeof(fpath), "%s/%s", crl_buf, name)
                    >= (int) sizeof(fpath))
                {
                    continue;
                }

                if (stat(fpath, &crl_st) != 0 || !S_ISREG(crl_st.st_mode)) {
                    continue;
                }

                fp = fopen(fpath, "r");
                if (fp == NULL) {
                    continue;
                }
                while ((crl_obj = PEM_read_X509_CRL(fp, NULL, NULL, NULL))
                       != NULL)
                {
                    if (X509_STORE_add_crl(store, crl_obj)) {
                        crl_count++;
                    }
                    X509_CRL_free(crl_obj);
                }
                fclose(fp);
            }
            closedir(dir);
        }

        if (crl_count > 0) {
            X509_STORE_set_flags(store,
                                 X509_V_FLAG_CRL_CHECK |
                                 X509_V_FLAG_CRL_CHECK_ALL);
        }

        if (crl_count_out != NULL) {
            *crl_count_out = crl_count;
        }
    }

    return store;
}

static ngx_int_t
webdav_cache_matches(ngx_http_xrootd_webdav_tls_auth_cache_t *cache,
                     ngx_http_xrootd_webdav_loc_conf_t *conf)
{
    return cache != NULL
           && cache->conf == conf
           && cache->store == conf->ca_store
           && cache->verify_depth == conf->verify_depth
           && cache->dn[0] != '\0';
}

static void
webdav_mark_req_verified(ngx_http_xrootd_webdav_req_ctx_t *ctx,
                         const char *dn, const char *source)
{
    if (dn != NULL) {
        ngx_cpystrn((u_char *) ctx->dn, (u_char *) dn, sizeof(ctx->dn));
    }

    ctx->verified = 1;
    ctx->auth_source = source;
}

static ngx_int_t
webdav_store_tls_auth_cache(ngx_http_request_t *r, SSL *ssl,
                            ngx_http_xrootd_webdav_loc_conf_t *conf,
                            const char *dn)
{
    ngx_http_xrootd_webdav_tls_auth_cache_t *cache;
    SSL_SESSION                             *sess;

    if (webdav_ssl_auth_cache_index < 0 || dn == NULL || dn[0] == '\0') {
        return NGX_OK;
    }

    cache = SSL_get_ex_data(ssl, webdav_ssl_auth_cache_index);
    if (!webdav_cache_matches(cache, conf)) {
        cache = ngx_pcalloc(r->connection->pool, sizeof(*cache));
        if (cache == NULL) {
            return NGX_ERROR;
        }

        cache->conf = conf;
        cache->store = conf->ca_store;
        cache->verify_depth = conf->verify_depth;
        ngx_cpystrn((u_char *) cache->dn, (u_char *) dn, sizeof(cache->dn));

        if (SSL_set_ex_data(ssl, webdav_ssl_auth_cache_index, cache) == 0) {
            return NGX_ERROR;
        }
    }

    if (webdav_ssl_session_auth_cache_index < 0) {
        return NGX_OK;
    }

    sess = SSL_get0_session(ssl);
    if (sess != NULL) {
        ngx_http_xrootd_webdav_tls_auth_cache_t *scache;

        scache = SSL_SESSION_get_ex_data(sess,
                                         webdav_ssl_session_auth_cache_index);
        if (scache == NULL) {
            scache = OPENSSL_malloc(sizeof(*scache));
            if (scache == NULL) {
                return NGX_ERROR;
            }
            ngx_memzero(scache, sizeof(*scache));

            scache->conf = conf;
            scache->store = conf->ca_store;
            scache->verify_depth = conf->verify_depth;
            ngx_cpystrn((u_char *) scache->dn, (u_char *) dn,
                        sizeof(scache->dn));

            if (SSL_SESSION_set_ex_data(sess,
                                        webdav_ssl_session_auth_cache_index,
                                        scache) == 0)
            {
                OPENSSL_free(scache);
                return NGX_ERROR;
            }
        }

        if (!webdav_cache_matches(scache, conf)) {
            scache->conf = conf;
            scache->store = conf->ca_store;
            scache->verify_depth = conf->verify_depth;
            ngx_cpystrn((u_char *) scache->dn, (u_char *) dn,
                        sizeof(scache->dn));
        }
    }

    return NGX_OK;
}

static ngx_int_t
webdav_try_cached_tls_auth(ngx_http_request_t *r, SSL *ssl,
                           ngx_http_xrootd_webdav_loc_conf_t *conf,
                           ngx_http_xrootd_webdav_req_ctx_t *ctx)
{
    ngx_http_xrootd_webdav_tls_auth_cache_t *cache;
    SSL_SESSION                             *sess;

    if (webdav_ssl_auth_cache_index >= 0) {
        cache = SSL_get_ex_data(ssl, webdav_ssl_auth_cache_index);
        if (webdav_cache_matches(cache, conf)) {
            webdav_mark_req_verified(ctx, cache->dn, "tls-connection");
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "xrootd_webdav: GSI auth reused from TLS connection cache");
            return NGX_OK;
        }
    }

    if (webdav_ssl_session_auth_cache_index >= 0) {
        sess = SSL_get0_session(ssl);
        if (sess != NULL) {
            cache = SSL_SESSION_get_ex_data(
                sess, webdav_ssl_session_auth_cache_index);
            if (webdav_cache_matches(cache, conf)) {
                webdav_mark_req_verified(ctx, cache->dn, "tls-session");
                if (webdav_store_tls_auth_cache(r, ssl, conf, cache->dn)
                    != NGX_OK)
                {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
                ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                              "xrootd_webdav: GSI auth reused from TLS session cache");
                return NGX_OK;
            }
        }
    }

    return NGX_DECLINED;
}

static ngx_int_t
webdav_nginx_verify_compatible(ngx_http_request_t *r,
                               ngx_http_xrootd_webdav_loc_conf_t *conf)
{
    ngx_http_ssl_srv_conf_t *sslcf;

    if (conf->cadir.len != 0 || conf->cafile.len == 0) {
        return 0;
    }

    sslcf = ngx_http_get_module_srv_conf(r, ngx_http_ssl_module);
    if (sslcf == NULL || sslcf->verify == 0) {
        return 0;
    }

    if (!webdav_str_equal(&conf->cafile, &sslcf->client_certificate)
        && !webdav_str_equal(&conf->cafile, &sslcf->trusted_certificate))
    {
        return 0;
    }

    if (conf->crl.len != 0 && !webdav_str_equal(&conf->crl, &sslcf->crl)) {
        return 0;
    }

    return 1;
}

static ngx_int_t
webdav_finish_verified_cert(ngx_http_request_t *r,
                            ngx_http_xrootd_webdav_loc_conf_t *conf,
                            ngx_http_xrootd_webdav_req_ctx_t *ctx,
                            SSL *ssl, X509 *leaf, const char *source)
{
    char *dn;

    dn = X509_NAME_oneline(X509_get_subject_name(leaf), NULL, 0);
    if (dn != NULL) {
        webdav_mark_req_verified(ctx, dn, source);
        (void) webdav_store_tls_auth_cache(r, ssl, conf, dn);
        OPENSSL_free(dn);
    } else {
        webdav_mark_req_verified(ctx, "", source);
    }

    {
        char dn_log[1024];

        xrootd_sanitize_log_string(ctx->dn, dn_log, sizeof(dn_log));
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "xrootd_webdav: GSI auth OK source=%s dn=\"%s\"",
                      source, dn_log);
    }

    return NGX_OK;
}

static ngx_int_t
webdav_verify_proxy_cert(ngx_http_request_t *r,
                         ngx_http_xrootd_webdav_loc_conf_t *conf)
{
    ngx_http_xrootd_webdav_req_ctx_t *ctx;
    SSL              *ssl;
    X509             *leaf = NULL;
    STACK_OF(X509)   *chain = NULL;
    X509_STORE_CTX   *vctx  = NULL;
    int               ok    = 0;
    long              verify_result;
    ngx_int_t         cache_rc;

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
        return NGX_HTTP_FORBIDDEN;
    }

    ssl  = r->connection->ssl->connection;

    cache_rc = webdav_try_cached_tls_auth(r, ssl, conf, ctx);
    if (cache_rc == NGX_OK) {
        return NGX_OK;
    }
    if (cache_rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return cache_rc;
    }

    leaf = SSL_get_peer_certificate(ssl);
    if (leaf == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "xrootd_webdav: no client certificate presented");
        return NGX_HTTP_FORBIDDEN;
    }

    verify_result = SSL_get_verify_result(ssl);
    if (verify_result == X509_V_OK
        && webdav_nginx_verify_compatible(r, conf))
    {
        ngx_int_t rc;

        rc = webdav_finish_verified_cert(r, conf, ctx, ssl, leaf, "nginx");
        webdav_free_verify_resources(NULL, leaf);
        return rc;
    }

    /* chain includes the leaf at index 0 plus any intermediate certs */
    chain = SSL_get_peer_cert_chain(ssl);

    if (conf->ca_store == NULL) {
        webdav_free_verify_resources(NULL, leaf);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "xrootd_webdav: cached CA store is unavailable");
        return NGX_HTTP_FORBIDDEN;
    }

    vctx = X509_STORE_CTX_new();
    if (vctx == NULL) {
        webdav_free_verify_resources(NULL, leaf);
        return NGX_HTTP_FORBIDDEN;
    }

    /*
     * The peer cert chain from TLS includes the leaf at index 0.  X509_STORE_CTX
     * expects leaf + chain separately, but SSL_get_peer_cert_chain includes the
     * leaf so we can pass it directly as the untrusted set.
     */
    if (!X509_STORE_CTX_init(vctx, conf->ca_store, leaf, chain)) {
        webdav_free_verify_resources(vctx, leaf);
        return NGX_HTTP_FORBIDDEN;
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
        webdav_free_verify_resources(vctx, leaf);
        return NGX_HTTP_FORBIDDEN;
    }

    cache_rc = webdav_finish_verified_cert(r, conf, ctx, ssl, leaf, "manual");
    webdav_free_verify_resources(vctx, leaf);
    return cache_rc;
}

/*
 * Bearer-token write authorization used by WebDAV mutating methods that carry
 * object data or fetch object data from elsewhere.  The x509 path does not
 * have WLCG scopes, so there is nothing to check for certificate-authenticated
 * requests.
 */
static ngx_int_t
webdav_check_token_write_scope(ngx_http_request_t *r, const char *method_name)
{
    ngx_http_xrootd_webdav_req_ctx_t *rctx;
    char                              uri_path[WEBDAV_MAX_PATH];
    size_t                            ulen;

    rctx = ngx_http_get_module_ctx(r, ngx_http_xrootd_webdav_module);
    if (rctx == NULL || !rctx->token_auth) {
        return NGX_OK;
    }

    ulen = r->uri.len < sizeof(uri_path) - 1
           ? r->uri.len : sizeof(uri_path) - 1;
    ngx_memcpy(uri_path, r->uri.data, ulen);
    uri_path[ulen] = '\0';

    if (xrootd_token_check_write(rctx->token_scopes,
                                 rctx->token_scope_count,
                                 uri_path))
    {
        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                  "xrootd_webdav: token scope denies %s write to \"%s\"",
                  method_name, uri_path);

    return NGX_HTTP_FORBIDDEN;
}

/*
 * webdav_verify_bearer_token — authenticate via Authorization: Bearer <JWT>.
 *
 * Returns NGX_OK on success, NGX_HTTP_UNAUTHORIZED/FORBIDDEN on failure,
 * NGX_DECLINED if no Bearer header present.
 */
static ngx_int_t
webdav_verify_bearer_token(ngx_http_request_t *r,
                           ngx_http_xrootd_webdav_loc_conf_t *conf)
{
    ngx_http_xrootd_webdav_req_ctx_t *ctx;
    xrootd_token_claims_t claims;
    ngx_str_t auth_hdr;
    const char *token;
    size_t token_len;
    int rc, i;

    /* Must have JWKS configured. */
    if (conf->jwks_key_count <= 0) {
        return NGX_DECLINED;
    }

    /* Get or create request context. */
    ctx = ngx_http_get_module_ctx(r, ngx_http_xrootd_webdav_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(*ctx));
        if (ctx == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
        ngx_http_set_ctx(r, ctx, ngx_http_xrootd_webdav_module);
    }

    /* Already verified via token (cached)? */
    if (ctx->token_auth) {
        return NGX_OK;
    }

    /* Extract Authorization header. */
    if (r->headers_in.authorization == NULL) {
        return NGX_DECLINED;
    }

    auth_hdr = r->headers_in.authorization->value;

    /* Must start with "Bearer " (case-sensitive per RFC 6750). */
    if (auth_hdr.len < 7 ||
        ngx_strncmp(auth_hdr.data, "Bearer ", 7) != 0)
    {
        return NGX_DECLINED;
    }

    token     = (const char *)(auth_hdr.data + 7);
    token_len = auth_hdr.len - 7;

    /* Skip leading whitespace after "Bearer ". */
    while (token_len > 0 && *token == ' ') {
        token++;
        token_len--;
    }

    if (token_len == 0) {
        return NGX_HTTP_UNAUTHORIZED;
    }

    rc = xrootd_token_validate(r->connection->log, token, token_len,
                               conf->jwks_keys, conf->jwks_key_count,
                               (const char *) conf->token_issuer.data,
                               (const char *) conf->token_audience.data,
                               &claims);
    if (rc != 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "xrootd_webdav: bearer token validation failed");
        return NGX_HTTP_UNAUTHORIZED;
    }

    /* Store identity. */
    ctx->verified   = 1;
    ctx->token_auth = 1;
    ctx->auth_source = "token";
    ngx_cpystrn((u_char *) ctx->dn, (u_char *) claims.sub, sizeof(ctx->dn));

    /* Store scopes for write authorization. */
    ctx->token_scope_count = claims.scope_count;
    for (i = 0; i < claims.scope_count && i < XROOTD_MAX_TOKEN_SCOPES; i++) {
        ctx->token_scopes[i] = claims.scopes[i];
    }

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "xrootd_webdav: token auth OK sub=\"%s\" scopes=%d",
                  claims.sub, claims.scope_count);

    return NGX_OK;
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
        if (auth_rc != NGX_OK) {
            /* Try bearer token as fallback. */
            auth_rc = webdav_verify_bearer_token(r, conf);
        }
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
        ngx_int_t rc;

        /* Write methods require explicit opt-in */
        if (!conf->allow_write) {
            return NGX_HTTP_FORBIDDEN;
        }
        rc = webdav_check_token_write_scope(r, "PUT");
        if (rc != NGX_OK) {
            return rc;
        }

        /* Delegate body reading; the handler finishes asynchronously */
        r->request_body_in_single_buf = 1;
        rc = ngx_http_read_client_request_body(r, webdav_handle_put_body);
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
    /* COPY - HTTP/WebDAV third-party-copy pull into this endpoint */
    if (r->method_name.len == 4 &&
        ngx_strncmp(r->method_name.data, "COPY", 4) == 0)
    {
        ngx_int_t rc;

        if (!conf->allow_write) {
            return NGX_HTTP_FORBIDDEN;
        }
        if (!conf->tpc) {
            return NGX_HTTP_NOT_ALLOWED;
        }
        rc = webdav_check_token_write_scope(r, "COPY");
        if (rc != NGX_OK) {
            return rc;
        }
        return ngx_http_xrootd_webdav_tpc_handle_copy(r);
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
    if (conf->allow_write && conf->tpc) {
        ngx_str_set(&h->value,
            "OPTIONS, GET, HEAD, PUT, DELETE, MKCOL, COPY, PROPFIND");
    } else if (conf->allow_write) {
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

    rc = ngx_http_xrootd_webdav_resolve_path(r, &conf->root, path,
                                             sizeof(path));
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

    rc = ngx_http_xrootd_webdav_resolve_path(r, &conf->root, path,
                                             sizeof(path));
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
        ngx_http_xrootd_webdav_log_safe_path(r->connection->log, NGX_LOG_ERR,
                                             ngx_errno,
                                             "xrootd_webdav: open() failed "
                                             "for",
                                             path);
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
    int             created = 0;
    struct stat     sb;
    ngx_int_t       status;
    u_char         *copy_scratch = NULL;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);

    rc = ngx_http_xrootd_webdav_resolve_path(r, &conf->root, path,
                                             sizeof(path));
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
        ngx_http_xrootd_webdav_log_safe_path(r->connection->log, NGX_LOG_ERR,
                                             ngx_errno,
                                             "xrootd_webdav: open() for write "
                                             "failed for",
                                             path);
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    /* Write all body buffers */
    if (r->request_body != NULL) {
        for (chain = r->request_body->bufs; chain != NULL; chain = chain->next) {
            buf = chain->buf;
            if (buf->in_file) {
                /*
                 * Large HTTPS uploads are commonly spooled to a temp file by
                 * nginx before this callback runs.  Prefer a kernel-side
                 * file-to-file copy so we do not bounce every 64 KiB through
                 * userspace on the way into the final destination.
                 */
                if (webdav_copy_spooled_file(r, fd, buf, path, &copy_scratch)
                    != NGX_OK)
                {
                    ngx_close_file(fd);
                    ngx_http_finalize_request(r,
                                              NGX_HTTP_INTERNAL_SERVER_ERROR);
                    return;
                }
            } else if (buf->pos < buf->last) {
                if (webdav_write_full(fd, buf->pos,
                                      (size_t) (buf->last - buf->pos))
                    != NGX_OK)
                {
                    ngx_http_xrootd_webdav_log_safe_path(
                        r->connection->log, NGX_LOG_ERR, ngx_errno,
                        "xrootd_webdav: write() failed for",
                        path);
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

    rc = ngx_http_xrootd_webdav_resolve_path(r, &conf->root, path,
                                             sizeof(path));
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

    rc = ngx_http_xrootd_webdav_resolve_path(r, &conf->root, path,
                                             sizeof(path));
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
    va_list      ap;
    va_list      ap_copy;
    char         tmp[2048];
    char        *src;
    int          n;
    ngx_buf_t    *b;
    ngx_chain_t  *lc;

    va_start(ap, fmt);
    va_copy(ap_copy, ap);
    n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);

    if (n < 0) {
        va_end(ap_copy);
        return NULL;
    }

    if ((size_t) n >= sizeof(tmp)) {
        src = ngx_pnalloc(pool, (size_t) n + 1);
        if (src == NULL) {
            va_end(ap_copy);
            return NULL;
        }

        (void) vsnprintf(src, (size_t) n + 1, fmt, ap_copy);
    } else {
        src = tmp;
    }

    va_end(ap_copy);

    if (n == 0) return (*tail ? (*tail)->buf : NULL);

    b = ngx_create_temp_buf(pool, (size_t) n);
    if (b == NULL) return NULL;
    ngx_memcpy(b->pos, src, (size_t) n);
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
    char  date_buf[64];
    char *safe_href;

    webdav_http_date(sb->st_mtime, date_buf, sizeof(date_buf));

    safe_href = webdav_escape_xml_text(pool, href);
    if (safe_href == NULL) {
        return NGX_ERROR;
    }

    if (propfind_append(pool, head, tail,
            "<D:response>"
            "<D:href>%s</D:href>"
            "<D:propstat>"
            "<D:prop>", safe_href) == NULL) return NGX_ERROR;

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

    rc = ngx_http_xrootd_webdav_resolve_path(r, &conf->root, path,
                                             sizeof(path));
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
                        if ((size_t) snprintf(href, sizeof(href), "%.*s/%s",
                                              (int) blen, base, de->d_name)
                            >= sizeof(href)) {
                            continue;
                        }
                    } else {
                        if ((size_t) snprintf(href, sizeof(href), "%.*s%s",
                                              (int) blen, base, de->d_name)
                            >= sizeof(href)) {
                            continue;
                        }
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
