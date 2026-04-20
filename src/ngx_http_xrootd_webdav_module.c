/*
 * ngx_http_xrootd_webdav_module.c — configuration, lifecycle, dispatcher, fd cache.
 *
 * This is the "spine" of the WebDAV module.  It owns:
 *   - nginx directive table and create/merge_loc_conf
 *   - postconfiguration (handler registration, SSL context patching)
 *   - the request dispatcher (auth → method → handler file)
 *   - the per-connection fd cache (survives HTTP keepalive)
 *   - I/O utility helpers (write_full, copy_spooled_file)
 *
 * Method handlers, authentication, and path utilities live in their own
 * translation units; see ngx_http_xrootd_webdav_module.h for the API.
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
#include <fcntl.h>
#include <limits.h>
#include <time.h>
#include <unistd.h>

#include "ngx_http_xrootd_webdav_module.h"

/* Maximum PUT body size (16 MiB) */
#define WEBDAV_MAX_PUT    (16 * 1024 * 1024)
/* PROPFIND response buffer initial size */
#define WEBDAV_XML_CHUNK  4096

/* ------------------------------------------------------------------ */
/* Forward declarations                                                */
/* ------------------------------------------------------------------ */

static ngx_int_t ngx_http_xrootd_webdav_handler(ngx_http_request_t *r);

static void     *ngx_http_xrootd_webdav_create_loc_conf(ngx_conf_t *cf);
static char     *ngx_http_xrootd_webdav_merge_loc_conf(ngx_conf_t *cf,
                                                        void *parent,
                                                        void *child);
static ngx_int_t ngx_http_xrootd_webdav_postconfiguration(ngx_conf_t *cf);

static void webdav_x509_store_cleanup(void *data);

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


ngx_int_t
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


ngx_int_t
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
/* Per-connection fd table (survives HTTP keepalive)                     */
/* ------------------------------------------------------------------ */

/*
 * The fd table is stored on c->pool (the connection pool, not the request pool).
 * This pool persists across keepalive requests on the same TCP connection,
 * so cached fds survive between sequential GET/HEAD/PUT requests.
 *
 * A pool cleanup handler ensures all cached fds are closed when the connection
 * terminates.  The table is keyed by resolved canonical path + dev/ino to
 * detect stale entries (file was deleted and recreated between requests).
 */


static void
webdav_fd_table_cleanup(void *data)
{
    webdav_fd_table_t *t = data;
    int i;

    for (i = 0; i < WEBDAV_FD_TABLE_SIZE; i++) {
        if (t->fds[i].fd != NGX_INVALID_FILE) {
            ngx_close_file(t->fds[i].fd);
            t->fds[i].fd = NGX_INVALID_FILE;
        }
    }
}

/* Index for SSL connection ex_data used to store the fd table pointer */
static int webdav_fd_table_conn_index = -1;

webdav_fd_table_t *
webdav_get_fd_table(ngx_connection_t *c)
{
    webdav_fd_table_t  *t;
    ngx_pool_cleanup_t *cln;
    int                 i;

    /*
     * Use SSL ex_data when TLS is active (HTTPS connections), otherwise fall
     * back to allocating on c->pool.  We use the SSL ex_data because the
     * nginx HTTP module layer does not provide a per-connection context hook
     * that survives across keepalive requests the way stream modules do.
     *
     * For non-TLS connections (unlikely in production but possible in tests),
     * we just allocate a fresh table per request since there's no reliable
     * per-connection storage.
     */
    if (c->ssl != NULL && webdav_fd_table_conn_index >= 0) {
        t = SSL_get_ex_data(c->ssl->connection, webdav_fd_table_conn_index);
        if (t != NULL) {
            return t;
        }
    }

    t = ngx_pcalloc(c->pool, sizeof(*t));
    if (t == NULL) {
        return NULL;
    }

    for (i = 0; i < WEBDAV_FD_TABLE_SIZE; i++) {
        t->fds[i].fd = NGX_INVALID_FILE;
    }
    t->count = 0;

    cln = ngx_pool_cleanup_add(c->pool, 0);
    if (cln == NULL) {
        return NULL;
    }
    cln->handler = webdav_fd_table_cleanup;
    cln->data = t;

    if (c->ssl != NULL && webdav_fd_table_conn_index >= 0) {
        SSL_set_ex_data(c->ssl->connection, webdav_fd_table_conn_index, t);
    }

    return t;
}

ngx_fd_t
webdav_fd_table_get(webdav_fd_table_t *t, const char *path,
    const struct stat *sb)
{
    int i;

    if (t == NULL) {
        return NGX_INVALID_FILE;
    }

    for (i = 0; i < WEBDAV_FD_TABLE_SIZE; i++) {
        if (t->fds[i].fd != NGX_INVALID_FILE
            && t->fds[i].ino == sb->st_ino
            && t->fds[i].dev == sb->st_dev
            && ngx_strcmp(t->fds[i].path, path) == 0)
        {
            return t->fds[i].fd;
        }
    }

    return NGX_INVALID_FILE;
}

void
webdav_fd_table_put(webdav_fd_table_t *t, const char *path,
    const struct stat *sb, ngx_fd_t fd, uint64_t uri_hash)
{
    int      i;
    int      oldest_idx = 0;
    ngx_msec_t oldest_time;

    if (t == NULL) {
        return;
    }

    /* Check for an existing entry with the same path */
    for (i = 0; i < WEBDAV_FD_TABLE_SIZE; i++) {
        if (t->fds[i].fd != NGX_INVALID_FILE
            && ngx_strcmp(t->fds[i].path, path) == 0)
        {
            /* Replace: close old fd, store new one */
            if (t->fds[i].fd != fd) {
                ngx_close_file(t->fds[i].fd);
            }
            t->fds[i].fd = fd;
            t->fds[i].ino = sb->st_ino;
            t->fds[i].dev = sb->st_dev;
            t->fds[i].uri_hash = uri_hash;
            t->fds[i].open_time = ngx_current_msec;
            return;
        }
    }

    /* Find a free slot */
    for (i = 0; i < WEBDAV_FD_TABLE_SIZE; i++) {
        if (t->fds[i].fd == NGX_INVALID_FILE) {
            goto fill;
        }
    }

    /* Table full — evict the oldest entry */
    oldest_time = t->fds[0].open_time;
    for (i = 1; i < WEBDAV_FD_TABLE_SIZE; i++) {
        if (t->fds[i].open_time < oldest_time) {
            oldest_time = t->fds[i].open_time;
            oldest_idx = i;
        }
    }
    i = oldest_idx;
    ngx_close_file(t->fds[i].fd);

fill:
    t->fds[i].fd = fd;
    t->fds[i].ino = sb->st_ino;
    t->fds[i].dev = sb->st_dev;
    t->fds[i].uri_hash = uri_hash;
    t->fds[i].open_time = ngx_current_msec;
    ngx_cpystrn((u_char *) t->fds[i].path, (u_char *) path,
                sizeof(t->fds[i].path));
    t->count++;
}

/*
 * FNV-1a 64-bit hash of the decoded URI string.  Used as a fast lookup key
 * in the fd table so GET can skip resolve_path + stat on cache hits.
 */
uint64_t
webdav_uri_hash(const char *s)
{
    uint64_t h = 14695981039346656037ULL;  /* FNV offset basis */

    while (*s) {
        h ^= (uint64_t) (unsigned char) *s++;
        h *= 1099511628211ULL;             /* FNV prime */
    }

    return h;
}

/*
 * Fast-path fd table lookup by decoded-URI hash.  Returns a cached fd and
 * fills *sb_out via fstat() on hit, or NGX_INVALID_FILE on miss.
 * Automatically evicts entries whose underlying file has been deleted
 * (st_nlink == 0).
 */
ngx_fd_t
webdav_fd_table_get_by_uri(webdav_fd_table_t *t, uint64_t uri_hash,
    struct stat *sb_out)
{
    int i;

    if (t == NULL) {
        return NGX_INVALID_FILE;
    }

    for (i = 0; i < WEBDAV_FD_TABLE_SIZE; i++) {
        if (t->fds[i].fd != NGX_INVALID_FILE
            && t->fds[i].uri_hash == uri_hash)
        {
            /* Validate: file must still exist (not unlinked) */
            if (fstat(t->fds[i].fd, sb_out) != 0
                || sb_out->st_nlink == 0)
            {
                ngx_close_file(t->fds[i].fd);
                t->fds[i].fd = NGX_INVALID_FILE;
                t->count--;
                return NGX_INVALID_FILE;
            }

            return t->fds[i].fd;
        }
    }

    return NGX_INVALID_FILE;
}

void
webdav_fd_table_evict(webdav_fd_table_t *t, const char *path)
{
    int i;

    if (t == NULL) {
        return;
    }

    for (i = 0; i < WEBDAV_FD_TABLE_SIZE; i++) {
        if (t->fds[i].fd != NGX_INVALID_FILE
            && ngx_strcmp(t->fds[i].path, path) == 0)
        {
            ngx_close_file(t->fds[i].fd);
            t->fds[i].fd = NGX_INVALID_FILE;
            t->count--;
            return;
        }
    }
}

/* ------------------------------------------------------------------ */
/* posix_fadvise helper                                                 */
/* ------------------------------------------------------------------ */

void
webdav_fadvise_willneed(ngx_log_t *log, ngx_fd_t fd, off_t offset, size_t len)
{
#if defined(POSIX_FADV_WILLNEED)
    int rc;

    if (fd == NGX_INVALID_FILE || len == 0) {
        return;
    }

    rc = posix_fadvise(fd, offset, (off_t) len, POSIX_FADV_WILLNEED);
    if (rc != 0) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                       "xrootd_webdav: POSIX_FADV_WILLNEED ignored: %s",
                       strerror(rc));
    }
#else
    (void) log;
    (void) fd;
    (void) offset;
    (void) len;
#endif
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

    { ngx_string("xrootd_webdav_thread_pool"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_xrootd_webdav_loc_conf_t, thread_pool_name),
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

        /*
         * Pre-resolve the root to a canonical absolute path at config time.
         * This eliminates a realpath() syscall (which does lstat on every
         * path component) from every single HTTP request.
         */
        {
            char root_buf[WEBDAV_MAX_PATH];

            if (conf->root.len >= sizeof(root_buf)) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "xrootd_webdav: root path too long");
                return NGX_CONF_ERROR;
            }

            ngx_memcpy(root_buf, conf->root.data, conf->root.len);
            root_buf[conf->root.len] = '\0';

            if (realpath(root_buf, conf->root_canon) == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, errno,
                                   "xrootd_webdav: cannot resolve root \"%V\"",
                                   &conf->root);
                return NGX_CONF_ERROR;
            }
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

    if (webdav_auth_init_ssl_indices(cf->log) != NGX_OK) {
        return NGX_ERROR;
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

    /* Allocate an SSL ex_data index for the per-connection fd table */
    if (webdav_fd_table_conn_index < 0) {
        webdav_fd_table_conn_index = SSL_get_ex_new_index(0, NULL, NULL,
                                                          NULL, NULL);
        if (webdav_fd_table_conn_index < 0) {
            ngx_log_error(NGX_LOG_WARN, cf->log, 0,
                          "xrootd_webdav: fd table ex_data index failed, "
                          "fd caching across keepalive disabled");
        }
    }

#if (NGX_THREADS)
    /*
     * Resolve thread pool names to pool objects for all enabled locations.
     * Walk servers → locations to find every xrootd_webdav_thread_pool.
     */
    {
        static ngx_str_t default_pool_name = ngx_string("default");

        for (s = 0; s < cmcf->servers.nelts; s++) {
            ngx_http_conf_ctx_t *ctx = cscfp[s]->ctx;
            ngx_str_t *pool_name;

            wdcf = ctx->loc_conf[ngx_http_xrootd_webdav_module.ctx_index];
            if (wdcf == NULL || !wdcf->enable) {
                continue;
            }

            pool_name = (wdcf->thread_pool_name.len > 0)
                        ? &wdcf->thread_pool_name
                        : &default_pool_name;

            wdcf->thread_pool = ngx_thread_pool_get(cf->cycle, pool_name);
            if (wdcf->thread_pool == NULL) {
                ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                    "xrootd_webdav: thread pool \"%V\" not found — "
                    "async file I/O disabled (add a thread_pool directive)",
                    pool_name);
            } else {
                ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                    "xrootd_webdav: using thread pool \"%V\" for async file I/O",
                    pool_name);
            }
        }
    }
#endif

    return NGX_OK;
}

/* ------------------------------------------------------------------ */
/* Utility: URL-decode a path segment into a fixed buffer              */

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


