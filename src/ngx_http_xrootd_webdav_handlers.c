/*
 * ngx_http_xrootd_webdav_handlers.c — HTTP method handlers.
 *
 * Implements OPTIONS, HEAD, GET (with Range + sendfile + fd-cache fast path),
 * PUT (synchronous and thread-pool AIO), DELETE, MKCOL, and PROPFIND
 * (Depth:0/1 with 207 Multi-Status XML generation).
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <sys/stat.h>
#include <sys/syscall.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <time.h>
#include <unistd.h>

#include "ngx_http_xrootd_webdav_module.h"

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
/* OPTIONS                                                              */
/* ------------------------------------------------------------------ */

ngx_int_t
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

ngx_int_t
webdav_handle_head(ngx_http_request_t *r, int send_body)
{
    ngx_http_xrootd_webdav_loc_conf_t *conf;
    char        path[WEBDAV_MAX_PATH];
    struct stat sb;
    ngx_int_t   rc;
    ngx_table_elt_t *h;
    char        date_buf[64];

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);

    rc = ngx_http_xrootd_webdav_resolve_path(r, conf->root_canon, path,
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

ngx_int_t
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
    int           fd_from_table = 0;
    ngx_buf_t    *b;
    ngx_chain_t   out;
    ngx_table_elt_t *h;
    char          cr_buf[64];
    char          date_buf[64];
    webdav_fd_table_t  *fdt;
    ngx_pool_cleanup_t *cln;
    ngx_pool_cleanup_file_t *clnf;
    char          uri_decoded[WEBDAV_MAX_PATH];
    uint64_t      uri_h = 0;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);

    /*
     * Fast path: decode the URI once and try a URI-hash-keyed fd table lookup.
     * On a hit the cached fd is validated via fstat() — this skips the
     * expensive resolve_path() (which calls realpath → multiple lstat syscalls)
     * and the separate stat() call entirely.  The only syscall on the hot path
     * is the single fstat() on the already-open fd.
     */
    fdt = webdav_get_fd_table(r->connection);

    {
        ngx_int_t urc;

        urc = webdav_urldecode(r->uri.data, r->uri.len,
                               uri_decoded, sizeof(uri_decoded));
        if (urc == NGX_OK) {
            size_t dlen = strlen(uri_decoded);
            while (dlen > 1 && uri_decoded[dlen - 1] == '/')
                uri_decoded[--dlen] = '\0';

            uri_h = webdav_uri_hash(uri_decoded);
            fd = webdav_fd_table_get_by_uri(fdt, uri_h, &sb);

            if (fd != NGX_INVALID_FILE) {
                if (S_ISDIR(sb.st_mode)) {
                    return NGX_HTTP_FORBIDDEN;
                }
                fd_from_table = 1;
                goto have_fd;
            }
        }
    }

    /*
     * Slow path: full resolve_path + open + fstat.  Uses open-then-fstat
     * instead of the previous stat-then-open to eliminate one path traversal
     * syscall on cache misses.
     */
    rc = ngx_http_xrootd_webdav_resolve_path(r, conf->root_canon, path,
                                             sizeof(path));
    if (rc != NGX_OK) return (ngx_int_t) rc;

    fd = ngx_open_file(path, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (fd == NGX_INVALID_FILE) {
        if (ngx_errno == NGX_ENOENT || ngx_errno == NGX_ENOTDIR) {
            return NGX_HTTP_NOT_FOUND;
        }
        ngx_http_xrootd_webdav_log_safe_path(r->connection->log,
                                             NGX_LOG_ERR,
                                             ngx_errno,
                                             "xrootd_webdav: open() failed "
                                             "for",
                                             path);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (fstat(fd, &sb) != 0) {
        ngx_close_file(fd);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (S_ISDIR(sb.st_mode)) {
        ngx_close_file(fd);
        return NGX_HTTP_FORBIDDEN;
    }

    /* Cache in the fd table for subsequent keepalive requests */
    webdav_fd_table_put(fdt, path, &sb, fd, uri_h);
    fd_from_table = 1;  /* now owned by table; don't close on error */

have_fd:

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

    /*
     * Readahead hint: tell the kernel to start paging in the file range we are
     * about to sendfile().  On Linux this populates the page cache
     * asynchronously so the actual sendfile() blocks less.
     */
    webdav_fadvise_willneed(r->connection->log, fd, range_start,
                            (size_t) send_len);

    /* Build response headers */
    r->headers_out.status           = has_range ? NGX_HTTP_PARTIAL_CONTENT
                                                 : NGX_HTTP_OK;
    r->headers_out.content_length_n = send_len;
    r->headers_out.last_modified_time = sb.st_mtime;

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) { return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    h->hash = 1;
    ngx_str_set(&h->key, "Content-Type");
    ngx_str_set(&h->value, "application/octet-stream");

    webdav_http_date(sb.st_mtime, date_buf, sizeof(date_buf));
    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) { return NGX_HTTP_INTERNAL_SERVER_ERROR; }
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
        if (h == NULL) { return NGX_HTTP_INTERNAL_SERVER_ERROR; }
        h->hash = 1;
        ngx_str_set(&h->key, "Content-Range");
        h->value.data = ngx_pstrdup(r->pool, &(ngx_str_t){strlen(cr_buf),
                                                            (u_char*)cr_buf});
        h->value.len  = strlen(cr_buf);
    }

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || r->header_only) {
        return rc;
    }

    /* Build sendfile buf */
    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) { return NGX_HTTP_INTERNAL_SERVER_ERROR; }

    b->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
    if (b->file == NULL) { return NGX_HTTP_INTERNAL_SERVER_ERROR; }

    /*
     * Copy path to pool-allocated memory so the file name reference stays
     * valid after this function's stack frame is gone (nginx may log the
     * file name later during sendfile error handling).
     */
    b->file->name.len  = ngx_strlen(path);
    b->file->name.data = ngx_pnalloc(r->pool, b->file->name.len + 1);
    if (b->file->name.data == NULL) { return NGX_HTTP_INTERNAL_SERVER_ERROR; }
    ngx_cpystrn(b->file->name.data, (u_char *) path, b->file->name.len + 1);

    b->in_file           = 1;
    b->last_buf          = 1;
    b->last_in_chain     = 1;
    b->file->fd          = fd;
    b->file->log         = r->connection->log;
    b->file_pos          = range_start;
    b->file_last         = range_start + send_len;

    /*
     * Register a pool cleanup for the fd.  Since the fd is cached in the fd
     * table (owned by c->pool), the cleanup handler is a no-op: it records
     * the fd but relies on the table's own cleanup to actually close it.
     * This ensures nginx's sendfile completes before anyone closes the fd.
     *
     * If the fd is NOT in the table (shouldn't happen now, but defensive),
     * the cleanup ensures the fd is eventually closed when r->pool dies.
     */
    cln = ngx_pool_cleanup_add(r->pool, sizeof(ngx_pool_cleanup_file_t));
    if (cln != NULL) {
        cln->handler = fd_from_table ? ngx_pool_cleanup_file
                                     : ngx_pool_cleanup_file;
        clnf = cln->data;
        clnf->fd   = fd;
        clnf->name = b->file->name.data;
        clnf->log  = r->pool->log;

        if (fd_from_table) {
            /*
             * The fd is owned by the connection fd table; mark cleanup fd
             * invalid so the request pool cleanup doesn't double-close it.
             */
            clnf->fd = NGX_INVALID_FILE;
        }
    }

    out.buf  = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}

/* ------------------------------------------------------------------ */
/* PUT body callback                                                    */
/* ------------------------------------------------------------------ */

/*
 * AIO task context for threaded PUT writes.  When a thread pool is configured,
 * the blocking pwrite() runs on a worker thread instead of the event loop.
 */
#if (NGX_THREADS)
typedef struct {
    ngx_http_request_t  *r;
    ngx_fd_t             fd;
    const u_char        *data;
    size_t               len;
    off_t                offset;
    ssize_t              nwritten;
    int                  io_errno;
    int                  created;    /* 201 vs 204 */
    char                 path[WEBDAV_MAX_PATH];
} webdav_put_aio_t;

static void webdav_put_aio_thread(void *data, ngx_log_t *log);
static void webdav_put_aio_done(ngx_event_t *ev);

static void
webdav_put_aio_thread(void *data, ngx_log_t *log)
{
    webdav_put_aio_t *t = data;
    size_t            remaining = t->len;
    off_t             off = t->offset;
    const u_char     *p = t->data;

    (void) log;

    t->nwritten = 0;
    t->io_errno = 0;

    while (remaining > 0) {
        ssize_t n = pwrite(t->fd, p, remaining, off);
        if (n < 0) {
            t->io_errno = errno;
            t->nwritten = -1;
            return;
        }
        p         += n;
        off       += n;
        remaining -= (size_t) n;
        t->nwritten += n;
    }
}

static void
webdav_put_aio_done(ngx_event_t *ev)
{
    ngx_thread_task_t *task = ev->data;
    webdav_put_aio_t  *t = task->ctx;
    ngx_http_request_t *r = t->r;
    ngx_int_t          status;
    webdav_fd_table_t *fdt;

    if (t->nwritten < 0 || (size_t) t->nwritten < t->len) {
        ngx_http_xrootd_webdav_log_safe_path(r->connection->log,
                                             NGX_LOG_ERR,
                                             (ngx_uint_t) t->io_errno,
                                             "xrootd_webdav: async write() "
                                             "failed for",
                                             t->path);
        ngx_close_file(t->fd);
        fdt = webdav_get_fd_table(r->connection);
        webdav_fd_table_evict(fdt, t->path);
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    ngx_close_file(t->fd);

    /* Evict any cached read fd for this path (content changed) */
    fdt = webdav_get_fd_table(r->connection);
    webdav_fd_table_evict(fdt, t->path);

    status = t->created ? NGX_HTTP_CREATED : NGX_HTTP_NO_CONTENT;
    r->headers_out.status           = status;
    r->headers_out.content_length_n = 0;
    ngx_http_send_header(r);
    ngx_http_finalize_request(r, ngx_http_send_special(r, NGX_HTTP_LAST));
}
#endif /* NGX_THREADS */

void
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
    off_t           write_offset = 0;
    webdav_fd_table_t *fdt;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);

    rc = ngx_http_xrootd_webdav_resolve_path(r, conf->root_canon, path,
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

    /* Evict any cached read fd for this path (content is changing) */
    fdt = webdav_get_fd_table(r->connection);
    webdav_fd_table_evict(fdt, path);

    /* Write all body buffers */
    if (r->request_body != NULL) {
        /*
         * Check if all body data is in memory (no temp-file spool).
         * When the entire body fits in a single memory buffer, we can
         * optionally offload the write to a thread pool.
         */
        int all_in_memory = 1;
        size_t total_mem_size = 0;

        for (chain = r->request_body->bufs; chain != NULL; chain = chain->next) {
            buf = chain->buf;
            if (buf->in_file) {
                all_in_memory = 0;
                break;
            }
            total_mem_size += (size_t) (buf->last - buf->pos);
        }

#if (NGX_THREADS)
        /*
         * Thread-pool AIO for memory-resident PUT bodies: offload the
         * blocking pwrite() to a worker thread so the event loop stays free.
         */
        if (all_in_memory && total_mem_size > 0 && conf->thread_pool != NULL) {
            ngx_thread_task_t *task;
            webdav_put_aio_t  *t;
            u_char            *wbuf;

            task = ngx_thread_task_alloc(r->pool,
                                        sizeof(webdav_put_aio_t));
            if (task == NULL) {
                ngx_close_file(fd);
                ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }

            t = task->ctx;
            t->r       = r;
            t->fd      = fd;
            t->offset  = 0;
            t->len     = total_mem_size;
            t->created = created;
            ngx_cpystrn((u_char *) t->path, (u_char *) path,
                        sizeof(t->path));

            /* Coalesce body chain into a single contiguous buffer */
            wbuf = ngx_palloc(r->pool, total_mem_size);
            if (wbuf == NULL) {
                ngx_close_file(fd);
                ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }
            {
                u_char *wp = wbuf;
                for (chain = r->request_body->bufs; chain; chain = chain->next) {
                    buf = chain->buf;
                    size_t n = (size_t) (buf->last - buf->pos);
                    if (n > 0) {
                        ngx_memcpy(wp, buf->pos, n);
                        wp += n;
                    }
                }
            }
            t->data = wbuf;

            task->handler = webdav_put_aio_thread;
            task->event.handler = webdav_put_aio_done;
            task->event.data = task;

            if (ngx_thread_task_post(conf->thread_pool, task) != NGX_OK) {
                ngx_close_file(fd);
                ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }

            /* Request processing continues in webdav_put_aio_done */
            r->main->count++;
            return;
        }
#endif /* NGX_THREADS */

        /*
         * Synchronous write path.  For memory buffers, write directly to the
         * destination fd.  For spooled (temp-file) buffers, use
         * copy_file_range/pread+write to avoid userspace bounce.
         */
        for (chain = r->request_body->bufs; chain != NULL; chain = chain->next) {
            buf = chain->buf;
            if (buf->in_file) {
                if (webdav_copy_spooled_file(r, fd, buf, path, &copy_scratch)
                    != NGX_OK)
                {
                    ngx_close_file(fd);
                    ngx_http_finalize_request(r,
                                              NGX_HTTP_INTERNAL_SERVER_ERROR);
                    return;
                }
            } else if (buf->pos < buf->last) {
                size_t blen = (size_t) (buf->last - buf->pos);
                ssize_t n = pwrite(fd, buf->pos, blen, write_offset);
                if (n < 0 || (size_t) n < blen) {
                    ngx_http_xrootd_webdav_log_safe_path(
                        r->connection->log, NGX_LOG_ERR, ngx_errno,
                        "xrootd_webdav: write() failed for",
                        path);
                    ngx_close_file(fd);
                    ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                    return;
                }
                write_offset += n;
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

ngx_int_t
webdav_handle_delete(ngx_http_request_t *r)
{
    ngx_http_xrootd_webdav_loc_conf_t *conf;
    char       path[WEBDAV_MAX_PATH];
    struct stat sb;
    ngx_int_t  rc;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);

    rc = ngx_http_xrootd_webdav_resolve_path(r, conf->root_canon, path,
                                             sizeof(path));
    if (rc != NGX_OK) return (ngx_int_t) rc;

    if (stat(path, &sb) != 0) {
        return (errno == ENOENT) ? NGX_HTTP_NOT_FOUND
                                 : NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Evict any cached fd for the target before unlinking */
    {
        webdav_fd_table_t *fdt = webdav_get_fd_table(r->connection);
        webdav_fd_table_evict(fdt, path);
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

ngx_int_t
webdav_handle_mkcol(ngx_http_request_t *r)
{
    ngx_http_xrootd_webdav_loc_conf_t *conf;
    char       path[WEBDAV_MAX_PATH];
    ngx_int_t  rc;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);

    rc = ngx_http_xrootd_webdav_resolve_path(r, conf->root_canon, path,
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

ngx_int_t
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

    rc = ngx_http_xrootd_webdav_resolve_path(r, conf->root_canon, path,
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
