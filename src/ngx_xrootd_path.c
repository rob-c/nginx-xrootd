#include "ngx_xrootd_module.h"

/* ================================================================== */
/*  Path resolution helpers                                             */
/* ================================================================== */

/*
 * xrootd_resolve_path_noexist
 *
 * Like xrootd_resolve_path_write but does NOT require any component of the
 * path to exist — suitable for recursive mkdir.
 *
 * Returns 1 on success (resolved[] filled), 0 on failure.
 */
int
xrootd_resolve_path_noexist(ngx_log_t *log, const ngx_str_t *root,
                              const char *reqpath, char *resolved, size_t resolvsz)
{
    char        combined[PATH_MAX * 2];
    const char *p;
    int         n;

    while (*reqpath == '/') {
        reqpath++;
    }

    if (*reqpath == '\0') {
        return 0;
    }

    p = reqpath;
    while (*p) {
        const char *seg_end = strchr(p, '/');
        size_t      seg_len = seg_end ? (size_t)(seg_end - p) : strlen(p);

        if (seg_len == 2 && p[0] == '.' && p[1] == '.') {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "xrootd: path traversal attempt: %s", reqpath);
            return 0;
        }
        if (seg_end == NULL) {
            break;
        }
        p = seg_end + 1;
    }

    n = snprintf(combined, sizeof(combined), "%.*s/%s",
                 (int) root->len, (char *) root->data, reqpath);
    if (n < 0 || (size_t) n >= sizeof(combined)) {
        ngx_log_error(NGX_LOG_WARN, log, 0, "xrootd: path too long");
        return 0;
    }

    if ((size_t) n >= resolvsz) {
        return 0;
    }

    ngx_cpystrn((u_char *) resolved, (u_char *) combined, resolvsz);
    return 1;
}

/*
 * xrootd_resolve_path
 *
 * Combine `root` and `reqpath` into a canonical absolute path,
 * then verify the result is still inside `root`.
 *
 * Returns 1 on success (resolved[] filled), 0 on failure.
 */
int
xrootd_resolve_path(ngx_log_t *log, const ngx_str_t *root,
                    const char *reqpath, char *resolved, size_t resolvsz)
{
    char combined[PATH_MAX * 2];
    char canonical[PATH_MAX];
    int  n;

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
        return 0;
    }

    if (strncmp(canonical, (char *) root->data, root->len) != 0) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd: path traversal attempt: %s", canonical);
        return 0;
    }

    if (canonical[root->len] != '\0' && canonical[root->len] != '/') {
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
 * xrootd_resolve_path_write
 *
 * Like xrootd_resolve_path but for write operations where the target file
 * may not yet exist.  Resolves the *parent directory* with realpath().
 *
 * Returns 1 on success (resolved[] filled), 0 on failure.
 */
int
xrootd_resolve_path_write(ngx_log_t *log, const ngx_str_t *root,
                           const char *reqpath, char *resolved, size_t resolvsz)
{
    char  combined[PATH_MAX * 2];
    char  parent_buf[PATH_MAX * 2];
    char  parent_canon[PATH_MAX];
    char *slash;
    const char *base;
    int   n;

    while (*reqpath == '/') {
        reqpath++;
    }

    n = snprintf(combined, sizeof(combined), "%.*s/%s",
                 (int) root->len, (char *) root->data, reqpath);
    if (n < 0 || (size_t) n >= sizeof(combined)) {
        ngx_log_error(NGX_LOG_WARN, log, 0, "xrootd: path too long");
        return 0;
    }

    ngx_cpystrn((u_char *) parent_buf, (u_char *) combined, sizeof(parent_buf));
    slash = strrchr(parent_buf, '/');
    if (slash == NULL || slash == parent_buf) {
        return 0;
    }
    base  = slash + 1;
    *slash = '\0';

    if (*base == '\0') {
        return 0;
    }

    if (realpath(parent_buf, parent_canon) == NULL) {
        return 0;
    }

    if (strncmp(parent_canon, (char *) root->data, root->len) != 0) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd: path traversal attempt in write: %s", parent_canon);
        return 0;
    }
    if (parent_canon[root->len] != '\0' && parent_canon[root->len] != '/') {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd: path traversal attempt in write: %s", parent_canon);
        return 0;
    }

    n = snprintf(resolved, resolvsz, "%s/%s", parent_canon, base);
    if (n < 0 || (size_t) n >= resolvsz) {
        return 0;
    }

    return 1;
}

/*
 * xrootd_mkdir_recursive — create a directory and all missing parent dirs.
 */
int
xrootd_mkdir_recursive(const char *path, mode_t mode)
{
    char  tmp[PATH_MAX];
    char *p;
    int   n;

    n = snprintf(tmp, sizeof(tmp), "%s", path);
    if (n < 0 || (size_t) n >= sizeof(tmp)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    if (n > 0 && tmp[n - 1] == '/') {
        tmp[n - 1] = '\0';
    }

    for (p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, mode) != 0 && errno != EEXIST) {
                return -1;
            }
            *p = '/';
        }
    }

    if (mkdir(tmp, mode) != 0 && errno != EEXIST) {
        return -1;
    }

    return 0;
}

/*
 * xrootd_strip_cgi — remove XRootD CGI query string from a path.
 */
void
xrootd_strip_cgi(const char *in, char *out, size_t outsz)
{
    const char *q = strchr(in, '?');
    size_t      len;

    if (q != NULL) {
        len = (size_t)(q - in);
    } else {
        len = strlen(in);
    }

    if (len >= outsz) {
        len = outsz - 1;
    }

    memcpy(out, in, len);
    out[len] = '\0';
}

/*
 * xrootd_make_stat_body — format a kXR_stat response body as ASCII.
 *
 * Format: "<id> <size> <flags> <mtime>\0"
 */
void
xrootd_make_stat_body(const struct stat *st, ngx_flag_t is_vfs,
                      char *out, size_t outsz)
{
    int flags = 0;

    if (is_vfs) {
        snprintf(out, outsz, "0 %lld %d %ld",
                 (long long) st->st_blocks * 512,
                 kXR_readable,
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

    snprintf(out, outsz, "%llu %lld %d %ld",
             (unsigned long long) st->st_ino,
             (long long) st->st_size,
             flags,
             (long) st->st_mtime);
}

/* ================================================================== */
/*  Access logging                                                      */
/* ================================================================== */

void
xrootd_log_access(xrootd_ctx_t *ctx, ngx_connection_t *c,
    const char *verb, const char *path, const char *detail,
    ngx_uint_t xrd_ok, uint16_t errcode, const char *errmsg, size_t bytes)
{
    ngx_stream_xrootd_srv_conf_t  *conf;
    ngx_msec_int_t                 duration_ms;
    char                           line[2048];
    int                            n;
    const char                    *authmethod, *identity;
    char                           client_ip[INET6_ADDRSTRLEN + 8];
    ngx_time_t                    *tp;
    struct tm                      tm;
    char                           timebuf[64];
    char                           errbuf[64];

    conf = ngx_stream_get_module_srv_conf(ctx->session, ngx_stream_xrootd_module);

    if (conf->access_log_fd == NGX_INVALID_FILE) {
        return;
    }

    if (c->addr_text.len > 0 && c->addr_text.len < sizeof(client_ip)) {
        ngx_memcpy(client_ip, c->addr_text.data, c->addr_text.len);
        client_ip[c->addr_text.len] = '\0';
    } else {
        client_ip[0] = '-';
        client_ip[1] = '\0';
    }

    if (conf->auth == XROOTD_AUTH_GSI) {
        authmethod = "gsi";
        identity   = (ctx->dn[0] != '\0') ? ctx->dn : "-";
    } else {
        authmethod = "anon";
        identity   = "-";
    }

    tp = ngx_timeofday();
    ngx_libc_localtime(tp->sec, &tm);
    strftime(timebuf, sizeof(timebuf), "%d/%b/%Y:%H:%M:%S %z", &tm);

    duration_ms = (ngx_msec_int_t)(ngx_current_msec - ctx->req_start);
    if (duration_ms < 0) {
        duration_ms = 0;
    }

    if (!xrd_ok && errmsg == NULL) {
        snprintf(errbuf, sizeof(errbuf), "code:%u", (unsigned) errcode);
        errmsg = errbuf;
    }

    if (xrd_ok) {
        n = snprintf(line, sizeof(line),
            "%s %s \"%s\" [%s] \"%s %s %s\" OK %zu %dms\n",
            client_ip,
            authmethod,
            identity,
            timebuf,
            verb,
            path   ? path   : "-",
            detail ? detail : "-",
            bytes,
            (int) duration_ms);
    } else {
        n = snprintf(line, sizeof(line),
            "%s %s \"%s\" [%s] \"%s %s %s\" ERR %zu %dms \"%s\"\n",
            client_ip,
            authmethod,
            identity,
            timebuf,
            verb,
            path   ? path   : "-",
            detail ? detail : "-",
            bytes,
            (int) duration_ms,
            errmsg);
    }

    if (n > 0 && (size_t) n < sizeof(line)) {
        (void) ngx_write_fd(conf->access_log_fd, line, (size_t) n);
    }
}
