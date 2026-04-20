/*
 * ngx_http_xrootd_webdav_path.c — URL decoding, path security, and resolution.
 *
 * Centralises all path-related security logic: URL-percent decoding, traversal
 * detection, realpath canonicalisation, and the within-root check.  This code
 * is security-critical and changes independently from feature work.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <sys/stat.h>
#include <limits.h>
#include <unistd.h>

#include "ngx_http_xrootd_webdav_module.h"

/* ------------------------------------------------------------------ */
/* Hex helpers                                                          */
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

/* ------------------------------------------------------------------ */
/* Safe logging                                                         */
/* ------------------------------------------------------------------ */

void
ngx_http_xrootd_webdav_log_safe_path(ngx_log_t *log, ngx_uint_t level,
                                     ngx_err_t err, const char *prefix,
                                     const char *path)
{
    char safe_path[512];

    xrootd_sanitize_log_string(path, safe_path, sizeof(safe_path));
    ngx_log_error(level, log, err, "%s: \"%s\"", prefix, safe_path);
}

/* ------------------------------------------------------------------ */
/* Path traversal detection                                             */
/* ------------------------------------------------------------------ */

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

/* ------------------------------------------------------------------ */
/* URL decoding                                                         */
/* ------------------------------------------------------------------ */

ngx_int_t
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

/* ------------------------------------------------------------------ */
/* XML text escaping                                                    */
/* ------------------------------------------------------------------ */

char *
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
/* Path resolution                                                      */
/* Returns NGX_OK and fills out[] on success, NGX_HTTP_* error code     */
/* on traversal attack or other error.                                  */
/* ------------------------------------------------------------------ */

ngx_int_t
ngx_http_xrootd_webdav_resolve_path(ngx_http_request_t *r,
                                    const char *root_canon,
                                    char *out, size_t outsz)
{
    char   uri_decoded[WEBDAV_MAX_PATH];
    char   combined[PATH_MAX];
    char   resolved[PATH_MAX];
    ngx_int_t rc;

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
