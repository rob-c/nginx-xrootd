/*
 * HTTP-TPC COPY pull support for ngx_http_xrootd_webdav_module.
 *
 * This file intentionally owns the non-vanilla WebDAV behavior:
 *   - parse COPY Source, Credential, TransferHeader-prefixed, and Overwrite
 *     headers
 *   - pull an https:// source into a temporary local file with curl
 *   - atomically publish the completed file under the WebDAV root
 *
 * Native root:// third-party-copy is a different XRootD protocol flow and
 * should not be wired into this HTTP helper.
 */

#include "ngx_http_xrootd_webdav_module.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <limits.h>
#include <time.h>
#include <unistd.h>

/* Bound argv/header growth for external HTTP-TPC helpers */
#define WEBDAV_TPC_MAX_HEADERS  64
#define WEBDAV_TPC_MAX_ARGS     (32 + WEBDAV_TPC_MAX_HEADERS * 2)

void
ngx_http_xrootd_webdav_tpc_create_loc_conf(
    ngx_http_xrootd_webdav_loc_conf_t *conf)
{
    conf->tpc         = NGX_CONF_UNSET;
    conf->tpc_timeout = NGX_CONF_UNSET_UINT;
}

void
ngx_http_xrootd_webdav_tpc_merge_loc_conf(
    ngx_http_xrootd_webdav_loc_conf_t *conf,
    ngx_http_xrootd_webdav_loc_conf_t *prev)
{
    ngx_conf_merge_value(conf->tpc,          prev->tpc,          0);
    ngx_conf_merge_str_value(conf->tpc_curl, prev->tpc_curl,
                             "/usr/bin/curl");
    ngx_conf_merge_str_value(conf->tpc_cert, prev->tpc_cert, "");
    ngx_conf_merge_str_value(conf->tpc_key,  prev->tpc_key,  "");
    ngx_conf_merge_str_value(conf->tpc_cadir, prev->tpc_cadir, "");
    ngx_conf_merge_str_value(conf->tpc_cafile, prev->tpc_cafile, "");
    ngx_conf_merge_uint_value(conf->tpc_timeout, prev->tpc_timeout, 0);

    /*
     * Default outbound trust to the inbound WebDAV trust settings.  Operators
     * can still override with xrootd_webdav_tpc_cadir/cafile when the source
     * side uses a different CA bundle.
     */
    if (conf->tpc_cadir.len == 0 && conf->cadir.len > 0) {
        conf->tpc_cadir = conf->cadir;
    }
    if (conf->tpc_cafile.len == 0 && conf->cafile.len > 0) {
        conf->tpc_cafile = conf->cafile;
    }
    if (conf->tpc_key.len == 0 && conf->tpc_cert.len > 0) {
        conf->tpc_key = conf->tpc_cert;
    }
}

static ngx_table_elt_t *
webdav_tpc_find_header(ngx_http_request_t *r, const char *name,
                       size_t name_len)
{
    ngx_list_part_t  *part;
    ngx_table_elt_t  *hdr;
    ngx_uint_t        i;

    part = &r->headers_in.headers.part;
    hdr = part->elts;

    for (;;) {
        for (i = 0; i < part->nelts; i++) {
            if (hdr[i].key.len == name_len
                && ngx_strncasecmp(hdr[i].key.data,
                                   (u_char *) name, name_len) == 0)
            {
                return &hdr[i];
            }
        }

        if (part->next == NULL) {
            break;
        }

        part = part->next;
        hdr = part->elts;
    }

    return NULL;
}

static ngx_flag_t
webdav_tpc_str_has_ctl(const u_char *data, size_t len)
{
    size_t i;

    if (data == NULL) {
        return 1;
    }

    for (i = 0; i < len; i++) {
        if (data[i] < 0x20 || data[i] == 0x7f) {
            return 1;
        }
    }

    return 0;
}

static ngx_int_t
webdav_tpc_header_value_equals(ngx_str_t *value, const char *literal)
{
    u_char *start, *end;
    size_t  len, literal_len;

    if (value == NULL || literal == NULL) {
        return 0;
    }

    start = value->data;
    end = value->data + value->len;

    while (start < end && (*start == ' ' || *start == '\t')) {
        start++;
    }
    while (end > start && (end[-1] == ' ' || end[-1] == '\t')) {
        end--;
    }

    len = (size_t) (end - start);
    literal_len = strlen(literal);

    return len == literal_len
           && ngx_strncasecmp(start, (u_char *) literal, literal_len) == 0;
}

static char *
webdav_tpc_pstrndup0(ngx_pool_t *pool, const u_char *data, size_t len)
{
    char *out;

    out = ngx_pnalloc(pool, len + 1);
    if (out == NULL) {
        return NULL;
    }

    ngx_memcpy(out, data, len);
    out[len] = '\0';
    return out;
}

static ngx_int_t
webdav_tpc_collect_transfer_headers(ngx_http_request_t *r, ngx_array_t **out)
{
    ngx_array_t      *headers;
    ngx_list_part_t  *part;
    ngx_table_elt_t  *hdr;
    ngx_uint_t        i;
    const size_t      prefix_len = sizeof("TransferHeader") - 1;

    headers = ngx_array_create(r->pool, 4, sizeof(ngx_str_t));
    if (headers == NULL) {
        return NGX_ERROR;
    }

    part = &r->headers_in.headers.part;
    hdr = part->elts;

    for (;;) {
        for (i = 0; i < part->nelts; i++) {
            ngx_str_t *dst;
            size_t     name_len, value_len, total_len;
            u_char    *p;

            if (hdr[i].key.len <= prefix_len
                || ngx_strncasecmp(hdr[i].key.data,
                                   (u_char *) "TransferHeader",
                                   prefix_len) != 0)
            {
                continue;
            }

            /*
             * TransferHeaderFoo: bar means "send header Foo: bar to the
             * source endpoint".  Build the exact curl -H argument here, after
             * rejecting control characters so a malicious client cannot splice
             * extra command-line arguments or headers.
             */
            if (headers->nelts >= WEBDAV_TPC_MAX_HEADERS) {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                              "xrootd_webdav: too many TransferHeader* "
                              "headers in HTTP-TPC request");
                return NGX_HTTP_BAD_REQUEST;
            }

            name_len = hdr[i].key.len - prefix_len;
            value_len = hdr[i].value.len;

            if (webdav_tpc_str_has_ctl(hdr[i].key.data + prefix_len,
                                       name_len)
                || webdav_tpc_str_has_ctl(hdr[i].value.data, value_len))
            {
                return NGX_HTTP_BAD_REQUEST;
            }

            total_len = name_len + sizeof(": ") - 1 + value_len;
            dst = ngx_array_push(headers);
            if (dst == NULL) {
                return NGX_ERROR;
            }

            dst->data = ngx_pnalloc(r->pool, total_len + 1);
            if (dst->data == NULL) {
                return NGX_ERROR;
            }

            p = dst->data;
            p = ngx_cpymem(p, hdr[i].key.data + prefix_len, name_len);
            p = ngx_cpymem(p, ": ", sizeof(": ") - 1);
            p = ngx_cpymem(p, hdr[i].value.data, value_len);
            *p = '\0';
            dst->len = total_len;
        }

        if (part->next == NULL) {
            break;
        }

        part = part->next;
        hdr = part->elts;
    }

    *out = headers;
    return NGX_OK;
}

static ngx_int_t
webdav_tpc_run_curl_pull(ngx_http_request_t *r,
                         ngx_http_xrootd_webdav_loc_conf_t *conf,
                         const char *source_url, const char *tmp_path,
                         ngx_array_t *transfer_headers)
{
    char       *argv[WEBDAV_TPC_MAX_ARGS];
    ngx_uint_t argc = 0;
    ngx_uint_t i;
    ngx_str_t *headers;
    pid_t      pid;
    int        status;
    char       timeout_buf[32];

    /*
     * The helper is deliberately an external curl process instead of in-process
     * libcurl.  nginx workers stay event-driven and small, while failures in
     * TLS negotiation, redirects, or source-side HTTP handling are isolated to
     * the child process and reported as a 502 to the client.
     */
#define WEBDAV_TPC_ARG(v)                                                   \
    do {                                                                    \
        if (argc + 1 >= WEBDAV_TPC_MAX_ARGS) {                              \
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,                \
                          "xrootd_webdav: HTTP-TPC curl argv too long");    \
            return NGX_HTTP_INTERNAL_SERVER_ERROR;                          \
        }                                                                   \
        argv[argc++] = (char *) (v);                                         \
    } while (0)

    WEBDAV_TPC_ARG((char *) conf->tpc_curl.data);
    WEBDAV_TPC_ARG("--fail");
    WEBDAV_TPC_ARG("--location");
    WEBDAV_TPC_ARG("--silent");
    WEBDAV_TPC_ARG("--show-error");
    WEBDAV_TPC_ARG("--proto");
    WEBDAV_TPC_ARG("=https");

    if (conf->tpc_timeout > 0) {
        (void) snprintf(timeout_buf, sizeof(timeout_buf), "%u",
                        (unsigned) conf->tpc_timeout);
        WEBDAV_TPC_ARG("--max-time");
        WEBDAV_TPC_ARG(timeout_buf);
    }

    if (conf->tpc_cert.len > 0) {
        WEBDAV_TPC_ARG("--cert");
        WEBDAV_TPC_ARG((char *) conf->tpc_cert.data);
    }
    if (conf->tpc_key.len > 0) {
        WEBDAV_TPC_ARG("--key");
        WEBDAV_TPC_ARG((char *) conf->tpc_key.data);
    }
    if (conf->tpc_cafile.len > 0) {
        WEBDAV_TPC_ARG("--cacert");
        WEBDAV_TPC_ARG((char *) conf->tpc_cafile.data);
    }
    if (conf->tpc_cadir.len > 0) {
        WEBDAV_TPC_ARG("--capath");
        WEBDAV_TPC_ARG((char *) conf->tpc_cadir.data);
    }

    if (transfer_headers != NULL && transfer_headers->nelts > 0) {
        headers = transfer_headers->elts;
        for (i = 0; i < transfer_headers->nelts; i++) {
            WEBDAV_TPC_ARG("-H");
            WEBDAV_TPC_ARG((char *) headers[i].data);
        }
    }

    WEBDAV_TPC_ARG("--output");
    WEBDAV_TPC_ARG((char *) tmp_path);
    WEBDAV_TPC_ARG((char *) source_url);
    argv[argc] = NULL;

#undef WEBDAV_TPC_ARG

    pid = fork();
    if (pid < 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                      "xrootd_webdav: fork() failed for HTTP-TPC curl");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (pid == 0) {
        int nullfd;
        long fd, maxfd;

        /*
         * Child process hygiene: curl should not inherit nginx client sockets,
         * listening sockets, or temporary-file descriptors.  stderr remains
         * inherited so curl diagnostics land in the nginx error log.
         */
        nullfd = open("/dev/null", O_RDONLY);
        if (nullfd >= 0) {
            (void) dup2(nullfd, STDIN_FILENO);
            if (nullfd > STDERR_FILENO) {
                close(nullfd);
            }
        }

        maxfd = sysconf(_SC_OPEN_MAX);
        if (maxfd < 0 || maxfd > 65536) {
            maxfd = 65536;
        }
        for (fd = STDERR_FILENO + 1; fd < maxfd; fd++) {
            close((int) fd);
        }

        if (strchr((const char *) conf->tpc_curl.data, '/') != NULL) {
            execv((const char *) conf->tpc_curl.data, argv);
        } else {
            execvp((const char *) conf->tpc_curl.data, argv);
        }

        _exit(127);
    }

    for (;;) {
        if (waitpid(pid, &status, 0) >= 0) {
            break;
        }
        if (errno == EINTR) {
            continue;
        }
        ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                      "xrootd_webdav: waitpid() failed for HTTP-TPC curl");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                  "xrootd_webdav: HTTP-TPC curl failed status=%d",
                  status);
    return NGX_HTTP_BAD_GATEWAY;
}

ngx_int_t
ngx_http_xrootd_webdav_tpc_handle_copy(ngx_http_request_t *r)
{
    ngx_http_xrootd_webdav_loc_conf_t *conf;
    ngx_table_elt_t *source_hdr;
    ngx_table_elt_t *dest_hdr;
    ngx_table_elt_t *credential_hdr;
    ngx_table_elt_t *overwrite_hdr;
    ngx_array_t     *transfer_headers = NULL;
    char            *source_url;
    char             path[WEBDAV_MAX_PATH];
    char             tmp_path[WEBDAV_MAX_PATH];
    struct stat      sb;
    ngx_int_t        rc;
    ngx_flag_t       existed;
    ngx_flag_t       overwrite = 1;
    ngx_int_t        status;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_xrootd_webdav_module);

    source_hdr = webdav_tpc_find_header(r, "Source", sizeof("Source") - 1);
    dest_hdr = webdav_tpc_find_header(r, "Destination",
                                      sizeof("Destination") - 1);

    if (source_hdr == NULL) {
        if (dest_hdr != NULL) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "xrootd_webdav: HTTP-TPC push COPY is not implemented");
            return NGX_HTTP_NOT_IMPLEMENTED;
        }
        return NGX_HTTP_BAD_REQUEST;
    }

    if (dest_hdr != NULL) {
        return NGX_HTTP_BAD_REQUEST;
    }

    if (source_hdr->value.len < sizeof("https://") - 1
        || ngx_strncasecmp(source_hdr->value.data,
                           (u_char *) "https://",
                           sizeof("https://") - 1) != 0
        || webdav_tpc_str_has_ctl(source_hdr->value.data,
                                  source_hdr->value.len))
    {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "xrootd_webdav: HTTP-TPC Source must be an https URL");
        return NGX_HTTP_BAD_REQUEST;
    }

    source_url = webdav_tpc_pstrndup0(r->pool, source_hdr->value.data,
                                      source_hdr->value.len);
    if (source_url == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /*
     * This implementation supports service-credential or TransferHeader*
     * based authorization.  GridSite/OIDC delegation endpoints are separate
     * protocols, so fail explicitly when a client demands them.
     */
    credential_hdr = webdav_tpc_find_header(r, "Credential",
                                            sizeof("Credential") - 1);
    if (credential_hdr == NULL) {
        credential_hdr = webdav_tpc_find_header(r, "Credentials",
                                                sizeof("Credentials") - 1);
    }
    if (credential_hdr != NULL
        && !webdav_tpc_header_value_equals(&credential_hdr->value, "none"))
    {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "xrootd_webdav: unsupported HTTP-TPC credential "
                      "delegation requested");
        return NGX_HTTP_BAD_REQUEST;
    }

    overwrite_hdr = webdav_tpc_find_header(r, "Overwrite",
                                           sizeof("Overwrite") - 1);
    if (overwrite_hdr != NULL) {
        if (webdav_tpc_header_value_equals(&overwrite_hdr->value, "F")) {
            overwrite = 0;
        } else if (webdav_tpc_header_value_equals(&overwrite_hdr->value, "T")) {
            overwrite = 1;
        } else {
            return NGX_HTTP_BAD_REQUEST;
        }
    }

    rc = ngx_http_xrootd_webdav_resolve_path(r, conf->root_canon, path,
                                             sizeof(path));
    if (rc != NGX_OK) {
        return (ngx_int_t) rc;
    }

    existed = (stat(path, &sb) == 0) ? 1 : 0;
    if (existed && S_ISDIR(sb.st_mode)) {
        return NGX_HTTP_CONFLICT;
    }
    if (existed && !overwrite) {
        return NGX_HTTP_PRECONDITION_FAILED;
    }

    if ((size_t) snprintf(tmp_path, sizeof(tmp_path),
                          "%s.nginx-xrootd-tpc.%ld.%ld",
                          path, (long) getpid(), (long) time(NULL))
        >= sizeof(tmp_path))
    {
        return NGX_HTTP_REQUEST_URI_TOO_LARGE;
    }

    (void) unlink(tmp_path);

    rc = webdav_tpc_collect_transfer_headers(r, &transfer_headers);
    if (rc != NGX_OK) {
        return rc;
    }

    rc = webdav_tpc_run_curl_pull(r, conf, source_url, tmp_path,
                                  transfer_headers);
    if (rc != NGX_OK) {
        (void) unlink(tmp_path);
        return rc;
    }

    if (!overwrite) {
        if (link(tmp_path, path) != 0) {
            status = (errno == EEXIST) ? NGX_HTTP_PRECONDITION_FAILED
                                       : NGX_HTTP_INTERNAL_SERVER_ERROR;
            (void) unlink(tmp_path);
            return status;
        }
        (void) unlink(tmp_path);
    } else if (rename(tmp_path, path) != 0) {
        ngx_http_xrootd_webdav_log_safe_path(r->connection->log, NGX_LOG_ERR,
                                             ngx_errno,
                                             "xrootd_webdav: HTTP-TPC rename "
                                             "failed for",
                                             path);
        (void) unlink(tmp_path);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    status = existed ? NGX_HTTP_NO_CONTENT : NGX_HTTP_CREATED;
    r->headers_out.status = status;
    r->headers_out.content_length_n = 0;

    ngx_http_send_header(r);
    return ngx_http_send_special(r, NGX_HTTP_LAST);
}
