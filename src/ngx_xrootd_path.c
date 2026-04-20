#include "ngx_xrootd_module.h"

static ngx_inline u_char
xrootd_hex_digit(u_char value)
{
    return (value < 10) ? (u_char) ('0' + value)
                        : (u_char) ('A' + (value - 10));
}

static int xrootd_get_canonical_root(ngx_log_t *log, const ngx_str_t *root,
                                     char *root_canon, size_t root_canon_sz);
static int xrootd_path_component_forbidden(const char *comp, size_t comp_len);

static ngx_flag_t
xrootd_path_prefix_match(const char *prefix, const char *path)
{
    size_t prefix_len;

    if (prefix == NULL || path == NULL) {
        return 0;
    }

    prefix_len = strlen(prefix);
    if (strncmp(prefix, path, prefix_len) != 0) {
        return 0;
    }

    return path[prefix_len] == '\0' || path[prefix_len] == '/';
}

static mode_t
xrootd_parent_group_mode_bits(const struct stat *parent, const struct stat *child)
{
    mode_t group_bits;

    if (S_ISDIR(child->st_mode)) {
        group_bits = parent->st_mode & S_IRWXG;
    } else {
        group_bits = parent->st_mode & (S_IRGRP | S_IWGRP);
        if (child->st_mode & S_IXGRP) {
            group_bits |= S_IXGRP;
        }
    }

    return group_bits;
}

static ngx_int_t
xrootd_apply_parent_group_policy_impl(ngx_log_t *log, int fd,
                                      const char *path, ngx_array_t *rules)
{
    const xrootd_group_rule_t *rule;
    struct stat                parent_st;
    struct stat                child_st;
    char                       parent[PATH_MAX];
    char                      *slash;
    mode_t                     desired_mode;
    int                        rc;

    (void) log;

    rule = xrootd_find_group_rule(path, rules);
    if (rule == NULL) {
        return NGX_DECLINED;
    }

    rc = snprintf(parent, sizeof(parent), "%s", path);
    if (rc < 0 || (size_t) rc >= sizeof(parent)) {
        errno = ENAMETOOLONG;
        return NGX_ERROR;
    }

    slash = strrchr(parent, '/');
    if (slash == NULL || slash == parent) {
        return NGX_DECLINED;
    }

    *slash = '\0';

    if (stat(parent, &parent_st) != 0) {
        return NGX_ERROR;
    }

    if (fd >= 0) {
        if (fstat(fd, &child_st) != 0) {
            return NGX_ERROR;
        }
    } else {
        if (stat(path, &child_st) != 0) {
            return NGX_ERROR;
        }
    }

    desired_mode = (child_st.st_mode & ~(S_IRWXG | S_ISGID))
                 | xrootd_parent_group_mode_bits(&parent_st, &child_st);

    if (S_ISDIR(child_st.st_mode) && (parent_st.st_mode & S_ISGID)) {
        desired_mode |= S_ISGID;
    }

    if (child_st.st_gid != parent_st.st_gid) {
        if (fd >= 0) {
            if (fchown(fd, (uid_t) -1, parent_st.st_gid) != 0) {
                return NGX_ERROR;
            }
        } else {
            if (chown(path, (uid_t) -1, parent_st.st_gid) != 0) {
                return NGX_ERROR;
            }
        }
    }

    if ((child_st.st_mode & 07777) != (desired_mode & 07777)) {
        if (fd >= 0) {
            if (fchmod(fd, desired_mode & 07777) != 0) {
                return NGX_ERROR;
            }
        } else {
            if (chmod(path, desired_mode & 07777) != 0) {
                return NGX_ERROR;
            }
        }
    }

    return NGX_OK;
}

/* VOMS extraction has moved to ngx_xrootd_voms.c (dlopen wrapper). */

size_t
xrootd_sanitize_log_string(const char *in, char *out, size_t outsz)
{
    const u_char *src;
    size_t        written = 0;
    u_char        ch;

    if (out == NULL || outsz == 0) {
        return 0;
    }

    src = (const u_char *) ((in != NULL) ? in : "-");

    while (*src != '\0' && written + 1 < outsz) {
        ch = *src++;

        /* Keep logs single-line and quote-safe by escaping whitespace/control bytes. */
        if (ch >= 0x21 && ch <= 0x7e && ch != '"' && ch != '\\') {
            out[written++] = (char) ch;
            continue;
        }

        if (written + 4 >= outsz) {
            break;
        }

        out[written++] = '\\';
        out[written++] = 'x';
        out[written++] = (char) xrootd_hex_digit((u_char) (ch >> 4));
        out[written++] = (char) xrootd_hex_digit((u_char) (ch & 0x0f));
    }

    out[written] = '\0';
    return written;
}

ngx_int_t
xrootd_normalize_policy_path(ngx_pool_t *pool, const ngx_str_t *src,
                             ngx_str_t *dst)
{
    u_char *out;
    size_t  i = 0;
    size_t  written = 0;

    if (pool == NULL || src == NULL || dst == NULL || src->len == 0) {
        return NGX_ERROR;
    }

    out = ngx_pnalloc(pool, src->len + 2);
    if (out == NULL) {
        return NGX_ERROR;
    }

    out[written++] = '/';

    while (i < src->len) {
        size_t start;
        size_t seg_len;

        while (i < src->len && src->data[i] == '/') {
            i++;
        }

        if (i == src->len) {
            break;
        }

        start = i;
        while (i < src->len && src->data[i] != '/') {
            i++;
        }

        seg_len = i - start;
        if (seg_len == 0) {
            continue;
        }

        if (xrootd_path_component_forbidden((const char *) src->data + start,
                                            seg_len)) {
            return NGX_ERROR;
        }

        if (written > 1) {
            out[written++] = '/';
        }

        ngx_memcpy(out + written, src->data + start, seg_len);
        written += seg_len;
    }

    if (written == 0) {
        out[written++] = '/';
    }

    out[written] = '\0';
    dst->data = out;
    dst->len = written;
    return NGX_OK;
}

ngx_array_t *
xrootd_merge_arrays(ngx_conf_t *cf, ngx_array_t *parent, ngx_array_t *child,
                    size_t element_size)
{
    ngx_array_t *merged;
    char        *dst;
    size_t       total = 0;

    if (parent != NULL) {
        total += parent->nelts;
    }
    if (child != NULL) {
        total += child->nelts;
    }

    if (total == 0) {
        return NULL;
    }

    merged = ngx_array_create(cf->pool, (ngx_uint_t) total, element_size);
    if (merged == NULL) {
        return NULL;
    }

    if (parent != NULL && parent->nelts > 0) {
        dst = ngx_array_push_n(merged, parent->nelts);
        if (dst == NULL) {
            return NULL;
        }
        ngx_memcpy(dst, parent->elts, parent->nelts * element_size);
    }

    if (child != NULL && child->nelts > 0) {
        dst = ngx_array_push_n(merged, child->nelts);
        if (dst == NULL) {
            return NULL;
        }
        ngx_memcpy(dst, child->elts, child->nelts * element_size);
    }

    return merged;
}

ngx_int_t
xrootd_finalize_vo_rules(ngx_log_t *log, const ngx_str_t *root,
                         ngx_array_t *rules)
{
    xrootd_vo_rule_t *rule;
    ngx_uint_t        i;
    char              root_canon[PATH_MAX];

    if (rules == NULL) {
        return NGX_OK;
    }

    if (!xrootd_get_canonical_root(log, root, root_canon, sizeof(root_canon))) {
        return NGX_ERROR;
    }

    rule = rules->elts;
    for (i = 0; i < rules->nelts; i++) {
        if (rule[i].path.len == 1 && rule[i].path.data[0] == '/') {
            ngx_cpystrn((u_char *) rule[i].resolved, (u_char *) root_canon,
                        sizeof(rule[i].resolved));
            continue;
        }

        if (!xrootd_resolve_path_noexist(log, root, (const char *) rule[i].path.data,
                                         rule[i].resolved,
                                         sizeof(rule[i].resolved))) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

ngx_int_t
xrootd_finalize_group_rules(ngx_log_t *log, const ngx_str_t *root,
                            ngx_array_t *rules)
{
    xrootd_group_rule_t *rule;
    ngx_uint_t           i;
    char                 root_canon[PATH_MAX];

    if (rules == NULL) {
        return NGX_OK;
    }

    if (!xrootd_get_canonical_root(log, root, root_canon, sizeof(root_canon))) {
        return NGX_ERROR;
    }

    rule = rules->elts;
    for (i = 0; i < rules->nelts; i++) {
        if (rule[i].path.len == 1 && rule[i].path.data[0] == '/') {
            ngx_cpystrn((u_char *) rule[i].resolved, (u_char *) root_canon,
                        sizeof(rule[i].resolved));
            continue;
        }

        if (!xrootd_resolve_path_noexist(log, root, (const char *) rule[i].path.data,
                                         rule[i].resolved,
                                         sizeof(rule[i].resolved))) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

const xrootd_vo_rule_t *
xrootd_find_vo_rule(const char *resolved_path, ngx_array_t *rules)
{
    const xrootd_vo_rule_t *best = NULL;
    xrootd_vo_rule_t       *rule;
    size_t                  best_len = 0;
    ngx_uint_t              i;

    if (resolved_path == NULL || rules == NULL) {
        return NULL;
    }

    rule = rules->elts;
    for (i = 0; i < rules->nelts; i++) {
        size_t rule_len = strlen(rule[i].resolved);

        if (!xrootd_path_prefix_match(rule[i].resolved, resolved_path)) {
            continue;
        }

        if (rule_len >= best_len) {
            best = &rule[i];
            best_len = rule_len;
        }
    }

    return best;
}

const xrootd_group_rule_t *
xrootd_find_group_rule(const char *resolved_path, ngx_array_t *rules)
{
    const xrootd_group_rule_t *best = NULL;
    xrootd_group_rule_t       *rule;
    size_t                     best_len = 0;
    ngx_uint_t                 i;

    if (resolved_path == NULL || rules == NULL) {
        return NULL;
    }

    rule = rules->elts;
    for (i = 0; i < rules->nelts; i++) {
        size_t rule_len = strlen(rule[i].resolved);

        if (!xrootd_path_prefix_match(rule[i].resolved, resolved_path)) {
            continue;
        }

        if (rule_len >= best_len) {
            best = &rule[i];
            best_len = rule_len;
        }
    }

    return best;
}

const xrootd_manager_map_t *
xrootd_find_manager_map(const char *reqpath, ngx_array_t *map)
{
    const xrootd_manager_map_t *best = NULL;
    xrootd_manager_map_t       *entry;
    size_t                      best_len = 0;
    ngx_uint_t                  i;

    if (reqpath == NULL || map == NULL) {
        return NULL;
    }

    entry = map->elts;
    for (i = 0; i < map->nelts; i++) {
        size_t prefix_len = entry[i].prefix.len;

        if (!xrootd_path_prefix_match((const char *) entry[i].prefix.data, reqpath)) {
            continue;
        }

        if (prefix_len >= best_len) {
            best = &entry[i];
            best_len = prefix_len;
        }
    }

    return best;
}

ngx_flag_t
xrootd_vo_list_contains(const char *vo_list, const char *required_vo)
{
    const char *start;
    const char *end;
    size_t      required_len;

    if (required_vo == NULL || required_vo[0] == '\0') {
        return 1;
    }

    if (vo_list == NULL || vo_list[0] == '\0') {
        return 0;
    }

    required_len = strlen(required_vo);
    start = vo_list;

    while (*start != '\0') {
        end = strchr(start, ',');
        if (end == NULL) {
            end = start + strlen(start);
        }

        if ((size_t) (end - start) == required_len
            && ngx_strncmp(start, required_vo, required_len) == 0)
        {
            return 1;
        }

        start = (*end == '\0') ? end : end + 1;
    }

    return 0;
}

/*
 * Check whether the resolved path is accessible given the client's VO
 * membership list.  Returns NGX_OK if allowed, NGX_ERROR if denied.
 *
 * Allow rules:
 *   - No vo_rules configured → open access.
 *   - Resolved path is not under any restricted tree → open access.
 *   - Path is under a restricted tree and client's vo_list contains the
 *     required VO → access granted.
 *   - Otherwise → denied.
 */
ngx_int_t
xrootd_check_vo_acl(ngx_log_t *log, const char *resolved_path,
                    ngx_array_t *vo_rules, const char *vo_list)
{
    const xrootd_vo_rule_t *rule;
    char                    safe_path[512];
    char                    safe_vo[128];

    if (vo_rules == NULL || vo_rules->nelts == 0) {
        return NGX_OK;
    }

    rule = xrootd_find_vo_rule(resolved_path, vo_rules);
    if (rule == NULL) {
        return NGX_OK;
    }

    if (xrootd_vo_list_contains(vo_list, (const char *) rule->vo.data)) {
        return NGX_OK;
    }

    xrootd_sanitize_log_string(resolved_path, safe_path, sizeof(safe_path));
    xrootd_sanitize_log_string((const char *) rule->vo.data, safe_vo, sizeof(safe_vo));
    ngx_log_error(NGX_LOG_WARN, log, 0,
                  "xrootd: VO ACL denied path=\"%s\" required_vo=\"%s\" "
                  "client_vos=\"%s\"",
                  safe_path, safe_vo, (vo_list && vo_list[0]) ? vo_list : "-");

    return NGX_ERROR;
}

ngx_int_t
xrootd_apply_parent_group_policy_fd(ngx_log_t *log, int fd, const char *path,
                                    ngx_array_t *rules)
{
    return xrootd_apply_parent_group_policy_impl(log, fd, path, rules);
}

ngx_int_t
xrootd_apply_parent_group_policy_path(ngx_log_t *log, const char *path,
                                      ngx_array_t *rules)
{
    return xrootd_apply_parent_group_policy_impl(log, -1, path, rules);
}

static void
xrootd_log_path_warning(ngx_log_t *log, const char *prefix, const char *path)
{
    char safe_path[512];

    xrootd_sanitize_log_string(path, safe_path, sizeof(safe_path));
    ngx_log_error(NGX_LOG_WARN, log, 0, "%s: %s", prefix, safe_path);
}

/*
 * Canonicalize the configured export root once per resolution attempt so all
 * subsequent prefix checks compare normalized absolute paths.
 */
static int
xrootd_get_canonical_root(ngx_log_t *log, const ngx_str_t *root,
                          char *root_canon, size_t root_canon_sz)
{
    char root_buf[PATH_MAX];

    /* Convert nginx's length-tracked ngx_str_t into a temporary C string first. */
    if (root == NULL || root->len == 0 || root->len >= sizeof(root_buf)) {
        return 0;
    }

    ngx_memcpy(root_buf, root->data, root->len);
    root_buf[root->len] = '\0';

    if (realpath(root_buf, root_canon) == NULL) {
        ngx_log_error(NGX_LOG_WARN, log, errno,
                      "xrootd: cannot canonicalize root \"%s\"", root_buf);
        return 0;
    }

    /* Guard against callers providing a destination buffer too small for the result. */
    if (ngx_strnlen((u_char *) root_canon, root_canon_sz) >= root_canon_sz) {
        return 0;
    }

    return 1;
}

/*
 * Accept either the root itself or any descendant path under it.  A plain
 * prefix comparison is not enough because "/data/root2" must not match
 * "/data/root".
 */
static int
xrootd_path_within_root(const char *root_canon, const char *path_canon)
{
    size_t root_len = strlen(root_canon);

    if (strncmp(path_canon, root_canon, root_len) != 0) {
        return 0;
    }

    return path_canon[root_len] == '\0' || path_canon[root_len] == '/';
}

/* Reject single-dot and dot-dot path components before touching the FS. */
static int
xrootd_path_component_forbidden(const char *comp, size_t comp_len)
{
    return (comp_len == 1 && comp[0] == '.')
        || (comp_len == 2 && comp[0] == '.' && comp[1] == '.');
}

/*
 * Copy an on-the-wire path payload into a C string after applying the XRootD
 * conventions used by real clients:
 *   - a single trailing NUL terminator is allowed inside dlen
 *   - embedded NUL bytes are rejected
 *   - CGI metadata suffixes can be stripped for ops that treat them as hints
 */
int
xrootd_extract_path(ngx_log_t *log, const u_char *payload, size_t payload_len,
                    char *out, size_t outsz, ngx_flag_t strip_cgi)
{
    const u_char *nul;
    const u_char *qmark;
    size_t        copy_len;

    if (payload == NULL || payload_len == 0 || out == NULL || outsz < 2) {
        return 0;
    }

    if (payload_len > XROOTD_MAX_PATH) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd: path payload too long (%uz bytes)", payload_len);
        return 0;
    }

    nul = memchr(payload, '\0', payload_len);
    if (nul != NULL) {
        /* Real XRootD clients often include the terminating NUL in dlen. */
        if (nul != payload + payload_len - 1) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "xrootd: rejecting path payload with embedded NUL");
            return 0;
        }
        payload_len--;
    }

    copy_len = payload_len;
    if (strip_cgi) {
        /* Ignore client-side metadata such as ?oss.asize=... during lookup. */
        qmark = memchr(payload, '?', payload_len);
        if (qmark != NULL) {
            copy_len = (size_t) (qmark - payload);
        }
    }

    if (copy_len == 0 || copy_len >= outsz) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd: invalid path payload length (%uz bytes)", copy_len);
        return 0;
    }

    ngx_memcpy(out, payload, copy_len);
    out[copy_len] = '\0';
    return 1;
}

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
    char        root_canon[PATH_MAX];
    char        current[PATH_MAX];
    char        candidate[PATH_MAX];
    struct stat st;
    const char *p;
    int         n;

    while (*reqpath == '/') {
        /* Treat client paths as root-relative even if they include repeated leading '/'. */
        reqpath++;
    }

    if (*reqpath == '\0') {
        return 0;
    }

    if (!xrootd_get_canonical_root(log, root, root_canon, sizeof(root_canon))) {
        return 0;
    }

    ngx_cpystrn((u_char *) current, (u_char *) root_canon, sizeof(current));

    p = reqpath;
    while (*p) {
        const char *seg_end;
        size_t      seg_len;

        /* Skip duplicate separators between path components. */
        while (*p == '/') {
            p++;
        }
        if (*p == '\0') {
            break;
        }

        seg_end = strchr(p, '/');
        seg_len = seg_end ? (size_t)(seg_end - p) : strlen(p);

        if (xrootd_path_component_forbidden(p, seg_len)) {
            xrootd_log_path_warning(log, "xrootd: path traversal attempt", reqpath);
            return 0;
        }

        /* Build the next path prefix one component at a time. */
        n = snprintf(candidate, sizeof(candidate), "%s/%.*s",
                     current, (int) seg_len, p);
        if (n < 0 || (size_t) n >= sizeof(candidate)) {
            ngx_log_error(NGX_LOG_WARN, log, 0, "xrootd: path too long");
            return 0;
        }

        if (lstat(candidate, &st) == 0) {
            /* Existing prefixes may be symlinks; canonicalize and re-check. */
            if (realpath(candidate, current) == NULL) {
                return 0;
            }
            if (!xrootd_path_within_root(root_canon, current)) {
                xrootd_log_path_warning(log, "xrootd: path traversal attempt", current);
                return 0;
            }

        } else if (errno == ENOENT) {
            /*
             * Missing suffixes are fine for mkdir -p / create-style requests.
             * From this point on we append lexically because there is nothing
             * on disk yet that realpath() could canonicalize.
             */
            ngx_cpystrn((u_char *) current, (u_char *) candidate, sizeof(current));

        } else {
            return 0;
        }

        if (seg_end == NULL) {
            break;
        }
        p = seg_end + 1;
    }

    n = snprintf(resolved, resolvsz, "%s", current);
    if (n < 0 || (size_t) n >= resolvsz) {
        return 0;
    }

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
    char root_canon[PATH_MAX];
    const char *p = reqpath;
    int  n;

    if (!xrootd_get_canonical_root(log, root, root_canon, sizeof(root_canon))) {
        return 0;
    }

    while (*p == '/') {
        /* Normalize client requests to a root-relative form. */
        p++;
    }

    if (*p == '\0') {
        /* A request for "/" resolves to the canonical export root itself. */
        n = snprintf(resolved, resolvsz, "%s", root_canon);
        return (n >= 0 && (size_t) n < resolvsz);
    }

    {
        const char *scan = p;
        while (*scan) {
            const char *seg_end = strchr(scan, '/');
            size_t      seg_len = seg_end ? (size_t) (seg_end - scan) : strlen(scan);

            /* Fast reject before any realpath() call normalizes the request. */
            if (xrootd_path_component_forbidden(scan, seg_len)) {
                xrootd_log_path_warning(log, "xrootd: path traversal attempt", reqpath);
                return 0;
            }

            if (seg_end == NULL) {
                break;
            }

            /* Continue scanning the lexical request one component at a time. */
            scan = seg_end + 1;
        }
    }

    n = snprintf(combined, sizeof(combined), "%.*s/%s",
                 (int) strlen(root_canon), root_canon, p);

    if (n < 0 || (size_t) n >= sizeof(combined)) {
        ngx_log_error(NGX_LOG_WARN, log, 0, "xrootd: path too long");
        return 0;
    }

    if (realpath(combined, canonical) == NULL) {
        return 0;
    }

    /* Canonical target must still live under the canonical export root. */
    if (!xrootd_path_within_root(root_canon, canonical)) {
        xrootd_log_path_warning(log, "xrootd: path traversal attempt", canonical);
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
    char  root_canon[PATH_MAX];
    char  combined[PATH_MAX * 2];
    char  parent_buf[PATH_MAX * 2];
    char  parent_canon[PATH_MAX];
    char *slash;
    const char *base;
    size_t base_len;
    int   n;

    if (!xrootd_get_canonical_root(log, root, root_canon, sizeof(root_canon))) {
        return 0;
    }

    while (*reqpath == '/') {
        /* Collapse client-leading slashes before splitting parent vs basename. */
        reqpath++;
    }

    if (*reqpath == '\0') {
        return 0;
    }

    n = snprintf(combined, sizeof(combined), "%.*s/%s",
                 (int) strlen(root_canon), root_canon, reqpath);
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

    base_len = strlen(base);
    /* The final component may not exist yet, but it still cannot be . or .. */
    if (xrootd_path_component_forbidden(base, base_len)) {
        xrootd_log_path_warning(log, "xrootd: path traversal attempt", reqpath);
        return 0;
    }

    /* Canonicalize only the existing parent; the leaf may be created next. */
    if (realpath(parent_buf, parent_canon) == NULL) {
        return 0;
    }

    /* Only the parent must already exist; the final leaf may be created next. */
    if (!xrootd_path_within_root(root_canon, parent_canon)) {
        xrootd_log_path_warning(log, "xrootd: path traversal attempt in write", parent_canon);
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
    return xrootd_mkdir_recursive_policy(path, mode, NULL, NULL);
}

int
xrootd_mkdir_recursive_policy(const char *path, mode_t mode,
                              ngx_log_t *log, ngx_array_t *rules)
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
            /* Temporarily cut the string here so mkdir() sees the current prefix only. */
            *p = '\0';
            if (mkdir(tmp, mode) != 0) {
                if (errno != EEXIST) {
                    return -1;
                }
            } else if (log != NULL && rules != NULL) {
                if (xrootd_apply_parent_group_policy_path(log, tmp, rules) == NGX_ERROR) {
                    return -1;
                }
            }
            /* Restore the separator and continue with the next deeper component. */
            *p = '/';
        }
    }

    /* Final mkdir handles the full requested path after all parent prefixes. */
    if (mkdir(tmp, mode) != 0) {
        if (errno != EEXIST) {
            return -1;
        }
    } else if (log != NULL && rules != NULL) {
        if (xrootd_apply_parent_group_policy_path(log, tmp, rules) == NGX_ERROR) {
            return -1;
        }
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

    /* Everything after '?' is client-side metadata, not part of the filesystem path. */
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
        /* VFS replies use capacity-style information instead of inode/path metadata. */
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

    /* XRootD stat flags are derived from POSIX mode bits and file type. */
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
    char                           line[4096];
    int                            n;
    const char                    *authmethod, *identity;
    char                           client_ip[INET6_ADDRSTRLEN + 8];
    char                           safe_client_ip[128];
    char                           safe_identity[1024];
    char                           safe_verb[64];
    char                           safe_path[1024];
    char                           safe_detail[512];
    char                           safe_errmsg[1024];
    ngx_time_t                    *tp;
    struct tm                      tm;
    char                           timebuf[64];
    char                           errbuf[64];

    conf = ngx_stream_get_module_srv_conf(ctx->session, ngx_stream_xrootd_module);

    if (conf->access_log_fd == NGX_INVALID_FILE) {
        return;
    }

    /* Snapshot the peer address into a local C string for the log line builder. */
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

    /* If the caller omitted text for a failed op, at least record the numeric code. */
    if (!xrd_ok && errmsg == NULL) {
        snprintf(errbuf, sizeof(errbuf), "code:%u", (unsigned) errcode);
        errmsg = errbuf;
    }

    xrootd_sanitize_log_string(client_ip, safe_client_ip, sizeof(safe_client_ip));
    xrootd_sanitize_log_string(identity, safe_identity, sizeof(safe_identity));
    xrootd_sanitize_log_string(verb ? verb : "-", safe_verb, sizeof(safe_verb));
    xrootd_sanitize_log_string(path ? path : "-", safe_path, sizeof(safe_path));
    xrootd_sanitize_log_string(detail ? detail : "-", safe_detail, sizeof(safe_detail));
    xrootd_sanitize_log_string(errmsg ? errmsg : "-", safe_errmsg, sizeof(safe_errmsg));

    if (xrd_ok) {
        n = snprintf(line, sizeof(line),
            "%s %s \"%s\" [%s] \"%s %s %s\" OK %zu %dms\n",
            safe_client_ip,
            authmethod,
            safe_identity,
            timebuf,
            safe_verb,
            safe_path,
            safe_detail,
            bytes,
            (int) duration_ms);
    } else {
        n = snprintf(line, sizeof(line),
            "%s %s \"%s\" [%s] \"%s %s %s\" ERR %zu %dms \"%s\"\n",
            safe_client_ip,
            authmethod,
            safe_identity,
            timebuf,
            safe_verb,
            safe_path,
            safe_detail,
            bytes,
            (int) duration_ms,
            safe_errmsg);
    }

    if (n > 0 && (size_t) n < sizeof(line)) {
        (void) ngx_write_fd(conf->access_log_fd, line, (size_t) n);
    }
}
