#include "ngx_xrootd_module.h"
#include <ctype.h>

/* ================================================================== */
/*  Configuration management                                            */
/* ================================================================== */

typedef enum {
    XROOTD_PATH_REGULAR_FILE,
    XROOTD_PATH_DIRECTORY,
    XROOTD_PATH_FILE_OR_DIRECTORY
} xrootd_path_kind_t;

static ngx_int_t
xrootd_validate_path(ngx_conf_t *cf, const char *label, const ngx_str_t *path,
                     xrootd_path_kind_t kind, int access_mode)
{
    struct stat st;

    if (path == NULL || path->len == 0 || path->data == NULL) {
        return NGX_OK;
    }

    if (stat((char *) path->data, &st) != 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           "xrootd: %s path \"%s\" is not accessible",
                           label, path->data);
        return NGX_ERROR;
    }

    switch (kind) {
    case XROOTD_PATH_REGULAR_FILE:
        if (!S_ISREG(st.st_mode)) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "xrootd: %s path \"%s\" must be a regular file",
                               label, path->data);
            return NGX_ERROR;
        }
        break;

    case XROOTD_PATH_DIRECTORY:
        if (!S_ISDIR(st.st_mode)) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "xrootd: %s path \"%s\" must be a directory",
                               label, path->data);
            return NGX_ERROR;
        }
        break;

    case XROOTD_PATH_FILE_OR_DIRECTORY:
        if (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode)) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "xrootd: %s path \"%s\" must be a file or directory",
                               label, path->data);
            return NGX_ERROR;
        }
        break;
    }

    if (access_mode != 0 && access((char *) path->data, access_mode) != 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           "xrootd: %s path \"%s\" failed permission check",
                           label, path->data);
        return NGX_ERROR;
    }

    return NGX_OK;
}

static char *
xrootd_copy_conf_string(ngx_conf_t *cf, const ngx_str_t *src, ngx_str_t *dst)
{
    dst->data = ngx_pnalloc(cf->pool, src->len + 1);
    if (dst->data == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memcpy(dst->data, src->data, src->len);
    dst->data[src->len] = '\0';
    dst->len = src->len;
    return NGX_CONF_OK;
}

char *
xrootd_conf_set_require_vo(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_xrootd_srv_conf_t *xcf = conf;
    ngx_str_t                    *value;
    xrootd_vo_rule_t             *rule;

    value = cf->args->elts;
    (void) cmd;

    if (xcf->vo_rules == NULL) {
        xcf->vo_rules = ngx_array_create(cf->pool, 2, sizeof(xrootd_vo_rule_t));
        if (xcf->vo_rules == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    rule = ngx_array_push(xcf->vo_rules);
    if (rule == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(rule, sizeof(*rule));

    if (xrootd_normalize_policy_path(cf->pool, &value[1], &rule->path) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_require_vo: invalid path \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    if (xrootd_copy_conf_string(cf, &value[2], &rule->vo) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

char *
xrootd_conf_set_inherit_parent_group(ngx_conf_t *cf, ngx_command_t *cmd,
                                     void *conf)
{
    ngx_stream_xrootd_srv_conf_t *xcf = conf;
    ngx_str_t                    *value;
    xrootd_group_rule_t          *rule;

    value = cf->args->elts;
    (void) cmd;

    if (xcf->group_rules == NULL) {
        xcf->group_rules = ngx_array_create(cf->pool, 2,
                                            sizeof(xrootd_group_rule_t));
        if (xcf->group_rules == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    rule = ngx_array_push(xcf->group_rules);
    if (rule == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(rule, sizeof(*rule));

    if (xrootd_normalize_policy_path(cf->pool, &value[1], &rule->path) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_inherit_parent_group: invalid path \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


char *
xrootd_conf_set_manager_map(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_xrootd_srv_conf_t *xcf = conf;
    ngx_str_t                    *value;
    xrootd_manager_map_t         *entry;
    char                         *addr_copy;
    char                         *endp;
    long                          pnum;

    value = cf->args->elts;
    (void) cmd;

    if (xcf->manager_map == NULL) {
        xcf->manager_map = ngx_array_create(cf->pool, 2,
                                           sizeof(xrootd_manager_map_t));
        if (xcf->manager_map == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    entry = ngx_array_push(xcf->manager_map);
    if (entry == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(entry, sizeof(*entry));

    /* Normalize and store the prefix path (policy-style) */
    if (xrootd_normalize_policy_path(cf->pool, &value[1], &entry->prefix) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_manager_map: invalid path \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    /* Copy the host:port argument into a NUL-terminated buffer for parsing. */
    addr_copy = ngx_pnalloc(cf->pool, value[2].len + 1);
    if (addr_copy == NULL) {
        return NGX_CONF_ERROR;
    }
    ngx_memcpy(addr_copy, value[2].data, value[2].len);
    addr_copy[value[2].len] = '\0';

    /* IPv6 literal form [addr]:port */
    if (addr_copy[0] == '[') {
        char *rb = strchr(addr_copy, ']');
        if (rb == NULL || rb == addr_copy) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd_manager_map: invalid IPv6 host \"%V\"", &value[2]);
            return NGX_CONF_ERROR;
        }
        if (*(rb + 1) != ':') {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd_manager_map: missing port in \"%V\"", &value[2]);
            return NGX_CONF_ERROR;
        }

        size_t hostlen = (size_t) (rb - addr_copy - 1);
        entry->host.data = ngx_pnalloc(cf->pool, hostlen + 1);
        if (entry->host.data == NULL) { return NGX_CONF_ERROR; }
        ngx_memcpy(entry->host.data, addr_copy + 1, hostlen);
        entry->host.data[hostlen] = '\0';
        entry->host.len = hostlen;

        pnum = strtol(rb + 2, &endp, 10);
        if (*endp != '\0' || pnum <= 0 || pnum > 65535) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd_manager_map: invalid port in \"%V\"", &value[2]);
            return NGX_CONF_ERROR;
        }
        entry->port = (uint16_t) pnum;

    } else {
        /* IPv4 or hostname form host:port — split on last colon. */
        char *colon = strrchr(addr_copy, ':');
        if (colon == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd_manager_map: missing port in \"%V\"", &value[2]);
            return NGX_CONF_ERROR;
        }

        size_t hostlen = (size_t) (colon - addr_copy);
        entry->host.data = ngx_pnalloc(cf->pool, hostlen + 1);
        if (entry->host.data == NULL) { return NGX_CONF_ERROR; }
        ngx_memcpy(entry->host.data, addr_copy, hostlen);
        entry->host.data[hostlen] = '\0';
        entry->host.len = hostlen;

        pnum = strtol(colon + 1, &endp, 10);
        if (*endp != '\0' || pnum <= 0 || pnum > 65535) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd_manager_map: invalid port in \"%V\"", &value[2]);
            return NGX_CONF_ERROR;
        }
        entry->port = (uint16_t) pnum;
    }

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
        "xrootd: manager_map configured: prefix=%s backend=%s:%d",
        (char *) entry->prefix.data, (char *) entry->host.data, (int) entry->port);

    return NGX_CONF_OK;
}

char *
xrootd_conf_set_upstream(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_xrootd_srv_conf_t *xcf = conf;
    ngx_str_t                    *value;
    char                         *addr_copy, *colon, *endp;
    long                          pnum;

    value = cf->args->elts;
    (void) cmd;

    addr_copy = ngx_pnalloc(cf->pool, value[1].len + 1);
    if (addr_copy == NULL) {
        return NGX_CONF_ERROR;
    }
    ngx_memcpy(addr_copy, value[1].data, value[1].len);
    addr_copy[value[1].len] = '\0';

    if (addr_copy[0] == '[') {
        /* IPv6 literal [addr]:port */
        char *rb = strchr(addr_copy, ']');
        if (rb == NULL || *(rb + 1) != ':') {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd_upstream: invalid address \"%V\"", &value[1]);
            return NGX_CONF_ERROR;
        }
        size_t hostlen = (size_t)(rb - addr_copy - 1);
        xcf->upstream_host.data = ngx_pnalloc(cf->pool, hostlen + 1);
        if (xcf->upstream_host.data == NULL) { return NGX_CONF_ERROR; }
        ngx_memcpy(xcf->upstream_host.data, addr_copy + 1, hostlen);
        xcf->upstream_host.data[hostlen] = '\0';
        xcf->upstream_host.len = hostlen;
        pnum = strtol(rb + 2, &endp, 10);
    } else {
        /* hostname:port or IPv4:port — split on last colon */
        colon = strrchr(addr_copy, ':');
        if (colon == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd_upstream: missing port in \"%V\"", &value[1]);
            return NGX_CONF_ERROR;
        }
        size_t hostlen = (size_t)(colon - addr_copy);
        xcf->upstream_host.data = ngx_pnalloc(cf->pool, hostlen + 1);
        if (xcf->upstream_host.data == NULL) { return NGX_CONF_ERROR; }
        ngx_memcpy(xcf->upstream_host.data, addr_copy, hostlen);
        xcf->upstream_host.data[hostlen] = '\0';
        xcf->upstream_host.len = hostlen;
        pnum = strtol(colon + 1, &endp, 10);
    }

    if (*endp != '\0' || pnum <= 0 || pnum > 65535) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_upstream: invalid port in \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }
    xcf->upstream_port = (uint16_t) pnum;

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
        "xrootd: upstream redirector: %s:%d",
        (char *) xcf->upstream_host.data, (int) xcf->upstream_port);

    return NGX_CONF_OK;
}

void *
ngx_stream_xrootd_create_srv_conf(ngx_conf_t *cf)
{
    ngx_stream_xrootd_srv_conf_t *conf;

    /*
     * nginx allocates one per-server config object during parsing and then
     * merges parent/child scopes later. Start everything in an explicit
     * "unset" or NULL state so the merge step can tell whether a directive
     * was omitted or configured intentionally.
     */
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_xrootd_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * Scalar fields use nginx's UNSET sentinels when they participate in merge
     * logic; runtime-only objects start out NULL/invalid and are created later
     * during postconfiguration once parsing has finished.
     */
    conf->enable       = NGX_CONF_UNSET;
    conf->auth         = NGX_CONF_UNSET_UINT;
    conf->allow_write  = NGX_CONF_UNSET;
    conf->crl_reload   = NGX_CONF_UNSET;
    conf->gsi_cert     = NULL;
    conf->gsi_key      = NULL;
    conf->gsi_store    = NULL;
    conf->gsi_ca_hash  = 0;
    conf->vo_rules     = NULL;
    conf->group_rules  = NULL;
    conf->access_log_fd = NGX_INVALID_FILE;
    conf->metrics_slot = -1;
    conf->tls          = NGX_CONF_UNSET;
    conf->tls_ctx      = NULL;
    conf->cms_addr     = NULL;
    conf->cms_interval = NGX_CONF_UNSET;
    conf->cms_ctx      = NULL;

    return conf;
}

char *
ngx_stream_xrootd_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_stream_xrootd_srv_conf_t *prev = parent;
    ngx_stream_xrootd_srv_conf_t *conf = child;
    ngx_array_t                  *child_vo_rules;
    ngx_array_t                  *child_group_rules;

    /*
     * Standard nginx inheritance rules: values set on the current server
     * override the parent, otherwise we fall back to the parent or the hard
     * coded module default.
     */
    ngx_conf_merge_value(conf->enable,      prev->enable,      0);
    ngx_conf_merge_str_value(conf->root,    prev->root,        "/");
    ngx_conf_merge_uint_value(conf->auth,   prev->auth,        XROOTD_AUTH_NONE);
    ngx_conf_merge_value(conf->allow_write, prev->allow_write, 0);
    ngx_conf_merge_str_value(conf->certificate,     prev->certificate,     "");
    ngx_conf_merge_str_value(conf->certificate_key, prev->certificate_key, "");
    ngx_conf_merge_str_value(conf->trusted_ca,      prev->trusted_ca,      "");
    ngx_conf_merge_str_value(conf->vomsdir,         prev->vomsdir,         "");
    ngx_conf_merge_str_value(conf->voms_cert_dir,   prev->voms_cert_dir,   "");
    ngx_conf_merge_str_value(conf->crl,             prev->crl,             "");
    ngx_conf_merge_value(conf->crl_reload,    prev->crl_reload,      0);
    ngx_conf_merge_str_value(conf->access_log,      prev->access_log,      "");
    ngx_conf_merge_str_value(conf->token_jwks,      prev->token_jwks,      "");
    ngx_conf_merge_str_value(conf->token_issuer,    prev->token_issuer,    "");
    ngx_conf_merge_str_value(conf->token_audience,  prev->token_audience,  "");
    ngx_conf_merge_value(conf->tls,             prev->tls,             0);
    ngx_conf_merge_str_value(conf->cms_paths,       prev->cms_paths,       "");
    ngx_conf_merge_value(conf->cms_interval,        prev->cms_interval,    30);

    if (conf->cms_addr == NULL && prev->cms_addr != NULL) {
        conf->cms_addr = prev->cms_addr;
        conf->cms_manager = prev->cms_manager;
    }

    child_vo_rules = conf->vo_rules;
    conf->vo_rules = xrootd_merge_arrays(cf, prev->vo_rules, child_vo_rules,
                                         sizeof(xrootd_vo_rule_t));
    if (conf->vo_rules == NULL && (prev->vo_rules != NULL || child_vo_rules != NULL)) {
        return NGX_CONF_ERROR;
    }

    child_group_rules = conf->group_rules;
    conf->group_rules = xrootd_merge_arrays(cf, prev->group_rules,
                                            child_group_rules,
                                            sizeof(xrootd_group_rule_t));
    if (conf->group_rules == NULL
        && (prev->group_rules != NULL || child_group_rules != NULL)) {
        return NGX_CONF_ERROR;
    }

    /* Merge manager_map entries (prefix -> backend mappings) */
    {
        ngx_array_t *child_manager_map = conf->manager_map;
        conf->manager_map = xrootd_merge_arrays(cf, prev->manager_map,
                                               child_manager_map,
                                               sizeof(xrootd_manager_map_t));
        if (conf->manager_map == NULL
            && (prev->manager_map != NULL || child_manager_map != NULL)) {
            return NGX_CONF_ERROR;
        }
    }

    /* Inherit upstream redirector from parent scope if not set locally */
    if (conf->upstream_host.len == 0 && prev->upstream_host.len > 0) {
        conf->upstream_host = prev->upstream_host;
        conf->upstream_port = prev->upstream_port;
    }

    return NGX_CONF_OK;
}

/*
 * ngx_stream_xrootd_enable — handler for the "xrootd on|off;" directive.
 */
char *
ngx_stream_xrootd_enable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_xrootd_srv_conf_t *xcf = conf;
    ngx_stream_core_srv_conf_t   *cscf;
    char                         *rv;

    rv = ngx_conf_set_flag_slot(cf, cmd, conf);
    if (rv != NGX_CONF_OK) {
        return rv;
    }

    /* Explicit `xrootd off;` leaves the server block as a normal stream server. */
    if (!xcf->enable) {
        return NGX_CONF_OK;
    }

    /*
     * The stream core owns the accept loop; enabling the directive swaps in
     * our session handler for this server block.
     */
    cscf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_core_module);
    cscf->handler = ngx_stream_xrootd_handler;

    return NGX_CONF_OK;
}

/* ================================================================== */
/*  CRL loading helpers                                                 */
/* ================================================================== */

/*
 * Load all PEM-encoded CRLs from a single file into the given X509_STORE.
 * Returns the number of CRLs added, or -1 on error opening the file.
 */
static int
xrootd_load_crls_from_file(X509_STORE *store, const char *path, ngx_log_t *log)
{
    FILE      *fp;
    X509_CRL  *crl;
    int        count = 0;

    fp = fopen(path, "r");
    if (fp == NULL) {
        ngx_log_error(NGX_LOG_WARN, log, ngx_errno,
                      "xrootd: cannot open CRL file \"%s\"", path);
        return -1;
    }

    while ((crl = PEM_read_X509_CRL(fp, NULL, NULL, NULL)) != NULL) {
        if (!X509_STORE_add_crl(store, crl)) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "xrootd: failed to add CRL entry from \"%s\"", path);
        } else {
            count++;
        }
        X509_CRL_free(crl);
    }

    fclose(fp);
    return count;
}

/*
 * Load CRLs from a path that is either a single PEM file or a directory
 * (scanning *.pem, *.r0, *.r1, … *.r9 files, matching /etc/grid-security/certificates).
 * Returns the total number of CRLs loaded, or -1 on error.
 */
static int
xrootd_load_crls(X509_STORE *store, const char *path, ngx_log_t *log)
{
    struct stat  st;
    DIR         *dir;
    struct dirent *ent;
    int          total = 0;
    int          n;

    if (stat(path, &st) != 0) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                      "xrootd: cannot stat CRL path \"%s\"", path);
        return -1;
    }

    /* Single file */
    if (S_ISREG(st.st_mode)) {
        return xrootd_load_crls_from_file(store, path, log);
    }

    /* Directory — scan for CRL files */
    if (!S_ISDIR(st.st_mode)) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "xrootd: CRL path \"%s\" is neither a file nor directory",
                      path);
        return -1;
    }

    dir = opendir(path);
    if (dir == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                      "xrootd: cannot open CRL directory \"%s\"", path);
        return -1;
    }

    while ((ent = readdir(dir)) != NULL) {
        const char *name = ent->d_name;
        size_t      nlen = strlen(name);
        char        fullpath[PATH_MAX];
        int         match = 0;

        /* Match *.pem */
        if (nlen > 4 && strcmp(name + nlen - 4, ".pem") == 0) {
            match = 1;
        }
        /* Match *.r0 through *.r9 (grid CA CRL naming convention) */
        if (nlen > 3 && name[nlen - 3] == '.' && name[nlen - 2] == 'r'
            && name[nlen - 1] >= '0' && name[nlen - 1] <= '9')
        {
            match = 1;
        }

        if (!match) {
            continue;
        }

        n = snprintf(fullpath, sizeof(fullpath), "%s/%s", path, name);
        if (n < 0 || (size_t) n >= sizeof(fullpath)) {
            continue;
        }

        /* Only load regular files, skip symlink targets that vanished etc. */
        if (stat(fullpath, &st) != 0 || !S_ISREG(st.st_mode)) {
            continue;
        }

        n = xrootd_load_crls_from_file(store, fullpath, log);
        if (n > 0) {
            total += n;
        }
    }

    closedir(dir);
    return total;
}

/*
 * Build (or rebuild) the X509_STORE used for GSI certificate verification.
 *
 * Loads the trusted CA from xcf->trusted_ca, then loads CRLs from xcf->crl
 * (which may be a single PEM file or a directory of *.pem / *.r0 files).
 *
 * On success the new store is atomically swapped into xcf->gsi_store and any
 * previous store is freed.  On failure the old store is left in place so
 * existing connections are not disrupted.
 */
ngx_int_t
xrootd_rebuild_gsi_store(ngx_stream_xrootd_srv_conf_t *xcf, ngx_log_t *log)
{
    X509_STORE   *store;
    X509_STORE   *old_store;
    X509_LOOKUP  *lookup;

    store = X509_STORE_new();
    if (store == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "xrootd: X509_STORE_new() failed");
        return NGX_ERROR;
    }

    X509_STORE_set_flags(store, X509_V_FLAG_ALLOW_PROXY_CERTS);

    lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
    if (lookup == NULL) {
        X509_STORE_free(store);
        return NGX_ERROR;
    }

    if (!X509_LOOKUP_load_file(lookup,
                               (char *) xcf->trusted_ca.data,
                               X509_FILETYPE_PEM))
    {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "xrootd: cannot load trusted CA \"%s\"",
                      xcf->trusted_ca.data);
        X509_STORE_free(store);
        return NGX_ERROR;
    }

    /* Load CRLs if configured (file or directory) */
    if (xcf->crl.len > 0) {
        int crl_count = xrootd_load_crls(store, (char *) xcf->crl.data, log);
        if (crl_count < 0) {
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "xrootd: failed to load CRLs from \"%s\"",
                          xcf->crl.data);
            X509_STORE_free(store);
            return NGX_ERROR;
        }

        if (crl_count > 0) {
            /*
             * Enable CRL checking on the store.  X509_V_FLAG_CRL_CHECK checks
             * the leaf issuer's CRL; _CHECK_ALL checks the entire chain.
             */
            X509_STORE_set_flags(store,
                                 X509_V_FLAG_CRL_CHECK |
                                 X509_V_FLAG_CRL_CHECK_ALL);
        }

        ngx_log_error(NGX_LOG_NOTICE, log, 0,
                      "xrootd: loaded %d CRL(s) from \"%s\"",
                      crl_count, xcf->crl.data);
    }

    /* Atomic swap */
    old_store = xcf->gsi_store;
    xcf->gsi_store = store;

    if (old_store != NULL) {
        X509_STORE_free(old_store);
    }

    return NGX_OK;
}

/* ================================================================== */
/*  CRL reload timer                                                    */
/* ================================================================== */

static void
xrootd_crl_reload_handler(ngx_event_t *ev)
{
    ngx_stream_xrootd_srv_conf_t *xcf = ev->data;

    ngx_log_error(NGX_LOG_INFO, ev->log, 0,
                  "xrootd: CRL reload timer fired, rebuilding store "
                  "from \"%s\"", xcf->crl.data);

    if (xrootd_rebuild_gsi_store(xcf, ev->log) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, ev->log, 0,
                      "xrootd: CRL reload failed — keeping previous store");
    }

    /* Re-arm the timer */
    if (xcf->crl_reload > 0) {
        ngx_add_timer(ev, (ngx_msec_t) xcf->crl_reload * 1000);
    }
}

/*
 * Worker process init: start CRL reload timers for every server block that
 * has xrootd_crl_reload configured.  Timers are per-worker because each
 * nginx worker process has its own event loop and its own copy of the config
 * pointers (but the X509_STORE* is shared within a worker).
 */
ngx_int_t
ngx_stream_xrootd_init_process(ngx_cycle_t *cycle)
{
    ngx_stream_core_main_conf_t   *cmcf;
    ngx_stream_core_srv_conf_t   **cscfp;
    ngx_stream_xrootd_srv_conf_t  *xcf;
    ngx_uint_t                     i;

    cmcf = ngx_stream_cycle_get_module_main_conf(cycle, ngx_stream_core_module);
    if (cmcf == NULL) {
        return NGX_OK;
    }

    cscfp = cmcf->servers.elts;

    for (i = 0; i < cmcf->servers.nelts; i++) {
        xcf = ngx_stream_conf_get_module_srv_conf(cscfp[i],
                                                   ngx_stream_xrootd_module);

        if (!xcf->enable) {
            continue;
        }

        if (xcf->cms_addr != NULL) {
            ngx_xrootd_cms_start(cycle, xcf);
        }

        if ((xcf->auth != XROOTD_AUTH_GSI && xcf->auth != XROOTD_AUTH_BOTH)
            || xcf->crl.len == 0 || xcf->crl_reload == 0)
        {
            continue;
        }

        /* Allocate and start the CRL reload timer */
        xcf->crl_timer = ngx_pcalloc(cycle->pool, sizeof(ngx_event_t));
        if (xcf->crl_timer == NULL) {
            return NGX_ERROR;
        }
        xcf->crl_timer->handler = xrootd_crl_reload_handler;
        xcf->crl_timer->data    = xcf;
        xcf->crl_timer->log     = cycle->log;

        ngx_add_timer(xcf->crl_timer, (ngx_msec_t) xcf->crl_reload * 1000);

        ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                      "xrootd: CRL reload timer started — interval=%ds "
                      "path=\"%s\"",
                      (int) xcf->crl_reload, xcf->crl.data);
    }

    return NGX_OK;
}

/* ================================================================== */
/*  Post-configuration: load GSI certificates                          */
/* ================================================================== */

char *
xrootd_conf_set_cms_manager(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_xrootd_srv_conf_t *xcf = conf;
    ngx_str_t                    *value;
    ngx_url_t                     url;
    ngx_addr_t                   *addr;

    value = cf->args->elts;
    (void) cmd;

    if (xcf->cms_addr != NULL) {
        return "is duplicate";
    }

    if (xrootd_copy_conf_string(cf, &value[1], &xcf->cms_manager)
        != NGX_CONF_OK)
    {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&url, sizeof(url));
    url.url = xcf->cms_manager;
    url.default_port = 0;

    if (ngx_parse_url(cf->pool, &url) != NGX_OK) {
        if (url.err != NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd_cms_manager: %s in \"%V\"", url.err, &value[1]);
        }
        return NGX_CONF_ERROR;
    }

    if (url.no_port) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_cms_manager: missing port in \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    if (url.naddrs == 0 || url.addrs == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_cms_manager: could not resolve \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    if (ngx_inet_get_port(url.addrs[0].sockaddr) == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "xrootd_cms_manager: invalid port in \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    addr = ngx_pcalloc(cf->pool, sizeof(ngx_addr_t));
    if (addr == NULL) {
        return NGX_CONF_ERROR;
    }

    addr->sockaddr = ngx_pnalloc(cf->pool, url.addrs[0].socklen);
    if (addr->sockaddr == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memcpy(addr->sockaddr, url.addrs[0].sockaddr, url.addrs[0].socklen);
    addr->socklen = url.addrs[0].socklen;
    addr->name = url.addrs[0].name;
    xcf->cms_addr = addr;

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
        "xrootd: CMS manager configured: %V", &xcf->cms_manager);

    return NGX_CONF_OK;
}

ngx_int_t
ngx_stream_xrootd_postconfiguration(ngx_conf_t *cf)
{
    ngx_stream_core_main_conf_t   *cmcf;
    ngx_stream_core_srv_conf_t   **cscfp;
    ngx_stream_xrootd_srv_conf_t  *xcf;
    ngx_uint_t                     i;

    cmcf  = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);
    cscfp = cmcf->servers.elts;

    /* Attempt to load libvomsapi.so.1 via dlopen.  If the library is not
     * present we continue; the config validation below will reject any
     * xrootd_require_vo directives when voms is unavailable. */
    (void) xrootd_voms_init(cf->log);

    /*
     * First pass over enabled servers:
     *   1. open any per-server access log
     *   2. load GSI server credentials when auth=gsi
     *
     * This happens after parsing is complete so inherited values are already
     * resolved and we only initialize resources for active server blocks.
     * Each later pass depends on state established here, so the ordering is
     * deliberate rather than just a convenience loop split.
     */
    for (i = 0; i < cmcf->servers.nelts; i++) {
        xcf = ngx_stream_conf_get_module_srv_conf(cscfp[i], ngx_stream_xrootd_module);

        if (!xcf->enable) {
            continue;
        }

        if (xrootd_validate_path(cf, "xrootd_root", &xcf->root,
                                 XROOTD_PATH_DIRECTORY,
                                 xcf->allow_write ? (R_OK | W_OK | X_OK)
                                                  : (R_OK | X_OK))
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        /*
         * Access log handling mirrors nginx conventions: empty means disabled by
         * default, the literal string "off" suppresses logging explicitly, and
         * any other value is treated as the path to append to.
         */
        if (xcf->access_log.len > 0
            && ngx_strcmp(xcf->access_log.data, (u_char *) "off") != 0)
        {
            xcf->access_log_fd = ngx_open_file(xcf->access_log.data,
                NGX_FILE_WRONLY,
                NGX_FILE_CREATE_OR_OPEN | NGX_FILE_APPEND,
                NGX_FILE_DEFAULT_ACCESS);

            if (xcf->access_log_fd == NGX_INVALID_FILE) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                    "xrootd: cannot open access log \"%s\"",
                    xcf->access_log.data);
                return NGX_ERROR;
            }

            ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                "xrootd: access log \"%s\" opened",
                xcf->access_log.data);
        }

        if (xcf->auth == XROOTD_AUTH_GSI || xcf->auth == XROOTD_AUTH_BOTH) {

        /* GSI mode is only meaningful when all three trust inputs are present. */
        if (xcf->certificate.len == 0 || xcf->certificate_key.len == 0
            || xcf->trusted_ca.len == 0)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd_auth gsi requires xrootd_certificate, "
                "xrootd_certificate_key and xrootd_trusted_ca");
            return NGX_ERROR;
        }

        if (xrootd_validate_path(cf, "xrootd_certificate", &xcf->certificate,
                                 XROOTD_PATH_REGULAR_FILE, R_OK) != NGX_OK
            || xrootd_validate_path(cf, "xrootd_certificate_key",
                                    &xcf->certificate_key,
                                    XROOTD_PATH_REGULAR_FILE, R_OK) != NGX_OK
            || xrootd_validate_path(cf, "xrootd_trusted_ca", &xcf->trusted_ca,
                                    XROOTD_PATH_REGULAR_FILE, R_OK) != NGX_OK
            || xrootd_validate_path(cf, "xrootd_crl", &xcf->crl,
                                    XROOTD_PATH_FILE_OR_DIRECTORY, R_OK) != NGX_OK)
        {
            return NGX_ERROR;
        }

        /* Load server certificate */
        {
            FILE *fp = fopen((char *) xcf->certificate.data, "r");
            if (fp == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                    "xrootd: cannot open certificate \"%s\"",
                    xcf->certificate.data);
                return NGX_ERROR;
            }
            xcf->gsi_cert = PEM_read_X509(fp, NULL, NULL, NULL);
            fclose(fp);
            if (xcf->gsi_cert == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "xrootd: cannot parse certificate \"%s\"",
                    xcf->certificate.data);
                return NGX_ERROR;
            }
        }

        /* Load server private key */
        {
            FILE *fp = fopen((char *) xcf->certificate_key.data, "r");
            if (fp == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                    "xrootd: cannot open private key \"%s\"",
                    xcf->certificate_key.data);
                return NGX_ERROR;
            }
            xcf->gsi_key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
            fclose(fp);
            if (xcf->gsi_key == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "xrootd: cannot parse private key \"%s\"",
                    xcf->certificate_key.data);
                return NGX_ERROR;
            }
        }

        /* Build trusted CA X509_STORE */
        if (xrootd_rebuild_gsi_store(xcf, cf->log) != NGX_OK) {
            return NGX_ERROR;
        }

        /* Run a lightweight PKI/CRL consistency check and log any problems. */
        (void) xrootd_check_pki_consistency_stream(cf->log, xcf);

        /* Compute CA hash (for kXRS_issuer_hash in kXGS_init) */
        {
            FILE  *fp;
            X509  *ca;

            fp = fopen((char *) xcf->trusted_ca.data, "r");
            if (fp) {
                ca = PEM_read_X509(fp, NULL, NULL, NULL);
                fclose(fp);
                if (ca) {
                    /*
                     * The protocol advertises the issuer hash during the GSI
                     * bootstrap so clients can confirm which CA the server wants.
                     */
                    xcf->gsi_ca_hash = (uint32_t) X509_subject_name_hash(ca);
                    X509_free(ca);
                }
            }
        }

        ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
            "xrootd: GSI auth configured — cert=%s ca_hash=%08xd",
            xcf->certificate.data, xcf->gsi_ca_hash);

        } /* end GSI setup */

        /* ---- kXR_ableTLS in-protocol TLS context ---- */
        if (xcf->tls) {
            if (xcf->certificate.len == 0 || xcf->certificate_key.len == 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "xrootd_tls requires xrootd_certificate and "
                    "xrootd_certificate_key");
                return NGX_ERROR;
            }

            xcf->tls_ctx = ngx_pcalloc(cf->pool, sizeof(ngx_ssl_t));
            if (xcf->tls_ctx == NULL) {
                return NGX_ERROR;
            }
            xcf->tls_ctx->log = cf->log;

            if (ngx_ssl_create(xcf->tls_ctx,
                               NGX_SSL_TLSv1_2 | NGX_SSL_TLSv1_3,
                               NULL) != NGX_OK)
            {
                return NGX_ERROR;
            }

            if (ngx_ssl_certificate(cf, xcf->tls_ctx,
                                    &xcf->certificate,
                                    &xcf->certificate_key,
                                    NULL) != NGX_OK)
            {
                return NGX_ERROR;
            }

            ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                "xrootd: kXR_ableTLS enabled — cert=%s",
                xcf->certificate.data);
        }

        /* ---- Token (JWT/WLCG) JWKS loading ---- */
        if ((xcf->auth == XROOTD_AUTH_TOKEN || xcf->auth == XROOTD_AUTH_BOTH)
            )
        {
            if (xcf->token_jwks.len == 0 || xcf->token_issuer.len == 0
                || xcf->token_audience.len == 0)
            {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "xrootd_auth token/both requires "
                    "xrootd_token_jwks, "
                    "xrootd_token_issuer and xrootd_token_audience");
                return NGX_ERROR;
            }

            if (xrootd_validate_path(cf, "xrootd_token_jwks",
                                     &xcf->token_jwks,
                                     XROOTD_PATH_REGULAR_FILE, R_OK)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            xcf->jwks_key_count = xrootd_jwks_load(
                cf->log, (const char *) xcf->token_jwks.data,
                xcf->jwks_keys, XROOTD_MAX_JWKS_KEYS);

            if (xcf->jwks_key_count < 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "xrootd: failed to load JWKS from \"%s\"",
                    xcf->token_jwks.data);
                return NGX_ERROR;
            }

            ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                "xrootd: token auth configured — jwks=%s issuer=%s "
                "audience=%s keys=%d",
                xcf->token_jwks.data, xcf->token_issuer.data,
                xcf->token_audience.data, xcf->jwks_key_count);
        }
    }

    for (i = 0; i < cmcf->servers.nelts; i++) {
        xcf = ngx_stream_conf_get_module_srv_conf(cscfp[i],
                                                   ngx_stream_xrootd_module);

        if (!xcf->enable) {
            continue;
        }

        if (xcf->vo_rules != NULL
            && xcf->auth != XROOTD_AUTH_GSI
            && xcf->auth != XROOTD_AUTH_TOKEN
            && xcf->auth != XROOTD_AUTH_BOTH)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd_require_vo requires xrootd_auth gsi, token or both");
            return NGX_ERROR;
        }

        if (xcf->vo_rules != NULL) {
            if (!xrootd_voms_available()) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "xrootd_require_vo requires libvomsapi.so.1 at runtime "
                    "(install voms-libs on EL9)");
                return NGX_ERROR;
            }
            if (xcf->vomsdir.len == 0 || xcf->voms_cert_dir.len == 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "xrootd_require_vo requires xrootd_vomsdir and xrootd_voms_cert_dir");
                return NGX_ERROR;
            }

            if (xrootd_validate_path(cf, "xrootd_vomsdir", &xcf->vomsdir,
                                     XROOTD_PATH_DIRECTORY, R_OK | X_OK)
                != NGX_OK
                || xrootd_validate_path(cf, "xrootd_voms_cert_dir",
                                        &xcf->voms_cert_dir,
                                        XROOTD_PATH_DIRECTORY, R_OK | X_OK)
                   != NGX_OK)
            {
                return NGX_ERROR;
            }
        }

        if (xrootd_finalize_vo_rules(cf->log, &xcf->root, xcf->vo_rules) != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd: failed to finalize xrootd_require_vo rules for root \"%V\"",
                &xcf->root);
            return NGX_ERROR;
        }

        if (xrootd_finalize_group_rules(cf->log, &xcf->root,
                                        xcf->group_rules) != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd: failed to finalize xrootd_inherit_parent_group rules for root \"%V\"",
                &xcf->root);
            return NGX_ERROR;
        }
    }

    /* ---- Prometheus metrics shared memory ---- */
    {
        ngx_str_t   zone_name = ngx_string("xrootd_metrics");
        size_t      zone_size;
        ngx_uint_t  slot = 0;

        /*
         * One shared zone is used for all enabled server blocks. Each server is
         * assigned a small integer slot; live connections cache that slot and
         * update counters lock-free via atomics.
         */

        /* Extra page headroom follows a common nginx shared-memory sizing pattern. */
        zone_size = sizeof(ngx_xrootd_metrics_t) + ngx_pagesize;
        ngx_xrootd_shm_zone = ngx_shared_memory_add(cf, &zone_name,
                                                      zone_size,
                                                      &ngx_stream_xrootd_module);
        if (ngx_xrootd_shm_zone == NULL) {
            return NGX_ERROR;
        }

        /* init() will either zero a new mapping or hand back an existing one. */
        ngx_xrootd_shm_zone->init = ngx_xrootd_metrics_shm_init;
        /* Non-NULL sentinel tells the init callback this is the first setup. */
        ngx_xrootd_shm_zone->data = (void *) 1;

        /* Second pass: assign deterministic metrics slots to enabled listeners. */
        for (i = 0; i < cmcf->servers.nelts; i++) {
            xcf = ngx_stream_conf_get_module_srv_conf(cscfp[i],
                                                       ngx_stream_xrootd_module);
            if (!xcf->enable || slot >= XROOTD_METRICS_MAX_SERVERS) {
                continue;
            }

            /* Slot numbers become stable label sources for the HTTP metrics exporter. */
            xcf->metrics_slot = (ngx_int_t) slot++;
        }
    }

#if (NGX_THREADS)
    {
        static ngx_str_t default_pool_name = ngx_string("default");

        /*
         * Third pass: resolve each enabled server's thread-pool name to the
         * concrete pool object created by nginx's top-level thread_pool config.
         * This is kept separate from the GSI/metrics passes because it depends
         * only on the final merged config and does not mutate shared structures.
         */
        for (i = 0; i < cmcf->servers.nelts; i++) {
            ngx_str_t *pool_name;

            xcf = ngx_stream_conf_get_module_srv_conf(cscfp[i],
                                                       ngx_stream_xrootd_module);
            if (!xcf->enable) {
                continue;
            }

            /* Empty name means "use nginx's default thread pool". */
            pool_name = (xcf->thread_pool_name.len > 0)
                        ? &xcf->thread_pool_name
                        : &default_pool_name;

            xcf->thread_pool = ngx_thread_pool_get(cf->cycle, pool_name);
            if (xcf->thread_pool == NULL) {
                ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                    "xrootd: thread pool \"%V\" not found — "
                    "async file I/O disabled (add a thread_pool directive)",
                    pool_name);
            } else {
                ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                    "xrootd: using thread pool \"%V\" for async file I/O",
                    pool_name);
            }
        }
    }
#endif

    return NGX_OK;
}

/*
 * ngx_xrootd_metrics_shm_init — shared memory zone init callback.
 */
ngx_int_t
ngx_xrootd_metrics_shm_init(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_xrootd_metrics_t *shm;

    if (data) {
        /*
         * nginx is reusing an existing shared zone across a reload; preserve
         * live counters instead of wiping them on every config reload.
         */
        shm_zone->data = data;
        return NGX_OK;
    }

    /* First initialization: zero the freshly mapped shared memory region. */
    shm = (ngx_xrootd_metrics_t *) shm_zone->shm.addr;
    ngx_memzero(shm, sizeof(*shm));

    /* Save the typed pointer so request paths do not have to recast repeatedly. */
    shm_zone->data = shm;
    return NGX_OK;
}
