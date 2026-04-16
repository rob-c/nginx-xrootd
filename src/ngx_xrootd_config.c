#include "ngx_xrootd_module.h"

/* ================================================================== */
/*  Configuration management                                            */
/* ================================================================== */

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
    conf->gsi_cert     = NULL;
    conf->gsi_key      = NULL;
    conf->gsi_store    = NULL;
    conf->gsi_ca_hash  = 0;
    conf->vo_rules     = NULL;
    conf->group_rules  = NULL;
    conf->access_log_fd = NGX_INVALID_FILE;
    conf->metrics_slot = -1;

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
    ngx_conf_merge_str_value(conf->access_log,      prev->access_log,      "");

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
/*  Post-configuration: load GSI certificates                          */
/* ================================================================== */

ngx_int_t
ngx_stream_xrootd_postconfiguration(ngx_conf_t *cf)
{
    ngx_stream_core_main_conf_t   *cmcf;
    ngx_stream_core_srv_conf_t   **cscfp;
    ngx_stream_xrootd_srv_conf_t  *xcf;
    ngx_uint_t                     i;

    cmcf  = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);
    cscfp = cmcf->servers.elts;

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

        if (xcf->auth != XROOTD_AUTH_GSI) {
            /* Non-GSI servers skip all OpenSSL/X509 setup in this pass. */
            continue;
        }

        /* GSI mode is only meaningful when all three trust inputs are present. */
        if (xcf->certificate.len == 0 || xcf->certificate_key.len == 0
            || xcf->trusted_ca.len == 0)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd_auth gsi requires xrootd_certificate, "
                "xrootd_certificate_key and xrootd_trusted_ca");
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
        {
            FILE  *fp;
            X509  *ca;
            X509_LOOKUP *lookup;

            /*
             * Verification context used later during kXR_auth. Proxy certs are
             * allowed explicitly because grid credentials are RFC 3820 proxies,
             * not just end-entity certs.
             */
            xcf->gsi_store = X509_STORE_new();
            if (xcf->gsi_store == NULL) {
                return NGX_ERROR;
            }

            X509_STORE_set_flags(xcf->gsi_store,
                                 X509_V_FLAG_ALLOW_PROXY_CERTS);

            lookup = X509_STORE_add_lookup(xcf->gsi_store,
                                           X509_LOOKUP_file());
            if (lookup == NULL) {
                return NGX_ERROR;
            }

            /*
             * The CA bundle is loaded into the store once here and then reused
             * by every GSI login handled by this listener.
             */
            if (!X509_LOOKUP_load_file(lookup,
                                       (char *) xcf->trusted_ca.data,
                                       X509_FILETYPE_PEM))
            {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "xrootd: cannot load trusted CA \"%s\"",
                    xcf->trusted_ca.data);
                return NGX_ERROR;
            }

            /* Compute CA hash (for kXRS_issuer_hash in kXGS_init) */
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
            "xrootd: GSI auth configured — cert=%s ca_hash=%08x",
            xcf->certificate.data, xcf->gsi_ca_hash);
    }

    for (i = 0; i < cmcf->servers.nelts; i++) {
        xcf = ngx_stream_conf_get_module_srv_conf(cscfp[i],
                                                   ngx_stream_xrootd_module);

        if (!xcf->enable) {
            continue;
        }

        if (xcf->vo_rules != NULL && xcf->auth != XROOTD_AUTH_GSI) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd_require_vo requires xrootd_auth gsi");
            return NGX_ERROR;
        }

#if !defined(XROOTD_HAVE_VOMS)
        if (xcf->vo_rules != NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd_require_vo requires nginx-xrootd to be built with libvomsapi");
            return NGX_ERROR;
        }
#else
        if (xcf->vo_rules != NULL) {
            if (xcf->vomsdir.len == 0 || xcf->voms_cert_dir.len == 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "xrootd_require_vo requires xrootd_vomsdir and xrootd_voms_cert_dir");
                return NGX_ERROR;
            }
        }
#endif

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
