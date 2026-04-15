#include "ngx_xrootd_module.h"

/* ================================================================== */
/*  Configuration management                                            */
/* ================================================================== */

void *
ngx_stream_xrootd_create_srv_conf(ngx_conf_t *cf)
{
    ngx_stream_xrootd_srv_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_xrootd_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable       = NGX_CONF_UNSET;
    conf->auth         = NGX_CONF_UNSET_UINT;
    conf->allow_write  = NGX_CONF_UNSET;
    conf->gsi_cert     = NULL;
    conf->gsi_key      = NULL;
    conf->gsi_store    = NULL;
    conf->gsi_ca_hash  = 0;
    conf->access_log_fd = NGX_INVALID_FILE;
    conf->metrics_slot = -1;

    return conf;
}

char *
ngx_stream_xrootd_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_stream_xrootd_srv_conf_t *prev = parent;
    ngx_stream_xrootd_srv_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable,      prev->enable,      0);
    ngx_conf_merge_str_value(conf->root,    prev->root,        "/");
    ngx_conf_merge_uint_value(conf->auth,   prev->auth,        XROOTD_AUTH_NONE);
    ngx_conf_merge_value(conf->allow_write, prev->allow_write, 0);
    ngx_conf_merge_str_value(conf->certificate,     prev->certificate,     "");
    ngx_conf_merge_str_value(conf->certificate_key, prev->certificate_key, "");
    ngx_conf_merge_str_value(conf->trusted_ca,      prev->trusted_ca,      "");
    ngx_conf_merge_str_value(conf->access_log,      prev->access_log,      "");

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

    if (!xcf->enable) {
        return NGX_CONF_OK;
    }

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

    for (i = 0; i < cmcf->servers.nelts; i++) {
        xcf = ngx_stream_conf_get_module_srv_conf(cscfp[i], ngx_stream_xrootd_module);

        if (!xcf->enable) {
            continue;
        }

        /* Open the access log for this server block */
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
            continue;
        }

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
                    xcf->gsi_ca_hash = (uint32_t) X509_subject_name_hash(ca);
                    X509_free(ca);
                }
            }
        }

        ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
            "xrootd: GSI auth configured — cert=%s ca_hash=%08x",
            xcf->certificate.data, xcf->gsi_ca_hash);
    }

    /* ---- Prometheus metrics shared memory ---- */
    {
        ngx_str_t   zone_name = ngx_string("xrootd_metrics");
        size_t      zone_size;
        ngx_uint_t  slot = 0;

        zone_size = sizeof(ngx_xrootd_metrics_t) + ngx_pagesize;
        ngx_xrootd_shm_zone = ngx_shared_memory_add(cf, &zone_name,
                                                      zone_size,
                                                      &ngx_stream_xrootd_module);
        if (ngx_xrootd_shm_zone == NULL) {
            return NGX_ERROR;
        }
        ngx_xrootd_shm_zone->init = ngx_xrootd_metrics_shm_init;
        ngx_xrootd_shm_zone->data = (void *) 1;

        for (i = 0; i < cmcf->servers.nelts; i++) {
            xcf = ngx_stream_conf_get_module_srv_conf(cscfp[i],
                                                       ngx_stream_xrootd_module);
            if (!xcf->enable || slot >= XROOTD_METRICS_MAX_SERVERS) {
                continue;
            }
            xcf->metrics_slot = (ngx_int_t) slot++;
        }
    }

#if (NGX_THREADS)
    {
        static ngx_str_t default_pool_name = ngx_string("default");

        for (i = 0; i < cmcf->servers.nelts; i++) {
            ngx_str_t *pool_name;

            xcf = ngx_stream_conf_get_module_srv_conf(cscfp[i],
                                                       ngx_stream_xrootd_module);
            if (!xcf->enable) {
                continue;
            }

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
        shm_zone->data = data;
        return NGX_OK;
    }

    shm = (ngx_xrootd_metrics_t *) shm_zone->shm.addr;
    ngx_memzero(shm, sizeof(*shm));
    shm_zone->data = shm;
    return NGX_OK;
}
