/*
 * ngx_http_xrootd_webdav_auth.c — GSI/x509 and bearer-token authentication.
 *
 * Handles all authentication concerns for the WebDAV module:
 *   - CA store building (from configured CA dir/file/CRL)
 *   - Three-level auth cache (request ctx → SSL connection → SSL session)
 *   - Manual X509_verify_cert() with RFC 3820 proxy certificate support
 *   - Bearer token (JWT/WLCG) validation and write-scope enforcement
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
#include <dirent.h>
#include <limits.h>
#include <unistd.h>

#include "ngx_http_xrootd_webdav_module.h"

/* ------------------------------------------------------------------ */
/* Per-connection/session auth cache entry                              */
/* ------------------------------------------------------------------ */

typedef struct {
    ngx_http_xrootd_webdav_loc_conf_t *conf;
    X509_STORE                        *store;
    ngx_uint_t                         verify_depth;
    char                               dn[1024];
} ngx_http_xrootd_webdav_tls_auth_cache_t;

/* SSL ex_data indices for the three-level auth cache */
static int webdav_ssl_auth_cache_index = -1;
static int webdav_ssl_session_auth_cache_index = -1;

/* ------------------------------------------------------------------ */
/* SSL session ex_data free callback                                    */
/* ------------------------------------------------------------------ */

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

/* ------------------------------------------------------------------ */
/* SSL ex_data index initialization (called from postconfiguration)    */
/* ------------------------------------------------------------------ */

ngx_int_t
webdav_auth_init_ssl_indices(ngx_log_t *log)
{
    if (webdav_ssl_auth_cache_index < 0) {
        webdav_ssl_auth_cache_index = SSL_get_ex_new_index(0, NULL, NULL,
                                                           NULL, NULL);
        if (webdav_ssl_auth_cache_index < 0) {
            ngx_log_error(NGX_LOG_EMERG, log, 0,
                          "xrootd_webdav: SSL_get_ex_new_index() failed");
            return NGX_ERROR;
        }
    }

    if (webdav_ssl_session_auth_cache_index < 0) {
        webdav_ssl_session_auth_cache_index =
            SSL_SESSION_get_ex_new_index(0, NULL, NULL, NULL,
                                         webdav_tls_auth_cache_free);
        if (webdav_ssl_session_auth_cache_index < 0) {
            ngx_log_error(NGX_LOG_EMERG, log, 0,
                          "xrootd_webdav: SSL_SESSION_get_ex_new_index() failed");
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

/* ------------------------------------------------------------------ */
/* Helpers                                                              */
/* ------------------------------------------------------------------ */

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

static void
webdav_free_verify_resources(X509_STORE_CTX *vctx, X509 *leaf)
{
    if (vctx)  X509_STORE_CTX_free(vctx);
    if (leaf)  X509_free(leaf);
    /* chain is owned by the SSL session — do not free */
}

/* ------------------------------------------------------------------ */
/* CA store builder                                                     */
/* ------------------------------------------------------------------ */

/*
 * Build an X509_STORE from the configured CA directory and/or file.
 * Returns NULL on allocation failure or over-length paths.
 */
X509_STORE *
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

/* ------------------------------------------------------------------ */
/* Auth cache helpers                                                   */
/* ------------------------------------------------------------------ */

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

/* ------------------------------------------------------------------ */
/* Proxy certificate verification                                       */
/* ------------------------------------------------------------------ */

ngx_int_t
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

/* ------------------------------------------------------------------ */
/* Bearer-token write scope check                                       */
/* ------------------------------------------------------------------ */

/*
 * Bearer-token write authorization used by WebDAV mutating methods that carry
 * object data or fetch object data from elsewhere.  The x509 path does not
 * have WLCG scopes, so there is nothing to check for certificate-authenticated
 * requests.
 */
ngx_int_t
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

/* ------------------------------------------------------------------ */
/* Bearer-token (JWT) authentication                                    */
/* ------------------------------------------------------------------ */

/*
 * webdav_verify_bearer_token — authenticate via Authorization: Bearer <JWT>.
 *
 * Returns NGX_OK on success, NGX_HTTP_UNAUTHORIZED/FORBIDDEN on failure,
 * NGX_DECLINED if no Bearer header present.
 */
ngx_int_t
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
