/*
 * ngx_xrootd_pki_check.c
 *
 * Check WLCG-style CA/PKI/CRL consistency at startup and log problems.
 *
 * This file implements lightweight checks invoked during module
 * postconfiguration to catch common misconfigurations early and emit
 * actionable messages to the nginx log.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>

/* OpenSSL compatibility: older versions use X509_CRL_get_issuer(), newer
 * versions expose X509_CRL_get0_issuer(). Use whichever is available. */
#ifndef HAVE_X509_CRL_GET0_ISSUER
# if defined(X509_CRL_get0_issuer)
#  define HAVE_X509_CRL_GET0_ISSUER 1
# else
#  define HAVE_X509_CRL_GET0_ISSUER 0
# endif
#endif

#if HAVE_X509_CRL_GET0_ISSUER
# define CRL_GET_ISSUER(crl) X509_CRL_get0_issuer((crl))
#else
# define CRL_GET_ISSUER(crl) X509_CRL_get_issuer((crl))
#endif

#include <dirent.h>
#include <sys/stat.h>
#include <limits.h>
#include <stdio.h>

#include "ngx_xrootd_module.h"
#include "ngx_http_xrootd_webdav_module.h"

/* Helper: load all PEM X.509 certificates from a file or directory. */
static STACK_OF(X509) *
load_certs_from_path(const char *path, ngx_log_t *log)
{
    struct stat st;
    STACK_OF(X509) *stack = NULL;

    if (stat(path, &st) != 0) {
        ngx_log_error(NGX_LOG_WARN, log, ngx_errno,
                      "xrootd_pki_check: cannot stat CA path \"%s\"",
                      path);
        return NULL;
    }

    stack = sk_X509_new_null();
    if (stack == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "xrootd_pki_check: failed to allocate cert stack");
        return NULL;
    }

    if (S_ISREG(st.st_mode)) {
        FILE *fp = fopen(path, "r");
        if (fp == NULL) {
            ngx_log_error(NGX_LOG_WARN, log, ngx_errno,
                          "xrootd_pki_check: cannot open CA file \"%s\"",
                          path);
            sk_X509_free(stack);
            return NULL;
        }

        X509 *x;
        while ((x = PEM_read_X509(fp, NULL, NULL, NULL)) != NULL) {
            sk_X509_push(stack, x);
        }
        fclose(fp);
    } else if (S_ISDIR(st.st_mode)) {
        DIR *d = opendir(path);
        if (d == NULL) {
            ngx_log_error(NGX_LOG_WARN, log, ngx_errno,
                          "xrootd_pki_check: cannot open CA dir \"%s\"",
                          path);
            sk_X509_free(stack);
            return NULL;
        }

        struct dirent *ent;
        while ((ent = readdir(d)) != NULL) {
            if (ent->d_name[0] == '.') {
                continue;
            }
            char fpath[PATH_MAX];
            if (snprintf(fpath, sizeof(fpath), "%s/%s", path, ent->d_name)
                >= (int) sizeof(fpath))
            {
                continue;
            }
            struct stat fst;
            if (stat(fpath, &fst) != 0 || !S_ISREG(fst.st_mode)) {
                continue;
            }

            FILE *fp = fopen(fpath, "r");
            if (fp == NULL) {
                continue;
            }
            X509 *x;
            while ((x = PEM_read_X509(fp, NULL, NULL, NULL)) != NULL) {
                sk_X509_push(stack, x);
            }
            fclose(fp);
        }
        closedir(d);
    }

    if (sk_X509_num(stack) == 0) {
        sk_X509_free(stack);
        return NULL;
    }

    return stack;
}

/* Helper: load CRLs from a file (single PEM with multiple CRLs) or a directory. */
static STACK_OF(X509_CRL) *
load_crls_from_path(const char *path, ngx_log_t *log)
{
    struct stat st;
    STACK_OF(X509_CRL) *stack = NULL;

    if (stat(path, &st) != 0) {
        ngx_log_error(NGX_LOG_WARN, log, ngx_errno,
                      "xrootd_pki_check: cannot stat CRL path \"%s\"",
                      path);
        return NULL;
    }

    stack = sk_X509_CRL_new_null();
    if (stack == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "xrootd_pki_check: failed to allocate CRL stack");
        return NULL;
    }

    if (S_ISREG(st.st_mode)) {
        FILE *fp = fopen(path, "r");
        if (fp == NULL) {
            ngx_log_error(NGX_LOG_WARN, log, ngx_errno,
                          "xrootd_pki_check: cannot open CRL file \"%s\"",
                          path);
            sk_X509_CRL_free(stack);
            return NULL;
        }
        X509_CRL *crl;
        while ((crl = PEM_read_X509_CRL(fp, NULL, NULL, NULL)) != NULL) {
            sk_X509_CRL_push(stack, crl);
        }
        fclose(fp);
    } else if (S_ISDIR(st.st_mode)) {
        DIR *d = opendir(path);
        if (d == NULL) {
            ngx_log_error(NGX_LOG_WARN, log, ngx_errno,
                          "xrootd_pki_check: cannot open CRL dir \"%s\"",
                          path);
            sk_X509_CRL_free(stack);
            return NULL;
        }

        struct dirent *ent;
        while ((ent = readdir(d)) != NULL) {
            const char *name = ent->d_name;
            size_t nlen = strlen(name);
            int match = 0;
            if (nlen > 4 && strcmp(name + nlen - 4, ".pem") == 0) {
                match = 1;
            }
            if (nlen > 3 && name[nlen - 3] == '.' && name[nlen - 2] == 'r'
                && name[nlen - 1] >= '0' && name[nlen - 1] <= '9')
            {
                match = 1;
            }
            if (!match) continue;

            char fpath[PATH_MAX];
            if (snprintf(fpath, sizeof(fpath), "%s/%s", path, name)
                >= (int) sizeof(fpath))
            {
                continue;
            }
            struct stat fst;
            if (stat(fpath, &fst) != 0 || !S_ISREG(fst.st_mode)) continue;
            FILE *fp = fopen(fpath, "r");
            if (fp == NULL) continue;
            X509_CRL *crl;
            while ((crl = PEM_read_X509_CRL(fp, NULL, NULL, NULL)) != NULL) {
                sk_X509_CRL_push(stack, crl);
            }
            fclose(fp);
        }
        closedir(d);
    }

    if (sk_X509_CRL_num(stack) == 0) {
        sk_X509_CRL_free(stack);
        return NULL;
    }

    return stack;
}

/* Convert an X509_NAME to a printable C string (caller must OPENSSL_free()). */
static char *
name_to_str(const X509_NAME *n)
{
    return X509_NAME_oneline(n, NULL, 0);
}

/* Stream module-specific PKI checks. */
ngx_int_t
xrootd_check_pki_consistency_stream(ngx_log_t *log,
                                    ngx_stream_xrootd_srv_conf_t *xcf)
{
    const char *ca_path = (xcf->trusted_ca.len > 0) ? (char *) xcf->trusted_ca.data : NULL;
    const char *crl_path = (xcf->crl.len > 0) ? (char *) xcf->crl.data : NULL;

    if (ca_path == NULL) {
        return NGX_OK;
    }

    STACK_OF(X509) *cas = load_certs_from_path(ca_path, log);
    if (cas == NULL) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd: PKI check: no CA certificates found in \"%s\"",
                      ca_path);
        return NGX_OK;
    }

    if (crl_path == NULL) {
        sk_X509_pop_free(cas, X509_free);
        return NGX_OK;
    }

    STACK_OF(X509_CRL) *crls = load_crls_from_path(crl_path, log);
    if (crls == NULL) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd: PKI check: no CRLs loaded from \"%s\"",
                      crl_path);
        sk_X509_pop_free(cas, X509_free);
        return NGX_OK;
    }

    /* For each CRL try to find a CA whose subject matches the CRL issuer and
     * verify the CRL signature with that CA's public key. */
    int ncrl = sk_X509_CRL_num(crls);
    for (int i = 0; i < ncrl; i++) {
        X509_CRL *crl = sk_X509_CRL_value(crls, i);
        X509_NAME *issuer = CRL_GET_ISSUER(crl);
        int found = 0;

        int nca = sk_X509_num(cas);
        for (int j = 0; j < nca; j++) {
            X509 *ca = sk_X509_value(cas, j);
            X509_NAME *subj = X509_get_subject_name(ca);
            if (X509_NAME_cmp(issuer, subj) == 0) {
                found = 1;
                EVP_PKEY *pkey = X509_get_pubkey(ca);
                if (pkey == NULL) {
                    char *s = name_to_str(subj);
                    ngx_log_error(NGX_LOG_ERR, log, 0,
                                  "xrootd: PKI check: CA %s has no public key",
                                  s ? s : "<unknown>");
                    if (s) OPENSSL_free(s);
                    EVP_PKEY_free(pkey);
                    continue;
                }
                int ok = X509_CRL_verify(crl, pkey);
                EVP_PKEY_free(pkey);
                if (ok != 1) {
                    char *s = name_to_str(subj);
                    ngx_log_error(NGX_LOG_ERR, log, 0,
                                  "xrootd: PKI check: CRL signature verification failed for CRL issuer %s",
                                  s ? s : "<unknown>");
                    if (s) OPENSSL_free(s);
                }
                break;
            }
        }
        if (!found) {
            char *s = name_to_str(issuer);
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "xrootd: PKI check: no matching CA found for CRL issuer %s",
                          s ? s : "<unknown>");
            if (s) OPENSSL_free(s);
        }
    }

    sk_X509_pop_free(cas, X509_free);
    sk_X509_CRL_pop_free(crls, X509_CRL_free);

    return NGX_OK;
}

/* WebDAV module-specific PKI checks. */
ngx_int_t
webdav_check_pki_consistency(ngx_log_t *log,
                             ngx_http_xrootd_webdav_loc_conf_t *conf)
{
    const char *ca_path = NULL;
    if (conf->cafile.len > 0) {
        ca_path = (char *) conf->cafile.data;
    } else if (conf->cadir.len > 0) {
        ca_path = (char *) conf->cadir.data;
    }

    const char *crl_path = (conf->crl.len > 0) ? (char *) conf->crl.data : NULL;

    if (ca_path == NULL) {
        return NGX_OK;
    }

    STACK_OF(X509) *cas = load_certs_from_path(ca_path, log);
    if (cas == NULL) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd_webdav: PKI check: no CA certificates found in \"%s\"",
                      ca_path);
        return NGX_OK;
    }

    if (crl_path == NULL) {
        sk_X509_pop_free(cas, X509_free);
        return NGX_OK;
    }

    STACK_OF(X509_CRL) *crls = load_crls_from_path(crl_path, log);
    if (crls == NULL) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd_webdav: PKI check: no CRLs loaded from \"%s\"",
                      crl_path);
        sk_X509_pop_free(cas, X509_free);
        return NGX_OK;
    }

    int ncrl = sk_X509_CRL_num(crls);
    for (int i = 0; i < ncrl; i++) {
        X509_CRL *crl = sk_X509_CRL_value(crls, i);
        X509_NAME *issuer = CRL_GET_ISSUER(crl);
        int found = 0;

        int nca = sk_X509_num(cas);
        for (int j = 0; j < nca; j++) {
            X509 *ca = sk_X509_value(cas, j);
            X509_NAME *subj = X509_get_subject_name(ca);
            if (X509_NAME_cmp(issuer, subj) == 0) {
                found = 1;
                EVP_PKEY *pkey = X509_get_pubkey(ca);
                if (pkey == NULL) {
                    char *s = name_to_str(subj);
                    ngx_log_error(NGX_LOG_ERR, log, 0,
                                  "xrootd_webdav: PKI check: CA %s has no public key",
                                  s ? s : "<unknown>");
                    if (s) OPENSSL_free(s);
                    EVP_PKEY_free(pkey);
                    continue;
                }
                int ok = X509_CRL_verify(crl, pkey);
                EVP_PKEY_free(pkey);
                if (ok != 1) {
                    char *s = name_to_str(subj);
                    ngx_log_error(NGX_LOG_ERR, log, 0,
                                  "xrootd_webdav: PKI check: CRL signature verification failed for CRL issuer %s",
                                  s ? s : "<unknown>");
                    if (s) OPENSSL_free(s);
                }
                break;
            }
        }
        if (!found) {
            char *s = name_to_str(issuer);
            ngx_log_error(NGX_LOG_ERR, log, 0,
                          "xrootd_webdav: PKI check: no matching CA found for CRL issuer %s",
                          s ? s : "<unknown>");
            if (s) OPENSSL_free(s);
        }
    }

    sk_X509_pop_free(cas, X509_free);
    sk_X509_CRL_pop_free(crls, X509_CRL_free);

    return NGX_OK;
}
