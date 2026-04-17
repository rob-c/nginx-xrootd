#pragma once

/*
 * ngx_xrootd_token.h
 *
 * JWT / WLCG bearer-token validation for nginx-xrootd.
 *
 * Shared between the stream (XRootD) module and the HTTP (WebDAV) module.
 * Requires ngx_core.h (for ngx_log_t etc.) to be included before this header.
 */

#include <openssl/evp.h>
#include <limits.h>

/* ------------------------------------------------------------------ */
/* Tunables                                                             */
/* ------------------------------------------------------------------ */

#define XROOTD_MAX_TOKEN_SCOPES   32
#define XROOTD_MAX_JWKS_KEYS      8

/* ------------------------------------------------------------------ */
/* Types                                                                */
/* ------------------------------------------------------------------ */

/* A single public key loaded from a JWKS file. */
typedef struct {
    char       kid[128];        /* Key ID ("kid" claim) */
    EVP_PKEY  *pkey;            /* RSA or EC public key */
} xrootd_jwks_key_t;

/* A parsed scope entry from the "scope" claim. */
typedef struct {
    char          path[PATH_MAX]; /* Scope path (e.g., "/" or "/data") */
    unsigned int  read   : 1;     /* storage.read */
    unsigned int  write  : 1;     /* storage.write */
    unsigned int  create : 1;     /* storage.create */
    unsigned int  modify : 1;     /* storage.modify */
} xrootd_token_scope_t;

/* Extracted claims from a validated JWT. */
typedef struct {
    char    sub[256];           /* Subject */
    char    iss[256];           /* Issuer */
    char    aud[256];           /* Audience */
    int64_t exp;                /* Expiry (Unix timestamp) */
    int64_t nbf;                /* Not-before (Unix timestamp) */
    int64_t iat;                /* Issued-at  (Unix timestamp) */
    char    scope_raw[1024];    /* Raw "scope" claim */
    char    groups[512];        /* Comma-separated groups (from wlcg.groups) */
    int                   scope_count;
    xrootd_token_scope_t  scopes[XROOTD_MAX_TOKEN_SCOPES];
} xrootd_token_claims_t;

/* ------------------------------------------------------------------ */
/* JWKS loading (called once at startup / config load)                  */
/* ------------------------------------------------------------------ */

/*
 * Load RSA public keys from a JWKS file.
 * Fills keys[] up to max_keys entries.
 * Returns ≥ 0 (count) on success, -1 on error.
 */
int xrootd_jwks_load(ngx_log_t *log, const char *path,
                     xrootd_jwks_key_t *keys, int max_keys);

/*
 * Free all loaded JWKS keys.
 */
void xrootd_jwks_free(xrootd_jwks_key_t *keys, int count);

/* ------------------------------------------------------------------ */
/* Token validation                                                     */
/* ------------------------------------------------------------------ */

/*
 * Validate a JWT bearer token.
 *
 * Checks: structure, signature (RS256), exp, nbf, iss, aud.
 * On success fills `claims` with the extracted claim values and
 * parsed scopes.
 *
 * Returns 0 on success, -1 on error.
 */
int xrootd_token_validate(ngx_log_t *log,
                          const char *token, size_t token_len,
                          const xrootd_jwks_key_t *keys, int key_count,
                          const char *expected_issuer,
                          const char *expected_audience,
                          xrootd_token_claims_t *claims);

/* ------------------------------------------------------------------ */
/* Scope checking                                                       */
/* ------------------------------------------------------------------ */

/*
 * Parse the "scope" claim string into structured scope entries.
 * Returns the number of entries parsed (≥ 0).
 */
int xrootd_token_parse_scopes(const char *scope_str,
                              xrootd_token_scope_t *scopes, int max_scopes);

/*
 * Check if scopes authorise read access to `path`.
 * `path` is relative to the xrootd_root (e.g. "/data/file.txt").
 * Returns 1 if allowed, 0 if denied.
 */
int xrootd_token_check_read(const xrootd_token_scope_t *scopes,
                            int scope_count, const char *path);

/*
 * Check if scopes authorise write access to `path`.
 * Returns 1 if allowed, 0 if denied.
 */
int xrootd_token_check_write(const xrootd_token_scope_t *scopes,
                             int scope_count, const char *path);
