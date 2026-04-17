/*
 * ngx_xrootd_token.c — JWT / WLCG bearer-token validation
 *
 * Implements RS256 JWT signature verification, JWKS loading,
 * and WLCG scope-based authorisation for nginx-xrootd.
 *
 * Designed for shared use by both the stream (XRootD) module and the
 * HTTP (WebDAV) module.  No dependency on ngx_stream.h — only ngx_core.h.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>

#include "ngx_xrootd_token.h"

#include <string.h>
#include <stdlib.h>
#include <time.h>

/* ================================================================== */
/*  Base64URL decoding                                                  */
/* ================================================================== */

/*
 * Decode base64url (RFC 4648 §5) into out[].
 * Returns decoded length, or -1 on error.
 */
static ssize_t
b64url_decode(const char *in, size_t in_len, u_char *out, size_t out_max)
{
    /* Translate base64url → standard base64 in a scratch buffer. */
    size_t padded_len = in_len + (4 - in_len % 4) % 4;
    if (padded_len > 8192) return -1;  /* sanity cap */

    u_char tmp[8192];
    size_t i;
    for (i = 0; i < in_len; i++) {
        if (in[i] == '-')      tmp[i] = '+';
        else if (in[i] == '_') tmp[i] = '/';
        else                   tmp[i] = (u_char) in[i];
    }
    for (; i < padded_len; i++) {
        tmp[i] = '=';
    }

    /* Use OpenSSL EVP base64 decode. */
    EVP_ENCODE_CTX *ctx = EVP_ENCODE_CTX_new();
    if (!ctx) return -1;

    EVP_DecodeInit(ctx);

    int out_len = 0, tmp_len = 0;
    if (EVP_DecodeUpdate(ctx, out, &out_len,
                         tmp, (int) padded_len) < 0)
    {
        EVP_ENCODE_CTX_free(ctx);
        return -1;
    }
    if (EVP_DecodeFinal(ctx, out + out_len, &tmp_len) < 0) {
        EVP_ENCODE_CTX_free(ctx);
        return -1;
    }
    EVP_ENCODE_CTX_free(ctx);

    return (ssize_t)(out_len + tmp_len);
}


/* ================================================================== */
/*  Minimal JSON utilities                                              */
/* ================================================================== */

/*
 * Skip JSON whitespace.
 */
static const char *
json_skip_ws(const char *p, const char *end)
{
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r'))
        p++;
    return p;
}

/*
 * Skip a JSON value (string, number, object, array, true, false, null).
 * Returns pointer past the value, or NULL on error.
 */
static const char *
json_skip_value(const char *p, const char *end)
{
    p = json_skip_ws(p, end);
    if (p >= end) return NULL;

    if (*p == '"') {
        /* String: scan to unescaped closing quote */
        p++;
        while (p < end) {
            if (*p == '\\') { p += 2; continue; }
            if (*p == '"') return p + 1;
            p++;
        }
        return NULL;
    }
    if (*p == '{') {
        /* Object: match braces */
        int depth = 1;
        p++;
        while (p < end && depth > 0) {
            if (*p == '\\') { p += 2; continue; }
            if (*p == '"') {
                p++;
                while (p < end && *p != '"') {
                    if (*p == '\\') p++;
                    p++;
                }
                if (p < end) p++;
                continue;
            }
            if (*p == '{') depth++;
            if (*p == '}') depth--;
            p++;
        }
        return depth == 0 ? p : NULL;
    }
    if (*p == '[') {
        /* Array: match brackets */
        int depth = 1;
        p++;
        while (p < end && depth > 0) {
            if (*p == '\\') { p += 2; continue; }
            if (*p == '"') {
                p++;
                while (p < end && *p != '"') {
                    if (*p == '\\') p++;
                    p++;
                }
                if (p < end) p++;
                continue;
            }
            if (*p == '[') depth++;
            if (*p == ']') depth--;
            p++;
        }
        return depth == 0 ? p : NULL;
    }
    /* Number, true, false, null — scan until delimiter */
    while (p < end && *p != ',' && *p != '}' && *p != ']' &&
           *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r')
        p++;
    return p;
}

/*
 * Find a key in a JSON object (top-level only, not recursive).
 * json points to the '{', end points past the closing '}'.
 * Returns pointer to the value start, or NULL if not found.
 */
static const char *
json_find_key(const char *json, const char *end, const char *key,
              const char **val_end)
{
    const char *p;
    size_t key_len = strlen(key);

    p = json_skip_ws(json, end);
    if (p >= end || *p != '{') return NULL;
    p++;  /* skip '{' */

    while (p < end) {
        p = json_skip_ws(p, end);
        if (p >= end || *p == '}') return NULL;

        /* Parse key string */
        if (*p != '"') return NULL;
        p++;
        const char *kstart = p;
        while (p < end && *p != '"') {
            if (*p == '\\') p++;
            p++;
        }
        if (p >= end) return NULL;
        size_t klen = (size_t)(p - kstart);
        p++;  /* skip closing quote */

        p = json_skip_ws(p, end);
        if (p >= end || *p != ':') return NULL;
        p++;  /* skip ':' */

        p = json_skip_ws(p, end);

        /* Is this the key we want? */
        if (klen == key_len && memcmp(kstart, key, key_len) == 0) {
            const char *vstart = p;
            const char *vend = json_skip_value(p, end);
            if (!vend) return NULL;
            if (val_end) *val_end = vend;
            return vstart;
        }

        /* Skip this value */
        p = json_skip_value(p, end);
        if (!p) return NULL;

        p = json_skip_ws(p, end);
        if (p < end && *p == ',') p++;
    }
    return NULL;
}

/*
 * Extract a JSON string value for the given key.
 * Writes into out[] (NUL-terminated), returns string length or -1.
 */
static ssize_t
json_get_string(const char *json, size_t json_len,
                const char *key, char *out, size_t out_max)
{
    const char *end = json + json_len;
    const char *val_end;
    const char *val = json_find_key(json, end, key, &val_end);
    if (!val || *val != '"') return -1;

    val++;  /* skip opening quote */
    const char *str_end = val;
    while (str_end < val_end - 1 && *str_end != '"') {
        if (*str_end == '\\') str_end++;
        str_end++;
    }

    size_t len = (size_t)(str_end - val);
    if (len >= out_max) len = out_max - 1;
    memcpy(out, val, len);
    out[len] = '\0';
    return (ssize_t) len;
}

/*
 * Extract a JSON integer value for the given key.
 * Returns 0 on success, -1 if not found.
 */
static int
json_get_int64(const char *json, size_t json_len,
               const char *key, int64_t *out)
{
    const char *end = json + json_len;
    const char *val_end;
    const char *val = json_find_key(json, end, key, &val_end);
    if (!val) return -1;

    /* Must start with digit or minus */
    if (*val != '-' && (*val < '0' || *val > '9')) return -1;

    char numbuf[32];
    size_t nlen = (size_t)(val_end - val);
    if (nlen >= sizeof(numbuf)) return -1;
    memcpy(numbuf, val, nlen);
    numbuf[nlen] = '\0';

    char *ep;
    *out = strtoll(numbuf, &ep, 10);
    return (*ep == '\0') ? 0 : -1;
}

/*
 * Extract a JSON array of strings for the given key.
 * Writes strings into out[] (each NUL-terminated, max str_max bytes).
 * Returns count (0 if key absent or not an array), -1 on error.
 */
static int
json_get_string_array(const char *json, size_t json_len,
                      const char *key,
                      char out[][256], int max_count)
{
    const char *end = json + json_len;
    const char *val_end;
    const char *val = json_find_key(json, end, key, &val_end);
    if (!val || *val != '[') return 0;

    const char *p = val + 1;  /* skip '[' */
    int count = 0;

    while (p < val_end && count < max_count) {
        p = json_skip_ws(p, val_end);
        if (p >= val_end || *p == ']') break;

        if (*p == '"') {
            p++;  /* skip quote */

            const char *sstart = p;
            while (p < val_end && *p != '"') {
                if (*p == '\\') p++;
                p++;
            }
            size_t slen = (size_t)(p - sstart);
            if (slen >= 256) slen = 255;
            memcpy(out[count], sstart, slen);
            out[count][slen] = '\0';
            count++;
            if (p < val_end) p++;  /* skip closing quote */
        } else {
            p = json_skip_value(p, val_end);
        }

        p = json_skip_ws(p, val_end);
        if (p < val_end && *p == ',') p++;
    }
    return count;
}


/* ================================================================== */
/*  JWKS loading — RSA public keys from JSON Web Key Set                */
/* ================================================================== */

/*
 * Construct an RSA EVP_PKEY from base64url-encoded n and e components.
 */
static EVP_PKEY *
rsa_pubkey_from_ne(const char *n_b64, size_t n_b64_len,
                   const char *e_b64, size_t e_b64_len,
                   ngx_log_t *log)
{
    u_char n_bin[512], e_bin[16];
    ssize_t n_len, e_len;

    n_len = b64url_decode(n_b64, n_b64_len, n_bin, sizeof(n_bin));
    e_len = b64url_decode(e_b64, e_b64_len, e_bin, sizeof(e_bin));
    if (n_len <= 0 || e_len <= 0) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "xrootd_token: JWKS: cannot decode RSA n/e");
        return NULL;
    }

    BIGNUM *bn_n = BN_bin2bn(n_bin, (int) n_len, NULL);
    BIGNUM *bn_e = BN_bin2bn(e_bin, (int) e_len, NULL);
    if (!bn_n || !bn_e) {
        BN_free(bn_n); BN_free(bn_e);
        return NULL;
    }

    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, bn_n);
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, bn_e);
    OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(bld);

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    EVP_PKEY *pkey = NULL;
    if (pctx) {
        EVP_PKEY_fromdata_init(pctx);
        EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_PUBLIC_KEY, params);
        EVP_PKEY_CTX_free(pctx);
    }

    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    BN_free(bn_n);
    BN_free(bn_e);

    return pkey;
}

/*
 * Load JWKS keys from a JSON file on disk.
 */
int
xrootd_jwks_load(ngx_log_t *log, const char *path,
                 xrootd_jwks_key_t *keys, int max_keys)
{
    FILE *fp;
    char *buf;
    long  fsize;
    int   count = 0;

    fp = fopen(path, "r");
    if (!fp) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                      "xrootd_token: cannot open JWKS file \"%s\"", path);
        return -1;
    }

    fseek(fp, 0, SEEK_END);
    fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (fsize <= 0 || fsize > 65536) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "xrootd_token: JWKS file too large or empty: %ld bytes",
                      fsize);
        fclose(fp);
        return -1;
    }

    buf = malloc((size_t) fsize + 1);
    if (!buf) { fclose(fp); return -1; }

    if (fread(buf, 1, (size_t) fsize, fp) != (size_t) fsize) {
        ngx_log_error(NGX_LOG_ERR, log, ngx_errno,
                      "xrootd_token: failed to read JWKS file");
        free(buf);
        fclose(fp);
        return -1;
    }
    buf[fsize] = '\0';
    fclose(fp);

    /* Find the "keys" array in the top-level object. */
    const char *end = buf + fsize;
    const char *val_end;
    const char *keys_arr = json_find_key(buf, end, "keys", &val_end);
    if (!keys_arr || *keys_arr != '[') {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "xrootd_token: JWKS missing \"keys\" array");
        free(buf);
        return -1;
    }

    /* Iterate over objects in the array. */
    const char *p = keys_arr + 1;
    while (p < val_end && count < max_keys) {
        const char *obj_start, *obj_end;

        p = json_skip_ws(p, val_end);
        if (p >= val_end || *p == ']') break;

        /* Skip non-object values in the array (shouldn't happen in valid JWKS). */
        obj_start = p;
        obj_end = json_skip_value(p, val_end);
        if (!obj_end) break;

        if (*obj_start != '{') {
            p = obj_end;
            p = json_skip_ws(p, val_end);
            if (p < val_end && *p == ',') p++;
            continue;
        }

        {
        size_t obj_len = (size_t)(obj_end - obj_start);

        /* Extract fields from this key object. */
        char kty[16] = {0}, kid[128] = {0};
        char n_b64[1024] = {0}, e_b64[32] = {0};

        json_get_string(obj_start, obj_len, "kty", kty, sizeof(kty));
        json_get_string(obj_start, obj_len, "kid", kid, sizeof(kid));
        json_get_string(obj_start, obj_len, "n", n_b64, sizeof(n_b64));
        json_get_string(obj_start, obj_len, "e", e_b64, sizeof(e_b64));

        if (strcmp(kty, "RSA") == 0 && n_b64[0] && e_b64[0]) {
            EVP_PKEY *pkey = rsa_pubkey_from_ne(
                n_b64, strlen(n_b64), e_b64, strlen(e_b64), log);
            if (pkey) {
                ngx_cpystrn((u_char *) keys[count].kid,
                            (u_char *) kid, sizeof(keys[count].kid));
                keys[count].pkey = pkey;
                count++;
                ngx_log_error(NGX_LOG_INFO, log, 0,
                              "xrootd_token: loaded JWKS key kid=\"%s\"", kid);
            }
        } else {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "xrootd_token: skipping JWKS key kty=\"%s\" "
                          "(only RSA supported)", kty);
        }
        }

        p = obj_end;
        p = json_skip_ws(p, val_end);
        if (p < val_end && *p == ',') p++;
    }

    free(buf);

    ngx_log_error(NGX_LOG_NOTICE, log, 0,
                  "xrootd_token: loaded %d JWKS key(s) from \"%s\"",
                  count, path);
    return count;
}

void
xrootd_jwks_free(xrootd_jwks_key_t *keys, int count)
{
    int i;
    for (i = 0; i < count; i++) {
        if (keys[i].pkey) {
            EVP_PKEY_free(keys[i].pkey);
            keys[i].pkey = NULL;
        }
    }
}


/* ================================================================== */
/*  JWT validation                                                      */
/* ================================================================== */

/*
 * Verify RS256 signature of a JWT.
 *
 * signed_data:  "header.payload" (raw base64url, NOT decoded)
 * sig:          decoded signature bytes
 * pkey:         RSA public key
 *
 * Returns 1 on success, 0 on failure.
 */
static int
jwt_verify_rs256(const u_char *signed_data, size_t signed_len,
                 const u_char *sig, size_t sig_len,
                 EVP_PKEY *pkey)
{
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) return 0;

    int ok = 0;
    if (EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pkey) == 1 &&
        EVP_DigestVerifyUpdate(mdctx, signed_data, signed_len) == 1 &&
        EVP_DigestVerifyFinal(mdctx, sig, sig_len) == 1)
    {
        ok = 1;
    }

    EVP_MD_CTX_free(mdctx);
    return ok;
}

static int
token_malformed(ngx_log_t *log)
{
    ngx_log_error(NGX_LOG_WARN, log, 0,
                  "xrootd_token: malformed JWT structure");
    return -1;
}

/*
 * Validate a JWT bearer token.
 *
 * Returns 0 on success, -1 on validation failure.
 */
int
xrootd_token_validate(ngx_log_t *log,
                      const char *token, size_t token_len,
                      const xrootd_jwks_key_t *keys, int key_count,
                      const char *expected_issuer,
                      const char *expected_audience,
                      xrootd_token_claims_t *claims)
{
    const char *dot1, *dot2;
    u_char      hdr_json[2048], pay_json[4096], sig_bin[512];
    ssize_t     hdr_len, pay_len, sig_len;
    char        alg[16] = {0}, kid[128] = {0};
    int         i;
    time_t      now;

    memset(claims, 0, sizeof(*claims));

    if (token_len == 0 || token_len > 8192) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd_token: token length invalid: %uz", token_len);
        return -1;
    }

    /* ---- Split on '.' ---- */
    dot1 = memchr(token, '.', token_len);
    if (!dot1) return token_malformed(log);
    dot2 = memchr(dot1 + 1, '.', token_len - (size_t)(dot1 + 1 - token));
    if (!dot2) return token_malformed(log);

    /* Reject tokens with more than 2 dots (JWE or malformed) */
    if (memchr(dot2 + 1, '.', token_len - (size_t)(dot2 + 1 - token))) {
        return token_malformed(log);
    }

    size_t hdr_b64_len = (size_t)(dot1 - token);
    size_t pay_b64_len = (size_t)(dot2 - dot1 - 1);
    size_t sig_b64_len = token_len - (size_t)(dot2 + 1 - token);

    /* ---- Decode header ---- */
    hdr_len = b64url_decode(token, hdr_b64_len, hdr_json, sizeof(hdr_json) - 1);
    if (hdr_len < 0) return token_malformed(log);
    hdr_json[hdr_len] = '\0';

    /* ---- Check algorithm (MUST be RS256, reject "none") ---- */
    json_get_string((char *) hdr_json, (size_t) hdr_len, "alg", alg, sizeof(alg));
    if (strcmp(alg, "RS256") != 0) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd_token: unsupported JWT algorithm \"%s\" "
                      "(only RS256 accepted)", alg);
        return -1;
    }

    /* ---- Extract kid ---- */
    json_get_string((char *) hdr_json, (size_t) hdr_len, "kid", kid, sizeof(kid));

    /* ---- Find matching key ---- */
    EVP_PKEY *pkey = NULL;
    for (i = 0; i < key_count; i++) {
        if (kid[0] == '\0' || strcmp(keys[i].kid, kid) == 0) {
            pkey = keys[i].pkey;
            break;
        }
    }
    if (!pkey && key_count == 1) {
        /* Single-key JWKS: use it regardless of kid */
        pkey = keys[0].pkey;
    }
    if (!pkey) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd_token: no JWKS key matching kid=\"%s\"", kid);
        return -1;
    }

    /* ---- Verify signature ---- */
    sig_len = b64url_decode(dot2 + 1, sig_b64_len, sig_bin, sizeof(sig_bin));
    if (sig_len < 0) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd_token: cannot decode JWT signature");
        return -1;
    }

    /* The signed data is the raw "header.payload" (base64url, NOT decoded). */
    size_t signed_len = (size_t)(dot2 - token);
    if (!jwt_verify_rs256((const u_char *) token, signed_len,
                          sig_bin, (size_t) sig_len, pkey))
    {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd_token: JWT signature verification failed");
        return -1;
    }

    /* ---- Decode payload ---- */
    pay_len = b64url_decode(dot1 + 1, pay_b64_len, pay_json,
                            sizeof(pay_json) - 1);
    if (pay_len < 0) return token_malformed(log);
    pay_json[pay_len] = '\0';

    /* ---- Extract claims ---- */
    json_get_string((char *) pay_json, (size_t) pay_len,
                    "iss", claims->iss, sizeof(claims->iss));
    json_get_string((char *) pay_json, (size_t) pay_len,
                    "sub", claims->sub, sizeof(claims->sub));
    json_get_string((char *) pay_json, (size_t) pay_len,
                    "aud", claims->aud, sizeof(claims->aud));
    json_get_string((char *) pay_json, (size_t) pay_len,
                    "scope", claims->scope_raw, sizeof(claims->scope_raw));

    json_get_int64((char *) pay_json, (size_t) pay_len, "exp", &claims->exp);
    json_get_int64((char *) pay_json, (size_t) pay_len, "nbf", &claims->nbf);
    json_get_int64((char *) pay_json, (size_t) pay_len, "iat", &claims->iat);

    /* Extract wlcg.groups array → comma-separated string */
    {
        char groups[16][256];
        int gcount = json_get_string_array(
            (char *) pay_json, (size_t) pay_len,
            "wlcg.groups", groups, 16);
        claims->groups[0] = '\0';
        for (i = 0; i < gcount; i++) {
            if (i > 0) {
                size_t cur = strlen(claims->groups);
                if (cur + 1 < sizeof(claims->groups))
                    claims->groups[cur] = ',';
                claims->groups[cur + 1] = '\0';
            }
            size_t cur = strlen(claims->groups);
            size_t rem = sizeof(claims->groups) - cur - 1;
            if (rem > 0) {
                size_t gl = strlen(groups[i]);
                if (gl > rem) gl = rem;
                memcpy(claims->groups + cur, groups[i], gl);
                claims->groups[cur + gl] = '\0';
            }
        }
    }

    /* ---- Validate issuer ---- */
    if (expected_issuer && expected_issuer[0]) {
        if (strcmp(claims->iss, expected_issuer) != 0) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "xrootd_token: issuer mismatch: got \"%s\" "
                          "expected \"%s\"", claims->iss, expected_issuer);
            return -1;
        }
    }

    /* ---- Validate audience ---- */
    if (expected_audience && expected_audience[0]) {
        if (strcmp(claims->aud, expected_audience) != 0) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "xrootd_token: audience mismatch: got \"%s\" "
                          "expected \"%s\"", claims->aud, expected_audience);
            return -1;
        }
    }

    /* ---- Check timing ---- */
    now = time(NULL);

    if (claims->exp > 0 && now > (time_t) claims->exp) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd_token: token expired at %L (now=%L)",
                      (long long) claims->exp, (long long) now);
        return -1;
    }

    if (claims->nbf > 0 && now < (time_t) claims->nbf) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd_token: token not yet valid (nbf=%L now=%L)",
                      (long long) claims->nbf, (long long) now);
        return -1;
    }

    /* ---- Parse scopes ---- */
    claims->scope_count = xrootd_token_parse_scopes(
        claims->scope_raw, claims->scopes, XROOTD_MAX_TOKEN_SCOPES);

    ngx_log_error(NGX_LOG_INFO, log, 0,
                  "xrootd_token: valid token sub=\"%s\" iss=\"%s\" "
                  "scope=\"%s\" groups=\"%s\" scopes=%d",
                  claims->sub, claims->iss,
                  claims->scope_raw, claims->groups,
                  claims->scope_count);
    return 0;
}


/* ================================================================== */
/*  Scope parsing and checking                                          */
/* ================================================================== */

/*
 * Parse the "scope" claim: space-separated entries like
 *   "storage.read:/ storage.write:/data storage.create:/uploads"
 */
int
xrootd_token_parse_scopes(const char *scope_str,
                          xrootd_token_scope_t *scopes, int max_scopes)
{
    const char *p = scope_str;
    int count = 0;

    if (!scope_str || !scope_str[0]) return 0;

    while (*p && count < max_scopes) {
        /* Skip whitespace. */
        while (*p == ' ') p++;
        if (!*p) break;

        /* Find end of this scope entry. */
        const char *end = p;
        while (*end && *end != ' ') end++;

        size_t entry_len = (size_t)(end - p);

        /* Parse "permission:path" */
        const char *colon = memchr(p, ':', entry_len);
        if (!colon) { p = end; continue; }

        size_t perm_len = (size_t)(colon - p);
        const char *path = colon + 1;
        size_t path_len = (size_t)(end - path);

        memset(&scopes[count], 0, sizeof(scopes[count]));

        /* Copy path */
        if (path_len == 0) {
            scopes[count].path[0] = '/';
            scopes[count].path[1] = '\0';
        } else {
            if (path_len >= PATH_MAX) path_len = PATH_MAX - 1;
            memcpy(scopes[count].path, path, path_len);
            scopes[count].path[path_len] = '\0';
        }

        /* Set permission bits */
        if (perm_len == 12 && memcmp(p, "storage.read", 12) == 0)
            scopes[count].read = 1;
        else if (perm_len == 13 && memcmp(p, "storage.write", 13) == 0)
            scopes[count].write = 1;
        else if (perm_len == 14 && memcmp(p, "storage.create", 14) == 0)
            scopes[count].create = 1;
        else if (perm_len == 14 && memcmp(p, "storage.modify", 14) == 0)
            scopes[count].modify = 1;

        count++;
        p = end;
    }
    return count;
}

/*
 * Check whether a scope path grants access to a request path.
 * Both paths should start with '/'.
 *
 * Rules:
 *   "/" matches everything.
 *   "/data" matches "/data", "/data/", "/data/file.txt".
 *   "/data" does NOT match "/data2/file.txt".
 */
static int
scope_path_matches(const char *scope_path, const char *request_path)
{
    size_t sp_len = strlen(scope_path);

    /* "/" matches everything */
    if (sp_len == 1 && scope_path[0] == '/') return 1;

    /* Remove trailing slash from scope for comparison */
    if (sp_len > 1 && scope_path[sp_len - 1] == '/') sp_len--;

    if (strncmp(scope_path, request_path, sp_len) != 0) return 0;

    char next = request_path[sp_len];
    return (next == '\0' || next == '/');
}

int
xrootd_token_check_read(const xrootd_token_scope_t *scopes,
                         int scope_count, const char *path)
{
    int i;
    for (i = 0; i < scope_count; i++) {
        if (scopes[i].read && scope_path_matches(scopes[i].path, path))
            return 1;
    }
    return 0;
}

int
xrootd_token_check_write(const xrootd_token_scope_t *scopes,
                          int scope_count, const char *path)
{
    int i;
    for (i = 0; i < scope_count; i++) {
        if ((scopes[i].write || scopes[i].create) &&
            scope_path_matches(scopes[i].path, path))
            return 1;
    }
    return 0;
}
