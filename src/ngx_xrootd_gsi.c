#include "ngx_xrootd_module.h"

/* ================================================================== */
/*                                                                    */
/*  GSI / x509 AUTHENTICATION PROTOCOL                                */
/*                                                                    */
/*  This section implements GSI (Grid Security Infrastructure) auth,  */
/*  the dominant authentication mechanism in High Energy Physics      */
/*  computing grids (CERN, SLAC, Fermilab, etc.).  It is based on    */
/*  RFC 3820 proxy certificates and a DH key exchange for session     */
/*  cipher setup.                                                      */
/*                                                                    */
/* ================================================================== */

/*
 * gsi_find_bucket — scan a binary XrdSutBuffer for a bucket of a given type.
 *
 * XrdSutBuffer binary wire layout (all multi-byte fields are big-endian):
 *
 *   [protocol_name\0]   null-terminated string, e.g. "gsi\0" (4 bytes)
 *   [step : uint32 BE]  e.g. kXGC_certreq=1000, kXGS_cert=2001
 *   zero or more buckets:
 *     [type : uint32 BE]
 *     [len  : uint32 BE]
 *     [data : len bytes]
 *   [kXRS_none : uint32 BE]  terminator
 */
int
gsi_find_bucket(const u_char *payload, size_t plen,
                uint32_t target_type,
                const u_char **data_out, size_t *len_out)
{
    const u_char *p   = payload;
    const u_char *end = payload + plen;
    size_t        proto_len;

    if (plen < 8) return -1;

    /* Every XrdSutBuffer starts with "gsi\0" followed by the step number. */
    proto_len = ngx_strnlen((u_char *) p, plen) + 1;
    if (proto_len >= plen) return -1;
    p += proto_len;

    if (p + 4 > end) return -1;
    p += 4;

    while (p + 8 <= end) {
        uint32_t btype, blen;

        /* Each loop iteration peels exactly one [type,len,data] bucket. */
        /* Bucket header = type + payload length; both are BE on the wire. */
        ngx_memcpy(&btype, p,     4); btype = ntohl(btype);
        ngx_memcpy(&blen,  p + 4, 4); blen  = ntohl(blen);
        p += 8;

        /* kXRS_none is the explicit end marker; there is no outer count field. */
        if (btype == (uint32_t) kXRS_none) break;
        if (p + blen > end) return -1;

        if (btype == target_type) {
            *data_out = p;
            *len_out  = blen;
            return 0;
        }

        /* Skip past buckets we are not interested in and continue scanning. */
        p += blen;
    }
    return -1;
}

/*
 * xrootd_gsi_parse_x509 — decrypt and extract the x509 chain from kXGC_cert.
 */
STACK_OF(X509) *
xrootd_gsi_parse_x509(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    const u_char      *payload = ctx->payload;
    size_t             plen    = ctx->cur_dlen;
    ngx_log_t         *log     = c->log;

    const u_char      *cpub_data = NULL, *main_data = NULL, *calg_data = NULL;
    size_t             cpub_len  = 0,    main_len   = 0,    calg_len   = 0;
    char              *pb, *pe;
    BIGNUM            *bnpub  = NULL;
    EVP_PKEY          *peer   = NULL;
    EVP_PKEY_CTX      *pkctx;
    OSSL_PARAM_BLD    *bld;
    OSSL_PARAM        *params1 = NULL, *params2 = NULL, *params = NULL;
    unsigned char     *secret  = NULL;
    size_t             secret_len = 0;
    const EVP_CIPHER  *evp_cipher;
    EVP_CIPHER_CTX    *dctx   = NULL;
    unsigned char     *plain  = NULL;
    int                olen   = 0, flen = 0;
    const u_char      *x509_data = NULL;
    size_t             x509_len  = 0;
    STACK_OF(X509)    *chain  = NULL;
    BIO               *bio;
    X509              *cert;
    char               cipher_name[64];
    char               cipher_log[128];

    if (ctx->gsi_dh_key == NULL) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd: GSI kXGC_cert: no server DH key (kXGC_certreq skipped?)");
        return NULL;
    }

    /* Step 1: Parse the client DH public key from kXRS_puk */
    if (gsi_find_bucket(payload, plen, (uint32_t) kXRS_puk,
                        &cpub_data, &cpub_len) != 0) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd: GSI kXGC_cert: kXRS_puk not found in outer buffer");
        return NULL;
    }

    pb = memmem((void *) cpub_data, cpub_len, "---BPUB---", 10);
    pe = memmem((void *) cpub_data, cpub_len, "---EPUB--",   9);
    if (!pb || !pe || pe <= pb + 10) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd: GSI kXGC_cert: malformed client DH blob");
        return NULL;
    }

    /* The PEM-ish parameter block wraps the public value between fixed sentinels. */
    pb += 10;
    {
        /* BN_hex2bn expects a C string, so temporarily NUL-terminate the span. */
        char saved = *pe;
        *pe = '\0';
        BN_hex2bn(&bnpub, pb);
        *pe = saved;
    }
    if (!bnpub) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd: GSI kXGC_cert: BN_hex2bn failed");
        return NULL;
    }

    /* Step 2: Determine session cipher from kXRS_cipher_alg */
    ngx_cpystrn((u_char *) cipher_name, (u_char *) "aes-256-cbc",
                sizeof(cipher_name));
    if (gsi_find_bucket(payload, plen, (uint32_t) kXRS_cipher_alg,
                        &calg_data, &calg_len) == 0 && calg_len > 0) {
        size_t i;
        /* The client sends a colon-delimited preference list; pick the first. */
        for (i = 0; i < calg_len && i < sizeof(cipher_name) - 1; i++) {
            if (calg_data[i] == ':') break;
            cipher_name[i] = calg_data[i];
        }
        cipher_name[i] = '\0';
    }

    /* Step 3: Locate kXRS_main in the outer buffer */
    if (gsi_find_bucket(payload, plen, (uint32_t) kXRS_main,
                        &main_data, &main_len) != 0) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd: GSI kXGC_cert: kXRS_main not found in outer buffer");
        BN_free(bnpub);
        return NULL;
    }

    /* Step 4: Derive the DH shared secret */
    /* Rebuild a peer EVP_PKEY from our params + the client's public value. */
    EVP_PKEY_todata(ctx->gsi_dh_key, EVP_PKEY_KEY_PARAMETERS, &params1);

    bld     = OSSL_PARAM_BLD_new();
    /* The peer key consists of our negotiated DH group plus the client's pubkey. */
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PUB_KEY, bnpub);
    params2 = OSSL_PARAM_BLD_to_param(bld);
    OSSL_PARAM_BLD_free(bld);
    BN_free(bnpub);  bnpub = NULL;

    /* Merge parameter blocks so OpenSSL can materialize a proper EVP_PKEY object. */
    params  = OSSL_PARAM_merge(params1, params2);
    OSSL_PARAM_free(params1);
    OSSL_PARAM_free(params2);

    pkctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
    EVP_PKEY_fromdata_init(pkctx);
    EVP_PKEY_fromdata(pkctx, &peer, EVP_PKEY_PUBLIC_KEY, params);
    OSSL_PARAM_free(params);
    EVP_PKEY_CTX_free(pkctx);

    if (!peer) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd: GSI kXGC_cert: cannot build client DH peer key");
        return NULL;
    }

    pkctx = EVP_PKEY_CTX_new(ctx->gsi_dh_key, NULL);
    EVP_PKEY_derive_init(pkctx);
    EVP_PKEY_CTX_set_dh_pad(pkctx, 0);
    EVP_PKEY_derive_set_peer(pkctx, peer);

    /* First call asks OpenSSL how large the derived secret buffer must be. */
    EVP_PKEY_derive(pkctx, NULL, &secret_len);
    secret = ngx_palloc(c->pool, secret_len);
    if (!secret) {
        EVP_PKEY_CTX_free(pkctx);
        EVP_PKEY_free(peer);
        return NULL;
    }

    /* Second call writes the actual shared secret bytes into the allocated buffer. */
    EVP_PKEY_derive(pkctx, secret, &secret_len);
    EVP_PKEY_CTX_free(pkctx);
    EVP_PKEY_free(peer);

    ngx_log_debug2(NGX_LOG_DEBUG_STREAM, log, 0,
                   "xrootd: GSI DH shared secret %uz bytes, cipher='%s'",
                   secret_len,
                   (xrootd_sanitize_log_string(cipher_name, cipher_log,
                                               sizeof(cipher_log)),
                    cipher_log));

    /* Step 5: Decrypt kXRS_main using the AES session key */
    evp_cipher = EVP_get_cipherbyname(cipher_name);
    if (!evp_cipher) {
        xrootd_sanitize_log_string(cipher_name, cipher_log, sizeof(cipher_log));
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd: GSI kXGC_cert: unknown cipher '%s'", cipher_log);
        return NULL;
    }

    {
        size_t ltmp = (secret_len > (size_t) EVP_MAX_KEY_LENGTH)
                      ? (size_t) EVP_MAX_KEY_LENGTH : secret_len;
        int    ldef     = EVP_CIPHER_key_length(evp_cipher);
        size_t use_len  = (size_t) ldef;

        /* Some ciphers allow a shorter negotiated key than their OpenSSL default. */
        if ((int) ltmp != ldef) {
            EVP_CIPHER_CTX *tctx = EVP_CIPHER_CTX_new();
            EVP_CipherInit_ex(tctx, evp_cipher, NULL, NULL, NULL, 0);
            EVP_CIPHER_CTX_set_key_length(tctx, (int) ltmp);
            if (EVP_CIPHER_CTX_key_length(tctx) == (int) ltmp) {
                use_len = ltmp;
            }
            EVP_CIPHER_CTX_free(tctx);
        }

        /* XRootD GSI uses an all-zero IV for this bootstrap message. */
        unsigned char iv[EVP_MAX_IV_LENGTH];
        ngx_memset(iv, 0, sizeof(iv));

        dctx = EVP_CIPHER_CTX_new();
        /* Two-step init lets us override key length before supplying key material. */
        EVP_DecryptInit_ex(dctx, evp_cipher, NULL, NULL, NULL);
        if (use_len != (size_t) ldef) {
            EVP_CIPHER_CTX_set_key_length(dctx, (int) use_len);
        }
        EVP_DecryptInit_ex(dctx, NULL, NULL, secret, iv);
    }

    {
        /* Leave room for any block-padding expansion plus a debug-friendly NUL. */
        size_t plain_size = main_len + (size_t) EVP_CIPHER_CTX_block_size(dctx) + 1;
        plain = ngx_palloc(c->pool, plain_size);
        if (!plain) {
            EVP_CIPHER_CTX_free(dctx);
            return NULL;
        }

        if (EVP_DecryptUpdate(dctx, plain, &olen,
                              main_data, (int) main_len) != 1) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "xrootd: GSI kXGC_cert: EVP_DecryptUpdate failed");
            EVP_CIPHER_CTX_free(dctx);
            return NULL;
        }
        if (EVP_DecryptFinal_ex(dctx, plain + olen, &flen) != 1) {
            char errstr[128];
            ERR_error_string_n(ERR_get_error(), errstr, sizeof(errstr));
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "xrootd: GSI kXGC_cert: EVP_DecryptFinal failed: %s",
                          errstr);
            EVP_CIPHER_CTX_free(dctx);
            return NULL;
        }
        EVP_CIPHER_CTX_free(dctx);
    }

    int plain_len = olen + flen;
    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, log, 0,
                   "xrootd: GSI decrypted kXRS_main: %d bytes", plain_len);

    /* Step 6: Parse the decrypted inner XrdSutBuffer for kXRS_x509 */
    if (gsi_find_bucket(plain, (size_t) plain_len, (uint32_t) kXRS_x509,
                        &x509_data, &x509_len) != 0) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd: GSI kXGC_cert: kXRS_x509 not found "
                      "in decrypted inner buffer");
        return NULL;
    }

    bio   = BIO_new_mem_buf(x509_data, (int) x509_len);
    chain = sk_X509_new_null();
    if (!bio || !chain) {
        /* BIO owns only the view; the certificate bytes still live in pool memory. */
        BIO_free(bio);
        sk_X509_free(chain);
        return NULL;
    }

    /* PEM_read_bio_X509 consumes one PEM block per call until EOF. */
    while ((cert = PEM_read_bio_X509(bio, NULL, NULL, NULL)) != NULL) {
        sk_X509_push(chain, cert);
    }
    BIO_free(bio);

    if (sk_X509_num(chain) == 0) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd: GSI kXGC_cert: kXRS_x509 contained no certs");
        sk_X509_pop_free(chain, X509_free);
        return NULL;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, log, 0,
                   "xrootd: GSI parsed %d cert(s) from kXRS_x509 after decrypt",
                   sk_X509_num(chain));
    return chain;
}

/*
 * xrootd_gsi_send_cert — respond to kXGC_certreq (step 1000) with kXGS_cert.
 */
static ngx_int_t
xrootd_gsi_send_cert(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    ngx_stream_xrootd_srv_conf_t *conf;
    EVP_PKEY_CTX *pctx;
    EVP_PKEY     *dhkey = NULL;
    BIGNUM       *pub_bn = NULL;
    char         *pub_hex = NULL;
    BIO          *bio;
    BUF_MEM      *bptr;
    u_char       *buf, *p;
    u_char       *cert_pem, *puk_blob;


    size_t        cert_len, puk_len, body_len, total;
    char          puk_buf[4096];
    int           puk_written;

    conf = ngx_stream_get_module_srv_conf(ctx->session,
                                          ngx_stream_xrootd_module);

    /* Export server certificate as PEM */
    bio = BIO_new(BIO_s_mem());
    if (bio == NULL) return NGX_ERROR;
    if (!PEM_write_bio_X509(bio, conf->gsi_cert)) {
        BIO_free(bio);
        return NGX_ERROR;
    }

    /* BIO_get_mem_ptr exposes the in-memory PEM bytes without copying yet. */
    BIO_get_mem_ptr(bio, &bptr);
    cert_len = bptr->length;

    /* Copy the BIO contents into pool memory because the BIO is freed immediately after. */
    cert_pem = ngx_palloc(c->pool, cert_len);
    if (cert_pem == NULL) { BIO_free(bio); return NGX_ERROR; }
    ngx_memcpy(cert_pem, bptr->data, cert_len);
    BIO_free(bio);

    /* Generate ephemeral DH key pair using ffdhe2048 */
    {
        /* A fresh server key is generated per auth exchange and kept in ctx. */
        OSSL_PARAM dh_params[] = {
            OSSL_PARAM_utf8_string("group", "ffdhe2048", 0),
            OSSL_PARAM_END
        };

        pctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
        if (pctx == NULL) return NGX_ERROR;
        EVP_PKEY_keygen_init(pctx);
        EVP_PKEY_CTX_set_params(pctx, dh_params);
        if (EVP_PKEY_keygen(pctx, &dhkey) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            return NGX_ERROR;
        }
        EVP_PKEY_CTX_free(pctx);
    }

    /* Extract DH public key as hex BIGNUM */
    if (!EVP_PKEY_get_bn_param(dhkey, "pub", &pub_bn)) {
        EVP_PKEY_free(dhkey);
        return NGX_ERROR;
    }
    pub_hex = BN_bn2hex(pub_bn);
    BN_free(pub_bn);
    if (pub_hex == NULL) {
        EVP_PKEY_free(dhkey);
        return NGX_ERROR;
    }

    /* Write DH parameters as PEM */
    bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        OPENSSL_free(pub_hex);
        EVP_PKEY_free(dhkey);
        return NGX_ERROR;
    }
    PEM_write_bio_Parameters(bio, dhkey);
    /* Save the private half now; the matching client reply consumes it later. */
    ctx->gsi_dh_key = dhkey;
    BIO_get_mem_ptr(bio, &bptr);

    /* The client expects DH params PEM followed by the public value marker block. */
    puk_written = snprintf(puk_buf, sizeof(puk_buf),
                           "%.*s---BPUB---%s---EPUB--",
                           (int) bptr->length, bptr->data, pub_hex);
    BIO_free(bio);
    OPENSSL_free(pub_hex);

    /* Format matches what the peer later scans for with ---BPUB--- / ---EPUB--. */
    if (puk_written <= 0 || (size_t) puk_written >= sizeof(puk_buf)) {
        return NGX_ERROR;
    }
    puk_len = (size_t) puk_written;

    puk_blob = ngx_palloc(c->pool, puk_len);
    if (puk_blob == NULL) return NGX_ERROR;
    ngx_memcpy(puk_blob, puk_buf, puk_len);

    /* Sign the client's random challenge (kXRS_rtag) */
    const u_char *main_data  = NULL;
    size_t        main_dlen  = 0;
    const u_char *clnt_rtag  = NULL;
    size_t        clnt_rtlen = 0;
    u_char       *signed_rtag    = NULL;
    size_t        signed_rtag_len = 0;

    if (gsi_find_bucket(ctx->payload, ctx->cur_dlen,
                        (uint32_t) kXRS_main, &main_data, &main_dlen) == 0) {
        /* The client challenge lives inside the encrypted/inner main buffer. */
        gsi_find_bucket(main_data, main_dlen,
                        (uint32_t) kXRS_rtag, &clnt_rtag, &clnt_rtlen);
    }

    /* The signed rtag is optional; older peers may omit the challenge bucket. */
    if (clnt_rtag && clnt_rtlen > 0) {
        EVP_PKEY_CTX *sctx = EVP_PKEY_CTX_new(conf->gsi_key, NULL);
        if (sctx) {
            size_t slen = (size_t) EVP_PKEY_size(conf->gsi_key);
            signed_rtag = ngx_palloc(c->pool, slen);
            if (signed_rtag &&
                EVP_PKEY_sign_init(sctx) > 0 &&
                EVP_PKEY_CTX_set_rsa_padding(sctx, RSA_PKCS1_PADDING) > 0 &&
                EVP_PKEY_sign(sctx, signed_rtag, &slen,
                              clnt_rtag, clnt_rtlen) > 0)
            {
                /* Keep only the actual signature length OpenSSL reported. */
                signed_rtag_len = slen;
            } else {
                /* Failure here is tolerated; the rest of the exchange can continue. */
                signed_rtag = NULL;
            }
            EVP_PKEY_CTX_free(sctx);
        }
    }

    /* Build the kXRS_main inner buffer */
    /* Layout: "gsi\0" + step + optional signed challenge + terminator. */
    size_t main_len = 4 + 4    /* "gsi\0" + step */
                    + 4;        /* kXRS_none      */
    if (signed_rtag_len > 0) {
        main_len += 4 + 4 + signed_rtag_len;
    }

    u_char *main_buf = ngx_palloc(c->pool, main_len);
    if (main_buf == NULL) return NGX_ERROR;
    {
        u_char *mp = main_buf;

        /* Inner buffer is itself another tiny XrdSutBuffer payload. */
        mp[0]='g'; mp[1]='s'; mp[2]='i'; mp[3]='\0'; mp += 4;
        *(uint32_t *) mp = htonl(kXGS_cert); mp += 4;
        if (signed_rtag_len > 0) {
            *(uint32_t *) mp = htonl(kXRS_signed_rtag); mp += 4;
            *(uint32_t *) mp = htonl((uint32_t) signed_rtag_len); mp += 4;
            ngx_memcpy(mp, signed_rtag, signed_rtag_len); mp += signed_rtag_len;
        }
        *(uint32_t *) mp = htonl(kXRS_none); mp += 4;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: kXGS_cert signed rtag=%uz bytes main_len=%uz",
                   signed_rtag_len, main_len);

    const char *cipher_alg = "aes-256-cbc:aes-128-cbc:bf-cbc";
    const char *md_alg     = "sha256:sha1";
    size_t      calg_len   = strlen(cipher_alg);
    size_t      malg_len   = strlen(md_alg);

    /* Outer buffer = protocol header + a sequence of typed buckets + terminator. */
    body_len = 4 + 4
             + 4 + 4 + puk_len
             + 4 + 4 + calg_len
             + 4 + 4 + malg_len
             + 4 + 4 + cert_len
             + 4 + 4 + main_len
             + 4;

    total = XRD_RESPONSE_HDR_LEN + body_len;
    buf   = ngx_palloc(c->pool, total);
    if (buf == NULL) return NGX_ERROR;

    /* Standard XRootD framing: 8-byte response header, then the authmore body. */
    xrootd_build_resp_hdr(ctx->cur_streamid, kXR_authmore,
                           (uint32_t) body_len,
                           (ServerResponseHdr *) buf);

    p = buf + XRD_RESPONSE_HDR_LEN;

    /* Outer authmore body starts with the protocol name and step number again. */
    p[0]='g'; p[1]='s'; p[2]='i'; p[3]='\0'; p += 4;
    *(uint32_t *) p = htonl(kXGS_cert); p += 4;

    /* Bucket sequence: server DH params, cipher prefs, digest prefs, cert, inner main. */
    *(uint32_t *) p = htonl(kXRS_puk);           p += 4;
    *(uint32_t *) p = htonl((uint32_t) puk_len);  p += 4;
    ngx_memcpy(p, puk_blob, puk_len);            p += puk_len;

    *(uint32_t *) p = htonl(kXRS_cipher_alg);           p += 4;
    *(uint32_t *) p = htonl((uint32_t) calg_len);        p += 4;
    ngx_memcpy(p, cipher_alg, calg_len);                p += calg_len;

    *(uint32_t *) p = htonl(kXRS_md_alg);               p += 4;
    *(uint32_t *) p = htonl((uint32_t) malg_len);        p += 4;
    ngx_memcpy(p, md_alg, malg_len);                    p += malg_len;

    *(uint32_t *) p = htonl(kXRS_x509);          p += 4;
    *(uint32_t *) p = htonl((uint32_t) cert_len); p += 4;
    ngx_memcpy(p, cert_pem, cert_len);            p += cert_len;

    *(uint32_t *) p = htonl(kXRS_main);           p += 4;
    *(uint32_t *) p = htonl((uint32_t) main_len);  p += 4;
    ngx_memcpy(p, main_buf, main_len);            p += main_len;

    /* Final bucket terminator closes the outer XrdSutBuffer. */
    *(uint32_t *) p = htonl(kXRS_none); p += 4;

    ngx_log_debug3(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: kXGS_cert sent cert_len=%uz puk_len=%uz main_len=%uz",
                   cert_len, puk_len, main_len);

    return xrootd_queue_response(ctx, c, buf, total);
}


/* ================================================================== */
/*  Bearer-token (JWT/WLCG) authentication — "ztn" credential type    */
/* ================================================================== */

/*
 * xrootd_handle_token_auth — validate a bearer token from kXR_auth.
 *
 * The ZTN wire format is simple:
 *   payload[0..3] = "ztn\0"   (credential type, already checked by caller)
 *   payload[4..N] = raw JWT token bytes
 *
 * Single round — no back-and-forth like GSI.
 */
static ngx_int_t
xrootd_handle_token_auth(xrootd_ctx_t *ctx, ngx_connection_t *c,
                         ngx_stream_xrootd_srv_conf_t *conf)
{
    xrootd_token_claims_t claims;
    const char *token;
    size_t      token_len;
    int         rc, i;

    if (ctx->payload == NULL || ctx->cur_dlen <= 4) {
        xrootd_log_access(ctx, c, "AUTH", "-", "ztn",
                          0, kXR_NotAuthorized, "empty token payload", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_AUTH);
        return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                 "empty bearer token");
    }

    /* Token follows the 4-byte "ztn\0" prefix. */
    token     = (const char *)(ctx->payload + 4);
    token_len = ctx->cur_dlen - 4;

    /* Strip trailing NUL bytes the client may have sent. */
    while (token_len > 0 && token[token_len - 1] == '\0')
        token_len--;

    if (token_len == 0) {
        xrootd_log_access(ctx, c, "AUTH", "-", "ztn",
                          0, kXR_NotAuthorized, "empty token payload", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_AUTH);
        return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                 "empty bearer token");
    }

    rc = xrootd_token_validate(c->log, token, token_len,
                               conf->jwks_keys, conf->jwks_key_count,
                               (const char *) conf->token_issuer.data,
                               (const char *) conf->token_audience.data,
                               &claims);
    if (rc != 0) {
        xrootd_log_access(ctx, c, "AUTH", "-", "ztn",
                          0, kXR_NotAuthorized, "token validation failed", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_AUTH);
        return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                 "bearer token validation failed");
    }

    /* Populate per-connection state from validated claims. */
    ctx->token_auth = 1;
    ctx->auth_done  = 1;

    /* Use sub claim as the identity (like DN in GSI). */
    ngx_cpystrn((u_char *) ctx->dn, (u_char *) claims.sub, sizeof(ctx->dn));

    /* Map wlcg.groups to vo_list (comma-separated → same format as VOMS). */
    if (claims.groups[0]) {
        ngx_cpystrn((u_char *) ctx->vo_list,
                    (u_char *) claims.groups,
                    sizeof(ctx->vo_list));
        /* Set primary_vo to the first group. */
        const char *comma = strchr(claims.groups, ',');
        size_t pvo_len = comma ? (size_t)(comma - claims.groups)
                               : strlen(claims.groups);
        if (pvo_len >= sizeof(ctx->primary_vo))
            pvo_len = sizeof(ctx->primary_vo) - 1;
        ngx_memcpy(ctx->primary_vo, claims.groups, pvo_len);
        ctx->primary_vo[pvo_len] = '\0';
    }

    /* Store parsed scopes for per-operation authorization. */
    ctx->token_scope_count = claims.scope_count;
    for (i = 0; i < claims.scope_count && i < XROOTD_MAX_TOKEN_SCOPES; i++) {
        ctx->token_scopes[i] = claims.scopes[i];
    }

    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                  "xrootd: token auth ok sub=\"%s\" scopes=%d groups=\"%s\"",
                  claims.sub, claims.scope_count, claims.groups);

    xrootd_log_access(ctx, c, "AUTH", "-", claims.sub, 1, 0, NULL, 0);
    XROOTD_OP_OK(ctx, XROOTD_OP_AUTH);

    return xrootd_send_ok(ctx, c, NULL, 0);
}


/*
 * xrootd_handle_auth — top-level kXR_auth dispatcher.
 *
 * This function is the entry point for ALL authentication in the module.
 * It routes to one of two paths based on the 4-byte credential type
 * in the request header:
 *
 *   "ztn\0" → Bearer token (JWT/WLCG), handled by xrootd_handle_token_auth()
 *   "gsi\0" → GSI/x509, handled inline below via a two-step exchange:
 *
 *     Step 1 (kXGC_certreq = 1000):
 *       Client sends a DH public key + cipher list.
 *       Server replies with its own DH public key + x509 certificate chain.
 *
 *     Step 2 (kXGS_cert = 2001):
 *       Client sends its x509 proxy certificate chain + signed DH parameters.
 *       Server verifies the chain against the CA store, extracts the subject
 *       DN and optional VOMS attributes, and (if valid) marks auth_done=1.
 *
 * After authentication, ctx->dn holds the subject and ctx->vo_list holds
 * any VOMS VOs.  These are used by VO ACL checks in the file handlers.
 */
ngx_int_t
xrootd_handle_auth(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    ngx_stream_xrootd_srv_conf_t *conf;
    STACK_OF(X509)               *chain;
    X509                         *leaf;
    X509_STORE_CTX               *vctx;
    char                         *dn_str;
    uint32_t                      gsi_step;
    int                           ok;

    if (!ctx->logged_in) {
        /* Match the normal protocol rule: auth is only valid after login. */
        return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                 "login required before auth");
    }

    conf = ngx_stream_get_module_srv_conf(ctx->session,
                                          ngx_stream_xrootd_module);

    if (conf->auth == XROOTD_AUTH_NONE) {
        /* Non-authenticated listeners complete auth immediately. */
        ctx->auth_done = 1;
        return xrootd_send_ok(ctx, c, NULL, 0);
    }

    {
        char credtype[5];
        char safe_credtype[32];

        ngx_memcpy(credtype, ctx->cur_body + 12, 4);
        credtype[4] = '\0';
        xrootd_sanitize_log_string(credtype, safe_credtype,
                                   sizeof(safe_credtype));

        ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, 0,
                       "xrootd: kXR_auth credtype=\"%s\" payloadlen=%d",
                       safe_credtype, (int) ctx->cur_dlen);

        /* ---- Route by credential type ---- */
        if (credtype[0] == 'z' && credtype[1] == 't' && credtype[2] == 'n') {
            /* Bearer token (JWT/WLCG) authentication */
            if (conf->auth != XROOTD_AUTH_TOKEN &&
                conf->auth != XROOTD_AUTH_BOTH)
            {
                return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                         "token auth not enabled");
            }
            return xrootd_handle_token_auth(ctx, c, conf);
        }

        if (credtype[0] != 'g' || credtype[1] != 's' || credtype[2] != 'i') {
            ngx_log_error(NGX_LOG_WARN, c->log, 0,
                          "xrootd: kXR_auth unknown credtype=\"%s\"",
                          safe_credtype);
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "unsupported credential type");
        }

        /* GSI authentication — fall through to GSI handling below */
        if (conf->auth != XROOTD_AUTH_GSI &&
            conf->auth != XROOTD_AUTH_BOTH)
        {
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "GSI auth not enabled");
        }
    }

    if (conf->gsi_store == NULL) {
        /* GSI requested but not configured (shouldn't happen). */
        return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                 "GSI not configured");
    }

    if (ctx->payload == NULL || ctx->cur_dlen < 8) {
        /* Need at least "gsi\0" + 4-byte step number before parsing buckets. */
        return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                 "empty GSI credential");
    }

    ngx_memcpy(&gsi_step, ctx->payload + 4, 4);
    gsi_step = ntohl(gsi_step);

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: GSI kXR_auth step=%ud", (unsigned) gsi_step);

    /* The auth exchange is a two-step state machine: certreq -> cert. */
    if (gsi_step == (uint32_t) kXGC_certreq) {
        /* First round-trip: send server cert, DH params, and optional signed challenge. */
        return xrootd_gsi_send_cert(ctx, c);
    }

    if (gsi_step != (uint32_t) kXGC_cert) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "xrootd: unexpected GSI step %ud", (unsigned) gsi_step);
        return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                 "unexpected GSI auth step");
    }

    chain = xrootd_gsi_parse_x509(ctx, c);

    /* The ephemeral server DH key is single-use and must not survive the request. */
    if (ctx->gsi_dh_key) {
        EVP_PKEY_free(ctx->gsi_dh_key);
        ctx->gsi_dh_key = NULL;
    }

    if (chain == NULL) {
        xrootd_log_access(ctx, c, "AUTH", "-", "gsi",
                          0, kXR_NotAuthorized, "cannot parse GSI credential", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_AUTH);
        return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                 "cannot parse GSI credential");
    }

    leaf = sk_X509_value(chain, 0);

    vctx = X509_STORE_CTX_new();
    if (vctx == NULL) {
        sk_X509_pop_free(chain, X509_free);
        return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                 "internal OpenSSL error");
    }

    STACK_OF(X509) *untrusted = NULL;
    if (sk_X509_num(chain) > 1) {
        /* leaf lives separately in the API; extra certs become the untrusted chain */
        untrusted = sk_X509_dup(chain);
        sk_X509_delete(untrusted, 0);
    }

    /* Verify the leaf against our CA store plus any chain certs the client sent. */
    X509_STORE_CTX_init(vctx, conf->gsi_store, leaf, untrusted);
    X509_STORE_CTX_set_flags(vctx, X509_V_FLAG_ALLOW_PROXY_CERTS);

    ok = X509_verify_cert(vctx);

    if (untrusted) {
        /* X509_STORE_CTX borrowed these extra cert pointers; free only the stack shell. */
        sk_X509_free(untrusted);
    }

    if (ok != 1) {
        int verr = X509_STORE_CTX_get_error(vctx);
        const char *verr_str = X509_verify_cert_error_string(verr);
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "xrootd: GSI cert verification failed: %s", verr_str);
        xrootd_log_access(ctx, c, "AUTH", "-", "gsi",
                          0, kXR_NotAuthorized, verr_str, 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_AUTH);
        X509_STORE_CTX_free(vctx);
        sk_X509_pop_free(chain, X509_free);
        return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                 "certificate verification failed");
    }

    X509_STORE_CTX_free(vctx);

    dn_str = X509_NAME_oneline(X509_get_subject_name(leaf), NULL, 0);
    if (dn_str) {
        /* Cache a printable subject DN for access logs and later policy hooks. */
        ngx_cpystrn((u_char *) ctx->dn,
                    (u_char *) dn_str,
                    sizeof(ctx->dn) - 1);
        OPENSSL_free(dn_str);
    }

    /* Extract VOMS VO membership while the cert chain is still live.
     * Must happen before sk_X509_pop_free frees the chain below. */
    if (xrootd_voms_available()
        && conf->vomsdir.len > 0 && conf->voms_cert_dir.len > 0)
    {
        ngx_int_t voms_rc = xrootd_extract_voms_info(
            c->log, leaf, chain,
            &conf->vomsdir, &conf->voms_cert_dir,
            ctx->primary_vo, sizeof(ctx->primary_vo),
            ctx->vo_list,    sizeof(ctx->vo_list));
        if (voms_rc == NGX_OK) {
            char vo_log[256];
            xrootd_sanitize_log_string(ctx->vo_list, vo_log, sizeof(vo_log));
            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "xrootd: VOMS VO membership: %s", vo_log);
        }
    }

    sk_X509_pop_free(chain, X509_free);

    /* From this point on the session is fully authenticated. */
    ctx->auth_done = 1;

    {
        char dn_log[1024];

        xrootd_sanitize_log_string(ctx->dn, dn_log, sizeof(dn_log));
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "xrootd: GSI auth OK dn=\"%s\"", dn_log);
    }

    xrootd_log_access(ctx, c, "AUTH", "-", "gsi", 1, 0, NULL, 0);
    XROOTD_OP_OK(ctx, XROOTD_OP_AUTH);

    return xrootd_send_ok(ctx, c, NULL, 0);
}
