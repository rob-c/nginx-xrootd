#include "ngx_xrootd_module.h"

/* ================================================================== */
/*  Session handlers                                                    */
/* ================================================================== */

/*
 * Session-level protocol operations:
 *   - kXR_protocol — negotiate version and auth capabilities
 *   - kXR_login    — establish a session (server assigns a session id)
 *   - kXR_ping     — connection liveness check
 *   - kXR_endsess  — tear down a session (close open handles, reset state)
 *
 * These run before any file I/O and establish the session identity.
 * kXR_login must precede kXR_auth; kXR_auth (in gsi.c) must complete
 * before file handlers will accept requests.
 */

static void
xrootd_count_login_ok(xrootd_ctx_t *ctx)
{
    if (ctx->metrics) {
        ngx_atomic_fetch_add(&ctx->metrics->op_ok[XROOTD_OP_LOGIN], 1);
    }
}

/*
 * kXR_protocol — negotiate protocol capabilities.
 */
ngx_int_t
xrootd_handle_protocol(xrootd_ctx_t *ctx, ngx_connection_t *c,
                       ngx_stream_xrootd_srv_conf_t *conf)
{
    ServerProtocolBody  body;
    u_char             *buf;
    size_t              bodylen, total;
    u_char              client_flags;
    int                 want_gsi;

    /* kXR_protocol packs client capability flags into the fifth byte of body[]. */
    client_flags = ctx->cur_body[4];
    want_gsi     = (conf->auth == XROOTD_AUTH_GSI || conf->auth == XROOTD_AUTH_BOTH);

    int want_token = (conf->auth == XROOTD_AUTH_TOKEN
                      || conf->auth == XROOTD_AUTH_BOTH);

    /* kXR_wantTLS: client requires TLS; kXR_ableTLS: client is TLS-capable. */
    int client_wants_tls = (client_flags & kXR_wantTLS) ? 1 : 0;
    int offer_tls = (conf->tls && conf->tls_ctx != NULL
                     && (client_flags & (kXR_ableTLS | kXR_wantTLS)));

    /* Reject if the client demands TLS but this listener has none configured. */
    if (client_wants_tls && (!conf->tls || conf->tls_ctx == NULL)) {
        return xrootd_send_error(ctx, c, kXR_TLSRequired,
                                 "TLS required by client but not configured on this server");
    }

    /*
     * Base kXR_protocol reply is the fixed 8-byte ServerProtocolBody.
     * If the client advertised security negotiation support, append the small
     * SecurityInfo trailer describing which auth protocols we offer.
     */
    bodylen = sizeof(body);
    if (client_flags & kXR_secreqs) {
        int sec_count = (want_gsi ? 1 : 0) + (want_token ? 1 : 0);
        bodylen += 4;                            /* SecurityInfo header */
        bodylen += (size_t) sec_count * 8;       /* 8 bytes per SecurityProtocol entry */
    }

    total = XRD_RESPONSE_HDR_LEN + bodylen;
    buf   = ngx_palloc(c->pool, total);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    xrootd_build_resp_hdr(ctx->cur_streamid, kXR_ok,
                           (uint32_t) bodylen,
                           (ServerResponseHdr *) buf);

    body.pval  = htonl(kXR_PROTOCOLVERSION);
    body.flags = htonl(kXR_isServer
                       | (conf->manager_map ? kXR_isManager : 0)
                       | (offer_tls ? (kXR_haveTLS | kXR_gotoTLS | kXR_tlsLogin) : 0));

    /* Fixed 8-byte prefix every protocol reply starts with after the response header. */
    ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN, &body, sizeof(body));

    if (client_flags & kXR_secreqs) {
        /*
         * SecurityInfo header:
         *   byte 1 advertises whether security is required,
         *   byte 2 is the number of following protocol entries.
         * bytes 0 and 3 are left zero because this implementation does not use
         * any of the optional legacy fields encoded there.
         */
        u_char *si = buf + XRD_RESPONSE_HDR_LEN + sizeof(body);
        int sec_count = (want_gsi ? 1 : 0) + (want_token ? 1 : 0);
        si[0] = 0;
        si[1] = sec_count > 0 ? 0x01 : 0x00;
        si[2] = (u_char) sec_count;
        si[3] = 0;
        {
            u_char *pe = si + 4;
            if (want_token) {
                pe[0] = 'z'; pe[1] = 't'; pe[2] = 'n'; pe[3] = ' ';
                pe[4] = 0;   pe[5] = 0;   pe[6] = 0;   pe[7] = 0;
                pe += 8;
            }
            if (want_gsi) {
                pe[0] = 'g'; pe[1] = 's'; pe[2] = 'i'; pe[3] = ' ';
                pe[4] = 0;   pe[5] = 0;   pe[6] = 0;   pe[7] = 0;
            }
        }
    }

    ngx_log_debug4(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: kXR_protocol ok (client_flags=0x%02x "
                   "bodylen=%uz auth=%s tls=%d)",
                   (int) client_flags, bodylen,
                   want_gsi && want_token ? "both" :
                   want_gsi ? "gsi" :
                   want_token ? "token" : "none",
                   offer_tls);

    if (offer_tls) {
        ctx->tls_pending = 1;
    }

    return xrootd_queue_response(ctx, c, buf, total);
}

/*
 * kXR_login — accept the username.
 */
ngx_int_t
xrootd_handle_login(xrootd_ctx_t *ctx, ngx_connection_t *c,
                    ngx_stream_xrootd_srv_conf_t *conf)
{
    ClientLoginRequest *req;
    u_char             *buf;
    size_t              total;
    char                user[9];
    char                user_log[64];

    req = (ClientLoginRequest *) ctx->hdr_buf;

    /* Username is an 8-byte fixed field on the wire, so copy and terminate it locally. */
    ngx_memcpy(user, req->username, 8);
    user[8] = '\0';
    xrootd_sanitize_log_string(user, user_log, sizeof(user_log));

    ngx_log_debug3(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: login user=\"%s\" pid=%d auth=%s",
                   user_log, (int) ntohl(req->pid),
                   (conf->auth == XROOTD_AUTH_GSI) ? "gsi" :
                   (conf->auth == XROOTD_AUTH_TOKEN) ? "token" :
                   (conf->auth == XROOTD_AUTH_BOTH) ? "both" : "none");

    /* Login marks the session as known; auth_done is deferred for GSI mode. */
    ctx->logged_in = 1;

    if (conf->auth == XROOTD_AUTH_NONE) {
        /* Anonymous mode completes login in one round-trip with only the sessid. */
        ctx->auth_done = 1;

        total = XRD_RESPONSE_HDR_LEN + XROOTD_SESSION_ID_LEN;
        buf   = ngx_palloc(c->pool, total);
        if (buf == NULL) {
            return NGX_ERROR;
        }

        xrootd_build_resp_hdr(ctx->cur_streamid, kXR_ok,
                               XROOTD_SESSION_ID_LEN,
                               (ServerResponseHdr *) buf);
        ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN, ctx->sessid,
                   XROOTD_SESSION_ID_LEN);

        /* Session timing starts at successful login so later disconnect stats have an origin. */
        ctx->session_start = ngx_current_msec;
        xrootd_log_access(ctx, c, "LOGIN", "-", user, 1, 0, NULL, 0);
        xrootd_count_login_ok(ctx);

        return xrootd_queue_response(ctx, c, buf, total);
    }

    /*
     * Authenticated modes send a text parameter block after the 16-byte
     * session id.  The client parses "&P=..." entries to decide which
     * security plugin to load.
     */
    {
        char   parms[256];
        size_t parms_len;

        /* Re-fetch the live merged srv_conf in case login inherited settings. */
        conf = ngx_stream_get_module_srv_conf(ctx->session,
                                              ngx_stream_xrootd_module);

        if (conf->auth == XROOTD_AUTH_TOKEN) {
            /* Token-only: advertise ztn, no CA hash needed. */
            parms_len = (size_t) snprintf(parms, sizeof(parms),
                            "&P=ztn,v:10000") + 1;
        } else if (conf->auth == XROOTD_AUTH_BOTH) {
            /* Both: token first (preferred), then GSI. */
            parms_len = (size_t) snprintf(parms, sizeof(parms),
                            "&P=ztn,v:10000&P=gsi,v:10000,c:ssl,ca:%08x",
                            (unsigned) conf->gsi_ca_hash) + 1;
        } else {
            /* GSI-only */
            parms_len = (size_t) snprintf(parms, sizeof(parms),
                            "&P=gsi,v:10000,c:ssl,ca:%08x",
                            (unsigned) conf->gsi_ca_hash) + 1;
        }

        /* Include the trailing NUL because clients treat the parameter block as C-string data. */

        total = XRD_RESPONSE_HDR_LEN + XROOTD_SESSION_ID_LEN + parms_len;
        buf   = ngx_palloc(c->pool, total);
        if (buf == NULL) {
            return NGX_ERROR;
        }

        xrootd_build_resp_hdr(ctx->cur_streamid, kXR_ok,
                               (uint32_t)(XROOTD_SESSION_ID_LEN + parms_len),
                               (ServerResponseHdr *) buf);

        ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN, ctx->sessid,
                   XROOTD_SESSION_ID_LEN);
        ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN + XROOTD_SESSION_ID_LEN,
                   parms, parms_len);

        ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, 0,
                       "xrootd: login→kXGS_init parms=\"%s\" ca_hash=%08xd",
                       parms, (unsigned) conf->gsi_ca_hash);

        /* Successful login still marks the start of the session even though auth continues. */
        ctx->session_start = ngx_current_msec;
        xrootd_log_access(ctx, c, "LOGIN", "-", user, 1, 0, NULL, 0);
        xrootd_count_login_ok(ctx);

        return xrootd_queue_response(ctx, c, buf, total);
    }
}

/* kXR_ping — liveness check */
ngx_int_t
xrootd_handle_ping(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    /* No state transition here; just account for the request and reply ok. */
    xrootd_log_access(ctx, c, "PING", "-", "-", 1, 0, NULL, 0);
    XROOTD_OP_OK(ctx, XROOTD_OP_PING);
    return xrootd_send_ok(ctx, c, NULL, 0);
}

/* kXR_endsess — client wants to end the session gracefully */
ngx_int_t
xrootd_handle_endsess(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: kXR_endsess received");

    /*
     * Mirror disconnect cleanup immediately so metrics and open-handle state
     * are settled before the final response is queued.
     * This keeps explicit end-of-session requests aligned with the same cleanup
     * bookkeeping used for timeouts and transport-level disconnects.
     */
    xrootd_on_disconnect(ctx, c);
    xrootd_close_all_files(ctx);

    /*
     * SECURITY: clear session-level auth flags so the dispatcher rejects any
     * further requests that the client attempts on this TCP connection.
     * Without this, a client could re-open files and read/write them after
     * kXR_endsess, bypassing the session-end semantics (and, in GSI deployments,
     * bypassing proxy-certificate expiry that triggered the endsess).
     */
    ctx->logged_in = 0;
    ctx->auth_done = 0;

    return xrootd_send_ok(ctx, c, NULL, 0);
}

/*
 * xrootd_handle_sigver — XRootD request signing (kXR_sigver).
 *
 * Protocol flow:
 *   1. Client sends kXR_sigver with HMAC-SHA256(signing_key, seqno || next_hdr
 *      [|| next_payload]) as the body, and expectrid = opcode of the next request.
 *   2. We save the HMAC and seqno in pending state on ctx.
 *   3. xrootd_dispatch() verifies the HMAC before routing the following request.
 *
 * For GSI sessions signing_active is 1 and signing_key = SHA-256(DH secret).
 * For token/anonymous sessions we accept sigver without verification; legitimate
 * clients should not send it unsolicited, but some do (e.g. when connecting to an
 * unknown server type).
 *
 * Only HMAC-SHA256 without RSA (kXR_SHA256, kXR_rsaKey unset) is verified.
 * RSA-signed requests are accepted without checking the asymmetric signature.
 */
ngx_int_t
xrootd_handle_sigver(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    ClientSigverRequest *req = (ClientSigverRequest *) ctx->hdr_buf;
    uint16_t expectrid;
    uint64_t seqno;

    ngx_memcpy(&expectrid, &req->expectrid, 2);
    expectrid = ntohs(expectrid);

    ngx_memcpy(&seqno, &req->seqno, 8);
    seqno = be64toh(seqno);

    if (ctx->signing_active) {
        /* Reject replays — seqno must strictly increase across the session. */
        if (seqno <= ctx->last_seqno) {
            ngx_log_error(NGX_LOG_WARN, c->log, 0,
                          "xrootd: sigver replay (seqno=%llu <= last=%llu)",
                          (unsigned long long) seqno,
                          (unsigned long long) ctx->last_seqno);
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "sigver replay detected");
        }
        ctx->last_seqno = seqno;

        if ((req->crypto & kXR_HashMask_sig) == kXR_SHA256_sig
            && !(req->crypto & kXR_rsaKey_sig))
        {
            /* Need exactly 32 bytes of HMAC in the body. */
            if (ctx->cur_dlen < 32 || ctx->payload == NULL) {
                return xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                         "sigver body too short");
            }

            ctx->sigver_pending   = 1;
            ctx->sigver_expectrid = expectrid;
            ctx->sigver_seqno     = seqno;
            ctx->sigver_nodata    = (req->flags & kXR_nodata_sig) ? 1 : 0;
            ngx_memcpy(ctx->sigver_hmac, ctx->payload, 32);

            ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, 0,
                           "xrootd: sigver pending expectrid=%d seqno=%llu",
                           (int) expectrid, (unsigned long long) seqno);
        } else {
            ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                           "xrootd: sigver crypto=0x%02x not verified (RSA path)",
                           (unsigned) req->crypto);
        }
    } else {
        ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                       "xrootd: sigver accepted without verification (no GSI key)");
    }

    xrootd_log_access(ctx, c, "SIGVER", "-", "-", 1, 0, NULL, 0);
    return xrootd_send_ok(ctx, c, NULL, 0);
}
