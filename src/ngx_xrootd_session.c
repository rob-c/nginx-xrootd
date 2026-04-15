#include "ngx_xrootd_module.h"

/* ================================================================== */
/*  Session handlers                                                    */
/* ================================================================== */

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

    client_flags = ctx->cur_body[4];
    want_gsi     = (conf->auth == XROOTD_AUTH_GSI);

    bodylen = sizeof(body);
    if (client_flags & 0x01) {                  /* kXR_secreqs */
        bodylen += 4;                            /* SecurityInfo header */
        if (want_gsi) {
            bodylen += 8;                        /* one SecurityProtocol entry */
        }
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
    body.flags = htonl(kXR_isServer);
    ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN, &body, sizeof(body));

    if (client_flags & 0x01) {
        u_char *si = buf + XRD_RESPONSE_HDR_LEN + sizeof(body);
        si[0] = 0;
        si[1] = want_gsi ? 0x01 : 0x00;
        si[2] = want_gsi ? 1    : 0;
        si[3] = 0;
        if (want_gsi) {
            u_char *pe = si + 4;
            pe[0] = 'g'; pe[1] = 's'; pe[2] = 'i'; pe[3] = ' ';
            pe[4] = 0;
            pe[5] = 0; pe[6] = 0; pe[7] = 0;
        }
    }

    ngx_log_debug3(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: kXR_protocol ok (client_flags=0x%02x "
                   "bodylen=%uz auth=%s)",
                   (int) client_flags, bodylen,
                   want_gsi ? "gsi" : "none");

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

    req = (ClientLoginRequest *) ctx->hdr_buf;
    ngx_memcpy(user, req->username, 8);
    user[8] = '\0';

    ngx_log_debug3(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: login user=\"%s\" pid=%d auth=%s",
                   user, (int) ntohl(req->pid),
                   (conf->auth == XROOTD_AUTH_GSI) ? "gsi" : "none");

    ctx->logged_in = 1;

    if (conf->auth == XROOTD_AUTH_NONE) {
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

        ctx->session_start = ngx_current_msec;
        xrootd_log_access(ctx, c, "LOGIN", "-", user, 1, 0, NULL, 0);
        XROOTD_OP_OK(ctx, XROOTD_OP_LOGIN);

        return xrootd_queue_response(ctx, c, buf, total);
    }

    /*
     * GSI auth: respond kXR_ok with sessid + "&P=" text-format challenge.
     */
    {
        char   parms[128];
        size_t parms_len;

        conf = ngx_stream_get_module_srv_conf(ctx->session,
                                              ngx_stream_xrootd_module);

        parms_len = (size_t) snprintf(parms, sizeof(parms),
                        "&P=gsi,v:10000,c:ssl,ca:%08x",
                        (unsigned) conf->gsi_ca_hash) + 1;

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

        ctx->session_start = ngx_current_msec;
        xrootd_log_access(ctx, c, "LOGIN", "-", user, 1, 0, NULL, 0);
        XROOTD_OP_OK(ctx, XROOTD_OP_LOGIN);

        return xrootd_queue_response(ctx, c, buf, total);
    }
}

/* kXR_ping — liveness check */
ngx_int_t
xrootd_handle_ping(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
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
    xrootd_on_disconnect(ctx, c);
    xrootd_close_all_files(ctx);
    return xrootd_send_ok(ctx, c, NULL, 0);
}
