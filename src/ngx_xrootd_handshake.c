#include "ngx_xrootd_module.h"

/* ================================================================== */
/*  Handshake                                                           */
/* ================================================================== */

/*
 * xrootd_process_handshake
 *
 * Validates the 20-byte client handshake and sends the server reply.
 *
 * In XRootD v5 the client sends handshake + kXR_protocol together in a
 * single 44-byte TCP segment.  We send a proper ServerResponseHdr
 * (streamid={0,0}, status=ok, dlen=8) followed by 8 bytes of protover+msgval.
 */
ngx_int_t
xrootd_process_handshake(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    ClientInitHandShake  *hs;
    ServerResponseHdr    *hdr;
    u_char               *buf;
    size_t                total;

    static const size_t BODY_LEN = 8;

    hs = (ClientInitHandShake *) ctx->hdr_buf;

    if (ntohl(hs->fourth) != 4 || ntohl(hs->fifth) != ROOTD_PQ) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "xrootd: invalid handshake magic "
                      "(fourth=%u fifth=%u)",
                      ntohl(hs->fourth), ntohl(hs->fifth));
        return NGX_ERROR;
    }

    total = XRD_RESPONSE_HDR_LEN + BODY_LEN;
    buf   = ngx_palloc(c->pool, total);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    hdr             = (ServerResponseHdr *) buf;
    hdr->streamid[0] = 0;
    hdr->streamid[1] = 0;
    hdr->status      = htons(kXR_ok);
    hdr->dlen        = htonl((kXR_unt32) BODY_LEN);

    u_char *body = buf + XRD_RESPONSE_HDR_LEN;
    *(kXR_unt32 *)(body + 0) = htonl(kXR_PROTOCOLVERSION);
    *(kXR_unt32 *)(body + 4) = htonl(kXR_DataServer);

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: handshake ok, sending standard-format response");

    return xrootd_queue_response(ctx, c, buf, total);
}

/* ================================================================== */
/*  Request dispatcher                                                  */
/* ================================================================== */

ngx_int_t
xrootd_dispatch(xrootd_ctx_t *ctx, ngx_connection_t *c,
                ngx_stream_xrootd_srv_conf_t *conf)
{
    ctx->req_start = ngx_current_msec;

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: dispatch reqid=%d", (int) ctx->cur_reqid);

    switch (ctx->cur_reqid) {

    case kXR_protocol:
        return xrootd_handle_protocol(ctx, c, conf);

    case kXR_login:
        return xrootd_handle_login(ctx, c, conf);

    case kXR_auth:
        return xrootd_handle_auth(ctx, c);

    case kXR_ping:
        return xrootd_handle_ping(ctx, c);

    case kXR_endsess:
        return xrootd_handle_endsess(ctx, c);

    case kXR_stat:
        if (!ctx->logged_in || !ctx->auth_done) {
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "authentication required");
        }
        return xrootd_handle_stat(ctx, c, conf);

    case kXR_open:
        if (!ctx->logged_in || !ctx->auth_done) {
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "authentication required");
        }
        return xrootd_handle_open(ctx, c, conf);

    case kXR_read:
        if (!ctx->logged_in || !ctx->auth_done) {
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "authentication required");
        }
        return xrootd_handle_read(ctx, c);

    case kXR_close:
        if (!ctx->logged_in || !ctx->auth_done) {
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "authentication required");
        }
        return xrootd_handle_close(ctx, c);

    case kXR_dirlist:
        if (!ctx->logged_in || !ctx->auth_done) {
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "authentication required");
        }
        return xrootd_handle_dirlist(ctx, c, conf);

    case kXR_write:
        if (!ctx->logged_in || !ctx->auth_done) {
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "authentication required");
        }
        if (!conf->allow_write) {
            return xrootd_send_error(ctx, c, kXR_fsReadOnly,
                                     "this is a read-only server");
        }
        return xrootd_handle_write(ctx, c);

    case kXR_pgwrite:
        if (!ctx->logged_in || !ctx->auth_done) {
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "authentication required");
        }
        if (!conf->allow_write) {
            return xrootd_send_error(ctx, c, kXR_fsReadOnly,
                                     "this is a read-only server");
        }
        return xrootd_handle_pgwrite(ctx, c);

    case kXR_sync:
        if (!ctx->logged_in || !ctx->auth_done) {
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "authentication required");
        }
        if (!conf->allow_write) {
            return xrootd_send_error(ctx, c, kXR_fsReadOnly,
                                     "this is a read-only server");
        }
        return xrootd_handle_sync(ctx, c);

    case kXR_truncate:
        if (!ctx->logged_in || !ctx->auth_done) {
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "authentication required");
        }
        if (!conf->allow_write) {
            return xrootd_send_error(ctx, c, kXR_fsReadOnly,
                                     "this is a read-only server");
        }
        return xrootd_handle_truncate(ctx, c, conf);

    case kXR_mkdir:
        if (!ctx->logged_in || !ctx->auth_done) {
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "authentication required");
        }
        if (!conf->allow_write) {
            return xrootd_send_error(ctx, c, kXR_fsReadOnly,
                                     "this is a read-only server");
        }
        return xrootd_handle_mkdir(ctx, c, conf);

    case kXR_rm:
        if (!ctx->logged_in || !ctx->auth_done) {
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "authentication required");
        }
        if (!conf->allow_write) {
            return xrootd_send_error(ctx, c, kXR_fsReadOnly,
                                     "this is a read-only server");
        }
        return xrootd_handle_rm(ctx, c, conf);

    case kXR_readv:
        if (!ctx->logged_in || !ctx->auth_done) {
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "authentication required");
        }
        return xrootd_handle_readv(ctx, c);

    case kXR_writev:
        if (!conf->allow_write) {
            return xrootd_send_error(ctx, c, kXR_fsReadOnly,
                                     "this is a read-only server");
        }
        return xrootd_send_error(ctx, c, kXR_Unsupported,
                                 "operation not implemented");

    case kXR_rmdir:
        if (!conf->allow_write) {
            return xrootd_send_error(ctx, c, kXR_fsReadOnly,
                                     "this is a read-only server");
        }
        return xrootd_handle_rmdir(ctx, c, conf);

    case kXR_mv:
        if (!conf->allow_write) {
            return xrootd_send_error(ctx, c, kXR_fsReadOnly,
                                     "this is a read-only server");
        }
        return xrootd_handle_mv(ctx, c, conf);

    case kXR_chmod:
        if (!conf->allow_write) {
            return xrootd_send_error(ctx, c, kXR_fsReadOnly,
                                     "this is a read-only server");
        }
        return xrootd_handle_chmod(ctx, c, conf);

    case kXR_query:
        if (!ctx->logged_in || !ctx->auth_done) {
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "authentication required");
        }
        return xrootd_handle_query(ctx, c, conf);

    default:
        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                       "xrootd: unsupported request %d",
                       (int) ctx->cur_reqid);
        return xrootd_send_error(ctx, c, kXR_Unsupported,
                                 "request not supported");
    }
}
