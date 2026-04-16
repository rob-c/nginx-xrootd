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

    /* Fixed v5-compatible body: protocol version + server role. */
    static const size_t BODY_LEN = 8;

    hs = (ClientInitHandShake *) ctx->hdr_buf;

    /*
     * The client hello has mostly fixed magic values; we only validate the
     * fields this implementation actually relies on before switching into the
     * normal request/response framing.
     */
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

    /* The initial reply uses streamid={0,0} because no request header exists yet. */
    hdr             = (ServerResponseHdr *) buf;
    hdr->streamid[0] = 0;
    hdr->streamid[1] = 0;
    hdr->status      = htons(kXR_ok);
    hdr->dlen        = htonl((kXR_unt32) BODY_LEN);

    /* Body layout is exactly two 32-bit words: protocol version then server type. */
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
    /* Every dispatched request resets the per-request timing origin for logging. */
    ctx->req_start = ngx_current_msec;

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: dispatch reqid=%d", (int) ctx->cur_reqid);

    /*
     * Routing policy is intentionally centralized here:
     *   1. decide which opcodes are legal before/after login+auth
     *   2. enforce read-only vs mutating behavior from config
     *   3. hand off to the request-specific implementation
     *
     * The repeated auth/write checks are deliberate. Keeping them inline in the
     * switch makes the protocol policy visible next to each opcode instead of
     * hiding it behind helper layers.
     */
    switch (ctx->cur_reqid) {

    /* ----- Session/bootstrap opcodes allowed before normal file access ----- */

    case kXR_protocol:
        /* Pre-login capability negotiation is always allowed. */
        return xrootd_handle_protocol(ctx, c, conf);

    case kXR_login:
        /* Login is the first stateful request that can transition the session forward. */
        return xrootd_handle_login(ctx, c, conf);

    case kXR_auth:
        /* Auth may be a no-op on non-GSI listeners but still routes through one path. */
        return xrootd_handle_auth(ctx, c);

    case kXR_ping:
        /* Liveness probes are allowed even before a full login/auth exchange. */
        return xrootd_handle_ping(ctx, c);

    case kXR_endsess:
        /* Clients may end a session cleanly even if no file operation was performed. */
        return xrootd_handle_endsess(ctx, c);

    /* ----- Authenticated read-side and metadata operations ----- */

    case kXR_stat:
        /* Read-side metadata ops require a fully established authenticated session. */
        if (!ctx->logged_in || !ctx->auth_done) {
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "authentication required");
        }
        return xrootd_handle_stat(ctx, c, conf);

    case kXR_open:
        /* open covers both read and write intent; write permission is enforced later. */
        if (!ctx->logged_in || !ctx->auth_done) {
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "authentication required");
        }
        return xrootd_handle_open(ctx, c, conf);

    case kXR_read:
        /* Plain reads only need session auth, not xrootd_allow_write. */
        if (!ctx->logged_in || !ctx->auth_done) {
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "authentication required");
        }
        return xrootd_handle_read(ctx, c);

    case kXR_close:
        /* close is treated like read-side cleanup, so it remains available on read-only exports. */
        if (!ctx->logged_in || !ctx->auth_done) {
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "authentication required");
        }
        return xrootd_handle_close(ctx, c);

    case kXR_dirlist:
        /* Directory listing is read-only but still requires a logged-in authenticated session. */
        if (!ctx->logged_in || !ctx->auth_done) {
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "authentication required");
        }
        return xrootd_handle_dirlist(ctx, c, conf);

    /* ----- Authenticated mutating operations, additionally gated by config ----- */

    case kXR_write:
        /* Mutating ops are gated both by session auth and by xrootd_allow_write. */
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
        /* pgwrite follows the same policy gate as plain write before CRC handling later. */
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
        /* sync affects on-disk durability, so treat it as a write-side operation. */
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
        /* Path- or handle-based length changes are always considered mutating. */
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
        /* Namespace creation shares the same gate as file writes. */
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
        /* File removal is mutating even though it carries only a path payload. */
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
        /* readv is still read-only, so it skips the xrootd_allow_write check. */
        if (!ctx->logged_in || !ctx->auth_done) {
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "authentication required");
        }
        return xrootd_handle_readv(ctx, c);

    /* ----- Unsupported or less common mutating opcodes still obey the same gate ----- */

    case kXR_writev:
        /* Keep unsupported mutating ops behind the same auth gate as writes. */
        if (!ctx->logged_in || !ctx->auth_done) {
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "authentication required");
        }
        if (!conf->allow_write) {
            return xrootd_send_error(ctx, c, kXR_fsReadOnly,
                                     "this is a read-only server");
        }
        return xrootd_send_error(ctx, c, kXR_Unsupported,
                                 "operation not implemented");

    case kXR_rmdir:
        /* These path-mutating ops used to skip auth; treat them like rm/mkdir. */
        if (!ctx->logged_in || !ctx->auth_done) {
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "authentication required");
        }
        if (!conf->allow_write) {
            return xrootd_send_error(ctx, c, kXR_fsReadOnly,
                                     "this is a read-only server");
        }
        return xrootd_handle_rmdir(ctx, c, conf);

    case kXR_mv:
        /* Rename/move updates namespace state, so it stays on the write side of the split. */
        if (!ctx->logged_in || !ctx->auth_done) {
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "authentication required");
        }
        if (!conf->allow_write) {
            return xrootd_send_error(ctx, c, kXR_fsReadOnly,
                                     "this is a read-only server");
        }
        return xrootd_handle_mv(ctx, c, conf);

    case kXR_chmod:
        /* chmod mutates metadata only, but still belongs behind the write gate. */
        if (!ctx->logged_in || !ctx->auth_done) {
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "authentication required");
        }
        if (!conf->allow_write) {
            return xrootd_send_error(ctx, c, kXR_fsReadOnly,
                                     "this is a read-only server");
        }
        return xrootd_handle_chmod(ctx, c, conf);

    case kXR_query:
        /* query multiplexes several read-side sub-operations, so it only needs auth. */
        if (!ctx->logged_in || !ctx->auth_done) {
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "authentication required");
        }
        return xrootd_handle_query(ctx, c, conf);

    default:
        /* Unknown opcodes stay visible in debug logs before returning kXR_Unsupported. */
        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                       "xrootd: unsupported request %d",
                       (int) ctx->cur_reqid);
        return xrootd_send_error(ctx, c, kXR_Unsupported,
                                 "request not supported");
    }
}
