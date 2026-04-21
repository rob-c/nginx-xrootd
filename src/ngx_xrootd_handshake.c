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
     * kXR_sigver verification.
     *
     * A kXR_sigver arrived earlier and set sigver_pending; now that we have
     * the next request's full 24-byte header (and optional payload), verify
     * HMAC-SHA256(signing_key, seqno_BE || hdr_buf [|| payload]).
     *
     * Another kXR_sigver clears and replaces the pending state (no error).
     * Any mismatch in expectrid or HMAC is a hard auth failure.
     */
    if (ctx->sigver_pending && ctx->cur_reqid != kXR_sigver) {
        ctx->sigver_pending = 0;

        if (ctx->signing_active) {
            if (ctx->sigver_expectrid != ctx->cur_reqid) {
                ngx_log_error(NGX_LOG_WARN, c->log, 0,
                              "xrootd: sigver expectrid=%d but got reqid=%d",
                              (int) ctx->sigver_expectrid, (int) ctx->cur_reqid);
                return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                         "signed request opcode mismatch");
            }

            /* HMAC input: seqno(8B BE) || request_header(24B) [|| payload] */
            {
                u_char        seqno_be[8];
                u_char        computed[32];
                uint64_t      seq  = ctx->sigver_seqno;
                EVP_MAC      *mac  = EVP_MAC_fetch(NULL, "HMAC", NULL);
                EVP_MAC_CTX  *mctx = mac ? EVP_MAC_CTX_new(mac) : NULL;
                OSSL_PARAM    params[2];
                size_t        clen = sizeof(computed);
                int           ok   = 0;

                seqno_be[0] = (u_char)(seq >> 56);
                seqno_be[1] = (u_char)(seq >> 48);
                seqno_be[2] = (u_char)(seq >> 40);
                seqno_be[3] = (u_char)(seq >> 32);
                seqno_be[4] = (u_char)(seq >> 24);
                seqno_be[5] = (u_char)(seq >> 16);
                seqno_be[6] = (u_char)(seq >>  8);
                seqno_be[7] = (u_char)(seq      );

                params[0] = OSSL_PARAM_construct_utf8_string("digest",
                                                              "SHA256", 0);
                params[1] = OSSL_PARAM_construct_end();

                if (mctx
                    && EVP_MAC_init(mctx, ctx->signing_key, 32, params) == 1
                    && EVP_MAC_update(mctx, seqno_be, 8) == 1
                    && EVP_MAC_update(mctx, ctx->hdr_buf,
                                      XRD_REQUEST_HDR_LEN) == 1)
                {
                    if (ctx->sigver_nodata
                        || ctx->payload == NULL
                        || ctx->cur_dlen == 0
                        || EVP_MAC_update(mctx, ctx->payload,
                                          ctx->cur_dlen) == 1)
                    {
                        ok = (EVP_MAC_final(mctx, computed, &clen,
                                            sizeof(computed)) == 1);
                    }
                }

                EVP_MAC_CTX_free(mctx);
                EVP_MAC_free(mac);

                if (ok && clen >= 32
                    && ngx_memcmp(computed, ctx->sigver_hmac, 32) != 0)
                {
                    ngx_log_error(NGX_LOG_WARN, c->log, 0,
                                  "xrootd: sigver HMAC mismatch for reqid=%d",
                                  (int) ctx->cur_reqid);
                    return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                             "signature verification failed");
                }

                if (ok) {
                    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                                   "xrootd: sigver verified reqid=%d",
                                   (int) ctx->cur_reqid);
                }
            }
        }
    } else if (ctx->cur_reqid == kXR_sigver) {
        /* A new sigver wipes any stale pending state before we handle it. */
        ctx->sigver_pending = 0;
    }

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
        if (!ctx->logged_in || !ctx->auth_done) {
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "authentication required");
        }
        if (!conf->allow_write) {
            return xrootd_send_error(ctx, c, kXR_fsReadOnly,
                                     "this is a read-only server");
        }
        return xrootd_handle_writev(ctx, c);

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

    case kXR_prepare:
        /* prepare is a staging/cache hint; the local implementation validates paths. */
        if (!ctx->logged_in || !ctx->auth_done) {
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "authentication required");
        }
        return xrootd_handle_prepare(ctx, c, conf);

    case kXR_pgread:
        if (!ctx->logged_in || !ctx->auth_done) {
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "authentication required");
        }
        return xrootd_handle_pgread(ctx, c);

    case kXR_locate:
        if (!ctx->logged_in || !ctx->auth_done) {
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "authentication required");
        }
        return xrootd_handle_locate(ctx, c, conf);

    case kXR_statx:
        if (!ctx->logged_in || !ctx->auth_done) {
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "authentication required");
        }
        return xrootd_handle_statx(ctx, c, conf);

    case kXR_sigver:
        /* sigver requires login; may arrive before auth_done in signing flows. */
        if (!ctx->logged_in) {
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "login required");
        }
        return xrootd_handle_sigver(ctx, c);

    case kXR_fattr:
        if (!ctx->logged_in || !ctx->auth_done) {
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "authentication required");
        }
        return xrootd_handle_fattr(ctx, c, conf);

    default:
        /* Unknown opcodes stay visible in debug logs before returning kXR_Unsupported. */
        ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                       "xrootd: unsupported request %d",
                       (int) ctx->cur_reqid);
        return xrootd_send_error(ctx, c, kXR_Unsupported,
                                 "request not supported");
    }
}
