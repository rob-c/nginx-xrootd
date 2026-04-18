#include "ngx_xrootd_module.h"

/* ================================================================== */
/*  kXR_dirlist handler                                                 */
/*                                                                      */
/*  This file handles the kXR_dirlist opcode, which lists the contents  */
/*  of a directory and optionally includes per-entry stat metadata.     */
/*                                                                      */
/*  Background for non-XRootD experts:                                  */
/*  The XRootD protocol's directory listing is a streaming operation.   */
/*  The server sends entries in newline-delimited text chunks, each     */
/*  preceded by a standard 8-byte response header.  Intermediate       */
/*  chunks use status kXR_oksofar ("more data follows") while the      */
/*  final chunk uses kXR_ok to signal completion.                       */
/*                                                                      */
/*  dStat mode (kXR_dstat flag, 0x02 in the options byte):             */
/*  When the client requests stat info alongside names, the response   */
/*  alternates between filename lines and stat lines.  The response    */
/*  body starts with a magic 10-byte sentinel ".\n0 0 0 0\n" that     */
/*  the client probes for to detect stat-pairing mode.  Without this   */
/*  sentinel, all lines are treated as plain filenames.  See inline    */
/*  comments for the exact wire format the client expects.             */
/*                                                                      */
/*  NUL-terminator convention: the response body ends with \0 (not     */
/*  \n) because the client interprets the body as a C string.  An      */
/*  extra trailing \n would create a spurious empty token that breaks   */
/*  the client's size%2 consistency check for dStat mode.              */
/* ================================================================== */


/*
 * Check whether a directory entry name contains control characters
 * that would break the newline-delimited wire format.
 * Returns 1 (unsafe) if any byte < 0x20 or 0x7F is found.
 */
static ngx_flag_t
xrootd_dirlist_name_is_unsafe(const char *name)
{
    const u_char *p;

    for (p = (const u_char *) name; *p != '\0'; p++) {
        if (*p < 0x20 || *p == 0x7f) {
            return 1;
        }
    }

    return 0;
}


/*
 * kXR_dirlist — list directory contents.
 *
 * Responses for large directories are split into chunks using
 * kXR_oksofar for intermediate chunks and kXR_ok for the last chunk.
 * Each chunk is built in a pool-allocated buffer.
 *
 * If the client set kXR_dstat (options byte 0x02) we append a second
 * line per entry with "id size flags mtime" (same order as kXR_stat /
 * kXR_open retstat — size BEFORE flags).
 */
ngx_int_t
xrootd_handle_dirlist(xrootd_ctx_t *ctx, ngx_connection_t *c,
                      ngx_stream_xrootd_srv_conf_t *conf)
{
    ClientDirlistRequest *req = (ClientDirlistRequest *) ctx->hdr_buf;
    u_char                options;
    char                  resolved[PATH_MAX];
    char                  reqpath[XROOTD_MAX_PATH + 1];
    DIR                  *dp;
    struct dirent        *de;
    ngx_flag_t            want_stat;
    /* We buffer one directory chunk at a time */
    u_char               *chunk;
    size_t                chunk_cap = 65536;
    size_t                chunk_pos = 0;
    char                  statbuf[128];
    ngx_int_t             rc;

    options   = req->options;
    want_stat = (options & kXR_dstat) ? 1 : 0;

    /*
     * dirlist is streamed one chunk at a time rather than precomputing the
     * whole directory body up front. That keeps memory bounded for large trees
     * while still preserving the exact newline-delimited body format clients parse.
     */

    if (ctx->payload == NULL || ctx->cur_dlen == 0) {
        xrootd_log_access(ctx, c, "DIRLIST", "-", "-",
                          0, kXR_ArgMissing, "no path given", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_DIRLIST);
        return xrootd_send_error(ctx, c, kXR_ArgMissing, "no path given");
    }

    if (!xrootd_extract_path(c->log, ctx->payload, ctx->cur_dlen,
                             reqpath, sizeof(reqpath), 0)) {
        xrootd_log_access(ctx, c, "DIRLIST", "-", "-",
                          0, kXR_ArgInvalid, "invalid path payload", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_DIRLIST);
        return xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                 "invalid path payload");
    }

    if (!xrootd_resolve_path(c->log, &conf->root,
                             reqpath,
                             resolved, sizeof(resolved))) {
        xrootd_log_access(ctx, c, "DIRLIST", reqpath, "-",
                          0, kXR_NotFound, "directory not found", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_DIRLIST);
        return xrootd_send_error(ctx, c, kXR_NotFound, "directory not found");
    }

    if (xrootd_check_vo_acl(c->log, resolved, conf->vo_rules,
                             ctx->vo_list) != NGX_OK) {
        xrootd_log_access(ctx, c, "DIRLIST", resolved, "-",
                          0, kXR_NotAuthorized, "VO not authorized", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_DIRLIST);
        return xrootd_send_error(ctx, c, kXR_NotAuthorized, "VO not authorized");
    }

    dp = opendir(resolved);
    if (dp == NULL) {
        int err = errno;
        if (err == ENOTDIR) {
            xrootd_log_access(ctx, c, "DIRLIST", resolved, "-",
                              0, kXR_NotFile, "path is not a directory", 0);
            XROOTD_OP_ERR(ctx, XROOTD_OP_DIRLIST);
            return xrootd_send_error(ctx, c, kXR_NotFile,
                                     "path is not a directory");
        }
        if (err == ENOENT) {
            xrootd_log_access(ctx, c, "DIRLIST", resolved, "-",
                              0, kXR_NotFound, "directory not found", 0);
            XROOTD_OP_ERR(ctx, XROOTD_OP_DIRLIST);
            return xrootd_send_error(ctx, c, kXR_NotFound,
                                     "directory not found");
        }
        xrootd_log_access(ctx, c, "DIRLIST", resolved, "-",
                          0, kXR_IOError, strerror(err), 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_DIRLIST);
        return xrootd_send_error(ctx, c, kXR_IOError, strerror(err));
    }

    chunk = ngx_palloc(c->pool, XRD_RESPONSE_HDR_LEN + chunk_cap);
    if (chunk == NULL) {
        closedir(dp);
        return NGX_ERROR;
    }

    /* We write entries starting after the response header, which is filled just before send. */
    u_char *data = chunk + XRD_RESPONSE_HDR_LEN;

    /*
     * dStat lead-in sentinel (kXR_dstat mode only)
     *
     * The XRootD client library (DirectoryList::HasStatInfo) looks for the
     * 9-byte prefix ".\n0 0 0 0" at byte 0 of the response body.  Only if
     * that prefix is present does the client enter stat-pairing mode, where
     * it alternates between treating a line as a filename and as a stat string.
     *
     * Without this sentinel every newline-delimited line is treated as a plain
     * filename, so the stat strings appear as extra directory entries.
     *
     * The reference xrootd server writes ".\n0 0 0 0\n" (10 bytes).  The
     * client strips only 9 bytes (the prefix without the trailing \n), leaving
     * the 10th byte (\n) as the first character of the remaining data.  The
     * client's splitString() skips zero-length tokens, so this leading \n is
     * harmlessly consumed.
     *
     * Wire layout after prepending the lead-in:
     *   ".\n0 0 0 0\n<name1>\n<stat1>\n<name2>\n<stat2>\n...\0"
     * where the final \n is replaced by \0 (see the NUL-terminator comment
     * near the final chunk send below).
     *
     * Each stat line is "<id> <size> <flags> <mtime>" — size before flags,
     * matching kXR_stat and kXR_open retstat order.
     */
    if (want_stat) {
        static const char dstat_leadin[] = ".\n0 0 0 0\n";
        ngx_memcpy(data, dstat_leadin, 10);
        chunk_pos = 10;
    }

    while ((de = readdir(dp)) != NULL) {
        const char *name = de->d_name;
        size_t      nlen = strlen(name);
        char        safe_name[256];

        /* Skip . and .. — XRootD clients do not expect them */
        if (name[0] == '.' && (name[1] == '\0' ||
            (name[1] == '.' && name[2] == '\0'))) {
            continue;
        }

        if (xrootd_dirlist_name_is_unsafe(name)) {
            xrootd_sanitize_log_string(name, safe_name, sizeof(safe_name));
            ngx_log_error(NGX_LOG_WARN, c->log, 0,
                          "xrootd: dirlist skipping entry with control bytes \"%s\"",
                          safe_name);
            continue;
        }

        /*
         * Estimate space needed for this entry.
         * name + '\n' + optional stat line ("<id> <f> <sz> <mt>\n") + '\0'
         */
        size_t need = nlen + 1;
        if (want_stat) {
            need += 80;   /* conservative room for stat line */
        }

        if (chunk_pos + need > chunk_cap) {
            /* Flush current chunk as kXR_oksofar (no NUL — raw data only) */
            xrootd_build_resp_hdr(ctx->cur_streamid, kXR_oksofar,
                                   (uint32_t)chunk_pos,
                                   (ServerResponseHdr *) chunk);

            rc = xrootd_queue_response(ctx, c, chunk,
                                       XRD_RESPONSE_HDR_LEN + chunk_pos);
            if (rc != NGX_OK) {
                closedir(dp);
                return rc;
            }

            /* Reuse the same chunk buffer from the front for the next batch of entries. */
            chunk_pos = 0;
        }

        /* Append the entry name exactly as readdir() reported it, plus a newline separator. */
        ngx_memcpy(data + chunk_pos, name, nlen);
        chunk_pos += nlen;
        data[chunk_pos++] = '\n';

        /* Optionally append stat info — use fstatat to avoid path concat */
        if (want_stat) {
            struct stat entry_st;
            if (fstatat(dirfd(dp), name, &entry_st, AT_SYMLINK_NOFOLLOW)
                    == 0) {
                size_t slen;
                /* fstatat avoids building another path string for each directory entry. */
                xrootd_make_stat_body(&entry_st, 0, statbuf, sizeof(statbuf));
                slen = strlen(statbuf);
                ngx_memcpy(data + chunk_pos, statbuf, slen);
                chunk_pos += slen;
                data[chunk_pos++] = '\n';
            }
        }
    }

    closedir(dp);

    /*
     * Send the final chunk as kXR_ok.
     *
     * NUL-terminator convention
     * ─────────────────────────
     * The XRootD client constructs a std::string from the response body via
     * a C-string (NUL-terminated) pointer.  The correct wire format places the
     * NUL at the position of the last '\n', not after it:
     *
     *   correct:  "file1\nfile2\0"          ← last \n → \0
     *   wrong:    "file1\nfile2\n\0"        ← extra \n before \0 creates
     *                                          a trailing empty token
     *
     * For dStat mode, splitString() is then applied to the body (after
     * stripping the 9-byte prefix).  An extra trailing empty string causes
     * entries.size() to be odd, which fails the size%2 sanity check and
     * discards the entire listing.
     *
     * Empty-directory edge cases
     * ──────────────────────────
     * No-stat, empty dir  (chunk_pos == 0): send kXR_ok with dlen=0.
     * dStat, empty dir    (chunk_pos == 10): the lead-in's trailing '\n'
     *   at data[9] becomes '\0', giving ".\n0 0 0 0\0".  After the client
     *   strips 9 bytes it sees "\0" → empty C-string → empty listing.
     */
    size_t final_len;
    if (chunk_pos == 0) {
        final_len = 0;                  /* empty dir, no stat */
    } else {
        data[chunk_pos - 1] = '\0';     /* replace trailing '\n' with NUL */
        final_len = chunk_pos;
    }

    xrootd_build_resp_hdr(ctx->cur_streamid, kXR_ok,
                           (uint32_t)final_len,
                           (ServerResponseHdr *) chunk);

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: kXR_dirlist final chunk %uz bytes", chunk_pos);

    xrootd_log_access(ctx, c, "DIRLIST", resolved,
                      want_stat ? "stat" : "-", 1, 0, NULL, 0);
    XROOTD_OP_OK(ctx, XROOTD_OP_DIRLIST);

    return xrootd_queue_response(ctx, c, chunk,
                                 XRD_RESPONSE_HDR_LEN + final_len);
}
