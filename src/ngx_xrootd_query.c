#include "ngx_xrootd_module.h"
#include <ctype.h>

/* ================================================================== */
/*  kXR_query handler                                                   */
/*                                                                      */
/*  This file handles the kXR_query opcode, which multiplexes several   */
/*  unrelated server-information requests behind a single request type. */
/*  The infotype field decides which sub-query is in use. Supported:    */
/*                                                                      */
/*    kXR_Qcksum  (3)  — compute file checksum by path or open handle.  */
/*                       Supported algorithms:                          */
/*                         - adler32  (default) — 8-hex-digit value      */
/*                         - md5      — 32-hex-digit value               */
/*                         - sha1     — 40-hex-digit value               */
/*                         - sha256   — 64-hex-digit value               */
/*                       Response: "<algo> <hexval>\0" (e.g.            */
/*                         "adler32 1a2b3c4d\0" or                     */
/*                         "md5 0123456789abcdef...\0")               */
/*                                                                      */
/*    kXR_QStats  (1)  — server statistics (XML blob)                   */
/*    kXR_Qxattr  (4)  — extended attributes for a path                 */
/*    kXR_Qspace  (5)  — storage space information (oss.* text)         */
/*    kXR_Qconfig (7)  — server configuration capability query          */
/*    kXR_QFinfo  (9)  — file information (compression/checksum hint)    */
/*    kXR_QFSinfo (10) — filesystem information (oss.* format)          */
/*                                                                      */
/*  kXR_query is read-only — it never mutates data. Each sub-query has  */
/*  its own payload expectations and response text format, documented   */
/*  inline below.                                                       */
/*                                                                      */
/*  Note: checksum requests may optionally prefix the path with an      */
/*  algorithm token using either "<alg>:<path>" or "<alg> <path>"      */
/*  (e.g. "md5:/file"), and handle-based checksum may supply the       */
/*  algorithm in a leading 0x00 payload byte followed by the token.     */
/* ================================================================== */


/* ------------------------------------------------------------------ */
/* Helpers                                                              */
/* ------------------------------------------------------------------ */

/*
 * Compute adler32 of a file identified by an already-resolved path.
 *
 * Adler32 algorithm (RFC 1950 §9):
 *   A_0 = 1, B_0 = 0
 *   For each byte b: A += b; B += A;  (mod 65521, the largest prime < 2^16)
 *   Result = (B << 16) | A
 *
 * Returns the checksum value, or 0xFFFFFFFF on I/O error.
 */
static uint32_t
xrootd_adler32_file(const char *path, ngx_log_t *log)
{
    int          fd;
    ssize_t      n;
    uint32_t     A = 1, B = 0;
    const uint32_t MOD = 65521;
    u_char       buf[65536];
    char         safe_path[512];

    xrootd_sanitize_log_string(path, safe_path, sizeof(safe_path));

    fd = open(path, O_RDONLY);
    if (fd < 0) {
        ngx_log_error(NGX_LOG_ERR, log, errno,
                      "xrootd: adler32 open(\"%s\") failed", safe_path);
        return 0xFFFFFFFF;
    }

    for (;;) {
        /* Stream the file in fixed-size blocks so checksum cost is bounded in memory. */
        n = read(fd, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR) continue;
            ngx_log_error(NGX_LOG_ERR, log, errno,
                          "xrootd: adler32 read(\"%s\") failed", safe_path);
            close(fd);
            return 0xFFFFFFFF;
        }
        if (n == 0) break;

        /* Adler32 is inherently iterative, so fold each byte into A/B in order. */
        for (ssize_t i = 0; i < n; i++) {
            A = (A + buf[i]) % MOD;
            B = (B + A)      % MOD;
        }
    }

    close(fd);
    return (B << 16) | A;
}

/*
 * Compute a generic digest for a file using OpenSSL EVP interface.
 * Returns 1 on success (out/outlen filled), 0 on I/O or digest error.
 */
static int
xrootd_digest_file(const char *path, const EVP_MD *md,
                    unsigned char *out, unsigned int *outlen,
                    ngx_log_t *log)
{
    int fd;
    ssize_t n;
    u_char buf[65536];
    EVP_MD_CTX *mdctx = NULL;

    fd = open(path, O_RDONLY);
    if (fd < 0) {
        char safe[512];
        xrootd_sanitize_log_string(path, safe, sizeof(safe));
        ngx_log_error(NGX_LOG_ERR, log, errno,
                      "xrootd: digest open(\"%s\") failed", safe);
        return 0;
    }

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        close(fd);
        return 0;
    }
    if (EVP_DigestInit_ex(mdctx, md, NULL) != 1) {
        EVP_MD_CTX_free(mdctx);
        close(fd);
        return 0;
    }

    for (;;) {
        n = read(fd, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR) continue;
            char safe[512];
            xrootd_sanitize_log_string(path, safe, sizeof(safe));
            ngx_log_error(NGX_LOG_ERR, log, errno,
                          "xrootd: digest read(\"%s\") failed", safe);
            EVP_MD_CTX_free(mdctx);
            close(fd);
            return 0;
        }
        if (n == 0) break;
        if (EVP_DigestUpdate(mdctx, buf, (size_t) n) != 1) {
            EVP_MD_CTX_free(mdctx);
            close(fd);
            return 0;
        }
    }

    if (EVP_DigestFinal_ex(mdctx, out, outlen) != 1) {
        EVP_MD_CTX_free(mdctx);
        close(fd);
        return 0;
    }

    EVP_MD_CTX_free(mdctx);
    close(fd);
    return 1;
}

/*
 * Append a formatted string to a kXR_Qconfig response buffer.
 * Returns 1 on success, 0 if the buffer is full.
 */
static ngx_flag_t
xrootd_qconfig_append(char *resp, size_t resp_sz, size_t *pos,
                      const char *fmt, ...)
{
    va_list ap;
    int     n;
    size_t  remaining;

    if (resp == NULL || pos == NULL || *pos >= resp_sz) {
        return 0;
    }

    remaining = resp_sz - *pos;

    va_start(ap, fmt);
    n = vsnprintf(resp + *pos, remaining, fmt, ap);
    va_end(ap);

    if (n < 0 || (size_t) n >= remaining) {
        resp[*pos] = '\0';
        return 0;
    }

    *pos += (size_t) n;
    return 1;
}


/* ------------------------------------------------------------------ */
/* kXR_query — query server information.                               */
/*                                                                     */
/* Supported infotypes:                                                */
/*   kXR_QChecksum (8) — compute adler32 checksum for a file by path  */
/*                       or by open handle.                            */
/*                       Response: "<algo> <hexval>\0"                 */
/*                       e.g.    "adler32 1a2b3c4d\0"                 */
/*                                                                     */
/*   kXR_QSpace (6)    — report available storage space for xrootd_root. */
/*                       Response: oss.* key-value string (text).      */
/*                       e.g. "oss.cgroup=default&oss.space=53687091200 */
/*                             &oss.free=42949672960&oss.maxf=42949672960 */
/*                             &oss.used=10737418240&oss.quota=-1\0"   */
/*                                                                     */
/*   kXR_Qconfig (7)   — server configuration capability query.       */
/*                       Payload: newline-separated list of config keys */
/*                       the client wants.                              */
/*                       Response: "key=value\n" pairs.                */
/*                       Unknown keys echo back as "key=0\n".          */
/*                                                                     */
/* All other infotypes return kXR_Unsupported.                         */
/* ------------------------------------------------------------------ */
ngx_int_t
xrootd_handle_query(xrootd_ctx_t *ctx, ngx_connection_t *c,
                    ngx_stream_xrootd_srv_conf_t *conf)
{
    ClientQueryRequest *req = (ClientQueryRequest *) ctx->hdr_buf;
    uint16_t infotype = ntohs(req->infotype);

    /*
     * kXR_query multiplexes several unrelated info requests behind one opcode.
     * The infotype field decides which sub-protocol is in use, so each branch
     * below has its own payload expectations and response text format.
     */

    /* ---- kXR_Qcksum (3): checksum by path or open handle (alg: adler32/md5) ---- */
    if (infotype == kXR_Qcksum) {
        char     resolved[PATH_MAX];
        char     pathbuf[XROOTD_MAX_PATH + 1];
        char     algo[32];
        char     resp[256];

        /* default algorithm */
        ngx_cpystrn((u_char *) algo, (u_char *) "adler32", sizeof(algo));

        /* Path-based request (payload present and not a leading 0x00 handle marker)
         * Accept optional algorithm prefix: "<alg>:<path>" or "<alg> <path>".
         */
        if (ctx->cur_dlen > 0 && ctx->payload != NULL && ctx->payload[0] != 0) {
            const u_char *payload = ctx->payload;
            size_t payload_len = (size_t) ctx->cur_dlen;
            size_t wire_len = strnlen((const char *) payload, payload_len);
            const u_char *sep = NULL;
            size_t alg_len = 0;
            const u_char *path_payload = payload;
            size_t path_payload_len = payload_len;

            for (size_t i = 0; i < wire_len; i++) {
                if (payload[i] == ':' || payload[i] == ' ') { sep = payload + i; alg_len = i; break; }
            }
            if (sep != NULL && alg_len > 0 && alg_len + 1 < payload_len) {
                int valid = 1;
                if (alg_len >= sizeof(algo)) valid = 0;
                for (size_t j = 0; j < alg_len && valid; j++) {
                    if (!isalnum((unsigned char) payload[j])) valid = 0;
                }
                if (valid) {
                    for (size_t j = 0; j < alg_len; j++) algo[j] = (char) tolower((unsigned char) payload[j]);
                    algo[alg_len] = '\0';
                    path_payload = sep + 1;
                    path_payload_len = payload_len - (alg_len + 1);
                }
            }

            if (!xrootd_extract_path(c->log, path_payload, path_payload_len,
                                     pathbuf, sizeof(pathbuf), 1)) {
                XROOTD_OP_ERR(ctx, XROOTD_OP_QUERY_CKSUM);
                return xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                         "invalid path payload");
            }

            if (!xrootd_resolve_path(c->log, &conf->root,
                                     pathbuf, resolved, sizeof(resolved))) {
                xrootd_log_access(ctx, c, "QUERY", pathbuf, "cksum",
                                  0, kXR_NotFound, "file not found", 0);
                XROOTD_OP_ERR(ctx, XROOTD_OP_QUERY_CKSUM);
                return xrootd_send_error(ctx, c, kXR_NotFound,
                                         "file not found");
            }

            if (xrootd_check_vo_acl(c->log, resolved, conf->vo_rules,
                                     ctx->vo_list) != NGX_OK) {
                xrootd_log_access(ctx, c, "QUERY", resolved, "cksum",
                                  0, kXR_NotAuthorized, "VO not authorized", 0);
                XROOTD_OP_ERR(ctx, XROOTD_OP_QUERY_CKSUM);
                return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                         "VO not authorized");
            }

            if (strcmp(algo, "adler32") == 0) {
                uint32_t cksum = xrootd_adler32_file(resolved, c->log);
                if (cksum == 0xFFFFFFFF) {
                    xrootd_log_access(ctx, c, "QUERY", resolved, "cksum",
                                      0, kXR_IOError, "read error", 0);
                    XROOTD_OP_ERR(ctx, XROOTD_OP_QUERY_CKSUM);
                    return xrootd_send_error(ctx, c, kXR_IOError,
                                             "checksum computation failed");
                }
                snprintf(resp, sizeof(resp), "adler32 %08x", (unsigned int) cksum);

            } else if (strcmp(algo, "md5") == 0) {
                unsigned char mdout[EVP_MAX_MD_SIZE];
                unsigned int mdlen = 0;
                if (!xrootd_digest_file(resolved, EVP_md5(), mdout, &mdlen, c->log)) {
                    XROOTD_OP_ERR(ctx, XROOTD_OP_QUERY_CKSUM);
                    return xrootd_send_error(ctx, c, kXR_IOError,
                                             "checksum computation failed");
                }
                /* build hex string */
                char hex[EVP_MAX_MD_SIZE * 2 + 1];
                for (unsigned int i = 0; i < mdlen; i++) snprintf(hex + i*2, 3, "%02x", mdout[i]);
                snprintf(resp, sizeof(resp), "md5 %s", hex);

            } else if (strcmp(algo, "sha1") == 0) {
                unsigned char mdout[EVP_MAX_MD_SIZE];
                unsigned int mdlen = 0;
                if (!xrootd_digest_file(resolved, EVP_sha1(), mdout, &mdlen, c->log)) {
                    XROOTD_OP_ERR(ctx, XROOTD_OP_QUERY_CKSUM);
                    return xrootd_send_error(ctx, c, kXR_IOError,
                                             "checksum computation failed");
                }
                char hex[EVP_MAX_MD_SIZE * 2 + 1];
                for (unsigned int i = 0; i < mdlen; i++) snprintf(hex + i*2, 3, "%02x", mdout[i]);
                snprintf(resp, sizeof(resp), "sha1 %s", hex);

            } else if (strcmp(algo, "sha256") == 0) {
                unsigned char mdout[EVP_MAX_MD_SIZE];
                unsigned int mdlen = 0;
                if (!xrootd_digest_file(resolved, EVP_sha256(), mdout, &mdlen, c->log)) {
                    XROOTD_OP_ERR(ctx, XROOTD_OP_QUERY_CKSUM);
                    return xrootd_send_error(ctx, c, kXR_IOError,
                                             "checksum computation failed");
                }
                char hex[EVP_MAX_MD_SIZE * 2 + 1];
                for (unsigned int i = 0; i < mdlen; i++) snprintf(hex + i*2, 3, "%02x", mdout[i]);
                snprintf(resp, sizeof(resp), "sha256 %s", hex);

            } else {
                XROOTD_OP_ERR(ctx, XROOTD_OP_QUERY_CKSUM);
                return xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                         "unknown checksum algorithm");
            }

            xrootd_log_access(ctx, c, "QUERY", resolved, "cksum", 1, 0, NULL, 0);
            XROOTD_OP_OK(ctx, XROOTD_OP_QUERY_CKSUM);
            return xrootd_send_ok(ctx, c, resp, (uint32_t)(strlen(resp) + 1));

        } else {
            /* Handle-based checksum. Optional algorithm may be supplied in
             * a payload starting with a leading 0x00 followed by an algorithm
             * token (eg. "\0md5"). Otherwise default to adler32. */
            if (ctx->payload != NULL && ctx->cur_dlen > 1 && ctx->payload[0] == 0) {
                const u_char *ap = ctx->payload + 1;
                size_t alen = strnlen((const char *) ap, (size_t)(ctx->cur_dlen - 1));
                if (alen > 0 && alen < sizeof(algo)) {
                    int valid = 1;
                    for (size_t j = 0; j < alen; j++) if (!isalnum((unsigned char) ap[j])) { valid = 0; break; }
                    if (valid) {
                        for (size_t j = 0; j < alen; j++) algo[j] = (char) tolower((unsigned char) ap[j]);
                        algo[alen] = '\0';
                    }
                }
            }

            int idx = (int)(unsigned char) req->fhandle[0];
            if (idx < 0 || idx >= XROOTD_MAX_FILES || ctx->files[idx].fd < 0) {
                XROOTD_OP_ERR(ctx, XROOTD_OP_QUERY_CKSUM);
                return xrootd_send_error(ctx, c, kXR_FileNotOpen,
                                         "invalid file handle");
            }
            ngx_cpystrn((u_char *) resolved, (u_char *) ctx->files[idx].path, sizeof(resolved));

            if (strcmp(algo, "adler32") == 0) {
                uint32_t cksum = xrootd_adler32_file(resolved, c->log);
                if (cksum == 0xFFFFFFFF) {
                    XROOTD_OP_ERR(ctx, XROOTD_OP_QUERY_CKSUM);
                    return xrootd_send_error(ctx, c, kXR_IOError,
                                             "checksum computation failed");
                }
                snprintf(resp, sizeof(resp), "adler32 %08x", (unsigned int) cksum);
            } else if (strcmp(algo, "md5") == 0) {
                unsigned char mdout[EVP_MAX_MD_SIZE];
                unsigned int mdlen = 0;
                if (!xrootd_digest_file(resolved, EVP_md5(), mdout, &mdlen, c->log)) {
                    XROOTD_OP_ERR(ctx, XROOTD_OP_QUERY_CKSUM);
                    return xrootd_send_error(ctx, c, kXR_IOError,
                                             "checksum computation failed");
                }
                char hex[EVP_MAX_MD_SIZE * 2 + 1];
                for (unsigned int i = 0; i < mdlen; i++) snprintf(hex + i*2, 3, "%02x", mdout[i]);
                snprintf(resp, sizeof(resp), "md5 %s", hex);
            } else if (strcmp(algo, "sha1") == 0) {
                unsigned char mdout[EVP_MAX_MD_SIZE];
                unsigned int mdlen = 0;
                if (!xrootd_digest_file(resolved, EVP_sha1(), mdout, &mdlen, c->log)) {
                    XROOTD_OP_ERR(ctx, XROOTD_OP_QUERY_CKSUM);
                    return xrootd_send_error(ctx, c, kXR_IOError,
                                             "checksum computation failed");
                }
                char hex[EVP_MAX_MD_SIZE * 2 + 1];
                for (unsigned int i = 0; i < mdlen; i++) snprintf(hex + i*2, 3, "%02x", mdout[i]);
                snprintf(resp, sizeof(resp), "sha1 %s", hex);
            } else if (strcmp(algo, "sha256") == 0) {
                unsigned char mdout[EVP_MAX_MD_SIZE];
                unsigned int mdlen = 0;
                if (!xrootd_digest_file(resolved, EVP_sha256(), mdout, &mdlen, c->log)) {
                    XROOTD_OP_ERR(ctx, XROOTD_OP_QUERY_CKSUM);
                    return xrootd_send_error(ctx, c, kXR_IOError,
                                             "checksum computation failed");
                }
                char hex[EVP_MAX_MD_SIZE * 2 + 1];
                for (unsigned int i = 0; i < mdlen; i++) snprintf(hex + i*2, 3, "%02x", mdout[i]);
                snprintf(resp, sizeof(resp), "sha256 %s", hex);
            } else {
                XROOTD_OP_ERR(ctx, XROOTD_OP_QUERY_CKSUM);
                return xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                         "unknown checksum algorithm");
            }

            XROOTD_OP_OK(ctx, XROOTD_OP_QUERY_CKSUM);
            xrootd_log_access(ctx, c, "QUERY", resolved, "cksum", 1, 0, NULL, 0);
            return xrootd_send_ok(ctx, c, resp, (uint32_t)(strlen(resp) + 1));
        }
    }

    /* ---- kXR_Qspace (5): storage space for xrootd_root ---- */
    if (infotype == kXR_Qspace) {
        struct statvfs  vfs;
        char            resp[256];
        unsigned long long total, free_bytes, used_bytes;

        /*
         * Space queries are export-level rather than path-level: ask the host
         * filesystem backing xrootd_root and report the answer in oss.* form.
         */
        if (statvfs((const char *) conf->root.data, &vfs) != 0) {
            xrootd_log_access(ctx, c, "QUERY", (char *) conf->root.data,
                              "space", 0, kXR_IOError, strerror(errno), 0);
            XROOTD_OP_ERR(ctx, XROOTD_OP_QUERY_SPACE);
            return xrootd_send_error(ctx, c, kXR_IOError,
                                     "statvfs failed");
        }

        total      = (unsigned long long) vfs.f_blocks * vfs.f_frsize;
        free_bytes = (unsigned long long) vfs.f_bavail * vfs.f_frsize;
        used_bytes = total - (unsigned long long) vfs.f_bfree * vfs.f_frsize;

        /*
         * oss.* key-value format as used by XRootD's OSS layer:
         *   oss.cgroup  — storage group name (use "default")
         *   oss.space   — total filesystem bytes
         *   oss.free    — bytes available to unpriv processes (f_bavail)
         *   oss.maxf    — largest single free segment (approximate: == free)
         *   oss.used    — bytes used
         *   oss.quota   — -1 means no quota configured
         */
        snprintf(resp, sizeof(resp),
                 "oss.cgroup=default"
                 "&oss.space=%llu"
                 "&oss.free=%llu"
                 "&oss.maxf=%llu"
                 "&oss.used=%llu"
                 "&oss.quota=-1",
                 total, free_bytes, free_bytes, used_bytes);

        xrootd_log_access(ctx, c, "QUERY", (char *) conf->root.data,
                          "space", 1, 0, NULL, 0);
        XROOTD_OP_OK(ctx, XROOTD_OP_QUERY_SPACE);
        return xrootd_send_ok(ctx, c, resp, (uint32_t)(strlen(resp) + 1));
    }

    /* ---- kXR_Qconfig (7): configuration query ---- */
    if (infotype == kXR_Qconfig) {
        /*
         * The payload is a newline-separated list of config keys the client
         * wants.  We respond with "key=value\n" pairs; keys we don't know
         * echo back as "key=0\n".  xrdcp queries "chksum" and "readv" among
         * others; we advertise adler32 support.
         */
        char    resp[512];
        size_t  pos = 0;
        const char *p = (ctx->payload && ctx->cur_dlen > 0)
                        ? (const char *) ctx->payload : "";
        const char *nl;

        /*
         * The client may ask for many keys in one request. We intentionally do
         * not fail unknown keys because upstream servers also answer best-effort
         * capability queries one line at a time.
         */
        /* Walk one requested key per iteration until the newline-delimited list is exhausted. */
        while (*p) {
            nl = strchr(p, '\n');
            size_t keylen = nl ? (size_t)(nl - p) : strlen(p);
            char key[128];
            if (keylen >= sizeof(key)) keylen = sizeof(key) - 1;
            memcpy(key, p, keylen);
            key[keylen] = '\0';

            if (strcmp(key, "chksum") == 0) {
                if (!xrootd_qconfig_append(resp, sizeof(resp), &pos,
                                           "chksum=adler32\n")) {
                    break;
                }
            } else if (strcmp(key, "readv") == 0) {
                if (!xrootd_qconfig_append(resp, sizeof(resp), &pos,
                                           "readv=1\n")) {
                    break;
                }
            } else {
                if (!xrootd_qconfig_append(resp, sizeof(resp), &pos,
                                           "%s=0\n", key)) {
                    break;
                }
            }
            p = nl ? nl + 1 : p + keylen;
        }
        if (pos == 0) {
            /* No keys requested is still a valid query, just with an empty body. */
            return xrootd_send_ok(ctx, c, NULL, 0);
        }
        return xrootd_send_ok(ctx, c, resp, (uint32_t) pos);
    }

    /* ---- kXR_QStats (1): server statistics ---- */
    if (infotype == kXR_QStats) {
        char  resp[1024];
        int   port = 0;
        long  conns_active = 0, conns_total = 0;
        long  bytes_in = 0, bytes_out = 0;
        time_t now = time(NULL);

        if (ctx->metrics) {
            port        = (int) ctx->metrics->port;
            conns_active = (long) ctx->metrics->connections_active;
            conns_total  = (long) ctx->metrics->connections_total;
            bytes_in     = (long) ctx->metrics->bytes_rx_total;
            bytes_out    = (long) ctx->metrics->bytes_tx_total;
        }
        if (port == 0) {
            struct sockaddr_in *sin = (struct sockaddr_in *) c->local_sockaddr;
            if (sin && c->local_sockaddr->sa_family == AF_INET) {
                port = (int) ntohs(sin->sin_port);
            }
        }

        int n = snprintf(resp, sizeof(resp) - 1,
            "<statistics id=\"xrootd\" ver=\"5.2.0\" tos=\"%ld\" pgm=\"nginx-xrootd\">"
            "<stats id=\"info\"><host>localhost</host><port>%d</port>"
            "<name>nginx-xrootd</name></stats>"
            "<stats id=\"link\"><num>%ld</num><tot>%ld</tot>"
            "<in>%ld</in><out>%ld</out><ctime>0</ctime>"
            "<ltime>0</ltime><sfps>0</sfps></stats>"
            "</statistics>",
            (long) now, port,
            conns_active, conns_total,
            bytes_in, bytes_out);

        xrootd_log_access(ctx, c, "QUERY", "-", "stats", 1, 0, NULL, 0);
        XROOTD_OP_OK(ctx, XROOTD_OP_QUERY_STATS);
        return xrootd_send_ok(ctx, c, resp, (uint32_t)(n + 1));
    }

    /* ---- kXR_Qxattr (4): extended attributes for a path ---- */
    if (infotype == kXR_Qxattr) {
        char     pathbuf[XROOTD_MAX_PATH + 1];
        char     resolved[PATH_MAX];

        if (ctx->cur_dlen == 0 || ctx->payload == NULL) {
            XROOTD_OP_ERR(ctx, XROOTD_OP_QUERY_XATTR);
            return xrootd_send_error(ctx, c, kXR_ArgMissing,
                                     "xattr: path required");
        }

        if (!xrootd_extract_path(c->log, ctx->payload, ctx->cur_dlen,
                                 pathbuf, sizeof(pathbuf), 1)) {
            XROOTD_OP_ERR(ctx, XROOTD_OP_QUERY_XATTR);
            return xrootd_send_error(ctx, c, kXR_ArgInvalid, "invalid path");
        }
        if (!xrootd_resolve_path(c->log, &conf->root, pathbuf,
                                 resolved, sizeof(resolved))) {
            XROOTD_OP_ERR(ctx, XROOTD_OP_QUERY_XATTR);
            return xrootd_send_error(ctx, c, kXR_NotFound, "file not found");
        }
        if (xrootd_check_vo_acl(c->log, resolved, conf->vo_rules,
                                 ctx->vo_list) != NGX_OK) {
            XROOTD_OP_ERR(ctx, XROOTD_OP_QUERY_XATTR);
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "VO not authorized");
        }

        /*
         * Return U.* xattrs as "name=value\n" text lines.
         * This format is implementation-specific; clients that query kXR_Qxattr
         * typically parse the result themselves or are xrootd-internal tools.
         */
        char resp[4096];
        int  pos = 0;
        char raw_list[4096];
        ssize_t list_sz = listxattr(resolved, raw_list, sizeof(raw_list));
        if (list_sz > 0) {
            char *lp = raw_list, *lend = raw_list + list_sz;
            while (lp < lend && pos < (int)sizeof(resp) - 256) {
                size_t nlen = strlen(lp);
                if (strncmp(lp, "user.U.", 7) == 0 && nlen > 7) {
                    char val[1024];
                    ssize_t vlen = getxattr(resolved, lp, val, sizeof(val) - 1);
                    if (vlen >= 0) {
                        val[vlen] = '\0';
                        /* strip "user." prefix to expose "U.name" */
                        pos += snprintf(resp + pos, sizeof(resp) - pos - 1,
                                        "%s=%.*s\n", lp + 5, (int) vlen, val);
                    }
                }
                lp += nlen + 1;
            }
        }

        xrootd_log_access(ctx, c, "QUERY", pathbuf, "xattr", 1, 0, NULL, 0);
        XROOTD_OP_OK(ctx, XROOTD_OP_QUERY_XATTR);
        if (pos == 0) {
            return xrootd_send_ok(ctx, c, NULL, 0);
        }
        return xrootd_send_ok(ctx, c, resp, (uint32_t)(pos + 1));
    }

    /* ---- kXR_QFinfo (9): file information (compression, checksum) ---- */
    if (infotype == kXR_QFinfo) {
        /*
         * For uncompressed POSIX files we report N=0 (no compression layers).
         * ROOT clients use this to skip decompression; "0\0" is the canonical
         * response for a plain file.
         */
        xrootd_log_access(ctx, c, "QUERY", "-", "finfo", 1, 0, NULL, 0);
        XROOTD_OP_OK(ctx, XROOTD_OP_QUERY_FINFO);
        return xrootd_send_ok(ctx, c, "0", 2);  /* "0\0" */
    }

    /* ---- kXR_QFSinfo (10): filesystem information ---- */
    if (infotype == kXR_QFSinfo) {
        /*
         * Return filesystem capacity info in the oss.* key-value format that
         * XRootD clients understand.  We use the same statvfs source as
         * kXR_Qspace; the format differs only in key names.
         */
        struct statvfs vfs;
        char           resp[256];

        if (statvfs((const char *) conf->root.data, &vfs) != 0) {
            XROOTD_OP_ERR(ctx, XROOTD_OP_QUERY_FSINFO);
            return xrootd_send_error(ctx, c, kXR_IOError, "statvfs failed");
        }

        unsigned long long total      = (unsigned long long) vfs.f_blocks * vfs.f_frsize;
        unsigned long long free_bytes = (unsigned long long) vfs.f_bavail * vfs.f_frsize;
        unsigned long long used_bytes = total - (unsigned long long) vfs.f_bfree * vfs.f_frsize;

        snprintf(resp, sizeof(resp),
                 "oss.paths=1"
                 "&oss.free=%llu"
                 "&oss.maxf=%llu"
                 "&oss.total=%llu"
                 "&oss.used=%llu"
                 "&oss.quota=-1",
                 free_bytes, free_bytes, total, used_bytes);

        xrootd_log_access(ctx, c, "QUERY", (char *) conf->root.data,
                          "fsinfo", 1, 0, NULL, 0);
        XROOTD_OP_OK(ctx, XROOTD_OP_QUERY_FSINFO);
        return xrootd_send_ok(ctx, c, resp, (uint32_t)(strlen(resp) + 1));
    }

    /* All other query types: not implemented */
    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: kXR_query unsupported infotype=%d",
                   (int) infotype);
    return xrootd_send_error(ctx, c, kXR_Unsupported,
                             "query type not supported");
}
