#include "ngx_xrootd_module.h"

/* ================================================================== */
/*  kXR_fattr — file extended attributes                               */
/*                                                                      */
/*  Subcodes:                                                           */
/*    kXR_fattrGet  (1) — read named attributes                        */
/*    kXR_fattrSet  (3) — write named attributes                       */
/*    kXR_fattrDel  (0) — remove named attributes                      */
/*    kXR_fattrList (2) — enumerate all attributes                     */
/*                                                                      */
/*  Wire namespace: client sends bare names ("foo"); stored on Linux    */
/*  as "user.U.foo", matching the reference XRootD server convention   */
/*  (U = user namespace prefix, user. = POSIX xattr namespace).        */
/*                                                                      */
/*  Payload layout for path-based requests (payload[0] != 0):          */
/*    [path\0][nvec][vvec]                                             */
/*                                                                      */
/*  Payload layout for handle-based (payload[0] == 0 or dlen == 0):    */
/*    [0x00][nvec][vvec]   or   (empty for list with dlen=0)           */
/*                                                                      */
/*  nvec entry: [kXR_unt16 = 0x0000][name\0]   (numattr entries)       */
/*  vvec entry: [kXR_int32 vlen BE][value]      (set only)             */
/*                                                                      */
/*  Response body (get):                                                */
/*    [nerrs:1][inum:1][nvec with rc codes][vvec with value data]      */
/*  Response body (set, del):                                           */
/*    [nerrs:1][inum:1][nvec with rc codes]                            */
/*  Response body (list, no kXR_fa_aData):                             */
/*    NUL-separated "U.name" strings                                   */
/*  Response body (list, with kXR_fa_aData):                           */
/*    ["U.name\0"][vlen_BE:4][value] per attribute                     */
/* ================================================================== */

/* Linux xattr key prefix: "user.U." maps to XRootD's "U." namespace */
#define XROOTD_FATTR_XKEY_PFX   "user.U."
#define XROOTD_FATTR_XKEY_PFX_LEN  7
/* "U." prefix in list responses (strips "user." from Linux keys) */
#define XROOTD_FATTR_RESP_PFX   "U."

/* Max value size to retrieve in one xattr call (Linux max is 65536) */
#define XROOTD_FATTR_MAX_VBUF   65536

/* Per-attribute working state for a single fattr operation */
typedef struct {
    u_char  *rc_ptr;        /* pointer into nvec copy where [rc:2] lives */
    char    *name;          /* bare wire name (no U. prefix)             */
    size_t   nlen;          /* strlen(name)                              */
    char     xkey[512];     /* "user.U." + name for Linux xattr calls    */
    u_char  *value;         /* retrieved value (pool-allocated)          */
    ssize_t  vlen;          /* value length (0 if error/not found)       */
    uint16_t errcode;       /* kXR error code (0 = success)             */
} xrootd_fattr_entry_t;

/* ------------------------------------------------------------------ */
/* Helpers                                                              */
/* ------------------------------------------------------------------ */

static uint16_t
fattr_errno_to_xrd(int err)
{
    switch (err) {
    case ENODATA:   return kXR_AttrNotFound;
    case ENOENT:
    case ENOTDIR:   return kXR_NotFound;
    case EPERM:
    case EACCES:    return kXR_NotAuthorized;
    case EEXIST:    return kXR_ItExists;
    case ERANGE:    return kXR_ArgTooLong;
    case ENOMEM:    return kXR_NoMemory;
    case ENOSPC:    return kXR_NoSpace;
    default:        return kXR_FSError;
    }
}

static void
fattr_set_rc(xrootd_fattr_entry_t *attr, uint16_t rc)
{
    attr->errcode = rc;
    uint16_t rc_be = htons(rc);
    ngx_memcpy(attr->rc_ptr, &rc_be, 2);
}

/*
 * Parse the nvec section of the args buffer.
 * Fills attrs[0..numattr-1] with pointers into nvec_copy.
 * Returns bytes consumed by the nvec, or -1 on parse error.
 */
static ssize_t
fattr_parse_nvec(ngx_log_t *log, u_char *nvec_copy, size_t buflen,
                 int numattr, xrootd_fattr_entry_t *attrs)
{
    u_char *p   = nvec_copy;
    u_char *end = nvec_copy + buflen;

    for (int i = 0; i < numattr; i++) {
        if (p + 2 > end) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "xrootd: fattr nvec truncated at entry %d", i);
            return -1;
        }
        attrs[i].rc_ptr  = p;
        attrs[i].errcode = 0;
        attrs[i].value   = NULL;
        attrs[i].vlen    = 0;
        p += 2;

        u_char *name_start = p;
        while (p < end && *p) p++;
        if (p >= end) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "xrootd: fattr name not null-terminated");
            return -1;
        }
        size_t nlen = (size_t)(p - name_start);
        if (nlen == 0 || nlen > kXR_faMaxNlen) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "xrootd: fattr name length %uz invalid", nlen);
            return -1;
        }
        attrs[i].name = (char *) name_start;
        attrs[i].nlen = nlen;
        snprintf(attrs[i].xkey, sizeof(attrs[i].xkey),
                 XROOTD_FATTR_XKEY_PFX "%.*s", (int) nlen, name_start);
        p++;
    }
    return (ssize_t)(p - nvec_copy);
}

/* ------------------------------------------------------------------ */
/* kXR_fattrGet                                                         */
/* ------------------------------------------------------------------ */

static ngx_int_t
fattr_get(xrootd_ctx_t *ctx, ngx_connection_t *c,
          const char *path, int fd,
          u_char *nvec_copy, size_t nvec_len,
          int numattr, xrootd_fattr_entry_t *attrs)
{
    ngx_pool_t *pool = c->pool;
    size_t resp_size = 2 + nvec_len;

    for (int i = 0; i < numattr; i++) {
        ssize_t vsz = path ? getxattr(path, attrs[i].xkey, NULL, 0)
                           : fgetxattr(fd, attrs[i].xkey, NULL, 0);
        if (vsz < 0) {
            fattr_set_rc(&attrs[i], fattr_errno_to_xrd(errno));
            resp_size += 4;
            continue;
        }
        if (vsz > kXR_faMaxVlen) vsz = kXR_faMaxVlen;

        attrs[i].value = ngx_palloc(pool, vsz + 1);
        if (attrs[i].value == NULL) {
            fattr_set_rc(&attrs[i], kXR_NoMemory);
            resp_size += 4;
            continue;
        }
        ssize_t got = path ? getxattr(path, attrs[i].xkey, attrs[i].value, vsz)
                           : fgetxattr(fd, attrs[i].xkey, attrs[i].value, vsz);
        if (got < 0) {
            fattr_set_rc(&attrs[i], fattr_errno_to_xrd(errno));
            attrs[i].vlen = 0;
        } else {
            attrs[i].vlen = got;
        }
        resp_size += 4 + (size_t)(attrs[i].vlen > 0 ? attrs[i].vlen : 0);
    }

    u_char *resp = ngx_palloc(pool, resp_size);
    if (resp == NULL) {
        return xrootd_send_error(ctx, c, kXR_NoMemory, "out of memory");
    }

    int nerrs = 0;
    for (int i = 0; i < numattr; i++) if (attrs[i].errcode) nerrs++;

    u_char *p = resp;
    *p++ = (u_char) nerrs;
    *p++ = (u_char) numattr;
    ngx_memcpy(p, nvec_copy, nvec_len);
    p += nvec_len;

    for (int i = 0; i < numattr; i++) {
        uint32_t vl = (uint32_t)(attrs[i].vlen > 0 ? attrs[i].vlen : 0);
        uint32_t vl_be = htonl(vl);
        ngx_memcpy(p, &vl_be, 4);
        p += 4;
        if (vl > 0 && attrs[i].value) {
            ngx_memcpy(p, attrs[i].value, vl);
            p += vl;
        }
    }

    XROOTD_OP_OK(ctx, XROOTD_OP_FATTR);
    return xrootd_send_ok(ctx, c, resp, (uint32_t) resp_size);
}

/* ------------------------------------------------------------------ */
/* kXR_fattrSet                                                         */
/* ------------------------------------------------------------------ */

static ngx_int_t
fattr_set(xrootd_ctx_t *ctx, ngx_connection_t *c,
          const char *path, int fd, int options,
          u_char *nvec_copy, size_t nvec_len,
          u_char *vvec_buf, size_t vvec_len,
          int numattr, xrootd_fattr_entry_t *attrs)
{
    ngx_pool_t *pool = c->pool;
    u_char *vp   = vvec_buf;
    u_char *vend = vvec_buf + vvec_len;

    for (int i = 0; i < numattr; i++) {
        if (vp + 4 > vend) {
            return xrootd_send_error(ctx, c, kXR_ArgMissing,
                                     "fattr set: vvec truncated");
        }
        int32_t vlen_be;
        ngx_memcpy(&vlen_be, vp, 4);
        int32_t vlen = (int32_t) ntohl((uint32_t) vlen_be);
        vp += 4;

        if (vlen < 0 || vlen > kXR_faMaxVlen || vp + vlen > vend) {
            return xrootd_send_error(ctx, c, vlen > kXR_faMaxVlen
                                     ? kXR_ArgTooLong : kXR_ArgInvalid,
                                     "fattr set: value invalid");
        }

        int xflag = (options & kXR_fa_isNew) ? XATTR_CREATE : 0;
        int rc = path ? setxattr(path, attrs[i].xkey, vp, vlen, xflag)
                      : fsetxattr(fd,  attrs[i].xkey, vp, vlen, xflag);
        if (rc != 0) {
            fattr_set_rc(&attrs[i], fattr_errno_to_xrd(errno));
        }
        vp += vlen;
    }

    int nerrs = 0;
    for (int i = 0; i < numattr; i++) if (attrs[i].errcode) nerrs++;

    size_t resp_size = 2 + nvec_len;
    u_char *resp = ngx_palloc(pool, resp_size);
    if (resp == NULL) {
        return xrootd_send_error(ctx, c, kXR_NoMemory, "out of memory");
    }
    resp[0] = (u_char) nerrs;
    resp[1] = (u_char) numattr;
    ngx_memcpy(resp + 2, nvec_copy, nvec_len);

    XROOTD_OP_OK(ctx, XROOTD_OP_FATTR);
    return xrootd_send_ok(ctx, c, resp, (uint32_t) resp_size);
}

/* ------------------------------------------------------------------ */
/* kXR_fattrDel                                                         */
/* ------------------------------------------------------------------ */

static ngx_int_t
fattr_del(xrootd_ctx_t *ctx, ngx_connection_t *c,
          const char *path, int fd,
          u_char *nvec_copy, size_t nvec_len,
          int numattr, xrootd_fattr_entry_t *attrs)
{
    ngx_pool_t *pool = c->pool;

    for (int i = 0; i < numattr; i++) {
        int rc = path ? removexattr(path, attrs[i].xkey)
                      : fremovexattr(fd,  attrs[i].xkey);
        if (rc != 0) {
            fattr_set_rc(&attrs[i], fattr_errno_to_xrd(errno));
        }
    }

    int nerrs = 0;
    for (int i = 0; i < numattr; i++) if (attrs[i].errcode) nerrs++;

    size_t resp_size = 2 + nvec_len;
    u_char *resp = ngx_palloc(pool, resp_size);
    if (resp == NULL) {
        return xrootd_send_error(ctx, c, kXR_NoMemory, "out of memory");
    }
    resp[0] = (u_char) nerrs;
    resp[1] = (u_char) numattr;
    ngx_memcpy(resp + 2, nvec_copy, nvec_len);

    XROOTD_OP_OK(ctx, XROOTD_OP_FATTR);
    return xrootd_send_ok(ctx, c, resp, (uint32_t) resp_size);
}

/* ------------------------------------------------------------------ */
/* kXR_fattrList                                                        */
/* ------------------------------------------------------------------ */

static ngx_int_t
fattr_list(xrootd_ctx_t *ctx, ngx_connection_t *c,
           const char *path, int fd, int options)
{
    ngx_pool_t *pool = c->pool;
    int aData = (options & kXR_fa_aData);

    /* Get total size of the xattr name list */
    ssize_t list_sz = path ? listxattr(path, NULL, 0)
                           : flistxattr(fd,   NULL, 0);
    if (list_sz < 0) {
        if (errno == ENOTSUP || errno == EOPNOTSUPP) {
            XROOTD_OP_OK(ctx, XROOTD_OP_FATTR);
            return xrootd_send_ok(ctx, c, NULL, 0);
        }
        XROOTD_OP_ERR(ctx, XROOTD_OP_FATTR);
        return xrootd_send_error(ctx, c, kXR_FSError, "listxattr failed");
    }
    if (list_sz == 0) {
        XROOTD_OP_OK(ctx, XROOTD_OP_FATTR);
        return xrootd_send_ok(ctx, c, NULL, 0);
    }

    char *raw = ngx_palloc(pool, list_sz + 4096);
    if (raw == NULL) {
        return xrootd_send_error(ctx, c, kXR_NoMemory, "out of memory");
    }

    ssize_t actual = path ? listxattr(path, raw, list_sz + 4096)
                          : flistxattr(fd,   raw, list_sz + 4096);
    if (actual < 0) {
        return xrootd_send_error(ctx, c, kXR_FSError, "listxattr failed");
    }
    if (actual == 0) {
        XROOTD_OP_OK(ctx, XROOTD_OP_FATTR);
        return xrootd_send_ok(ctx, c, NULL, 0);
    }

    /*
     * Estimate response buffer: each xattr name max 255 bytes in "U.name\0"
     * form; with aData, add 4 + max value size per entry.
     */
    size_t resp_cap = (size_t) actual + kXR_faMaxVars * (4 + 4096) + 64;
    u_char *resp = ngx_palloc(pool, resp_cap);
    if (resp == NULL) {
        return xrootd_send_error(ctx, c, kXR_NoMemory, "out of memory");
    }

    u_char *wp   = resp;
    char   *lp   = raw;
    char   *lend = raw + actual;

    while (lp < lend) {
        size_t full_nlen = strlen(lp);

        /* Only expose our U. namespace (Linux key "user.U.name") */
        if (strncmp(lp, XROOTD_FATTR_XKEY_PFX, XROOTD_FATTR_XKEY_PFX_LEN) == 0
            && full_nlen > XROOTD_FATTR_XKEY_PFX_LEN)
        {
            /* Response name: strip "user." → keep "U.name" */
            const char *resp_name = lp + 5;  /* skip "user." */
            size_t      resp_nlen = full_nlen - 5;

            /* Safety check: don't overflow response buffer */
            size_t space_needed = resp_nlen + 1
                                  + (aData ? 4 + 4096 : 0);
            if ((size_t)(wp - resp) + space_needed > resp_cap) break;

            ngx_memcpy(wp, resp_name, resp_nlen);
            wp += resp_nlen;
            *wp++ = '\0';

            if (aData) {
                char    val[4096];
                ssize_t vlen = path ? getxattr(path, lp, val, sizeof(val))
                                    : fgetxattr(fd,   lp, val, sizeof(val));
                if (vlen < 0) vlen = 0;
                uint32_t vlen_be = htonl((uint32_t) vlen);
                ngx_memcpy(wp, &vlen_be, 4);
                wp += 4;
                if (vlen > 0) {
                    ngx_memcpy(wp, val, vlen);
                    wp += vlen;
                }
            }
        }
        lp += full_nlen + 1;
    }

    XROOTD_OP_OK(ctx, XROOTD_OP_FATTR);
    size_t resp_len = (size_t)(wp - resp);
    if (resp_len == 0) {
        return xrootd_send_ok(ctx, c, NULL, 0);
    }
    return xrootd_send_ok(ctx, c, resp, (uint32_t) resp_len);
}

/* ------------------------------------------------------------------ */
/* Main dispatch                                                         */
/* ------------------------------------------------------------------ */

ngx_int_t
xrootd_handle_fattr(xrootd_ctx_t *ctx, ngx_connection_t *c,
                    ngx_stream_xrootd_srv_conf_t *conf)
{
    ClientFattrRequest *req = (ClientFattrRequest *) ctx->hdr_buf;
    int   subcode  = req->subcode;
    int   numattr  = req->numattr;
    int   options  = req->options;
    char  resolved[PATH_MAX];
    char  pathbuf[XROOTD_MAX_PATH + 1];
    const char *path = NULL;
    int   fd = -1;
    u_char *args_buf = NULL;
    size_t  args_len = 0;

    if (subcode > kXR_fattrMaxSC) {
        return xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                 "fattr: invalid subcode");
    }
    if (subcode == kXR_fattrList) {
        if (numattr != 0) {
            return xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                     "fattr list: numattr must be 0");
        }
    } else {
        if (numattr == 0 || numattr > kXR_faMaxVars) {
            return xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                     "fattr: invalid numattr");
        }
    }

    /* Write operations require allow_write */
    if ((subcode == kXR_fattrSet || subcode == kXR_fattrDel)
        && !conf->allow_write)
    {
        XROOTD_OP_ERR(ctx, XROOTD_OP_FATTR);
        return xrootd_send_error(ctx, c, kXR_fsReadOnly,
                                 "fattr: server is read-only");
    }

    /* Determine path-based vs handle-based and locate the args buffer */
    if (ctx->cur_dlen == 0) {
        /* Handle-based, no payload (only valid for list) */
        if (subcode != kXR_fattrList) {
            return xrootd_send_error(ctx, c, kXR_ArgMissing,
                                     "fattr: missing arguments");
        }
        int idx = (int)(unsigned char) req->fhandle[0];
        if (idx < 0 || idx >= XROOTD_MAX_FILES || ctx->files[idx].fd < 0) {
            XROOTD_OP_ERR(ctx, XROOTD_OP_FATTR);
            return xrootd_send_error(ctx, c, kXR_FileNotOpen,
                                     "fattr: invalid file handle");
        }
        fd   = ctx->files[idx].fd;
        path = NULL;

    } else if (ctx->payload != NULL && ctx->payload[0] == 0) {
        /* Handle-based with payload (leading 0x00 byte) */
        int idx = (int)(unsigned char) req->fhandle[0];
        if (idx < 0 || idx >= XROOTD_MAX_FILES || ctx->files[idx].fd < 0) {
            XROOTD_OP_ERR(ctx, XROOTD_OP_FATTR);
            return xrootd_send_error(ctx, c, kXR_FileNotOpen,
                                     "fattr: invalid file handle");
        }
        fd   = ctx->files[idx].fd;
        path = NULL;
        if (ctx->cur_dlen > 1) {
            args_buf = ctx->payload + 1;
            args_len = ctx->cur_dlen - 1;
        }

    } else {
        /* Path-based */
        if (ctx->payload == NULL || ctx->cur_dlen == 0) {
            return xrootd_send_error(ctx, c, kXR_ArgMissing,
                                     "fattr: missing path");
        }

        /*
         * The payload is [path\0][nvec...].  xrootd_extract_path rejects any
         * payload with an embedded NUL (it expects NUL at the very last byte),
         * so we must compute the path wire length first and pass only the
         * path portion.  strnlen stops at the first NUL or at cur_dlen if
         * no NUL is found.
         */
        size_t path_wire_len = strnlen((char *) ctx->payload, ctx->cur_dlen);
        /* path_wire_len+1 bytes: path bytes + their null terminator */
        size_t path_payload_len = path_wire_len + 1;

        if (!xrootd_extract_path(c->log, ctx->payload, path_payload_len,
                                 pathbuf, sizeof(pathbuf), 1)) {
            XROOTD_OP_ERR(ctx, XROOTD_OP_FATTR);
            return xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                     "fattr: invalid path");
        }
        if (!xrootd_resolve_path(c->log, &conf->root, pathbuf,
                                 resolved, sizeof(resolved))) {
            XROOTD_OP_ERR(ctx, XROOTD_OP_FATTR);
            return xrootd_send_error(ctx, c, kXR_NotFound,
                                     "fattr: file not found");
        }
        if (xrootd_check_vo_acl(c->log, resolved, conf->vo_rules,
                                 ctx->vo_list) != NGX_OK) {
            XROOTD_OP_ERR(ctx, XROOTD_OP_FATTR);
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "fattr: VO not authorized");
        }
        path = resolved;

        if (path_payload_len < ctx->cur_dlen) {
            args_buf = ctx->payload + path_payload_len;
            args_len = ctx->cur_dlen - path_payload_len;
        }
    }

    /* Dispatch list (no nvec needed) */
    if (subcode == kXR_fattrList) {
        return fattr_list(ctx, c, path, fd, options);
    }

    /* get/set/del need a non-empty nvec */
    if (args_buf == NULL || args_len == 0) {
        return xrootd_send_error(ctx, c, kXR_ArgMissing,
                                 "fattr: missing nvec");
    }

    /* Work on a writable copy of the nvec so we can fill in rc fields */
    u_char *nvec_copy = ngx_palloc(c->pool, args_len);
    if (nvec_copy == NULL) {
        return xrootd_send_error(ctx, c, kXR_NoMemory, "out of memory");
    }
    ngx_memcpy(nvec_copy, args_buf, args_len);

    xrootd_fattr_entry_t attrs[kXR_faMaxVars];
    ssize_t nvec_used = fattr_parse_nvec(c->log, nvec_copy, args_len,
                                         numattr, attrs);
    if (nvec_used < 0) {
        return xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                 "fattr: malformed nvec");
    }

    size_t  nvec_len = (size_t) nvec_used;
    u_char *vvec_buf = nvec_copy + nvec_len;
    size_t  vvec_len = args_len - nvec_len;

    switch (subcode) {
    case kXR_fattrGet:
        return fattr_get(ctx, c, path, fd, nvec_copy, nvec_len,
                         numattr, attrs);
    case kXR_fattrSet:
        return fattr_set(ctx, c, path, fd, options,
                         nvec_copy, nvec_len, vvec_buf, vvec_len,
                         numattr, attrs);
    case kXR_fattrDel:
        return fattr_del(ctx, c, path, fd, nvec_copy, nvec_len,
                         numattr, attrs);
    }

    return xrootd_send_error(ctx, c, kXR_Unsupported,
                             "fattr: unknown subcode");
}
