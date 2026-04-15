/*
 * ngx_stream_xrootd_module.c
 *
 * nginx stream module implementing the XRootD root:// protocol.
 * Acts as a kXR_DataServer at the TCP level, with optional write support.
 *
 * Read operations (always available when logged in):
 *   handshake / protocol negotiation
 *   kXR_protocol   — negotiate capabilities and security mode
 *   kXR_login      — accept username; triggers GSI auth when configured
 *   kXR_auth       — GSI/x509 proxy certificate authentication
 *   kXR_ping       — liveness check
 *   kXR_stat       — path-based and handle-based stat
 *   kXR_open       — open files for reading or writing
 *   kXR_read       — read file data (chunked with kXR_oksofar)
 *   kXR_readv      — scatter-gather vector read (up to 1024 segments)
 *   kXR_close      — close an open handle (logs throughput)
 *   kXR_dirlist    — list a directory (with optional kXR_dstat per-entry stat)
 *   kXR_query      — kXR_Qcksum (adler32), kXR_Qspace (statvfs), kXR_Qconfig
 *   kXR_endsess    — graceful session termination
 *
 * Write operations (require xrootd_allow_write on):
 *   kXR_pgwrite    — paged write with CRC32c integrity (used by xrdcp v5)
 *   kXR_write      — raw write at offset (v3/v4 clients)
 *   kXR_sync       — fsync an open handle
 *   kXR_truncate   — truncate by path or open handle
 *   kXR_mkdir      — create directory; recursive with kXR_mkdirpath
 *   kXR_rmdir      — remove an empty directory
 *   kXR_rm         — remove a file
 *   kXR_mv         — rename/move a file or directory
 *   kXR_chmod      — change permission bits
 *
 * -------------------------------------------------------------------------
 * Build
 * -------------------------------------------------------------------------
 *
 *   ./configure --with-stream --add-module=/path/to/nginx-xrootd
 *   make && make install
 */

#include "ngx_xrootd_module.h"

/* ------------------------------------------------------------------ */
/* Module directives                                                    */
/* ------------------------------------------------------------------ */

static ngx_conf_enum_t xrootd_auth_modes[] = {
    { ngx_string("none"), XROOTD_AUTH_NONE },
    { ngx_string("gsi"),  XROOTD_AUTH_GSI  },
    { ngx_null_string,    0                }
};

static ngx_command_t ngx_stream_xrootd_commands[] = {

    { ngx_string("xrootd"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_stream_xrootd_enable,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, enable),
      NULL },

    { ngx_string("xrootd_root"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, root),
      NULL },

    { ngx_string("xrootd_auth"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, auth),
      xrootd_auth_modes },

    { ngx_string("xrootd_certificate"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, certificate),
      NULL },

    { ngx_string("xrootd_certificate_key"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, certificate_key),
      NULL },

    { ngx_string("xrootd_trusted_ca"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, trusted_ca),
      NULL },

    { ngx_string("xrootd_allow_write"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, allow_write),
      NULL },

    { ngx_string("xrootd_access_log"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, access_log),
      NULL },

#if (NGX_THREADS)
    { ngx_string("xrootd_thread_pool"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, thread_pool_name),
      NULL },
#endif

    ngx_null_command
};

/* ------------------------------------------------------------------ */
/* Module context                                                       */
/* ------------------------------------------------------------------ */

static ngx_stream_module_t ngx_stream_xrootd_module_ctx = {
    NULL,                                 /* preconfiguration  */
    ngx_stream_xrootd_postconfiguration,  /* postconfiguration */
    NULL,                                 /* create main conf  */
    NULL,                                 /* init main conf    */
    ngx_stream_xrootd_create_srv_conf,    /* create srv conf   */
    ngx_stream_xrootd_merge_srv_conf,     /* merge srv conf    */
};

/* ------------------------------------------------------------------ */
/* Module definition                                                    */
/* ------------------------------------------------------------------ */

ngx_module_t ngx_stream_xrootd_module = {
    NGX_MODULE_V1,
    &ngx_stream_xrootd_module_ctx,
    ngx_stream_xrootd_commands,
    NGX_STREAM_MODULE,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NGX_MODULE_V1_PADDING
};
