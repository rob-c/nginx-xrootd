#pragma once

/*
 * ngx_xrootd_module.h
 *
 * Shared internal header for the nginx XRootD stream module.
 * Included by all .c files in the module.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <fcntl.h>
#include <dirent.h>
#include <limits.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/params.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>

#include "xrootd_protocol.h"
#include "ngx_xrootd_metrics.h"

#if (NGX_THREADS)
#include <ngx_thread_pool.h>
#endif

/* ------------------------------------------------------------------ */
/* Module forward declaration                                           */
/* ------------------------------------------------------------------ */

extern ngx_module_t ngx_stream_xrootd_module;

/* ------------------------------------------------------------------ */
/* Tunables                                                             */
/* ------------------------------------------------------------------ */

/*
 * Maximum file data returned per kXR_read response.
 * XRootD clients typically request ≤2 MB chunks; we cap at 4 MB.
 */
#define XROOTD_READ_MAX      (4 * 1024 * 1024)

/* Maximum simultaneously open files per connection */
#define XROOTD_MAX_FILES     16

/* Maximum path length accepted from a client */
#define XROOTD_MAX_PATH      4096

/*
 * Maximum write payload per request.  xrdcp v5 uses 8 MiB chunks by default;
 * each pgwrite payload adds 4-byte CRC per 4096-byte page ≈ 0.1% overhead.
 * We cap at 16 MiB to accommodate non-default chunk sizes with headroom.
 */
#define XROOTD_MAX_WRITE_PAYLOAD  (16 * 1024 * 1024)

/* TCP receive buffer (sized to hold the largest expected request) */
#define XROOTD_RECV_BUF      (XROOTD_MAX_PATH + XRD_REQUEST_HDR_LEN + 64)

/* Increment a per-operation metric counter.  No-ops when metrics are disabled. */
#define XROOTD_OP_OK(ctx, op)  \
    do { if ((ctx)->metrics) { \
        ngx_atomic_fetch_add(&(ctx)->metrics->op_ok[(op)], 1); \
    } } while (0)

#define XROOTD_OP_ERR(ctx, op) \
    do { if ((ctx)->metrics) { \
        ngx_atomic_fetch_add(&(ctx)->metrics->op_err[(op)], 1); \
    } } while (0)

/* ------------------------------------------------------------------ */
/* Per-connection state machine                                         */
/* ------------------------------------------------------------------ */

/*
 * Per-connection state machine states.
 *
 * Normal flow:
 *   HANDSHAKE → REQ_HEADER → REQ_PAYLOAD (if dlen > 0) → REQ_HEADER → …
 *
 * SENDING: entered when xrootd_queue_response_base() gets EAGAIN from
 *   c->send().  The remaining bytes are stored in ctx->wbuf and the write
 *   event is armed.
 *
 * AIO: entered when a pread(2)/pwrite(2) is posted to the thread pool.
 */
typedef enum {
    XRD_ST_HANDSHAKE,   /* accumulating the 20-byte client hello  */
    XRD_ST_REQ_HEADER,  /* accumulating a 24-byte request header  */
    XRD_ST_REQ_PAYLOAD, /* accumulating dlen bytes of payload     */
    XRD_ST_SENDING,     /* draining a large pending write buffer  */
    XRD_ST_AIO,         /* async file I/O posted to thread pool   */
} xrootd_state_t;

/* ------------------------------------------------------------------ */
/* Per-open-file bookkeeping                                            */
/* ------------------------------------------------------------------ */

typedef struct {
    int        fd;                 /* OS file descriptor; -1 = slot unused */
    char       path[PATH_MAX];     /* resolved absolute path               */
    size_t     bytes_read;         /* bytes successfully read from this handle */
    size_t     bytes_written;      /* bytes successfully written to this handle */
    ngx_msec_t open_time;          /* ngx_current_msec when file was opened */
    int        writable;           /* 1 if opened for writing, 0 if read-only */
} xrootd_file_t;

/* ------------------------------------------------------------------ */
/* Per-connection context                                               */
/* ------------------------------------------------------------------ */

typedef struct {
    ngx_stream_session_t  *session;
    xrootd_state_t         state;

    /* Input accumulation for handshake / request header */
    u_char     hdr_buf[24];
    size_t     hdr_pos;       /* bytes accumulated so far */

    /* Parsed fields from the most recent 24-byte request header */
    u_char     cur_streamid[2];
    uint16_t   cur_reqid;     /* host byte order */
    u_char     cur_body[16];  /* request-specific parameter bytes */
    uint32_t   cur_dlen;      /* payload length, host byte order */

    /* Payload buffer */
    u_char    *payload;       /* allocated from pool */
    size_t     payload_pos;   /* bytes accumulated so far */

    /* Session */
    u_char     sessid[XROOTD_SESSION_ID_LEN];
    ngx_flag_t logged_in;    /* kXR_login received */
    ngx_flag_t auth_done;    /* authentication completed */
    char       dn[512];      /* authenticated subject DN (GSI), or empty */

    /* Open file table; index 0..XROOTD_MAX_FILES-1 is the handle number */
    xrootd_file_t  files[XROOTD_MAX_FILES];

    /* Pending write queue (one buffer at a time) */
    u_char    *wbuf;          /* allocated from pool */
    size_t     wbuf_len;
    size_t     wbuf_pos;
    u_char    *wbuf_base;     /* base of wbuf allocation */

    /* GSI handshake state */
    EVP_PKEY  *gsi_dh_key;   /* freed after kXGC_cert processing */

    /* Per-request timing */
    ngx_msec_t  req_start;

    /* Session-level transfer accounting */
    size_t      session_bytes;
    size_t      session_bytes_written;
    ngx_msec_t  session_start;

    /* Pointer into shared metrics slot for this connection's server */
    ngx_xrootd_srv_metrics_t  *metrics;

    /* Async I/O guard */
    ngx_uint_t                  destroyed;

} xrootd_ctx_t;

/* ------------------------------------------------------------------ */
/* Module configuration                                                 */
/* ------------------------------------------------------------------ */

#define XROOTD_AUTH_NONE   0   /* no authentication required (anonymous) */
#define XROOTD_AUTH_GSI    1   /* GSI/x509 authentication required       */

typedef struct {
    ngx_flag_t  enable;
    ngx_str_t   root;
    ngx_uint_t  auth;

    /* GSI certificate paths */
    ngx_str_t   certificate;
    ngx_str_t   certificate_key;
    ngx_str_t   trusted_ca;

    /* Loaded OpenSSL objects */
    X509        *gsi_cert;
    EVP_PKEY    *gsi_key;
    X509_STORE  *gsi_store;
    uint32_t     gsi_ca_hash;

    /* Write support */
    ngx_flag_t   allow_write;

    /* Access logging */
    ngx_str_t    access_log;
    ngx_fd_t     access_log_fd;

    /* Prometheus metrics */
    ngx_int_t    metrics_slot;

#if (NGX_THREADS)
    ngx_thread_pool_t  *thread_pool;
    ngx_str_t           thread_pool_name;
#endif
} ngx_stream_xrootd_srv_conf_t;

/* ------------------------------------------------------------------ */
/* Forward declarations                                                 */
/* ------------------------------------------------------------------ */

/* ngx_xrootd_config.c */
void *ngx_stream_xrootd_create_srv_conf(ngx_conf_t *cf);
char *ngx_stream_xrootd_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child);
char *ngx_stream_xrootd_enable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
ngx_int_t ngx_stream_xrootd_postconfiguration(ngx_conf_t *cf);
ngx_int_t ngx_xrootd_metrics_shm_init(ngx_shm_zone_t *shm_zone, void *data);

/* ngx_xrootd_connection.c */
void ngx_stream_xrootd_handler(ngx_stream_session_t *s);
void ngx_stream_xrootd_recv(ngx_event_t *rev);
void ngx_stream_xrootd_send(ngx_event_t *wev);
ngx_int_t xrootd_queue_response_base(xrootd_ctx_t *ctx, ngx_connection_t *c,
    u_char *buf, size_t len, u_char *base);
ngx_int_t xrootd_queue_response(xrootd_ctx_t *ctx, ngx_connection_t *c,
    u_char *buf, size_t len);
ngx_int_t xrootd_flush_pending(xrootd_ctx_t *ctx, ngx_connection_t *c);
void xrootd_on_disconnect(xrootd_ctx_t *ctx, ngx_connection_t *c);
void xrootd_close_all_files(xrootd_ctx_t *ctx);
int  xrootd_alloc_fhandle(xrootd_ctx_t *ctx);
void xrootd_free_fhandle(xrootd_ctx_t *ctx, int idx);

/* ngx_xrootd_handshake.c */
ngx_int_t xrootd_process_handshake(xrootd_ctx_t *ctx, ngx_connection_t *c);
ngx_int_t xrootd_dispatch(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);

/* ngx_xrootd_session.c */
ngx_int_t xrootd_handle_protocol(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);
ngx_int_t xrootd_handle_login(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);
ngx_int_t xrootd_handle_ping(xrootd_ctx_t *ctx, ngx_connection_t *c);
ngx_int_t xrootd_handle_endsess(xrootd_ctx_t *ctx, ngx_connection_t *c);

/* ngx_xrootd_gsi.c */
int gsi_find_bucket(const u_char *payload, size_t plen,
    uint32_t target_type, const u_char **data_out, size_t *len_out);
STACK_OF(X509) *xrootd_gsi_parse_x509(xrootd_ctx_t *ctx, ngx_connection_t *c);
ngx_int_t xrootd_handle_auth(xrootd_ctx_t *ctx, ngx_connection_t *c);

/* ngx_xrootd_read_handlers.c */
ngx_int_t xrootd_handle_stat(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);
ngx_int_t xrootd_handle_open(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);
ngx_int_t xrootd_handle_read(xrootd_ctx_t *ctx, ngx_connection_t *c);
ngx_int_t xrootd_handle_readv(xrootd_ctx_t *ctx, ngx_connection_t *c);
ngx_int_t xrootd_handle_close(xrootd_ctx_t *ctx, ngx_connection_t *c);
ngx_int_t xrootd_handle_dirlist(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);
ngx_int_t xrootd_handle_query(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);

/* ngx_xrootd_write_handlers.c */
ngx_int_t xrootd_handle_write(xrootd_ctx_t *ctx, ngx_connection_t *c);
ngx_int_t xrootd_handle_pgwrite(xrootd_ctx_t *ctx, ngx_connection_t *c);
ngx_int_t xrootd_handle_sync(xrootd_ctx_t *ctx, ngx_connection_t *c);
ngx_int_t xrootd_handle_truncate(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);
ngx_int_t xrootd_handle_mkdir(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);
ngx_int_t xrootd_handle_rm(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);
ngx_int_t xrootd_handle_rmdir(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);
ngx_int_t xrootd_handle_mv(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);
ngx_int_t xrootd_handle_chmod(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);

/* ngx_xrootd_response.c */
void xrootd_build_resp_hdr(const u_char *streamid, uint16_t status,
    uint32_t dlen, ServerResponseHdr *out);
ngx_int_t xrootd_send_ok(xrootd_ctx_t *ctx, ngx_connection_t *c,
    const void *body, uint32_t bodylen);
ngx_int_t xrootd_send_error(xrootd_ctx_t *ctx, ngx_connection_t *c,
    uint16_t errcode, const char *msg);
ngx_int_t xrootd_send_pgwrite_status(xrootd_ctx_t *ctx,
    ngx_connection_t *c, int64_t write_offset);

/* ngx_xrootd_path.c */
size_t xrootd_sanitize_log_string(const char *in, char *out, size_t outsz);
int  xrootd_resolve_path_noexist(ngx_log_t *log, const ngx_str_t *root,
    const char *reqpath, char *resolved, size_t resolvsz);
int  xrootd_resolve_path(ngx_log_t *log, const ngx_str_t *root,
    const char *reqpath, char *resolved, size_t resolvsz);
int  xrootd_resolve_path_write(ngx_log_t *log, const ngx_str_t *root,
    const char *reqpath, char *resolved, size_t resolvsz);
int  xrootd_extract_path(ngx_log_t *log, const u_char *payload,
    size_t payload_len, char *out, size_t outsz, ngx_flag_t strip_cgi);
int  xrootd_mkdir_recursive(const char *path, mode_t mode);
void xrootd_strip_cgi(const char *in, char *out, size_t outsz);
void xrootd_make_stat_body(const struct stat *st, ngx_flag_t is_vfs,
    char *out, size_t outsz);
void xrootd_log_access(xrootd_ctx_t *ctx, ngx_connection_t *c,
    const char *verb, const char *path, const char *detail,
    ngx_uint_t xrd_ok, uint16_t errcode, const char *errmsg, size_t bytes);

/* ngx_xrootd_aio.c — AIO response builders (used by read/write handlers) */
u_char *xrootd_build_read_response(xrootd_ctx_t *ctx, ngx_connection_t *c,
    u_char *databuf, size_t data_total, size_t *rsp_total_out);
u_char *xrootd_build_readv_response(xrootd_ctx_t *ctx, ngx_connection_t *c,
    u_char *databuf, size_t rsp_total, size_t *out_size);

#if (NGX_THREADS)

/* AIO task context structs — shared between aio.c and the handler files */

typedef struct {
    ngx_connection_t              *c;
    xrootd_ctx_t                  *ctx;
    ngx_stream_xrootd_srv_conf_t  *conf;
    int       fd;
    int       handle_idx;
    off_t     offset;
    size_t    rlen;
    u_char   *databuf;
    u_char    streamid[2];
    ssize_t   nread;
    int       io_errno;
} xrootd_read_aio_t;

typedef struct {
    ngx_connection_t              *c;
    xrootd_ctx_t                  *ctx;
    ngx_stream_xrootd_srv_conf_t  *conf;
    int            fd;
    int            handle_idx;
    off_t          offset;
    const u_char  *data;
    size_t         len;
    u_char         streamid[2];
    char           path[PATH_MAX];
    int64_t        req_offset;
    ngx_uint_t     is_pgwrite;
    ssize_t        nwritten;
    int            io_errno;
    u_char        *payload_to_free;
} xrootd_write_aio_t;

typedef struct {
    int       fd;
    int       handle_idx;
    off_t     offset;
    uint32_t  rlen;
    u_char   *hdr_rlen_ptr;
    u_char   *data_ptr;
} xrootd_readv_seg_desc_t;

typedef struct {
    ngx_connection_t              *c;
    xrootd_ctx_t                  *ctx;
    size_t                         n_segs;
    xrootd_readv_seg_desc_t       *segs;
    u_char                        *databuf;
    u_char  streamid[2];
    size_t  bytes_total;
    size_t  rsp_total;
    int     io_error;
    char    err_msg[64];
} xrootd_readv_aio_t;

void xrootd_aio_resume(ngx_connection_t *c);
void xrootd_read_aio_done(ngx_event_t *ev);
void xrootd_write_aio_done(ngx_event_t *ev);
void xrootd_readv_aio_done(ngx_event_t *ev);
void xrootd_read_aio_thread(void *data, ngx_log_t *log);
void xrootd_write_aio_thread(void *data, ngx_log_t *log);
void xrootd_readv_aio_thread(void *data, ngx_log_t *log);
#endif
