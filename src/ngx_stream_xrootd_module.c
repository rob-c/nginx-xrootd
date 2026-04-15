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
 * ANONYMOUS CONNECTION FLOW
 * -------------------------------------------------------------------------
 *
 *   Client                                              Server
 *   ──────                                              ──────
 *   20-byte handshake (ClientInitHandShake) ──────────>
 *                                           <────────── 8-byte hdr + 8-byte body
 *   kXR_protocol (capability negotiation)  ──────────>
 *                                           <────────── kXR_ok + pval + flags
 *                                                        [+ SecurityInfo if secreqs set]
 *   kXR_login (username)                   ──────────>
 *                                           <────────── kXR_ok + 16-byte sessid
 *   kXR_stat / kXR_open / kXR_dirlist /    ──────────>
 *   kXR_read / kXR_close / kXR_ping        <────────── response
 *   kXR_endsess                            ──────────>
 *                                           <────────── kXR_ok
 *   [TCP close]
 *
 * -------------------------------------------------------------------------
 * GSI / x509 CONNECTION FLOW
 * -------------------------------------------------------------------------
 *
 *   Client                                              Server
 *   ──────                                              ──────
 *   handshake                              ──────────>
 *                                           <────────── handshake response
 *   kXR_protocol (secreqs=1)               ──────────>
 *                                           <────────── kXR_ok + SecurityInfo
 *                                                        (secopt=force, nProt=1, "gsi ")
 *   kXR_login                              ──────────>
 *                                           <────────── kXR_ok + sessid
 *                                                        + "&P=gsi,v:10000,c:ssl,ca:<hash>"
 *   kXR_auth [kXGC_certreq, step=1000]     ──────────>
 *     XrdSutBuffer{ "gsi\0", step=1000,
 *       kXRS_main{ kXRS_rtag(random) } }
 *                                           <────────── kXR_authmore + XrdSutBuffer{
 *                                                          "gsi\0", step=kXGS_cert(2001),
 *                                                          kXRS_puk(DH blob),
 *                                                          kXRS_cipher_alg("aes-256-cbc:..."),
 *                                                          kXRS_md_alg("sha256:sha1"),
 *                                                          kXRS_x509(server cert PEM),
 *                                                          kXRS_main{ kXRS_signed_rtag } }
 *   kXR_auth [kXGC_cert, step=1001]        ──────────>
 *     XrdSutBuffer{ "gsi\0", step=1001,
 *       kXRS_puk(client DH blob),
 *       kXRS_cipher_alg, kXRS_md_alg,
 *       kXRS_main=AES(session_key,
 *         { kXRS_x509(proxy chain PEM),
 *           kXRS_rtag }) }
 *                                           <────────── kXR_ok  (auth complete)
 *   kXR_stat / kXR_open / ...              ──────────>
 *                                           <────────── response
 *
 * See the "GSI Authentication Protocol" block comment near xrootd_handle_auth
 * for detailed wire format documentation and implementation gotchas.
 *
 * -------------------------------------------------------------------------
 * nginx.conf example
 * -------------------------------------------------------------------------
 *
 *   stream {
 *       # Anonymous endpoint
 *       server {
 *           listen 1094;
 *           xrootd on;
 *           xrootd_root /data/store;
 *       }
 *
 *       # GSI/x509 authenticated endpoint
 *       server {
 *           listen 1095;
 *           xrootd on;
 *           xrootd_auth gsi;
 *           xrootd_root /data/store;
 *           xrootd_certificate     /etc/grid-security/hostcert.pem;
 *           xrootd_certificate_key /etc/grid-security/hostkey.pem;
 *           xrootd_trusted_ca      /etc/grid-security/ca.pem;
 *       }
 *   }
 *
 * -------------------------------------------------------------------------
 * Build
 * -------------------------------------------------------------------------
 *
 *   ./configure --with-stream --add-module=/path/to/nginx-xrootd
 *   make && make install
 *
 * -------------------------------------------------------------------------
 * Protocol references
 * -------------------------------------------------------------------------
 *
 *   XRootD Protocol Specification v5.2.0:
 *     https://xrootd.web.cern.ch/doc/dev56/XRdv520.htm
 *   Canonical wire constants:
 *     xrootd/xrootd src/XProtocol/XProtocol.hh
 *   GSI security protocol (source of truth for the auth handshake):
 *     xrootd/xrootd src/XrdSecgsi/ (XrdSecProtocolgsi.cc, XrdCryptosslCipher.cc)
 *   Java reference implementation:
 *     dcache/xrootd4j
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
/* Module forward declaration (defined at bottom of file)              */
/* ------------------------------------------------------------------ */

extern ngx_module_t ngx_stream_xrootd_module;

/* ------------------------------------------------------------------ */
/* Tunables                                                             */
/* ------------------------------------------------------------------ */

/*
 * Maximum file data returned per kXR_read response.
 * XRootD clients typically request ≤2 MB chunks; we cap at 4 MB.
 * If rlen > XROOTD_READ_MAX the client will get a short read and MUST
 * retry at offset + bytes_received (standard XRootD client behaviour).
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
 *   event is armed.  ngx_stream_xrootd_recv() returns immediately to avoid
 *   reading a second request while the first response is still in flight.
 *   ngx_stream_xrootd_send() drains wbuf and, when done, resets to
 *   REQ_HEADER and re-invokes ngx_stream_xrootd_recv().
 *
 *   CRITICAL: the write handler must guard against state having already
 *   advanced beyond SENDING (see the comment in ngx_stream_xrootd_send).
 *
 * AIO: entered when a pread(2)/pwrite(2) is posted to the thread pool.
 *   The module keeps accepting incoming TCP data so the client's kernel
 *   send buffer does not fill and stall the connection, but it does not
 *   dispatch any new XRootD requests.  When the thread finishes, the
 *   completion handler (xrootd_read_aio_done / xrootd_write_aio_done)
 *   builds and queues the response, then calls xrootd_aio_resume() which
 *   posts a read event so the loop re-enters without waiting for epoll.
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
    char       path[PATH_MAX];     /* resolved absolute path (for fhandle stat) */
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
    ngx_flag_t auth_done;    /* authentication completed (always 1 when auth=none) */
    char       dn[512];      /* authenticated subject DN (GSI), or empty */

    /* Open file table; index 0..XROOTD_MAX_FILES-1 is the handle number */
    xrootd_file_t  files[XROOTD_MAX_FILES];

    /* Pending write queue (one buffer at a time) */
    u_char    *wbuf;          /* allocated from pool */
    size_t     wbuf_len;
    size_t     wbuf_pos;
    u_char    *wbuf_base;     /* base of wbuf allocation (for ngx_pfree after drain) */

    /* GSI handshake state: ephemeral DH key kept from kXGS_cert until kXGC_cert */
    EVP_PKEY  *gsi_dh_key;   /* freed after kXGC_cert processing */

    /* Per-request timing: set at the top of xrootd_dispatch() so every
     * handler can report how long its request took in the access log. */
    ngx_msec_t  req_start;

    /* Session-level transfer accounting (for DISCONNECT summary line) */
    size_t      session_bytes;         /* cumulative bytes transferred this session */
    size_t      session_bytes_written; /* cumulative bytes written this session     */
    ngx_msec_t  session_start;         /* ngx_current_msec at LOGIN                 */

    /* Pointer into shared metrics slot for this connection's server */
    ngx_xrootd_srv_metrics_t  *metrics;

    /* Async I/O guard: set to 1 when the connection is being torn down so
     * thread-pool completion handlers know to skip response delivery. */
    ngx_uint_t                  destroyed;

} xrootd_ctx_t;

/* ------------------------------------------------------------------ */
/* Module configuration                                                 */
/* ------------------------------------------------------------------ */

/* xrootd_auth directive values */
#define XROOTD_AUTH_NONE   0   /* no authentication required (anonymous) */
#define XROOTD_AUTH_GSI    1   /* GSI/x509 authentication required       */

typedef struct {
    ngx_flag_t  enable;
    ngx_str_t   root;              /* local filesystem root directory    */
    ngx_uint_t  auth;              /* XROOTD_AUTH_NONE or XROOTD_AUTH_GSI */

    /* GSI certificate paths (set via directives) */
    ngx_str_t   certificate;       /* path to hostcert.pem               */
    ngx_str_t   certificate_key;   /* path to hostkey.pem                */
    ngx_str_t   trusted_ca;        /* path to ca.pem                     */

    /* Loaded OpenSSL objects — initialised in postconfiguration          */
    X509        *gsi_cert;         /* server certificate                 */
    EVP_PKEY    *gsi_key;          /* server private key                 */
    X509_STORE  *gsi_store;        /* trusted CA verification store      */
    uint32_t     gsi_ca_hash;      /* CA subject hash for kXRS_issuer_hash */

    /* Write support                                                       */
    ngx_flag_t   allow_write;      /* xrootd_allow_write on|off (def: off) */

    /* Access logging                                                     */
    ngx_str_t    access_log;       /* path from xrootd_access_log directive */
    ngx_fd_t     access_log_fd;    /* opened O_WRONLY|O_APPEND file, or
                                    * NGX_INVALID_FILE when not configured  */

    /* Prometheus metrics — index into the shared memory server array */
    ngx_int_t    metrics_slot;    /* -1 = not assigned                  */

#if (NGX_THREADS)
    /* Async file I/O thread pool (resolved in postconfiguration) */
    ngx_thread_pool_t  *thread_pool;        /* NULL = sync fallback   */
    ngx_str_t           thread_pool_name;   /* default: "default"     */
#endif
} ngx_stream_xrootd_srv_conf_t;

/* ------------------------------------------------------------------ */
/* Forward declarations                                                 */
/* ------------------------------------------------------------------ */

static void *ngx_stream_xrootd_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_xrootd_merge_srv_conf(ngx_conf_t *cf,
    void *parent, void *child);
static char *ngx_stream_xrootd_enable(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_stream_xrootd_postconfiguration(ngx_conf_t *cf);
static ngx_int_t ngx_xrootd_metrics_shm_init(ngx_shm_zone_t *shm_zone, void *data);

static void ngx_stream_xrootd_handler(ngx_stream_session_t *s);
static void ngx_stream_xrootd_recv(ngx_event_t *rev);
static void ngx_stream_xrootd_send(ngx_event_t *wev);

static ngx_int_t xrootd_queue_response(xrootd_ctx_t *ctx,
    ngx_connection_t *c, u_char *buf, size_t len);
static ngx_int_t xrootd_flush_pending(xrootd_ctx_t *ctx,
    ngx_connection_t *c);

/* GSI helpers — defined later in this file */
static int gsi_find_bucket(const u_char *payload, size_t plen,
    uint32_t target_type,
    const u_char **data_out, size_t *len_out);
static STACK_OF(X509) *xrootd_gsi_parse_x509(xrootd_ctx_t *ctx,
    ngx_connection_t *c);

static ngx_int_t xrootd_process_handshake(xrootd_ctx_t *ctx,
    ngx_connection_t *c);
static ngx_int_t xrootd_dispatch(xrootd_ctx_t *ctx,
    ngx_connection_t *c, ngx_stream_xrootd_srv_conf_t *conf);

static ngx_int_t xrootd_handle_protocol(xrootd_ctx_t *ctx,
    ngx_connection_t *c, ngx_stream_xrootd_srv_conf_t *conf);
static ngx_int_t xrootd_handle_login(xrootd_ctx_t *ctx,
    ngx_connection_t *c, ngx_stream_xrootd_srv_conf_t *conf);
static ngx_int_t xrootd_handle_auth(xrootd_ctx_t *ctx,
    ngx_connection_t *c);
static ngx_int_t xrootd_handle_ping(xrootd_ctx_t *ctx,
    ngx_connection_t *c);
static ngx_int_t xrootd_handle_stat(xrootd_ctx_t *ctx,
    ngx_connection_t *c, ngx_stream_xrootd_srv_conf_t *conf);
static ngx_int_t xrootd_handle_open(xrootd_ctx_t *ctx,
    ngx_connection_t *c, ngx_stream_xrootd_srv_conf_t *conf);
static ngx_int_t xrootd_handle_read(xrootd_ctx_t *ctx,
    ngx_connection_t *c);
static ngx_int_t xrootd_handle_close(xrootd_ctx_t *ctx,
    ngx_connection_t *c);
static ngx_int_t xrootd_handle_dirlist(xrootd_ctx_t *ctx,
    ngx_connection_t *c, ngx_stream_xrootd_srv_conf_t *conf);
static ngx_int_t xrootd_handle_endsess(xrootd_ctx_t *ctx,
    ngx_connection_t *c);
static ngx_int_t xrootd_handle_write(xrootd_ctx_t *ctx,
    ngx_connection_t *c);
static ngx_int_t xrootd_handle_pgwrite(xrootd_ctx_t *ctx,
    ngx_connection_t *c);
static ngx_int_t xrootd_handle_sync(xrootd_ctx_t *ctx,
    ngx_connection_t *c);
static ngx_int_t xrootd_handle_truncate(xrootd_ctx_t *ctx,
    ngx_connection_t *c, ngx_stream_xrootd_srv_conf_t *conf);
static ngx_int_t xrootd_handle_mkdir(xrootd_ctx_t *ctx,
    ngx_connection_t *c, ngx_stream_xrootd_srv_conf_t *conf);
static ngx_int_t xrootd_handle_rm(xrootd_ctx_t *ctx,
    ngx_connection_t *c, ngx_stream_xrootd_srv_conf_t *conf);
static ngx_int_t xrootd_handle_rmdir(xrootd_ctx_t *ctx,
    ngx_connection_t *c, ngx_stream_xrootd_srv_conf_t *conf);
static ngx_int_t xrootd_handle_mv(xrootd_ctx_t *ctx,
    ngx_connection_t *c, ngx_stream_xrootd_srv_conf_t *conf);
static ngx_int_t xrootd_handle_chmod(xrootd_ctx_t *ctx,
    ngx_connection_t *c, ngx_stream_xrootd_srv_conf_t *conf);
static ngx_int_t xrootd_handle_query(xrootd_ctx_t *ctx,
    ngx_connection_t *c, ngx_stream_xrootd_srv_conf_t *conf);
static ngx_int_t xrootd_handle_readv(xrootd_ctx_t *ctx,
    ngx_connection_t *c);

static ngx_int_t xrootd_send_ok(xrootd_ctx_t *ctx, ngx_connection_t *c,
    const void *body, uint32_t bodylen);
static ngx_int_t xrootd_send_error(xrootd_ctx_t *ctx,
    ngx_connection_t *c, uint16_t errcode, const char *msg);
static ngx_int_t xrootd_send_pgwrite_status(xrootd_ctx_t *ctx,
    ngx_connection_t *c, int64_t write_offset);

static void xrootd_build_resp_hdr(const u_char *streamid, uint16_t status,
    uint32_t dlen, ServerResponseHdr *out);

static int  xrootd_resolve_path_noexist(ngx_log_t *log,
    const ngx_str_t *root, const char *reqpath,
    char *resolved, size_t resolvsz);
static int  xrootd_resolve_path(ngx_log_t *log,
    const ngx_str_t *root, const char *reqpath,
    char *resolved, size_t resolvsz);
static int  xrootd_resolve_path_write(ngx_log_t *log,
    const ngx_str_t *root, const char *reqpath,
    char *resolved, size_t resolvsz);
static int  xrootd_mkdir_recursive(const char *path, mode_t mode);
static void xrootd_strip_cgi(const char *in, char *out, size_t outsz);
static int  xrootd_alloc_fhandle(xrootd_ctx_t *ctx);
static void xrootd_free_fhandle(xrootd_ctx_t *ctx, int idx);
static void xrootd_close_all_files(xrootd_ctx_t *ctx);
static void xrootd_on_disconnect(xrootd_ctx_t *ctx, ngx_connection_t *c);
static void xrootd_make_stat_body(const struct stat *st, ngx_flag_t is_vfs,
    char *out, size_t outsz);

/* Access logging */
static void xrootd_log_access(xrootd_ctx_t *ctx, ngx_connection_t *c,
    const char *verb, const char *path, const char *detail,
    ngx_uint_t xrd_ok, uint16_t errcode, const char *errmsg, size_t bytes);

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

    /*
     * xrootd_allow_write on|off;
     *
     * When set to "on", the server accepts write operations: kXR_open with
     * write flags (kXR_new, kXR_delete, kXR_open_updt, kXR_open_apnd),
     * kXR_write, kXR_sync, kXR_truncate, kXR_mkdir, and kXR_rm.
     * When set to "off" (the default), any write attempt returns kXR_fsReadOnly.
     *
     * Example:
     *   server {
     *       listen 1094;
     *       xrootd on;
     *       xrootd_root /data/upload;
     *       xrootd_allow_write on;
     *   }
     */
    { ngx_string("xrootd_allow_write"),
      NGX_STREAM_SRV_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, allow_write),
      NULL },

    /*
     * xrootd_access_log /path/to/access.log;
     *
     * Write one log line per XRootD operation (OPEN, READ, STAT, DIRLIST,
     * CLOSE, LOGIN, AUTH, PING) to the specified file.  The file is opened
     * O_WRONLY|O_APPEND|O_CREAT at configuration time and is safe for use
     * by multiple worker processes.  Log rotation: send SIGUSR1 to the
     * nginx master to reopen all log files.
     *
     * Log line format:
     *   <ip> <auth> "<identity>" [<timestamp>] "<verb> <path> <detail>" \
     *   <status> <bytes> <ms>ms ["<errmsg>"]
     *
     * Fields:
     *   ip        — client IP address
     *   auth      — "anon" or "gsi"
     *   identity  — authenticated DN (GSI) or "-"
     *   timestamp — DD/Mon/YYYY:HH:MM:SS +ZZZZ (nginx access-log format)
     *   verb      — OPEN READ STAT DIRLIST CLOSE LOGIN AUTH PING
     *   path      — filesystem path or "-"
     *   detail    — OPEN: mode ("rd"); READ: "offset+len"; LOGIN: username;
     *               AUTH: protocol ("gsi"); others: "-"
     *   status    — "OK" or "ERR"
     *   bytes     — data bytes transferred (0 for non-data operations)
     *   ms        — server-side processing time in milliseconds
     *   errmsg    — error description, omitted on success
     *
     * Example lines:
     *   192.168.1.1 gsi "/DC=org/CN=A.Einstein" [15/Jan/2024:10:23:45 +0000] \
     *     "OPEN /store/mc/data.root rd" OK 0 3ms
     *   192.168.1.1 gsi "/DC=org/CN=A.Einstein" [15/Jan/2024:10:23:45 +0000] \
     *     "READ /store/mc/data.root 0+4194304" OK 4194304 21ms
     *   10.0.0.5 anon "-" [15/Jan/2024:10:23:45 +0000] \
     *     "STAT /" OK 0 1ms
     *   192.168.1.2 gsi "-" [15/Jan/2024:10:23:45 +0000] \
     *     "AUTH gsi -" ERR 0 2ms "certificate verification failed"
     */
    { ngx_string("xrootd_access_log"),
      NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_xrootd_srv_conf_t, access_log),
      NULL },

#if (NGX_THREADS)
    /*
     * xrootd_thread_pool <name>;
     *
     * Name of the thread_pool to use for async file I/O (kXR_read, kXR_write,
     * kXR_pgwrite, kXR_readv).  Must match a thread_pool directive at the main
     * config level.  Defaults to "default" when omitted.
     *
     * Example:
     *   thread_pool xrootd_io threads=8 max_queue=65536;
     *   server { xrootd_thread_pool xrootd_io; }
     */
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

/* ================================================================== */
/*  Configuration management                                            */
/* ================================================================== */

static void *
ngx_stream_xrootd_create_srv_conf(ngx_conf_t *cf)
{
    ngx_stream_xrootd_srv_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_xrootd_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable       = NGX_CONF_UNSET;
    conf->auth         = NGX_CONF_UNSET_UINT;
    conf->allow_write  = NGX_CONF_UNSET;
    conf->gsi_cert     = NULL;
    conf->gsi_key      = NULL;
    conf->gsi_store    = NULL;
    conf->gsi_ca_hash  = 0;
    conf->access_log_fd = NGX_INVALID_FILE;
    conf->metrics_slot = -1;

    return conf;
}

static char *
ngx_stream_xrootd_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_stream_xrootd_srv_conf_t *prev = parent;
    ngx_stream_xrootd_srv_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable,      prev->enable,      0);
    ngx_conf_merge_str_value(conf->root,    prev->root,        "/");
    ngx_conf_merge_uint_value(conf->auth,   prev->auth,        XROOTD_AUTH_NONE);
    ngx_conf_merge_value(conf->allow_write, prev->allow_write, 0);
    ngx_conf_merge_str_value(conf->certificate,     prev->certificate,     "");
    ngx_conf_merge_str_value(conf->certificate_key, prev->certificate_key, "");
    ngx_conf_merge_str_value(conf->trusted_ca,      prev->trusted_ca,      "");
    ngx_conf_merge_str_value(conf->access_log,      prev->access_log,      "");

    return NGX_CONF_OK;
}

/*
 * ngx_stream_xrootd_enable — handler for the "xrootd on|off;" directive.
 * When enabled, installs ourselves as the stream content handler so we
 * take over the TCP connection after the session is established.
 */
static char *
ngx_stream_xrootd_enable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_xrootd_srv_conf_t *xcf = conf;
    ngx_stream_core_srv_conf_t   *cscf;
    char                         *rv;

    rv = ngx_conf_set_flag_slot(cf, cmd, conf);
    if (rv != NGX_CONF_OK) {
        return rv;
    }

    if (!xcf->enable) {
        return NGX_CONF_OK;
    }

    cscf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_core_module);
    cscf->handler = ngx_stream_xrootd_handler;

    return NGX_CONF_OK;
}

/* ================================================================== */
/*  Post-configuration: load GSI certificates                          */
/* ================================================================== */

/*
 * ngx_stream_xrootd_postconfiguration
 *
 * Called after the configuration is fully parsed.  For every server
 * block that has xrootd_auth gsi, load the host certificate, private
 * key, and trusted CA into OpenSSL objects so they are ready for use
 * at request time without re-reading disk per connection.
 *
 * We walk the stream server blocks via the core module's server array.
 */
static ngx_int_t
ngx_stream_xrootd_postconfiguration(ngx_conf_t *cf)
{
    ngx_stream_core_main_conf_t   *cmcf;
    ngx_stream_core_srv_conf_t   **cscfp;
    ngx_stream_xrootd_srv_conf_t  *xcf;
    ngx_uint_t                     i;

    cmcf  = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);
    cscfp = cmcf->servers.elts;

    for (i = 0; i < cmcf->servers.nelts; i++) {
        xcf = ngx_stream_conf_get_module_srv_conf(cscfp[i], ngx_stream_xrootd_module);

        if (!xcf->enable) {
            continue;
        }

        /* Open the access log for this server block (anonymous or GSI alike) */
        if (xcf->access_log.len > 0
            && ngx_strcmp(xcf->access_log.data, (u_char *) "off") != 0)
        {
            xcf->access_log_fd = ngx_open_file(xcf->access_log.data,
                NGX_FILE_WRONLY,
                NGX_FILE_CREATE_OR_OPEN | NGX_FILE_APPEND,
                NGX_FILE_DEFAULT_ACCESS);

            if (xcf->access_log_fd == NGX_INVALID_FILE) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                    "xrootd: cannot open access log \"%s\"",
                    xcf->access_log.data);
                return NGX_ERROR;
            }

            ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                "xrootd: access log \"%s\" opened",
                xcf->access_log.data);
        }

        if (xcf->auth != XROOTD_AUTH_GSI) {
            continue;
        }

        if (xcf->certificate.len == 0 || xcf->certificate_key.len == 0
            || xcf->trusted_ca.len == 0)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "xrootd_auth gsi requires xrootd_certificate, "
                "xrootd_certificate_key and xrootd_trusted_ca");
            return NGX_ERROR;
        }

        /* Load server certificate */
        {
            FILE *fp = fopen((char *) xcf->certificate.data, "r");
            if (fp == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                    "xrootd: cannot open certificate \"%s\"",
                    xcf->certificate.data);
                return NGX_ERROR;
            }
            xcf->gsi_cert = PEM_read_X509(fp, NULL, NULL, NULL);
            fclose(fp);
            if (xcf->gsi_cert == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "xrootd: cannot parse certificate \"%s\"",
                    xcf->certificate.data);
                return NGX_ERROR;
            }
        }

        /* Load server private key */
        {
            FILE *fp = fopen((char *) xcf->certificate_key.data, "r");
            if (fp == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                    "xrootd: cannot open private key \"%s\"",
                    xcf->certificate_key.data);
                return NGX_ERROR;
            }
            xcf->gsi_key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
            fclose(fp);
            if (xcf->gsi_key == NULL) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "xrootd: cannot parse private key \"%s\"",
                    xcf->certificate_key.data);
                return NGX_ERROR;
            }
        }

        /* Build trusted CA X509_STORE */
        {
            FILE  *fp;
            X509  *ca;
            X509_LOOKUP *lookup;

            xcf->gsi_store = X509_STORE_new();
            if (xcf->gsi_store == NULL) {
                return NGX_ERROR;
            }

            /* Allow proxy certs in chain verification */
            X509_STORE_set_flags(xcf->gsi_store,
                                 X509_V_FLAG_ALLOW_PROXY_CERTS);

            lookup = X509_STORE_add_lookup(xcf->gsi_store,
                                           X509_LOOKUP_file());
            if (lookup == NULL) {
                return NGX_ERROR;
            }
            if (!X509_LOOKUP_load_file(lookup,
                                       (char *) xcf->trusted_ca.data,
                                       X509_FILETYPE_PEM))
            {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "xrootd: cannot load trusted CA \"%s\"",
                    xcf->trusted_ca.data);
                return NGX_ERROR;
            }

            /* Compute CA hash (for kXRS_issuer_hash in kXGS_init) */
            fp = fopen((char *) xcf->trusted_ca.data, "r");
            if (fp) {
                ca = PEM_read_X509(fp, NULL, NULL, NULL);
                fclose(fp);
                if (ca) {
                    xcf->gsi_ca_hash = (uint32_t) X509_subject_name_hash(ca);
                    X509_free(ca);
                }
            }
        }

        ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
            "xrootd: GSI auth configured — cert=%s ca_hash=%08x",
            xcf->certificate.data, xcf->gsi_ca_hash);
    }

    /* ---- Prometheus metrics shared memory ---- */
    {
        ngx_str_t   zone_name = ngx_string("xrootd_metrics");
        size_t      zone_size;
        ngx_uint_t  slot = 0;

        zone_size = sizeof(ngx_xrootd_metrics_t) + ngx_pagesize;
        ngx_xrootd_shm_zone = ngx_shared_memory_add(cf, &zone_name,
                                                      zone_size,
                                                      &ngx_stream_xrootd_module);
        if (ngx_xrootd_shm_zone == NULL) {
            return NGX_ERROR;
        }
        ngx_xrootd_shm_zone->init = ngx_xrootd_metrics_shm_init;
        ngx_xrootd_shm_zone->data = (void *) 1; /* mark as configured */

        /* Assign one slot per enabled server block */
        for (i = 0; i < cmcf->servers.nelts; i++) {
            xcf = ngx_stream_conf_get_module_srv_conf(cscfp[i],
                                                       ngx_stream_xrootd_module);
            if (!xcf->enable || slot >= XROOTD_METRICS_MAX_SERVERS) {
                continue;
            }
            xcf->metrics_slot = (ngx_int_t) slot++;
        }
    }

#if (NGX_THREADS)
    /* Resolve the thread pool for each enabled server block.
     * If xrootd_thread_pool was not set, default to "default". */
    {
        static ngx_str_t default_pool_name = ngx_string("default");

        for (i = 0; i < cmcf->servers.nelts; i++) {
            ngx_str_t *pool_name;

            xcf = ngx_stream_conf_get_module_srv_conf(cscfp[i],
                                                       ngx_stream_xrootd_module);
            if (!xcf->enable) {
                continue;
            }

            pool_name = (xcf->thread_pool_name.len > 0)
                        ? &xcf->thread_pool_name
                        : &default_pool_name;

            xcf->thread_pool = ngx_thread_pool_get(cf->cycle, pool_name);
            if (xcf->thread_pool == NULL) {
                ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                    "xrootd: thread pool \"%V\" not found — "
                    "async file I/O disabled (add a thread_pool directive)",
                    pool_name);
            } else {
                ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                    "xrootd: using thread pool \"%V\" for async file I/O",
                    pool_name);
            }
        }
    }
#endif

    return NGX_OK;
}

/*
 * ngx_xrootd_metrics_shm_init — shared memory zone init callback.
 *
 * Called by nginx after the shared memory region is mapped.  We zero
 * the region on first init; on reload (data != NULL) we preserve the
 * existing counters so metrics survive nginx reload without resetting.
 */
static ngx_int_t
ngx_xrootd_metrics_shm_init(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_xrootd_metrics_t *shm;

    if (data) {
        /* Reload: reuse existing counters */
        shm_zone->data = data;
        return NGX_OK;
    }

    shm = (ngx_xrootd_metrics_t *) shm_zone->shm.addr;
    ngx_memzero(shm, sizeof(*shm));
    shm_zone->data = shm;
    return NGX_OK;
}

/* ================================================================== */
/*  Connection entry point                                              */
/* ================================================================== */

/*
 * ngx_stream_xrootd_handler
 *
 * Called by nginx after the TCP connection is accepted and any pre-
 * content phases (access, etc.) have passed.  From here we own the
 * connection and drive the XRootD state machine.
 */
static void
ngx_stream_xrootd_handler(ngx_stream_session_t *s)
{
    ngx_connection_t  *c = s->connection;
    xrootd_ctx_t      *ctx;
    int                i;

    /* Allocate zeroed per-connection context */
    ctx = ngx_pcalloc(c->pool, sizeof(xrootd_ctx_t));
    if (ctx == NULL) {
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ctx->session = s;
    ctx->state   = XRD_ST_HANDSHAKE;
    ctx->hdr_pos = 0;

    /* Mark all file slots as unused */
    for (i = 0; i < XROOTD_MAX_FILES; i++) {
        ctx->files[i].fd = -1;
    }

    /* Generate a pseudo-random 16-byte session id from time + pid + conn */
    {
        uint32_t parts[4];
        parts[0] = (uint32_t) ngx_time();
        parts[1] = (uint32_t) ngx_pid;
        parts[2] = (uint32_t) (uintptr_t) c;
        parts[3] = (uint32_t) ngx_random();
        ngx_memcpy(ctx->sessid, parts, XROOTD_SESSION_ID_LEN);
    }

    ngx_stream_set_ctx(s, ctx, ngx_stream_xrootd_module);

    /* Bind metrics slot for this connection */
    {
        ngx_stream_xrootd_srv_conf_t *mconf;
        mconf = ngx_stream_get_module_srv_conf(s, ngx_stream_xrootd_module);
        if (mconf->metrics_slot >= 0 && ngx_xrootd_shm_zone != NULL
            && ngx_xrootd_shm_zone->data != NULL
            && ngx_xrootd_shm_zone->data != (void *) 1)
        {
            ngx_xrootd_metrics_t     *shm = ngx_xrootd_shm_zone->data;
            ngx_xrootd_srv_metrics_t *srv = &shm->servers[mconf->metrics_slot];
            ctx->metrics = srv;

            /* Populate static metadata on first use */
            if (!srv->in_use) {
                srv->in_use = 1;
                ngx_cpystrn((u_char *) srv->auth,
                            (u_char *) (mconf->auth == 1 ? "gsi" : "anon"),
                            sizeof(srv->auth));
                /* Port: get from local socket address */
                if (c->local_sockaddr) {
                    sa_family_t fam = c->local_sockaddr->sa_family;
                    if (fam == AF_INET) {
                        struct sockaddr_in *sin =
                            (struct sockaddr_in *) c->local_sockaddr;
                        srv->port = ntohs(sin->sin_port);
                    } else if (fam == AF_INET6) {
                        struct sockaddr_in6 *sin6 =
                            (struct sockaddr_in6 *) c->local_sockaddr;
                        srv->port = ntohs(sin6->sin6_port);
                    }
                }
            }

            /* Connection accepted */
            ngx_atomic_fetch_add(&srv->connections_total, 1);
            ngx_atomic_fetch_add(&srv->connections_active, 1);
        }
    }

    /* Install event handlers */
    c->read->handler  = ngx_stream_xrootd_recv;
    c->write->handler = ngx_stream_xrootd_send;

    /* Start reading immediately */
    ngx_stream_xrootd_recv(c->read);
}

/* ================================================================== */
/*  Read event handler                                                  */
/* ================================================================== */

static void
ngx_stream_xrootd_recv(ngx_event_t *rev)
{
    ngx_connection_t              *c;
    ngx_stream_session_t          *s;
    ngx_stream_xrootd_srv_conf_t  *conf;
    xrootd_ctx_t                  *ctx;
    ssize_t                        n;
    ngx_int_t                      rc;

    c    = rev->data;
    s    = c->data;
    ctx  = ngx_stream_get_module_ctx(s, ngx_stream_xrootd_module);
    conf = ngx_stream_get_module_srv_conf(s, ngx_stream_xrootd_module);

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                      "xrootd: client connection timed out");
        xrootd_on_disconnect(ctx, c);
        xrootd_close_all_files(ctx);
        ngx_stream_finalize_session(s, NGX_STREAM_OK);
        return;
    }

    /* Read loop: consume as much data as is available this wakeup */
    for (;;) {

        if (ctx->state == XRD_ST_SENDING) {
            /*
             * We have a pending write; don't try to process more input
             * until the write handler drains it and re-enters us.
             */
            return;
        }

        if (ctx->state == XRD_ST_AIO) {
            /* Async file I/O is in flight.  Buffer any arriving client data
             * but don't process it yet — the completion handler will re-arm
             * the read event once the I/O finishes. */
            if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                goto fatal;
            }
            return;
        }

        /* ---------------------------------------------------------- */
        /* Determine where to put incoming bytes and how many we need  */
        /* ---------------------------------------------------------- */

        u_char *dest;
        size_t  need, avail;

        if (ctx->state == XRD_ST_HANDSHAKE) {
            /* Expecting 20 bytes (ClientInitHandShake) */
            dest  = ctx->hdr_buf + ctx->hdr_pos;
            need  = XRD_HANDSHAKE_LEN - ctx->hdr_pos;

        } else if (ctx->state == XRD_ST_REQ_HEADER) {
            /* Expecting 24 bytes (ClientRequestHdr) */
            dest  = ctx->hdr_buf + ctx->hdr_pos;
            need  = XRD_REQUEST_HDR_LEN - ctx->hdr_pos;

        } else {
            /* XRD_ST_REQ_PAYLOAD: accumulate dlen bytes */
            dest  = ctx->payload + ctx->payload_pos;
            need  = ctx->cur_dlen - ctx->payload_pos;
        }

        if (need == 0) {
            goto process;
        }

        /*
         * Force an actual recv(2) syscall each iteration.
         *
         * nginx uses EPOLLRDHUP edge-triggered epoll.  When the kernel
         * signals a hang-up (RDHUP), nginx sets rev->available = 0 and the
         * c->recv() shim skips the syscall entirely, returning NGX_AGAIN.
         * Setting available = -1 tells the shim to call recv() unconditionally.
         * Without this, connections stall after the client half-closes its
         * write side (which is how xrdcp signals end-of-upload).
         */
        rev->available = -1;
        n = c->recv(c, dest, need);

        if (n == NGX_AGAIN) {
            /* No data right now; wait for the next read event */
            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "xrootd: recv AGAIN st=%d hdr_pos=%uz avail=%d"
                          " ready=%d active=%d",
                          (int)ctx->state, ctx->hdr_pos,
                          rev->available, (int)rev->ready, (int)rev->active);
            if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                goto fatal;
            }
            return;
        }

        if (n == NGX_ERROR || n == 0) {
            /* Connection closed or error */
            ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                           "xrootd: client disconnected");
            xrootd_on_disconnect(ctx, c);
            xrootd_close_all_files(ctx);
            ngx_stream_finalize_session(s, NGX_STREAM_OK);
            return;
        }

        avail = (size_t) n;

        if (ctx->state == XRD_ST_HANDSHAKE) {
            ctx->hdr_pos += avail;
        } else if (ctx->state == XRD_ST_REQ_HEADER) {
            ctx->hdr_pos += avail;
        } else {
            ctx->payload_pos += avail;
        }

        if (avail < need) {
            /* Got a partial buffer; come back when there's more data */
            continue;
        }

process:
        /* We have a full handshake / header / payload to process */

        if (ctx->state == XRD_ST_HANDSHAKE) {

            rc = xrootd_process_handshake(ctx, c);
            if (rc != NGX_OK) {
                goto fatal;
            }
            /* Transition: start expecting request headers */
            ctx->state   = XRD_ST_REQ_HEADER;
            ctx->hdr_pos = 0;

        } else if (ctx->state == XRD_ST_REQ_HEADER) {

            /* Parse the standard 24-byte request header */
            ClientRequestHdr *hdr = (ClientRequestHdr *) ctx->hdr_buf;

            ctx->cur_streamid[0] = hdr->streamid[0];
            ctx->cur_streamid[1] = hdr->streamid[1];
            ctx->cur_reqid       = ntohs(hdr->requestid);
            ngx_memcpy(ctx->cur_body, hdr->body, 16);
            ctx->cur_dlen        = (uint32_t) ntohl(hdr->dlen);

            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "xrootd: req sid=[%02xd%02xd] reqid=%04xd dlen=%uz"
                          " avail=%d ready=%d",
                          (int)ctx->cur_streamid[0], (int)ctx->cur_streamid[1],
                          (int)ctx->cur_reqid, (size_t)ctx->cur_dlen,
                          c->read->available, (int)c->read->ready);

            {
                /* Write payloads (pgwrite/write/writev) can be up to 16 MiB.
                 * All other payloads are paths, tokens, or small metadata. */
                uint32_t max_pl;
                if (ctx->cur_reqid == kXR_pgwrite ||
                    ctx->cur_reqid == kXR_write   ||
                    ctx->cur_reqid == kXR_writev) {
                    max_pl = XROOTD_MAX_WRITE_PAYLOAD;
                } else if (ctx->cur_reqid == kXR_readv) {
                    /* readv payload = up to 1024 readahead_list structs = 16 KiB */
                    max_pl = XROOTD_READV_MAXSEGS * XROOTD_READV_SEGSIZE;
                } else {
                    max_pl = XROOTD_MAX_PATH + 64;
                }
                if (ctx->cur_dlen > max_pl) {
                    ngx_log_error(NGX_LOG_WARN, c->log, 0,
                                  "xrootd: payload too large (%uz), closing",
                                  (size_t) ctx->cur_dlen);
                    goto fatal;
                }
            }

            if (ctx->cur_dlen > 0) {
                /* Allocate a pool buffer and start collecting payload */
                ctx->payload = ngx_palloc(c->pool, ctx->cur_dlen + 1);
                if (ctx->payload == NULL) {
                    goto fatal;
                }
                ctx->payload[ctx->cur_dlen] = '\0'; /* convenient NUL */
                ctx->payload_pos = 0;
                ctx->state       = XRD_ST_REQ_PAYLOAD;
                ctx->hdr_pos     = 0;   /* reset for next header */
                continue;
            }

            /* No payload: dispatch immediately */
            ctx->payload = NULL;
            rc = xrootd_dispatch(ctx, c, conf);
            if (rc == NGX_ERROR) {
                goto fatal;
            }

            /* Reset for next request (dispatch may have set SENDING or AIO) */
            if (ctx->state == XRD_ST_AIO) {
                /* Re-arm the read event so epoll wakes us when the client
                 * sends its next request (after the AIO response is sent). */
                if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                    goto fatal;
                }
                return;   /* async I/O posted — resume loop when I/O completes */
            }
            if (ctx->state != XRD_ST_SENDING) {
                ctx->state   = XRD_ST_REQ_HEADER;
                ctx->hdr_pos = 0;
            }

        } else {
            /* XRD_ST_REQ_PAYLOAD — payload is complete */
            ctx->state = XRD_ST_REQ_HEADER;   /* reset before dispatch */
            ctx->hdr_pos = 0;

            rc = xrootd_dispatch(ctx, c, conf);
            if (rc == NGX_ERROR) {
                goto fatal;
            }

            if (ctx->state == XRD_ST_SENDING) {
                return;
            }
        }
    }

fatal:
    xrootd_on_disconnect(ctx, c);
    xrootd_close_all_files(ctx);
    ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
}

/* ================================================================== */
/*  Write event handler — drains the pending write buffer              */
/*                                                                      */
/*  This handler runs when the OS send buffer has room after a prior   */
/*  c->send() returned EAGAIN (stored in ctx->wbuf, state=SENDING).    */
/*                                                                      */
/*  Race condition to guard against                                     */
/*  ─────────────────────────────────                                   */
/*  After transitioning to SENDING and arming the write event, the AIO  */
/*  completion path (xrootd_read_aio_done / xrootd_write_aio_done) can  */
/*  fire first via ngx_post_event and advance the state to AIO,         */
/*  REQ_PAYLOAD, or REQ_HEADER before the write handler runs.           */
/*                                                                      */
/*  If the write handler unconditionally resets to REQ_HEADER and calls */
/*  ngx_stream_xrootd_recv(), a second concurrent AIO is dispatched.   */
/*  Both AIOs then race to overwrite ctx->wbuf, silently discarding     */
/*  part of a response and corrupting the TCP stream.  Clients receive  */
/*  a truncated response and hang waiting for the missing bytes.        */
/*                                                                      */
/*  Fix: only proceed to REQ_HEADER+recv if state is still SENDING.    */
/*  Any other state means the pipeline already advanced correctly via   */
/*  the read-event path; just return.                                   */
/* ================================================================== */

static void
ngx_stream_xrootd_send(ngx_event_t *wev)
{
    ngx_connection_t     *c;
    ngx_stream_session_t *s;
    xrootd_ctx_t         *ctx;
    ngx_int_t             rc;

    c   = wev->data;
    s   = c->data;
    ctx = ngx_stream_get_module_ctx(s, ngx_stream_xrootd_module);

    if (wev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                      "xrootd: write timed out");
        xrootd_on_disconnect(ctx, c);
        xrootd_close_all_files(ctx);
        ngx_stream_finalize_session(s, NGX_STREAM_OK);
        return;
    }

    rc = xrootd_flush_pending(ctx, c);
    if (rc == NGX_ERROR) {
        xrootd_on_disconnect(ctx, c);
        xrootd_close_all_files(ctx);
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    if (rc == NGX_AGAIN) {
        /* Still more to write; write handler will be called again */
        return;
    }

    /* All data sent.
     *
     * Only transition back to reading if we are still in XRD_ST_SENDING.
     * Between arming the write event and the write completing, the posted
     * read event may have already fired and advanced the state machine to
     * XRD_ST_AIO, XRD_ST_REQ_PAYLOAD, or even XRD_ST_REQ_HEADER.
     * Overwriting those states would corrupt the pipeline.
     *
     * In those cases return immediately; the state machine is already
     * advancing correctly via the read-event path.
     */
    if (ctx->state != XRD_ST_SENDING) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "xrootd: send_done (state=%d, no recv) avail=%d ready=%d active=%d",
                      (int)ctx->state,
                      c->read->available, (int)c->read->ready,
                      (int)c->read->active);
        return;
    }

    ctx->state   = XRD_ST_REQ_HEADER;
    ctx->hdr_pos = 0;
    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                  "xrootd: send_done avail=%d ready=%d active=%d",
                  c->read->available, (int)c->read->ready, (int)c->read->active);
    ngx_stream_xrootd_recv(c->read);
}

/* ================================================================== */
/*  Write helpers                                                       */
/* ================================================================== */

/*
 * xrootd_queue_response
 *
 * Try to send `len` bytes from `buf` right now.  If the OS send buffer
 * is full (EAGAIN) stash the remainder and transition to SENDING state
 * so the write handler drains it asynchronously.
 *
 * Returns NGX_OK (all sent or queued), NGX_ERROR on failure.
 */
/*
 * xrootd_queue_response_base — like xrootd_queue_response but also saves
 * `base` into ctx->wbuf_base so that xrootd_flush_pending can ngx_pfree it
 * once the buffer has been fully drained.  Pass NULL for `base` when the
 * caller does not need deferred freeing (e.g. stack-allocated or small buffers
 * that the pool can reclaim at connection close).
 */
static ngx_int_t
xrootd_queue_response_base(xrootd_ctx_t *ctx, ngx_connection_t *c,
                            u_char *buf, size_t len, u_char *base)
{
    ssize_t n;

    while (len > 0) {
        n = c->send(c, buf, len);
        if (n > 0) {
            buf += n;
            len -= (size_t) n;
            continue;
        }
        if (n == NGX_AGAIN) {
            /* Store unsent remainder; track base for deferred ngx_pfree */
            ctx->wbuf      = buf;
            ctx->wbuf_len  = len;
            ctx->wbuf_pos  = 0;
            ctx->wbuf_base = base;   /* NULL → no deferred free */
            ctx->state     = XRD_ST_SENDING;

            if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
                return NGX_ERROR;
            }
            return NGX_OK;
        }
        return NGX_ERROR;
    }
    /* Fully sent — caller is responsible for freeing `base` if non-NULL */
    return NGX_OK;
}

static ngx_int_t
xrootd_queue_response(xrootd_ctx_t *ctx, ngx_connection_t *c,
                      u_char *buf, size_t len)
{
    return xrootd_queue_response_base(ctx, c, buf, len, NULL);
}

/*
 * xrootd_flush_pending — called from the write handler to drain wbuf.
 */
static ngx_int_t
xrootd_flush_pending(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    ssize_t n;

    while (ctx->wbuf_pos < ctx->wbuf_len) {
        n = c->send(c, ctx->wbuf + ctx->wbuf_pos,
                    ctx->wbuf_len - ctx->wbuf_pos);
        if (n > 0) {
            ctx->wbuf_pos += (size_t) n;
            continue;
        }
        if (n == NGX_AGAIN) {
            if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
                return NGX_ERROR;
            }
            return NGX_AGAIN;
        }
        return NGX_ERROR;
    }

    /* Free large AIO response buffer if it was tracked for deferred release */
    if (ctx->wbuf_base) {
        ngx_pfree(c->pool, ctx->wbuf_base);
        ctx->wbuf_base = NULL;
    }
    ctx->wbuf     = NULL;
    ctx->wbuf_len = 0;
    ctx->wbuf_pos = 0;
    return NGX_OK;
}

/* ================================================================== */
/*  Handshake                                                           */
/* ================================================================== */

/*
 * xrootd_process_handshake
 *
 * Validates the 20-byte client handshake and sends the server reply.
 *
 * In XRootD v5 the client sends handshake + kXR_protocol together in a
 * single 44-byte TCP segment.  The client then reads EACH server reply as a
 * standard 8-byte ServerResponseHdr + body:
 *
 *   1. Handshake response  (16 bytes): header(8) + {protover,msgval}(8)
 *   2. kXR_protocol response (8+N bytes): header(8) + body(N)
 *
 * The old 12-byte ServerInitHandShake framing (msglen+protover+msgval) is
 * NOT compatible with this because its first 8 bytes parse as
 * status=0x0008 / dlen=0x00000520=1312, causing the client to stall.
 *
 * We therefore send a proper ServerResponseHdr (streamid={0,0}, status=ok,
 * dlen=8) followed by 8 bytes of protover+msgval.  The kXR_protocol handler
 * sends its own response immediately after.
 */
static ngx_int_t
xrootd_process_handshake(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    ClientInitHandShake  *hs;
    ServerResponseHdr    *hdr;
    u_char               *buf;
    size_t                total;

    /* protover(4) + msgval(4) */
    static const size_t BODY_LEN = 8;

    hs = (ClientInitHandShake *) ctx->hdr_buf;

    /* Validate the magic fields */
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

    /* Standard response header: streamid={0,0} (no client streamid in
     * the handshake), status=kXR_ok, dlen=8. */
    hdr             = (ServerResponseHdr *) buf;
    hdr->streamid[0] = 0;
    hdr->streamid[1] = 0;
    hdr->status      = htons(kXR_ok);
    hdr->dlen        = htonl((kXR_unt32) BODY_LEN);

    /* Body: protocol version + server type */
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

static ngx_int_t
xrootd_dispatch(xrootd_ctx_t *ctx, ngx_connection_t *c,
                ngx_stream_xrootd_srv_conf_t *conf)
{
    /* Capture the start time so handlers can report processing duration. */
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

    /*
     * The following requests require a successful login first.
     * Sending kXR_NotAuthorized is the correct response per spec.
     */
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

    /*
     * Write operations — only accepted when xrootd_allow_write is on.
     * Unimplemented write ops (writev, pgwrite, rmdir, mv, chmod) are
     * rejected with kXR_Unsupported even when writes are enabled.
     */
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

/* ================================================================== */
/*  Request handlers                                                    */
/* ================================================================== */

/*
 * kXR_protocol — negotiate protocol capabilities.
 *
 * Client flags byte (cur_body[4]):
 *   kXR_secreqs  0x01 — client wants the server's security requirements
 *   kXR_ableTLS  0x02 — client supports TLS
 *   kXR_bifreqs  0x08 — client wants back-information frames
 *
 * When kXR_secreqs is set we append SecurityInfo after pval+flags.
 *
 * SecurityInfo header (4 bytes):
 *   secver  [1]  version, always 0
 *   secopt  [1]  0x01=kXR_secOFrce (auth required), 0=anonymous ok
 *   nProt   [1]  number of SecurityProtocol entries that follow
 *   rsvd    [1]  0
 *
 * SecurityProtocol entry (8 bytes each, when nProt > 0):
 *   prot[4]      protocol name, space-padded (e.g. "gsi ")
 *   plvl[1]      security level (0 = kXR_secNone)
 *   pargs[3]     reserved, 0
 *
 * For auth=gsi:  secopt=0x01, nProt=1, entry={"gsi ",0,{0,0,0}}  → 12 bytes
 * For auth=none: secopt=0x00, nProt=0                             →  4 bytes
 */
static ngx_int_t
xrootd_handle_protocol(xrootd_ctx_t *ctx, ngx_connection_t *c,
                       ngx_stream_xrootd_srv_conf_t *conf)
{
    ServerProtocolBody  body;
    u_char             *buf;
    size_t              bodylen, total;
    u_char              client_flags;
    int                 want_gsi;

    /* flags byte is at offset 4 of the 16-byte body section */
    client_flags = ctx->cur_body[4];
    want_gsi     = (conf->auth == XROOTD_AUTH_GSI);

    /*
     * Body = pval(4) + flags(4) [+ SecurityInfo if client asked]
     * SecurityInfo = 4-byte header [+ 8 bytes per protocol entry]
     */
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
        si[0] = 0;                           /* secver = 0             */
        si[1] = want_gsi ? 0x01 : 0x00;     /* secopt: force or none  */
        si[2] = want_gsi ? 1    : 0;        /* nProt                  */
        si[3] = 0;                           /* rsvd                   */
        if (want_gsi) {
            u_char *pe = si + 4;             /* SecurityProtocol entry */
            pe[0] = 'g'; pe[1] = 's'; pe[2] = 'i'; pe[3] = ' '; /* "gsi " */
            pe[4] = 0;                       /* plvl = kXR_secNone     */
            pe[5] = 0; pe[6] = 0; pe[7] = 0; /* pargs reserved        */
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
 * kXR_login — accept the username; set auth_done immediately when auth=none,
 * or leave it clear for auth=gsi (client must follow up with kXR_auth).
 */
static ngx_int_t
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
        /*
         * Anonymous: respond kXR_ok + 16-byte sessid.  auth_done immediately.
         */
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
     *
     * The XrdSecGSI client's ClientDoInit() parses the challenge via
     * XrdSutBuffer(&P=...) and reads the options with GetOptions().  The
     * challenge MUST use the "&P=gsi,v:<ver>,c:<crypto>,ca:<hash>" text
     * format, NOT the binary XrdSutBuffer bucket format.
     *
     * We advertise v:10000 (old-protocol mode) so the subsequent kXGS_cert
     * message only needs an unsigned kXRS_puk (RSA public key), rather than
     * a DH public key signed with the server private key (which requires
     * v >= 10400).
     *
     * Response is kXR_ok.  Per ServerLoginBody, dlen > 16 signals that the
     * bytes after the sessid are a server security challenge; the client
     * will answer with kXR_auth (kXGC_certreq, then kXGC_cert).
     */
    {
        char   parms[128];
        size_t parms_len;

        conf = ngx_stream_get_module_srv_conf(ctx->session,
                                              ngx_stream_xrootd_module);

        /* "&P=gsi,v:10000,c:ssl,ca:XXXXXXXX\0" */
        parms_len = (size_t) snprintf(parms, sizeof(parms),
                        "&P=gsi,v:10000,c:ssl,ca:%08x",
                        (unsigned) conf->gsi_ca_hash) + 1; /* include \0 */

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
        /* Log the login event; identity will be filled in after kXGC_cert */
        xrootd_log_access(ctx, c, "LOGIN", "-", user, 1, 0, NULL, 0);
        XROOTD_OP_OK(ctx, XROOTD_OP_LOGIN);

        return xrootd_queue_response(ctx, c, buf, total);
    }
}

/*
 * xrootd_gsi_parse_x509 — decrypt and extract the x509 chain from kXGC_cert.
 *
 * The client's proxy certificate arrives encrypted inside the kXRS_main bucket
 * of the outer XrdSutBuffer.  We must:
 *
 *   1. Parse the client DH public key from kXRS_puk in the outer buffer.
 *   2. Determine the session cipher from kXRS_cipher_alg (first name in the
 *      colon-separated list the client chose from our offered ciphers).
 *   3. Extract the ciphertext from kXRS_main in the outer buffer.
 *   4. Derive the DH shared secret using ctx->gsi_dh_key (our ephemeral private
 *      key saved from xrootd_gsi_send_cert) and the client's public BIGNUM.
 *      Key = first EVP_CIPHER_key_length bytes of the raw shared secret.
 *      IV  = all zeros (old protocol HasPad=0, useIV=false).
 *   5. AES-CBC decrypt kXRS_main.
 *   6. Parse the decrypted inner XrdSutBuffer for kXRS_x509 and PEM-decode
 *      the certificate chain.
 *
 * Returns a STACK_OF(X509) on success (caller must free with sk_X509_pop_free),
 * or NULL on any error (already logged).
 *
 * See the "GSI Authentication Protocol" block comment for full wire-format
 * documentation and common gotchas.
 */
static STACK_OF(X509) *
xrootd_gsi_parse_x509(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    const u_char      *payload = ctx->payload;
    size_t             plen    = ctx->cur_dlen;
    ngx_log_t         *log     = c->log;

    const u_char      *cpub_data = NULL, *main_data = NULL, *calg_data = NULL;
    size_t             cpub_len  = 0,    main_len   = 0,    calg_len   = 0;
    char              *pb, *pe;
    BIGNUM            *bnpub  = NULL;
    EVP_PKEY          *peer   = NULL;
    EVP_PKEY_CTX      *pkctx;
    OSSL_PARAM_BLD    *bld;
    OSSL_PARAM        *params1 = NULL, *params2 = NULL, *params = NULL;
    unsigned char     *secret  = NULL;
    size_t             secret_len = 0;
    const EVP_CIPHER  *evp_cipher;
    EVP_CIPHER_CTX    *dctx   = NULL;
    unsigned char     *plain  = NULL;
    int                olen   = 0, flen = 0;
    const u_char      *x509_data = NULL;
    size_t             x509_len  = 0;
    STACK_OF(X509)    *chain  = NULL;
    BIO               *bio;
    X509              *cert;
    char               cipher_name[64];

    if (ctx->gsi_dh_key == NULL) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd: GSI kXGC_cert: no server DH key (kXGC_certreq skipped?)");
        return NULL;
    }

    /*
     * Step 1: Parse the client DH public key from kXRS_puk in the outer buffer.
     *
     * The kXRS_puk blob format is:
     *   <DH PARAMETERS PEM>---BPUB---<hex BIGNUM of pub key>---EPUB--
     *
     * The closing sentinel is "---EPUB--" (9 chars, no trailing dash).
     * We extract the hex BIGNUM string between ---BPUB--- and ---EPUB--
     * and convert it to an OpenSSL BIGNUM with BN_hex2bn().
     *
     * This BIGNUM is the client's DH public value g^a mod p, where p and g
     * come from the ffdhe2048 group parameters we sent in kXGS_cert.
     */
    if (gsi_find_bucket(payload, plen, (uint32_t) kXRS_puk,
                        &cpub_data, &cpub_len) != 0) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd: GSI kXGC_cert: kXRS_puk not found in outer buffer");
        return NULL;
    }

    pb = memmem((void *) cpub_data, cpub_len, "---BPUB---", 10);
    pe = memmem((void *) cpub_data, cpub_len, "---EPUB--",   9);
    if (!pb || !pe || pe <= pb + 10) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd: GSI kXGC_cert: malformed client DH blob");
        return NULL;
    }
    pb += 10;   /* skip past the "---BPUB---" sentinel to reach the hex string */
    {
        char saved = *pe;
        *pe = '\0';
        BN_hex2bn(&bnpub, pb);
        *pe = saved;
    }
    if (!bnpub) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd: GSI kXGC_cert: BN_hex2bn failed");
        return NULL;
    }

    /*
     * Step 2: Determine session cipher from kXRS_cipher_alg.
     *
     * The client chooses one cipher from the colon-separated list we sent in
     * kXGS_cert ("aes-256-cbc:aes-128-cbc:bf-cbc").  It sends its choice as
     * the first (and often only) name in its kXRS_cipher_alg bucket, or the
     * full list if it doesn't narrow it down.  We read up to the first ':'.
     *
     * If kXRS_cipher_alg is absent we default to aes-256-cbc (what the
     * XRootD C++ client typically picks first).
     */
    ngx_cpystrn((u_char *) cipher_name, (u_char *) "aes-256-cbc",
                sizeof(cipher_name));
    if (gsi_find_bucket(payload, plen, (uint32_t) kXRS_cipher_alg,
                        &calg_data, &calg_len) == 0 && calg_len > 0) {
        size_t i;
        for (i = 0; i < calg_len && i < sizeof(cipher_name) - 1; i++) {
            if (calg_data[i] == ':') break;
            cipher_name[i] = calg_data[i];
        }
        cipher_name[i] = '\0';
    }

    /*
     * Step 3: Locate the encrypted inner buffer (kXRS_main) in the outer buffer.
     *
     * GOTCHA: kXRS_x509 is NOT in the outer buffer — it is inside kXRS_main
     * after decryption.  Searching the outer buffer for kXRS_x509 will always
     * fail.  Only kXRS_puk, kXRS_cipher_alg, kXRS_md_alg, and kXRS_main are
     * present in the outer buffer for kXGC_cert.
     */
    if (gsi_find_bucket(payload, plen, (uint32_t) kXRS_main,
                        &main_data, &main_len) != 0) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd: GSI kXGC_cert: kXRS_main not found in outer buffer");
        BN_free(bnpub);
        return NULL;
    }

    /*
     * Step 4: Derive the DH shared secret.
     *
     * We need to reconstruct the client's DH public key as an EVP_PKEY so
     * OpenSSL can do the modular exponentiation.  The approach:
     *
     *   a. Export our server DH key parameters (the ffdhe2048 group: p, g, q)
     *      with EVP_PKEY_todata(..., EVP_PKEY_KEY_PARAMETERS).
     *   b. Build a new OSSL_PARAM set that adds the client's public BIGNUM
     *      (from step 1) as OSSL_PKEY_PARAM_PUB_KEY.
     *   c. Merge parameters (a) and (b) — the merged set has the group
     *      parameters plus the peer's public value.
     *   d. Create the peer EVP_PKEY with EVP_PKEY_fromdata(..., PUBLIC_KEY).
     *   e. EVP_PKEY_derive using our server DH private key and the peer key.
     *
     * EVP_PKEY_CTX_set_dh_pad(0) is REQUIRED: the old protocol (v:10000)
     * uses HasPad=false, meaning the raw shared secret bytes are used without
     * zero-padding to the DH prime length.  With the default (pad=1), OpenSSL
     * left-pads the secret to match the 256-byte ffdhe2048 prime — the client
     * does not, so the first N bytes would not match.
     */
    EVP_PKEY_todata(ctx->gsi_dh_key, EVP_PKEY_KEY_PARAMETERS, &params1);

    bld     = OSSL_PARAM_BLD_new();
    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PUB_KEY, bnpub);
    params2 = OSSL_PARAM_BLD_to_param(bld);
    OSSL_PARAM_BLD_free(bld);
    BN_free(bnpub);  bnpub = NULL;

    params  = OSSL_PARAM_merge(params1, params2);
    OSSL_PARAM_free(params1);
    OSSL_PARAM_free(params2);

    pkctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
    EVP_PKEY_fromdata_init(pkctx);
    EVP_PKEY_fromdata(pkctx, &peer, EVP_PKEY_PUBLIC_KEY, params);
    OSSL_PARAM_free(params);
    EVP_PKEY_CTX_free(pkctx);

    if (!peer) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd: GSI kXGC_cert: cannot build client DH peer key");
        return NULL;
    }

    pkctx = EVP_PKEY_CTX_new(ctx->gsi_dh_key, NULL);
    EVP_PKEY_derive_init(pkctx);
    EVP_PKEY_CTX_set_dh_pad(pkctx, 0);       /* no padding — old protocol */
    EVP_PKEY_derive_set_peer(pkctx, peer);
    EVP_PKEY_derive(pkctx, NULL, &secret_len); /* query size */
    secret = ngx_palloc(c->pool, secret_len);
    if (!secret) {
        EVP_PKEY_CTX_free(pkctx);
        EVP_PKEY_free(peer);
        return NULL;
    }
    EVP_PKEY_derive(pkctx, secret, &secret_len);
    EVP_PKEY_CTX_free(pkctx);
    EVP_PKEY_free(peer);

    ngx_log_debug2(NGX_LOG_DEBUG_STREAM, log, 0,
                   "xrootd: GSI DH shared secret %uz bytes, cipher='%s'",
                   secret_len, cipher_name);

    /*
     * Step 5: Decrypt kXRS_main using the AES session key.
     *
     * Key length selection mirrors XrdCryptosslCipher::Finalize():
     *
     *   ltmp = min(secret_len, EVP_MAX_KEY_LENGTH)
     *   ldef = EVP_CIPHER_key_length(cipher)   // e.g. 32 for aes-256-cbc
     *
     *   if (ltmp == ldef):
     *       use first ldef bytes of shared secret as key   ← common case
     *   else:
     *       try EVP_CIPHER_CTX_set_key_length(ltmp)
     *       if cipher accepted the new length (variable-length ciphers like bf-cbc):
     *           use ltmp bytes
     *       else:
     *           use ldef bytes (cipher ignores variable-length request)
     *
     * For aes-256-cbc: ldef=32, ffdhe2048 secret_len is typically 256 bytes,
     * so ltmp = min(256, EVP_MAX_KEY_LENGTH=64) = 64 ≠ 32.
     * The variable-key attempt will fail (AES doesn't accept 64-byte keys),
     * so we fall back to the first 32 bytes of the shared secret.
     *
     * IV = all zeros (useIV=false in the old protocol).  This was intentional
     * in the original XRootD design: the session key is already unique per
     * connection from the DH exchange, so a fixed IV does not reuse a key+IV
     * pair across sessions.
     */
    evp_cipher = EVP_get_cipherbyname(cipher_name);
    if (!evp_cipher) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd: GSI kXGC_cert: unknown cipher '%s'", cipher_name);
        return NULL;
    }

    {
        size_t ltmp = (secret_len > (size_t) EVP_MAX_KEY_LENGTH)
                      ? (size_t) EVP_MAX_KEY_LENGTH : secret_len;
        int    ldef     = EVP_CIPHER_key_length(evp_cipher);
        size_t use_len  = (size_t) ldef;   /* default */

        /* Check if variable key length succeeds (e.g. bf-cbc accepts 64 bytes) */
        if ((int) ltmp != ldef) {
            EVP_CIPHER_CTX *tctx = EVP_CIPHER_CTX_new();
            EVP_CipherInit_ex(tctx, evp_cipher, NULL, NULL, NULL, 0);
            EVP_CIPHER_CTX_set_key_length(tctx, (int) ltmp);
            if (EVP_CIPHER_CTX_key_length(tctx) == (int) ltmp) {
                use_len = ltmp;   /* variable-length cipher: use ltmp bytes */
            }
            EVP_CIPHER_CTX_free(tctx);
        }

        unsigned char iv[EVP_MAX_IV_LENGTH];
        ngx_memset(iv, 0, sizeof(iv));

        dctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(dctx, evp_cipher, NULL, NULL, NULL);
        if (use_len != (size_t) ldef) {
            EVP_CIPHER_CTX_set_key_length(dctx, (int) use_len);
        }
        EVP_DecryptInit_ex(dctx, NULL, NULL, secret, iv);
    }

    {
        size_t plain_size = main_len + (size_t) EVP_CIPHER_CTX_block_size(dctx) + 1;
        plain = ngx_palloc(c->pool, plain_size);
        if (!plain) {
            EVP_CIPHER_CTX_free(dctx);
            return NULL;
        }

        if (EVP_DecryptUpdate(dctx, plain, &olen,
                              main_data, (int) main_len) != 1) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "xrootd: GSI kXGC_cert: EVP_DecryptUpdate failed");
            EVP_CIPHER_CTX_free(dctx);
            return NULL;
        }
        if (EVP_DecryptFinal_ex(dctx, plain + olen, &flen) != 1) {
            char errstr[128];
            ERR_error_string_n(ERR_get_error(), errstr, sizeof(errstr));
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "xrootd: GSI kXGC_cert: EVP_DecryptFinal failed: %s",
                          errstr);
            EVP_CIPHER_CTX_free(dctx);
            return NULL;
        }
        EVP_CIPHER_CTX_free(dctx);
    }

    int plain_len = olen + flen;
    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, log, 0,
                   "xrootd: GSI decrypted kXRS_main: %d bytes", plain_len);

    /*
     * Step 6: Parse the decrypted inner XrdSutBuffer for kXRS_x509.
     *
     * The decrypted inner buffer is itself a well-formed XrdSutBuffer:
     *   "gsi\0"  step=1001
     *   kXRS_x509   <PEM-encoded proxy cert + issuing cert chain>
     *   kXRS_rtag   <client's new random nonce>
     *   kXRS_none   (terminator)
     *
     * The PEM block typically contains 2-3 concatenated certificates:
     *   [0] proxy certificate (end-entity, issued by [1])
     *   [1] user certificate  (end-entity, issued by the CA)
     *   [2] ... (optional intermediate CAs)
     *
     * We read all PEM certificates out of kXRS_x509 and return them as a
     * STACK_OF(X509).  The caller (xrootd_handle_auth) passes them to
     * X509_verify_cert() with X509_V_FLAG_ALLOW_PROXY_CERTS set.
     */
    if (gsi_find_bucket(plain, (size_t) plain_len, (uint32_t) kXRS_x509,
                        &x509_data, &x509_len) != 0) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd: GSI kXGC_cert: kXRS_x509 not found "
                      "in decrypted inner buffer");
        return NULL;
    }

    bio   = BIO_new_mem_buf(x509_data, (int) x509_len);
    chain = sk_X509_new_null();
    if (!bio || !chain) {
        BIO_free(bio);
        sk_X509_free(chain);
        return NULL;
    }
    while ((cert = PEM_read_bio_X509(bio, NULL, NULL, NULL)) != NULL) {
        sk_X509_push(chain, cert);
    }
    BIO_free(bio);

    if (sk_X509_num(chain) == 0) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd: GSI kXGC_cert: kXRS_x509 contained no certs");
        sk_X509_pop_free(chain, X509_free);
        return NULL;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, log, 0,
                   "xrootd: GSI parsed %d cert(s) from kXRS_x509 after decrypt",
                   sk_X509_num(chain));
    return chain;
}

/*
 * gsi_find_bucket — scan a binary XrdSutBuffer for a bucket of a given type.
 *
 * XrdSutBuffer binary wire layout (all multi-byte fields are big-endian):
 *
 *   [protocol_name\0]   null-terminated string, e.g. "gsi\0" (4 bytes)
 *   [step : uint32 BE]  e.g. kXGC_certreq=1000, kXGS_cert=2001
 *   zero or more buckets:
 *     [type : uint32 BE]  bucket type constant (kXRS_puk, kXRS_x509, ...)
 *     [len  : uint32 BE]  length of the data that follows, in bytes
 *     [data : len bytes]
 *   [kXRS_none : uint32 BE]  terminator (type=0, no len/data fields)
 *
 * This function skips the protocol name and step header, then does a linear
 * scan of the bucket list looking for the first bucket of type target_type.
 *
 * On success: fills *data_out (pointer into payload) and *len_out, returns 0.
 * On failure (not found, or malformed buffer): returns -1.
 *
 * Note: *data_out points into the caller's payload buffer; no copy is made.
 * The caller must not free or modify the data at *data_out.
 */
static int
gsi_find_bucket(const u_char *payload, size_t plen,
                uint32_t target_type,
                const u_char **data_out, size_t *len_out)
{
    const u_char *p   = payload;
    const u_char *end = payload + plen;
    size_t        proto_len;

    if (plen < 8) return -1;

    /* Skip null-terminated protocol name */
    proto_len = ngx_strnlen((u_char *) p, plen) + 1;   /* include '\0' */
    if (proto_len >= plen) return -1;
    p += proto_len;

    /* Skip step (4 bytes) */
    if (p + 4 > end) return -1;
    p += 4;

    /* Scan buckets */
    while (p + 8 <= end) {
        uint32_t btype, blen;
        ngx_memcpy(&btype, p,     4); btype = ntohl(btype);
        ngx_memcpy(&blen,  p + 4, 4); blen  = ntohl(blen);
        p += 8;

        if (btype == (uint32_t) kXRS_none) break;
        if (p + blen > end) return -1;

        if (btype == target_type) {
            *data_out = p;
            *len_out  = blen;
            return 0;
        }
        p += blen;
    }
    return -1;
}

/*
 * xrootd_gsi_send_cert — respond to kXGC_certreq (step 1000) with kXGS_cert
 * (step 2001) carried in a kXR_authmore response.
 *
 * Our response is an XrdSutBuffer with:
 *
 *   "gsi\0"             protocol name (null-terminated)
 *   step = kXGS_cert    (2001, big-endian uint32)
 *   kXRS_puk            our ephemeral DH public key blob (see format below)
 *   kXRS_cipher_alg     offered ciphers: "aes-256-cbc:aes-128-cbc:bf-cbc"
 *   kXRS_md_alg         offered hashes:  "sha256:sha1"
 *   kXRS_x509           our host certificate PEM (for client to verify us)
 *   kXRS_main           inner XrdSutBuffer (NOT encrypted at this step):
 *     "gsi\0"           protocol name
 *     step = kXGS_cert  (2001)
 *     kXRS_signed_rtag  RSA_PKCS1_sign(server_private_key, client_rtag)
 *     kXRS_none
 *   kXRS_none           outer terminator
 *
 * kXRS_puk blob format (XrdCryptosslCipher convention):
 *   <DH PARAMETERS PEM>---BPUB---<hex BIGNUM of pub key>---EPUB--
 *
 *   The closing sentinel is "---EPUB--" (9 characters, no trailing dash).
 *   The DH PARAMETERS PEM is the standard OpenSSL parameters block for the
 *   ffdhe2048 named group (RFC 7919 well-known MODP group, 2048-bit).
 *
 * DH key generation note: We use the ffdhe2048 named group because it is
 * safe against small-subgroup attacks and is the group XRootD uses by
 * default.  Key generation takes ~1ms and is done per-connection to provide
 * forward secrecy.
 *
 * kXRS_signed_rtag: The client embedded a random challenge (kXRS_rtag) in
 * its kXGC_certreq inner buffer.  We sign it with RSA PKCS1 padding using
 * our server private key.  The client then calls DecryptPublic() (verify-
 * recover) with our public key to confirm we hold the matching private key
 * — i.e., that we are who the certificate says we are.
 *
 * The ephemeral DH key is stored in ctx->gsi_dh_key for later use when
 * deriving the shared secret from the client's DH public key in kXGC_cert.
 * It must NOT be freed here.
 */
static ngx_int_t
xrootd_gsi_send_cert(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    ngx_stream_xrootd_srv_conf_t *conf;
    EVP_PKEY_CTX *pctx;
    EVP_PKEY     *dhkey = NULL;
    BIGNUM       *pub_bn = NULL;
    char         *pub_hex = NULL;
    BIO          *bio;
    BUF_MEM      *bptr;
    u_char       *buf, *p;
    u_char       *cert_pem, *puk_blob;
    size_t        cert_len, puk_len, body_len, total;
    char          puk_buf[4096];
    int           puk_written;

    conf = ngx_stream_get_module_srv_conf(ctx->session,
                                          ngx_stream_xrootd_module);

    /* Export server certificate as PEM */
    bio = BIO_new(BIO_s_mem());
    if (bio == NULL) return NGX_ERROR;
    if (!PEM_write_bio_X509(bio, conf->gsi_cert)) {
        BIO_free(bio);
        return NGX_ERROR;
    }
    BIO_get_mem_ptr(bio, &bptr);
    cert_len = bptr->length;
    cert_pem = ngx_palloc(c->pool, cert_len);
    if (cert_pem == NULL) { BIO_free(bio); return NGX_ERROR; }
    ngx_memcpy(cert_pem, bptr->data, cert_len);
    BIO_free(bio);

    /*
     * Generate ephemeral DH key pair using the ffdhe2048 well-known group.
     * Key generation from a named group is fast (milliseconds).
     */
    {
        OSSL_PARAM dh_params[] = {
            OSSL_PARAM_utf8_string("group", "ffdhe2048", 0),
            OSSL_PARAM_END
        };
        pctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
        if (pctx == NULL) return NGX_ERROR;
        EVP_PKEY_keygen_init(pctx);
        EVP_PKEY_CTX_set_params(pctx, dh_params);
        if (EVP_PKEY_keygen(pctx, &dhkey) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            return NGX_ERROR;
        }
        EVP_PKEY_CTX_free(pctx);
    }

    /* Extract DH public key as hex BIGNUM */
    if (!EVP_PKEY_get_bn_param(dhkey, "pub", &pub_bn)) {
        EVP_PKEY_free(dhkey);
        return NGX_ERROR;
    }
    pub_hex = BN_bn2hex(pub_bn);
    BN_free(pub_bn);
    if (pub_hex == NULL) {
        EVP_PKEY_free(dhkey);
        return NGX_ERROR;
    }

    /* Write DH parameters as PEM */
    bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        OPENSSL_free(pub_hex);
        EVP_PKEY_free(dhkey);
        return NGX_ERROR;
    }
    PEM_write_bio_Parameters(bio, dhkey);
    /* Keep dhkey alive for kXGC_cert DH shared-secret derivation */
    ctx->gsi_dh_key = dhkey;
    BIO_get_mem_ptr(bio, &bptr);

    /*
     * kXRS_puk blob = DH_params_PEM + "---BPUB---" + hex + "---EPUB--"
     * Note: closing sentinel is "---EPUB--" (9 chars), not 10.
     */
    puk_written = snprintf(puk_buf, sizeof(puk_buf),
                           "%.*s---BPUB---%s---EPUB--",
                           (int) bptr->length, bptr->data, pub_hex);
    BIO_free(bio);
    OPENSSL_free(pub_hex);

    if (puk_written <= 0 || (size_t) puk_written >= sizeof(puk_buf)) {
        return NGX_ERROR;
    }
    puk_len = (size_t) puk_written;

    puk_blob = ngx_palloc(c->pool, puk_len);
    if (puk_blob == NULL) return NGX_ERROR;
    ngx_memcpy(puk_blob, puk_buf, puk_len);

    /*
     * Sign the client's random challenge (kXRS_rtag) from kXGC_certreq.
     *
     * The client puts a random nonce inside the kXRS_main inner buffer of its
     * kXGC_certreq message.  We must:
     *   1. Find kXRS_main in the outer kXGC_certreq buffer.
     *   2. Find kXRS_rtag inside that inner buffer.
     *   3. Sign the rtag bytes with our RSA private key using PKCS1 padding.
     *      This is identical to XrdCryptosslRSA::EncryptPrivate().
     *   4. Return the signature as kXRS_signed_rtag in our kXGS_cert response.
     *
     * The client verifies the signature with DecryptPublic() (RSA verify_recover
     * using the server public key from the kXRS_x509 cert we also send).  This
     * proves server identity — the client knows we hold the private key matching
     * the certificate we claimed.
     *
     * If we cannot sign (rtag absent or private key error) we proceed without
     * kXRS_signed_rtag.  The client may reject us, but logging this lets the
     * operator diagnose configuration issues.
     */
    const u_char *main_data  = NULL;
    size_t        main_dlen  = 0;
    const u_char *clnt_rtag  = NULL;
    size_t        clnt_rtlen = 0;
    u_char       *signed_rtag    = NULL;
    size_t        signed_rtag_len = 0;

    /* Locate kXRS_main in the outer (kXGC_certreq) XrdSutBuffer */
    if (gsi_find_bucket(ctx->payload, ctx->cur_dlen,
                        (uint32_t) kXRS_main, &main_data, &main_dlen) == 0) {
        /* Locate kXRS_rtag in the inner (unencrypted) XrdSutBuffer */
        gsi_find_bucket(main_data, main_dlen,
                        (uint32_t) kXRS_rtag, &clnt_rtag, &clnt_rtlen);
    }

    if (clnt_rtag && clnt_rtlen > 0) {
        /* Sign with server RSA private key — identical to EncryptPrivate() */
        EVP_PKEY_CTX *sctx = EVP_PKEY_CTX_new(conf->gsi_key, NULL);
        if (sctx) {
            size_t slen = (size_t) EVP_PKEY_size(conf->gsi_key);
            signed_rtag = ngx_palloc(c->pool, slen);
            if (signed_rtag &&
                EVP_PKEY_sign_init(sctx) > 0 &&
                EVP_PKEY_CTX_set_rsa_padding(sctx, RSA_PKCS1_PADDING) > 0 &&
                EVP_PKEY_sign(sctx, signed_rtag, &slen,
                              clnt_rtag, clnt_rtlen) > 0)
            {
                signed_rtag_len = slen;
            } else {
                signed_rtag = NULL;  /* sign failed, skip */
            }
            EVP_PKEY_CTX_free(sctx);
        }
    }

    /*
     * Build the kXRS_main inner buffer.
     *
     * This is a nested XrdSutBuffer (same format as the outer one) containing
     * only kXRS_signed_rtag.  It is NOT encrypted — we don't yet have a shared
     * session key because the client's DH public key hasn't arrived yet.
     * The client receives our kXRS_main, reads the kXRS_signed_rtag bucket,
     * and uses RSA verify_recover to confirm we hold the server private key.
     *
     * Wire layout:
     *   [4] "gsi\0"
     *   [4] step = kXGS_cert (2001), big-endian
     *   if signed_rtag available:
     *     [4] kXRS_signed_rtag type
     *     [4] signed_rtag_len
     *     [N] signature bytes
     *   [4] kXRS_none terminator
     */
    size_t main_len = 4 + 4    /* "gsi\0" + step */
                    + 4;        /* kXRS_none      */
    if (signed_rtag_len > 0) {
        main_len += 4 + 4 + signed_rtag_len;   /* kXRS_signed_rtag bucket */
    }

    u_char *main_buf = ngx_palloc(c->pool, main_len);
    if (main_buf == NULL) return NGX_ERROR;
    {
        u_char *mp = main_buf;
        mp[0]='g'; mp[1]='s'; mp[2]='i'; mp[3]='\0'; mp += 4;
        *(uint32_t *) mp = htonl(kXGS_cert); mp += 4;
        if (signed_rtag_len > 0) {
            *(uint32_t *) mp = htonl(kXRS_signed_rtag); mp += 4;
            *(uint32_t *) mp = htonl((uint32_t) signed_rtag_len); mp += 4;
            ngx_memcpy(mp, signed_rtag, signed_rtag_len); mp += signed_rtag_len;
        }
        *(uint32_t *) mp = htonl(kXRS_none); mp += 4;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: kXGS_cert signed rtag=%uz bytes main_len=%uz",
                   signed_rtag_len, main_len);

    /* Cipher and MD algorithm strings */
    const char *cipher_alg = "aes-256-cbc:aes-128-cbc:bf-cbc";
    const char *md_alg     = "sha256:sha1";
    size_t      calg_len   = strlen(cipher_alg);
    size_t      malg_len   = strlen(md_alg);

    body_len = 4 + 4                    /* "gsi\0" + step          */
             + 4 + 4 + puk_len          /* kXRS_puk  bucket        */
             + 4 + 4 + calg_len         /* kXRS_cipher_alg bucket  */
             + 4 + 4 + malg_len         /* kXRS_md_alg bucket      */
             + 4 + 4 + cert_len         /* kXRS_x509 bucket        */
             + 4 + 4 + main_len         /* kXRS_main bucket        */
             + 4;                       /* kXRS_none terminator    */

    total = XRD_RESPONSE_HDR_LEN + body_len;
    buf   = ngx_palloc(c->pool, total);
    if (buf == NULL) return NGX_ERROR;

    xrootd_build_resp_hdr(ctx->cur_streamid, kXR_authmore,
                           (uint32_t) body_len,
                           (ServerResponseHdr *) buf);

    p = buf + XRD_RESPONSE_HDR_LEN;

    p[0]='g'; p[1]='s'; p[2]='i'; p[3]='\0'; p += 4;

    *(uint32_t *) p = htonl(kXGS_cert); p += 4;

    *(uint32_t *) p = htonl(kXRS_puk);           p += 4;
    *(uint32_t *) p = htonl((uint32_t) puk_len);  p += 4;
    ngx_memcpy(p, puk_blob, puk_len);            p += puk_len;

    *(uint32_t *) p = htonl(kXRS_cipher_alg);           p += 4;
    *(uint32_t *) p = htonl((uint32_t) calg_len);        p += 4;
    ngx_memcpy(p, cipher_alg, calg_len);                p += calg_len;

    *(uint32_t *) p = htonl(kXRS_md_alg);               p += 4;
    *(uint32_t *) p = htonl((uint32_t) malg_len);        p += 4;
    ngx_memcpy(p, md_alg, malg_len);                    p += malg_len;

    *(uint32_t *) p = htonl(kXRS_x509);          p += 4;
    *(uint32_t *) p = htonl((uint32_t) cert_len); p += 4;
    ngx_memcpy(p, cert_pem, cert_len);            p += cert_len;

    *(uint32_t *) p = htonl(kXRS_main);           p += 4;
    *(uint32_t *) p = htonl((uint32_t) main_len);  p += 4;
    ngx_memcpy(p, main_buf, main_len);            p += main_len;

    *(uint32_t *) p = htonl(kXRS_none); p += 4;

    ngx_log_debug3(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: kXGS_cert sent cert_len=%uz puk_len=%uz main_len=%uz",
                   cert_len, puk_len, main_len);

    return xrootd_queue_response(ctx, c, buf, total);
}

/* ================================================================== */
/*                                                                    */
/*  GSI / x509 AUTHENTICATION PROTOCOL                                */
/*                                                                    */
/*  This section implements GSI (Grid Security Infrastructure) auth,  */
/*  the dominant authentication mechanism in High Energy Physics      */
/*  computing grids (CERN, SLAC, Fermilab, etc.).  It is based on    */
/*  RFC 3820 proxy certificates and a DH key exchange for session     */
/*  cipher setup.                                                      */
/*                                                                    */
/* ------------------------------------------------------------------ */
/*  KEY DATA STRUCTURE: XrdSutBuffer                                  */
/* ------------------------------------------------------------------ */
/*                                                                    */
/*  All GSI messages (both client→server and server→client) carry     */
/*  their payload as an XrdSutBuffer — a binary container format:     */
/*                                                                    */
/*    [protocol_name\0]  (null-terminated, e.g. "gsi\0")             */
/*    [step : uint32 BE]                                              */
/*    bucket...          (zero or more)                               */
/*    [kXRS_none : uint32 BE]  (terminator)                          */
/*                                                                    */
/*  Each bucket:                                                      */
/*    [type : uint32 BE]                                              */
/*    [len  : uint32 BE]                                              */
/*    [data : len bytes]                                              */
/*                                                                    */
/*  Bucket type constants (from XrdSecgsiTrace.hh / XrdSutBucket.hh):*/
/*    kXRS_none        0  terminator                                  */
/*    kXRS_main        2  inner payload buffer (may be encrypted)     */
/*    kXRS_puk         4  DH public key blob (see format below)       */
/*    kXRS_x509       22  PEM-encoded certificate chain               */
/*    kXRS_cipher_alg 27  cipher name list ("aes-256-cbc:aes-128-cbc")*/
/*    kXRS_md_alg     28  hash name list ("sha256:sha1")              */
/*    kXRS_rtag       33  client random challenge (nonce)             */
/*    kXRS_signed_rtag 34 server's signature of the client's rtag     */
/*                                                                    */
/*  See gsi_find_bucket() for the parsing implementation.             */
/*                                                                    */
/* ------------------------------------------------------------------ */
/*  KEY DATA STRUCTURE: kXRS_puk DH blob                              */
/* ------------------------------------------------------------------ */
/*                                                                    */
/*  The kXRS_puk bucket is NOT an RSA public key PEM.  It is a       */
/*  custom text blob used by XrdCryptosslCipher to carry DH           */
/*  parameters and the DH public key:                                 */
/*                                                                    */
/*    <DH PARAMETERS PEM>---BPUB---<hex BIGNUM>---EPUB--              */
/*                                                                    */
/*  The DH PARAMETERS PEM is a standard OpenSSL parameters block.    */
/*  The hex BIGNUM is BN_bn2hex() of the public key value.           */
/*  The closing sentinel is "---EPUB--" — 9 characters, NOT 10.      */
/*                                                                    */
/*  GOTCHA: Sending an RSA PEM in kXRS_puk causes the client to      */
/*  print "could not instantiate session cipher" and disconnect.      */
/*                                                                    */
/* ------------------------------------------------------------------ */
/*  STEP 1: kXR_login response — the GSI challenge string            */
/* ------------------------------------------------------------------ */
/*                                                                    */
/*  When GSI auth is configured, the kXR_login response is:          */
/*    kXR_ok + 16-byte sessid + "&P=gsi,v:10000,c:ssl,ca:<hash>\0"  */
/*                                                                    */
/*  GOTCHA: The challenge string MUST be plain text in "&P=..." form, */
/*  not a binary XrdSutBuffer.  The XRootD client's ClientDoInit()   */
/*  calls GetOptions() on the challenge, which only parses "&P=..."   */
/*  text format.  Sending a binary buffer here causes the client to  */
/*  print "No protocols left to try" and disconnect.                  */
/*                                                                    */
/*  We advertise v:10000 (the "old protocol").  Versions >= 10400    */
/*  require the server to sign the kXRS_puk DH blob with its RSA     */
/*  private key.  v:10000 skips that signature requirement.          */
/*                                                                    */
/*  The ca:<hash> field is the hex-encoded X509_subject_name_hash()  */
/*  of the trusted CA certificate.  Clients use this to find the     */
/*  matching CA certificate in their X509_CERT_DIR to verify our     */
/*  host certificate later.                                           */
/*                                                                    */
/* ------------------------------------------------------------------ */
/*  STEP 2: kXGC_certreq (step 1000) — client's first auth message   */
/* ------------------------------------------------------------------ */
/*                                                                    */
/*  The client sends kXR_auth with this XrdSutBuffer:                */
/*    "gsi\0"  step=kXGC_certreq(1000)                               */
/*    kXRS_main{ "gsi\0", step=...,                                  */
/*               kXRS_rtag(<32 random bytes>) }                       */
/*                                                                    */
/*  The kXRS_rtag inside kXRS_main is the client's random challenge.  */
/*  We must sign it with our RSA private key (PKCS1 padding) and     */
/*  return the signature as kXRS_signed_rtag in our response.         */
/*                                                                    */
/*  The client verifies the signature using DecryptPublic (i.e.,      */
/*  RSA verify_recover with the server cert public key), so the      */
/*  server proves it holds the private key matching the cert we send. */
/*                                                                    */
/* ------------------------------------------------------------------ */
/*  STEP 3: kXGS_cert (step 2001) — server's auth response           */
/* ------------------------------------------------------------------ */
/*                                                                    */
/*  We respond with kXR_authmore + XrdSutBuffer:                     */
/*    "gsi\0"  step=kXGS_cert(2001)                                  */
/*    kXRS_puk       <DH PARAMS PEM>---BPUB---<hex>---EPUB--         */
/*    kXRS_cipher_alg  "aes-256-cbc:aes-128-cbc:bf-cbc"             */
/*    kXRS_md_alg      "sha256:sha1"                                 */
/*    kXRS_x509        <server host certificate PEM>                 */
/*    kXRS_main{                                                      */
/*        "gsi\0"  step=kXGS_cert(2001)                              */
/*        kXRS_signed_rtag  <RSA_PKCS1_sign(server_key, client_rtag)>*/
/*    }                                                               */
/*                                                                    */
/*  IMPORTANT: kXRS_main in our kXGS_cert response is NOT encrypted. */
/*  Session cipher setup happens on the client side using its own DH  */
/*  private key and our DH public key.  The client then encrypts its  */
/*  kXRS_main in kXGC_cert.  We receive that and must decrypt it.    */
/*                                                                    */
/*  We store the ephemeral DH key (ctx->gsi_dh_key) across the two   */
/*  kXR_auth messages so we can derive the shared secret later.       */
/*                                                                    */
/* ------------------------------------------------------------------ */
/*  STEP 4: kXGC_cert (step 1001) — client's proxy certificate       */
/* ------------------------------------------------------------------ */
/*                                                                    */
/*  Client sends kXR_auth + XrdSutBuffer (outer, unencrypted):        */
/*    "gsi\0"  step=kXGC_cert(1001)                                  */
/*    kXRS_puk       <client DH blob, same format as server's>        */
/*    kXRS_cipher_alg  <chosen cipher from our offered list>          */
/*    kXRS_md_alg      <chosen hash>                                 */
/*    kXRS_main        <AES-CBC encrypted inner buffer>               */
/*                                                                    */
/*  GOTCHA: The proxy cert is NOT in the outer buffer.  It is inside  */
/*  kXRS_main after decryption.  Scanning the outer buffer for        */
/*  kXRS_x509 will always fail.                                        */
/*                                                                    */
/*  Decrypted kXRS_main (inner XrdSutBuffer):                        */
/*    "gsi\0"  step=1001                                             */
/*    kXRS_x509    <proxy cert + issuing chain PEM>                  */
/*    kXRS_rtag    <client's new random tag>                         */
/*                                                                    */
/* ------------------------------------------------------------------ */
/*  DH SESSION KEY DERIVATION (old protocol, v:10000, HasPad=0)       */
/* ------------------------------------------------------------------ */
/*                                                                    */
/*  1. Server generates ephemeral DH key pair using ffdhe2048 group   */
/*     (RFC 7919 well-known MODP group, safe against subgroup attacks)*/
/*                                                                    */
/*  2. Server sends DH public key in kXRS_puk (kXGS_cert step).      */
/*                                                                    */
/*  3. Client generates its own DH key pair, sends its public key in  */
/*     kXRS_puk (kXGC_cert step).                                     */
/*                                                                    */
/*  4. Server derives shared secret:                                  */
/*       EVP_PKEY_CTX_set_dh_pad(ctx, 0)   ← no padding, old protocol*/
/*       EVP_PKEY_derive(ctx, secret, &secret_len)                   */
/*                                                                    */
/*  GOTCHA: HasPad=0 means no leading-zero padding.  The default      */
/*  OpenSSL DH derive pads the secret to match the DH prime length.   */
/*  We must disable padding to match the client's derivation.          */
/*                                                                    */
/*  5. Key length: mirrors XrdCryptosslCipher::Finalize():            */
/*       ltmp = min(secret_len, EVP_MAX_KEY_LENGTH)                  */
/*       if (ltmp == EVP_CIPHER_key_length):                          */
/*           use ltmp bytes of secret as key                          */
/*       else:                                                         */
/*           try EVP_CIPHER_CTX_set_key_length(ltmp);                */
/*           if that works (variable-length cipher like bf-cbc):      */
/*               use ltmp bytes                                        */
/*           else:                                                     */
/*               use EVP_CIPHER_key_length bytes                      */
/*     For aes-256-cbc: ldef=32, typically secret_len=256, ltmp=32,  */
/*     so we use the first 32 bytes of the shared secret.             */
/*                                                                    */
/*  6. IV = all zeros (useIV=false for old protocol v:10000).         */
/*                                                                    */
/* ------------------------------------------------------------------ */
/*  PROXY CERTIFICATE VERIFICATION                                    */
/* ------------------------------------------------------------------ */
/*                                                                    */
/*  RFC 3820 proxy certificates have a proxyCertInfo extension with   */
/*  OID 1.3.6.1.5.5.7.1.14.  Standard OpenSSL X509_verify_cert()     */
/*  rejects them unless X509_V_FLAG_ALLOW_PROXY_CERTS is set on both  */
/*  the X509_STORE and the X509_STORE_CTX.                           */
/*                                                                    */
/*  The kXRS_x509 bucket from kXGC_cert contains the full chain:     */
/*    [0] proxy certificate (the leaf — presented to the server)      */
/*    [1] user end-entity certificate (the proxy's issuer)            */
/*    [2] ... (optional intermediate CA certificates)                 */
/*                                                                    */
/*  We pass the leaf (cert[0]) as the subject, and certs[1..N] as     */
/*  the untrusted chain, letting X509_STORE_CTX walk up to the CA.   */
/*                                                                    */
/* ------------------------------------------------------------------ */
/*  STAT WIRE FORMAT (easy to get wrong)                              */
/* ------------------------------------------------------------------ */
/*                                                                    */
/*  kXR_stat response body:                                           */
/*    "<id> <size> <flags> <mtime>\0"   (size BEFORE flags)          */
/*                                                                    */
/*  kXR_open retstat body (after ServerOpenBody):                     */
/*    "<id> <size> <flags> <mtime>\0"   (same order)                 */
/*                                                                    */
/*  GOTCHA: Earlier versions of this code (and many online examples)  */
/*  sent "<id> <flags> <size> <mtime>" (flags before size), which     */
/*  causes the client to interpret flags=4096 (kXR_isDir) as file     */
/*  size and size=24 as flags.  The correct order was verified in     */
/*  XrdClXRootDResponses.cc ParseServerResponse() lines 148-155:     */
/*    chunks[0]=id, chunks[1]=size, chunks[2]=flags, chunks[3]=mtime  */
/*                                                                    */
/* ================================================================== */

/*
 * kXR_auth — handle GSI authentication sub-steps.
 *
 * Two sub-steps arrive as separate kXR_auth messages:
 *
 *   kXGC_certreq (step 1000) — client requests our host certificate.
 *     We extract the client's random tag (kXRS_rtag) from the inner buffer,
 *     generate an ephemeral DH key pair, sign the rtag with our RSA private
 *     key, and respond with kXR_authmore carrying kXGS_cert.
 *
 *   kXGC_cert (step 1001) — client sends its proxy certificate chain
 *     encrypted under the DH-derived session key.  We derive the shared
 *     secret, decrypt kXRS_main, extract and verify the kXRS_x509 chain
 *     against the trusted CA store, and send kXR_ok on success.
 *
 * The DH ephemeral key (ctx->gsi_dh_key) is stored between the two steps
 * and freed immediately after kXGC_cert processing.
 */
static ngx_int_t
xrootd_handle_auth(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    ngx_stream_xrootd_srv_conf_t *conf;
    STACK_OF(X509)               *chain;
    X509                         *leaf;
    X509_STORE_CTX               *vctx;
    char                         *dn_str;
    uint32_t                      gsi_step;
    int                           ok;

    if (!ctx->logged_in) {
        return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                 "login required before auth");
    }

    conf = ngx_stream_get_module_srv_conf(ctx->session,
                                          ngx_stream_xrootd_module);

    if (conf->auth != XROOTD_AUTH_GSI || conf->gsi_store == NULL) {
        ctx->auth_done = 1;
        return xrootd_send_ok(ctx, c, NULL, 0);
    }

    ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: kXR_auth credtype=\"%.4s\" payloadlen=%d",
                   ctx->cur_body, (int) ctx->cur_dlen);

    if (ctx->payload == NULL || ctx->cur_dlen < 8) {
        return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                 "empty GSI credential");
    }

    /* Verify protocol name */
    if (ctx->payload[0] != 'g' || ctx->payload[1] != 's' ||
        ctx->payload[2] != 'i')
    {
        return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                 "not a GSI credential");
    }

    /* Dispatch on GSI step */
    ngx_memcpy(&gsi_step, ctx->payload + 4, 4);
    gsi_step = ntohl(gsi_step);

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: GSI kXR_auth step=%ud", (unsigned) gsi_step);

    if (gsi_step == (uint32_t) kXGC_certreq) {
        return xrootd_gsi_send_cert(ctx, c);
    }

    if (gsi_step != (uint32_t) kXGC_cert) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "xrootd: unexpected GSI step %ud", (unsigned) gsi_step);
        return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                 "unexpected GSI auth step");
    }

    /* kXGC_cert (1001): decrypt inner buffer and verify client proxy chain */

    /* Derive DH session key, decrypt kXRS_main, extract kXRS_x509 */
    chain = xrootd_gsi_parse_x509(ctx, c);

    /* DH key no longer needed after this point */
    if (ctx->gsi_dh_key) {
        EVP_PKEY_free(ctx->gsi_dh_key);
        ctx->gsi_dh_key = NULL;
    }

    if (chain == NULL) {
        xrootd_log_access(ctx, c, "AUTH", "-", "gsi",
                          0, kXR_NotAuthorized, "cannot parse GSI credential", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_AUTH);
        return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                 "cannot parse GSI credential");
    }

    /* leaf cert = first cert in the chain (the proxy cert or user cert) */
    leaf = sk_X509_value(chain, 0);

    /* Verify the chain against the trusted CA store */
    vctx = X509_STORE_CTX_new();
    if (vctx == NULL) {
        sk_X509_pop_free(chain, X509_free);
        return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                 "internal OpenSSL error");
    }

    /*
     * For proxy certs, the "untrusted" chain contains the intermediate
     * user cert(s); X509_STORE_CTX will walk from leaf to root.
     * sk_X509_dup creates a shallow copy (pointers copied, not certs).
     */
    STACK_OF(X509) *untrusted = NULL;
    if (sk_X509_num(chain) > 1) {
        untrusted = sk_X509_dup(chain);
        /* Remove the leaf from the untrusted set */
        sk_X509_delete(untrusted, 0);
    }

    X509_STORE_CTX_init(vctx, conf->gsi_store, leaf, untrusted);

    /* Allow proxy certificates in the verification path */
    X509_STORE_CTX_set_flags(vctx, X509_V_FLAG_ALLOW_PROXY_CERTS);

    ok = X509_verify_cert(vctx);

    if (untrusted) {
        sk_X509_free(untrusted);   /* shallow free — don't free the certs */
    }

    if (ok != 1) {
        int verr = X509_STORE_CTX_get_error(vctx);
        const char *verr_str = X509_verify_cert_error_string(verr);
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "xrootd: GSI cert verification failed: %s", verr_str);
        xrootd_log_access(ctx, c, "AUTH", "-", "gsi",
                          0, kXR_NotAuthorized, verr_str, 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_AUTH);
        X509_STORE_CTX_free(vctx);
        sk_X509_pop_free(chain, X509_free);
        return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                 "certificate verification failed");
    }

    X509_STORE_CTX_free(vctx);

    /* Extract the subject DN for logging / policy */
    dn_str = X509_NAME_oneline(X509_get_subject_name(leaf), NULL, 0);
    if (dn_str) {
        ngx_cpystrn((u_char *) ctx->dn,
                    (u_char *) dn_str,
                    sizeof(ctx->dn) - 1);
        OPENSSL_free(dn_str);
    }

    sk_X509_pop_free(chain, X509_free);

    ctx->auth_done = 1;

    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                  "xrootd: GSI auth OK dn=\"%s\"", ctx->dn);

    /* Log the completed auth — identity (DN) is now populated in ctx->dn */
    xrootd_log_access(ctx, c, "AUTH", "-", "gsi", 1, 0, NULL, 0);
    XROOTD_OP_OK(ctx, XROOTD_OP_AUTH);

    return xrootd_send_ok(ctx, c, NULL, 0);
}

/* kXR_ping — liveness check */
static ngx_int_t
xrootd_handle_ping(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    xrootd_log_access(ctx, c, "PING", "-", "-", 1, 0, NULL, 0);
    XROOTD_OP_OK(ctx, XROOTD_OP_PING);
    return xrootd_send_ok(ctx, c, NULL, 0);
}

/* ================================================================== */
/*  Write handlers                                                      */
/* ================================================================== */

/*
 * kXR_write — write data to an open file handle.
 *
 * The payload IS the data to write.  The request header carries the
 * file handle index and offset; cur_dlen is the number of bytes.
 *
 * Protocol:
 *   ClientWriteRequest.fhandle[0]  — our slot index
 *   ClientWriteRequest.offset      — big-endian int64
 *   ClientWriteRequest.dlen        — payload length (= bytes to write)
 *   payload                        — raw file data
 *
 * We use pwrite(2) so the offset in the header is honoured without
 * a separate lseek call.  This also makes concurrent writes safe if the
 * kernel delivers them in order (which it will for a single TCP stream).
 */
/* ================================================================== */
/*  Async I/O helpers — thread pool support for blocking file I/O     */
/* ================================================================== */

/*
 * xrootd_build_read_response — allocate and return the chunked kXR_read
 * response buffer.  Called from the sync path and from the AIO completion.
 *
 * Returns NULL on allocation failure (caller should return NGX_ERROR).
 */
static u_char *
xrootd_build_read_response(xrootd_ctx_t *ctx, ngx_connection_t *c,
    u_char *databuf, size_t data_total, size_t *rsp_total_out)
{
    size_t   n_chunks, last_size, rsp_total;
    u_char  *rspbuf;
    size_t   ri, di;

    n_chunks = (data_total + XROOTD_READ_MAX - 1) / XROOTD_READ_MAX;
    if (n_chunks == 0) { n_chunks = 1; }
    last_size = data_total % XROOTD_READ_MAX;
    if (last_size == 0 && data_total > 0) { last_size = XROOTD_READ_MAX; }

    rsp_total = n_chunks * XRD_RESPONSE_HDR_LEN + data_total;
    rspbuf    = ngx_palloc(c->pool, rsp_total);
    if (rspbuf == NULL) { return NULL; }

    ri = 0; di = 0;
    for (size_t chunk = 0; chunk < n_chunks; chunk++) {
        size_t   chunk_data = (chunk < n_chunks - 1) ? XROOTD_READ_MAX : last_size;
        uint16_t status     = (chunk == n_chunks - 1) ? kXR_ok : kXR_oksofar;

        xrootd_build_resp_hdr(ctx->cur_streamid, status,
                              (uint32_t) chunk_data,
                              (ServerResponseHdr *)(rspbuf + ri));
        ri += XRD_RESPONSE_HDR_LEN;
        ngx_memcpy(rspbuf + ri, databuf + di, chunk_data);
        ri += chunk_data;
        di += chunk_data;
    }

    *rsp_total_out = rsp_total;
    return rspbuf;
}

/*
 * xrootd_build_readv_response — build and return the chunked kXR_readv
 * response buffer from a pre-assembled databuf (readahead_list headers
 * + data bytes already in place).
 */
static u_char *
xrootd_build_readv_response(xrootd_ctx_t *ctx, ngx_connection_t *c,
    u_char *databuf, size_t rsp_total, size_t *out_size)
{
    size_t   n_chunks, last_size, buf_size;
    u_char  *rspbuf;
    size_t   ri, di;

    n_chunks = (rsp_total + XROOTD_READ_MAX - 1) / XROOTD_READ_MAX;
    if (n_chunks == 0) { n_chunks = 1; }
    last_size = rsp_total % XROOTD_READ_MAX;
    if (last_size == 0 && rsp_total > 0) { last_size = XROOTD_READ_MAX; }

    buf_size = n_chunks * XRD_RESPONSE_HDR_LEN + rsp_total;
    rspbuf   = ngx_palloc(c->pool, buf_size);
    if (rspbuf == NULL) { return NULL; }

    ri = 0; di = 0;
    for (size_t chunk = 0; chunk < n_chunks; chunk++) {
        size_t   chunk_data = (chunk < n_chunks - 1) ? XROOTD_READ_MAX : last_size;
        uint16_t status     = (chunk == n_chunks - 1) ? kXR_ok : kXR_oksofar;

        xrootd_build_resp_hdr(ctx->cur_streamid, status,
                              (uint32_t) chunk_data,
                              (ServerResponseHdr *)(rspbuf + ri));
        ri += XRD_RESPONSE_HDR_LEN;
        ngx_memcpy(rspbuf + ri, databuf + di, chunk_data);
        ri += chunk_data;
        di += chunk_data;
    }

    *out_size = buf_size;
    return rspbuf;
}

#if (NGX_THREADS)

/* ------------------------------------------------------------------ */
/*  AIO task context structs                                            */
/* ------------------------------------------------------------------ */

/* kXR_read async task */
typedef struct {
    ngx_connection_t              *c;
    xrootd_ctx_t                  *ctx;
    ngx_stream_xrootd_srv_conf_t  *conf;

    int       fd;
    int       handle_idx;
    off_t     offset;
    size_t    rlen;
    u_char   *databuf;

    /* Saved request streamid (ctx may be reused by the time completion fires) */
    u_char    streamid[2];

    /* Result from pread() */
    ssize_t   nread;
    int       io_errno;
} xrootd_read_aio_t;

/* kXR_write / kXR_pgwrite async task */
typedef struct {
    ngx_connection_t              *c;
    xrootd_ctx_t                  *ctx;
    ngx_stream_xrootd_srv_conf_t  *conf;

    int            fd;
    int            handle_idx;
    off_t          offset;        /* file offset to write at        */
    const u_char  *data;          /* flat data buffer (no CRC gaps) */
    size_t         len;           /* bytes to write                 */

    /* Saved context for response / logging */
    u_char         streamid[2];
    char           path[PATH_MAX];
    int64_t        req_offset;    /* original request offset        */
    ngx_uint_t     is_pgwrite;    /* 1 = kXR_pgwrite, 0 = kXR_write */

    /* Result */
    ssize_t        nwritten;
    int            io_errno;

    /* Pool-allocated payload buffer to free after pwrite() completes */
    u_char        *payload_to_free;
} xrootd_write_aio_t;

/* kXR_readv per-segment descriptor for the thread */
typedef struct {
    int       fd;
    int       handle_idx;
    off_t     offset;
    uint32_t  rlen;
    u_char   *hdr_rlen_ptr;  /* pointer to rlen field in databuf (to patch) */
    u_char   *data_ptr;      /* pointer to data area in databuf             */
} xrootd_readv_seg_desc_t;

/* kXR_readv async task */
typedef struct {
    ngx_connection_t              *c;
    xrootd_ctx_t                  *ctx;

    size_t                         n_segs;
    xrootd_readv_seg_desc_t       *segs;     /* palloc'd array */
    u_char                        *databuf;  /* full response body (pre-sized) */

    u_char  streamid[2];

    /* Written by thread */
    size_t  bytes_total;
    size_t  rsp_total;
    int     io_error;
    char    err_msg[64];
} xrootd_readv_aio_t;

/* ------------------------------------------------------------------ */
/*  Thread handlers — run in the pool thread (blocking I/O is fine)   */
/* ------------------------------------------------------------------ */

static void
xrootd_read_aio_thread(void *data, ngx_log_t *log)
{
    xrootd_read_aio_t *t = data;
    t->nread = pread(t->fd, t->databuf, t->rlen, t->offset);
    if (t->nread < 0) {
        t->io_errno = errno;
    }
}

static void
xrootd_write_aio_thread(void *data, ngx_log_t *log)
{
    xrootd_write_aio_t *t = data;
    t->nwritten = pwrite(t->fd, t->data, t->len, t->offset);
    if (t->nwritten < 0) {
        t->io_errno = errno;
    }
}

static void
xrootd_readv_aio_thread(void *data, ngx_log_t *log)
{
    xrootd_readv_aio_t *t = data;
    size_t i;

    t->bytes_total = 0;
    t->io_error    = 0;
    t->rsp_total   = 0;

    for (i = 0; i < t->n_segs; i++) {
        xrootd_readv_seg_desc_t *seg = &t->segs[i];
        ssize_t nread;

        nread = pread(seg->fd, seg->data_ptr, (size_t) seg->rlen, seg->offset);
        if (nread < 0) {
            t->io_error = 1;
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "readv I/O error at seg %d: %s", (int) i, strerror(errno));
            return;
        }
        if ((uint32_t) nread < seg->rlen) {
            t->io_error = 2;
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "readv past EOF at seg %d", (int) i);
            return;
        }
        /* Patch the response readahead_list rlen field with actual bytes */
        uint32_t rlen_be = htonl((uint32_t) nread);
        ngx_memcpy(seg->hdr_rlen_ptr, &rlen_be, 4);

        t->bytes_total += (size_t) nread;
    }

    /* Total response body = N headers (16 B each) + all data bytes */
    t->rsp_total = t->n_segs * XROOTD_READV_SEGSIZE + t->bytes_total;
}

/* ------------------------------------------------------------------ */
/*  Completion handlers — run in the event loop after thread finishes  */
/*                                                                      */
/*  Execution model                                                     */
/*  ────────────────                                                    */
/*  Thread-pool tasks (xrootd_*_aio_thread) run in a worker thread.   */
/*  When the task finishes, nginx posts the task->event to the main    */
/*  event loop via the eventfd mechanism.  The completion handler      */
/*  (task->event.handler = xrootd_*_aio_done) then runs in the main   */
/*  thread — the same thread that drives the nginx event loop — so     */
/*  there are no data races on ctx or c.                               */
/*                                                                      */
/*  After building and queuing the response each handler calls         */
/*  xrootd_aio_resume() to post the read event.  This ensures the     */
/*  client's next request is processed in the same epoll iteration     */
/*  rather than waiting for the next kernel notification.              */
/* ------------------------------------------------------------------ */

/*
 * xrootd_aio_resume — re-enter the XRootD read loop after AIO completion.
 *
 * Uses ngx_post_event() to schedule ngx_stream_xrootd_recv() at the end of
 * the current epoll iteration.  Any data the client already buffered is
 * consumed immediately without an extra epoll round-trip.
 *
 * ngx_handle_read_event() is called first only if the read event is not
 * already active/ready; it is a no-op otherwise.
 */
static void
xrootd_aio_resume(ngx_connection_t *c)
{
    ngx_event_t *rev = c->read;
    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                  "xrootd: aio_resume avail=%d ready=%d active=%d posted=%d",
                  rev->available, (int)rev->ready,
                  (int)rev->active, (int)rev->posted);
    if (!rev->active && !rev->ready) {
        if (ngx_handle_read_event(rev, 0) != NGX_OK) {
            ngx_stream_finalize_session(c->data, NGX_STREAM_INTERNAL_SERVER_ERROR);
        }
    }
    ngx_post_event(rev, &ngx_posted_events);
}

static void
xrootd_read_aio_done(ngx_event_t *ev)
{
    ngx_thread_task_t  *task = ev->data;
    xrootd_read_aio_t  *t   = task->ctx;
    xrootd_ctx_t       *ctx = t->ctx;
    ngx_connection_t   *c   = t->c;
    size_t              rsp_total;
    u_char             *rspbuf;

    if (ctx->destroyed) {
        return;   /* connection gone; pool may already be freed */
    }

    /* Restore the saved streamid so xrootd_build_read_response uses it */
    ctx->cur_streamid[0] = t->streamid[0];
    ctx->cur_streamid[1] = t->streamid[1];

    if (t->nread < 0) {
        ctx->state = XRD_ST_REQ_HEADER;
        ctx->hdr_pos = 0;
        ngx_pfree(c->pool, t->databuf);
        XROOTD_OP_ERR(ctx, XROOTD_OP_READ);
        xrootd_send_error(ctx, c, kXR_IOError,
                          t->io_errno ? strerror(t->io_errno) : "async read error");
        xrootd_aio_resume(c);
        return;
    }

    ctx->files[t->handle_idx].bytes_read += (size_t) t->nread;
    ctx->session_bytes                   += (size_t) t->nread;
    XROOTD_OP_OK(ctx, XROOTD_OP_READ);

    rspbuf = xrootd_build_read_response(ctx, c,
                                        t->databuf, (size_t) t->nread,
                                        &rsp_total);
    /* databuf has been copied into rspbuf; release it now */
    ngx_pfree(c->pool, t->databuf);

    if (rspbuf == NULL) {
        ctx->state = XRD_ST_REQ_HEADER;
        xrootd_aio_resume(c);
        return;
    }

    ctx->state   = XRD_ST_REQ_HEADER;
    ctx->hdr_pos = 0;

    /* Pass rspbuf as the pool-allocated base so xrootd_flush_pending can
     * free it once the entire response has been written to the socket. */
    xrootd_queue_response_base(ctx, c, rspbuf, rsp_total, rspbuf);
    if (ctx->state != XRD_ST_SENDING) {
        /* Fully sent inline — free the response buffer now */
        ngx_pfree(c->pool, rspbuf);
    }
    xrootd_aio_resume(c);
}

static void
xrootd_write_aio_done(ngx_event_t *ev)
{
    ngx_thread_task_t   *task = ev->data;
    xrootd_write_aio_t  *t   = task->ctx;
    xrootd_ctx_t        *ctx = t->ctx;
    ngx_connection_t    *c   = t->c;
    char                 detail[64];
    ngx_int_t            op  = t->is_pgwrite ? XROOTD_OP_WRITE : XROOTD_OP_WRITE;

    if (ctx->destroyed) { return; }

    ctx->cur_streamid[0] = t->streamid[0];
    ctx->cur_streamid[1] = t->streamid[1];
    ctx->state   = XRD_ST_REQ_HEADER;
    ctx->hdr_pos = 0;

    /* Free the payload buffer (written to disk; no longer needed) */
    if (t->payload_to_free) {
        ngx_pfree(c->pool, t->payload_to_free);
    }

    snprintf(detail, sizeof(detail), "%lld+%zu",
             (long long) t->req_offset, t->len);

    if (t->nwritten < 0) {
        xrootd_log_access(ctx, c, "WRITE", t->path, detail,
                          0, kXR_IOError,
                          t->io_errno ? strerror(t->io_errno) : "async write error",
                          0);
        XROOTD_OP_ERR(ctx, op);
        xrootd_send_error(ctx, c, kXR_IOError,
                          t->io_errno ? strerror(t->io_errno) : "async write error");
        xrootd_aio_resume(c);
        return;
    }

    if ((size_t) t->nwritten < t->len) {
        xrootd_log_access(ctx, c, "WRITE", t->path, detail,
                          0, kXR_IOError, "short write (disk full?)", 0);
        XROOTD_OP_ERR(ctx, op);
        xrootd_send_error(ctx, c, kXR_IOError, "short write (disk full?)");
        xrootd_aio_resume(c);
        return;
    }

    ctx->files[t->handle_idx].bytes_written += (size_t) t->nwritten;
    ctx->session_bytes_written              += (size_t) t->nwritten;

    xrootd_log_access(ctx, c, "WRITE", t->path, detail,
                      1, 0, NULL, (size_t) t->nwritten);
    XROOTD_OP_OK(ctx, op);

    if (t->is_pgwrite) {
        xrootd_send_pgwrite_status(ctx, c, t->req_offset + (int64_t) t->nwritten);
    } else {
        xrootd_send_ok(ctx, c, NULL, 0);
    }

    xrootd_aio_resume(c);
}

static void
xrootd_readv_aio_done(ngx_event_t *ev)
{
    ngx_thread_task_t   *task = ev->data;
    xrootd_readv_aio_t  *t   = task->ctx;
    xrootd_ctx_t        *ctx = t->ctx;
    ngx_connection_t    *c   = t->c;
    size_t               out_size;
    u_char              *rspbuf;

    if (ctx->destroyed) { return; }

    ctx->cur_streamid[0] = t->streamid[0];
    ctx->cur_streamid[1] = t->streamid[1];
    ctx->state   = XRD_ST_REQ_HEADER;
    ctx->hdr_pos = 0;

    if (t->io_error) {
        ngx_pfree(c->pool, t->databuf);
        XROOTD_OP_ERR(ctx, XROOTD_OP_READV);
        xrootd_send_error(ctx, c, kXR_IOError, t->err_msg);
        xrootd_aio_resume(c);
        return;
    }

    XROOTD_OP_OK(ctx, XROOTD_OP_READV);
    ctx->session_bytes += t->bytes_total;

    rspbuf = xrootd_build_readv_response(ctx, c,
                                         t->databuf, t->rsp_total,
                                         &out_size);
    /* databuf has been copied into rspbuf; release it now */
    ngx_pfree(c->pool, t->databuf);

    if (rspbuf == NULL) {
        xrootd_aio_resume(c);
        return;
    }

    xrootd_queue_response_base(ctx, c, rspbuf, out_size, rspbuf);
    if (ctx->state != XRD_ST_SENDING) {
        ngx_pfree(c->pool, rspbuf);
    }
    xrootd_aio_resume(c);
}

#endif /* NGX_THREADS */

static ngx_int_t
xrootd_handle_write(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    ClientWriteRequest           *req  = (ClientWriteRequest *) ctx->hdr_buf;
    ngx_stream_xrootd_srv_conf_t *conf =
        ngx_stream_get_module_srv_conf((ngx_stream_session_t *)(c->data), ngx_stream_xrootd_module);
    int     idx    = (int)(unsigned char) req->fhandle[0];
    int64_t offset = (int64_t) be64toh((uint64_t) req->offset);
    size_t  wlen   = ctx->cur_dlen;
    ssize_t nwritten;
    char    write_detail[64];

    if (idx < 0 || idx >= XROOTD_MAX_FILES || ctx->files[idx].fd < 0) {
        xrootd_log_access(ctx, c, "WRITE", "-", "-",
                          0, kXR_FileNotOpen, "invalid file handle", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_WRITE);
        return xrootd_send_error(ctx, c, kXR_FileNotOpen,
                                 "invalid file handle");
    }

    if (!ctx->files[idx].writable) {
        xrootd_log_access(ctx, c, "WRITE", ctx->files[idx].path, "-",
                          0, kXR_NotAuthorized, "file not open for writing", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_WRITE);
        return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                 "file not open for writing");
    }

    if (wlen == 0) {
        XROOTD_OP_OK(ctx, XROOTD_OP_WRITE);
        return xrootd_send_ok(ctx, c, NULL, 0);
    }

#if (NGX_THREADS)
    if (conf->thread_pool != NULL) {
        ngx_thread_task_t   *task;
        xrootd_write_aio_t  *t;

        task = ngx_thread_task_alloc(c->pool, sizeof(xrootd_write_aio_t));
        if (task == NULL) { return NGX_ERROR; }

        t = task->ctx;
        t->c               = c;
        t->ctx             = ctx;
        t->conf            = conf;
        t->fd              = ctx->files[idx].fd;
        t->handle_idx      = idx;
        t->offset          = (off_t) offset;
        t->data            = ctx->payload ? ctx->payload : (u_char *) "";
        t->len             = wlen;
        t->req_offset      = offset;
        t->is_pgwrite      = 0;
        t->nwritten        = -1;
        t->io_errno        = 0;
        t->payload_to_free = ctx->payload;   /* freed in done handler */
        t->streamid[0]     = ctx->cur_streamid[0];
        t->streamid[1]     = ctx->cur_streamid[1];
        ngx_memcpy(t->path, ctx->files[idx].path, sizeof(t->path));

        task->handler       = xrootd_write_aio_thread;
        task->event.handler = xrootd_write_aio_done;
        task->event.data    = task;

        if (ngx_thread_task_post(conf->thread_pool, task) != NGX_OK) {
            ngx_log_error(NGX_LOG_WARN, c->log, 0,
                          "xrootd: thread_task_post failed, falling back to sync write");
            goto sync_write;
        }

        ctx->state = XRD_ST_AIO;
        return NGX_OK;
    }

sync_write:
#endif /* NGX_THREADS */

    nwritten = pwrite(ctx->files[idx].fd,
                      ctx->payload ? ctx->payload : (u_char *) "",
                      wlen, (off_t) offset);

    snprintf(write_detail, sizeof(write_detail), "%lld+%zu",
             (long long) offset, wlen);

    if (nwritten < 0) {
        xrootd_log_access(ctx, c, "WRITE", ctx->files[idx].path,
                          write_detail, 0, kXR_IOError, strerror(errno), 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_WRITE);
        return xrootd_send_error(ctx, c, kXR_IOError, strerror(errno));
    }

    if ((size_t) nwritten < wlen) {
        xrootd_log_access(ctx, c, "WRITE", ctx->files[idx].path,
                          write_detail, 0, kXR_IOError, "short write (disk full?)", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_WRITE);
        return xrootd_send_error(ctx, c, kXR_IOError, "short write (disk full?)");
    }

    ctx->files[idx].bytes_written  += (size_t) nwritten;
    ctx->session_bytes_written     += (size_t) nwritten;

    xrootd_log_access(ctx, c, "WRITE", ctx->files[idx].path,
                      write_detail, 1, 0, NULL, (size_t) nwritten);
    XROOTD_OP_OK(ctx, XROOTD_OP_WRITE);

    return xrootd_send_ok(ctx, c, NULL, 0);
}

/*
 * kXR_pgwrite — paged write with per-page CRC32c checksums.
 *
 * Used by modern xrdcp (XRootD v5+) in preference to kXR_write.
 *
 * Payload layout (CRC comes FIRST, not last):
 *   [4 bytes CRC32c][up to 4096 bytes data] per page, back-to-back.
 *   The last page may carry fewer than 4096 data bytes but still has 4 bytes CRC32c.
 *   CRC32c uses the Castagnoli polynomial (not generic CRC32).
 *
 * We strip the CRC32c fields to produce a flat data buffer, then write it
 * with a single pwrite() — either synchronously or via the thread pool.
 * CRC32c verification is intentionally skipped: the TCP checksum already
 * ensures integrity on loopback and LAN.
 *
 * Response format: kXR_status (NOT plain kXR_ok).
 *   The xrdcp v5 client parses pgwrite responses as ServerResponseV2
 *   (32 bytes: 8-byte header + 16-byte Status body + 8-byte pgWrite body).
 *   Sending a plain 8-byte kXR_ok causes the client to read 24 bytes past
 *   the end of the response buffer and crash.  See xrootd_send_pgwrite_status().
 */
static ngx_int_t
xrootd_handle_pgwrite(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    ClientPgWriteRequest         *req  = (ClientPgWriteRequest *) ctx->hdr_buf;
    ngx_stream_xrootd_srv_conf_t *conf =
        ngx_stream_get_module_srv_conf((ngx_stream_session_t *)(c->data), ngx_stream_xrootd_module);
    int     idx     = (int)(unsigned char) req->fhandle[0];
    int64_t offset  = (int64_t) be64toh((uint64_t) req->offset);
    size_t  dlen    = ctx->cur_dlen;
    u_char *payload = ctx->payload;
    int64_t write_offset;
    size_t  page_data, total_written;
    ssize_t nw;
    char    write_detail[64];

    if (idx < 0 || idx >= XROOTD_MAX_FILES || ctx->files[idx].fd < 0) {
        xrootd_log_access(ctx, c, "WRITE", "-", "-",
                          0, kXR_FileNotOpen, "invalid file handle", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_WRITE);
        return xrootd_send_error(ctx, c, kXR_FileNotOpen,
                                 "invalid file handle");
    }

    if (!ctx->files[idx].writable) {
        xrootd_log_access(ctx, c, "WRITE", ctx->files[idx].path, "-",
                          0, kXR_NotAuthorized, "file not open for writing", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_WRITE);
        return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                 "file not open for writing");
    }

    if (payload == NULL || dlen == 0) {
        XROOTD_OP_OK(ctx, XROOTD_OP_WRITE);
        return xrootd_send_ok(ctx, c, NULL, 0);
    }

    /*
     * Strip interleaved 4-byte CRC32c fields from the pgwrite payload to
     * produce a flat data buffer for pwrite().
     *
     * Payload layout (CRC first):
     *   [XRD_PGWRITE_CKSZ=4 bytes CRC32c][up to XRD_PGWRITE_PAGESZ=4096 bytes data]
     * repeated for each page.  The last page may have fewer than 4096 data
     * bytes.  The CRC32c values are discarded.
     */
    {
        u_char *flat    = ngx_palloc(c->pool, dlen);   /* upper bound */
        u_char *src     = payload;
        u_char *dst;
        size_t  rem     = dlen;
        size_t  flat_sz = 0;

        if (flat == NULL) { return NGX_ERROR; }
        dst = flat;

        while (rem > XRD_PGWRITE_CKSZ) {
            src += XRD_PGWRITE_CKSZ;
            rem -= XRD_PGWRITE_CKSZ;
            page_data = (rem >= XRD_PGWRITE_PAGESZ) ? XRD_PGWRITE_PAGESZ : rem;
            ngx_memcpy(dst, src, page_data);
            dst     += page_data;
            src     += page_data;
            rem     -= page_data;
            flat_sz += page_data;
        }

#if (NGX_THREADS)
        if (conf->thread_pool != NULL) {
            ngx_thread_task_t   *task;
            xrootd_write_aio_t  *t;

            task = ngx_thread_task_alloc(c->pool, sizeof(xrootd_write_aio_t));
            if (task == NULL) { return NGX_ERROR; }

            t = task->ctx;
            t->c               = c;
            t->ctx             = ctx;
            t->conf            = conf;
            t->fd              = ctx->files[idx].fd;
            t->handle_idx      = idx;
            t->offset          = (off_t) offset;
            t->data            = flat;
            t->len             = flat_sz;
            t->req_offset      = offset;
            t->is_pgwrite      = 1;
            t->nwritten        = -1;
            t->io_errno        = 0;
            t->payload_to_free = flat;   /* freed in done handler */
            t->streamid[0]     = ctx->cur_streamid[0];
            t->streamid[1]     = ctx->cur_streamid[1];
            ngx_memcpy(t->path, ctx->files[idx].path, sizeof(t->path));

            task->handler       = xrootd_write_aio_thread;
            task->event.handler = xrootd_write_aio_done;
            task->event.data    = task;

            if (ngx_thread_task_post(conf->thread_pool, task) == NGX_OK) {
                ctx->state = XRD_ST_AIO;
                return NGX_OK;
            }
            ngx_log_error(NGX_LOG_WARN, c->log, 0,
                          "xrootd: thread_task_post failed, falling back to sync pgwrite");
        }
#endif /* NGX_THREADS */

        /* Synchronous path: write the flat buffer page by page */
        write_offset  = offset;
        total_written = 0;
        src = flat;
        rem = flat_sz;

        while (rem > 0) {
            page_data = (rem >= XRD_PGWRITE_PAGESZ) ? XRD_PGWRITE_PAGESZ : rem;
            nw = pwrite(ctx->files[idx].fd, src, page_data, (off_t) write_offset);
            if (nw < 0) {
                snprintf(write_detail, sizeof(write_detail), "%lld+%zu",
                         (long long) offset, total_written);
                xrootd_log_access(ctx, c, "WRITE", ctx->files[idx].path,
                                  write_detail, 0, kXR_IOError, strerror(errno), 0);
                XROOTD_OP_ERR(ctx, XROOTD_OP_WRITE);
                return xrootd_send_error(ctx, c, kXR_IOError, strerror(errno));
            }
            if ((size_t) nw < page_data) {
                snprintf(write_detail, sizeof(write_detail), "%lld+%zu",
                         (long long) offset, total_written);
                xrootd_log_access(ctx, c, "WRITE", ctx->files[idx].path,
                                  write_detail, 0, kXR_IOError, "short write (disk full?)", 0);
                XROOTD_OP_ERR(ctx, XROOTD_OP_WRITE);
                return xrootd_send_error(ctx, c, kXR_IOError, "short write (disk full?)");
            }
            total_written += (size_t) nw;
            write_offset  += (int64_t) nw;
            src           += page_data;
            rem           -= page_data;
        }

        ctx->files[idx].bytes_written += total_written;
        ctx->session_bytes_written    += total_written;

        snprintf(write_detail, sizeof(write_detail), "%lld+%zu",
                 (long long) offset, total_written);
        xrootd_log_access(ctx, c, "WRITE", ctx->files[idx].path,
                          write_detail, 1, 0, NULL, total_written);
        XROOTD_OP_OK(ctx, XROOTD_OP_WRITE);

        return xrootd_send_pgwrite_status(ctx, c, write_offset);
    }
}

/*
 * kXR_sync — flush/fsync an open file handle.
 *
 * Ensures all previously written data is durable on the underlying
 * filesystem.  xrdcp issues kXR_sync before kXR_close on uploads.
 */
static ngx_int_t
xrootd_handle_sync(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    ClientSyncRequest *req = (ClientSyncRequest *) ctx->hdr_buf;
    int idx = (int)(unsigned char) req->fhandle[0];

    if (idx < 0 || idx >= XROOTD_MAX_FILES || ctx->files[idx].fd < 0) {
        xrootd_log_access(ctx, c, "SYNC", "-", "-",
                          0, kXR_FileNotOpen, "invalid file handle", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_SYNC);
        return xrootd_send_error(ctx, c, kXR_FileNotOpen,
                                 "invalid file handle");
    }

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: kXR_sync handle=%d", idx);

    if (fsync(ctx->files[idx].fd) != 0) {
        xrootd_log_access(ctx, c, "SYNC", ctx->files[idx].path, "-",
                          0, kXR_IOError, strerror(errno), 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_SYNC);
        return xrootd_send_error(ctx, c, kXR_IOError, strerror(errno));
    }

    xrootd_log_access(ctx, c, "SYNC", ctx->files[idx].path, "-",
                      1, 0, NULL, 0);
    XROOTD_OP_OK(ctx, XROOTD_OP_SYNC);
    return xrootd_send_ok(ctx, c, NULL, 0);
}

/*
 * kXR_truncate — truncate a file by path or open handle.
 *
 * If dlen > 0: path-based truncate (payload is path).
 * If dlen == 0: handle-based truncate using fhandle[0].
 * The offset field carries the target file length.
 */
static ngx_int_t
xrootd_handle_truncate(xrootd_ctx_t *ctx, ngx_connection_t *c,
                        ngx_stream_xrootd_srv_conf_t *conf)
{
    ClientTruncateRequest *req = (ClientTruncateRequest *) ctx->hdr_buf;
    int64_t  length = (int64_t) be64toh((uint64_t) req->offset);
    char     detail[64];
    int      rc;

    snprintf(detail, sizeof(detail), "%lld", (long long) length);

    if (ctx->cur_dlen > 0) {
        /* Path-based truncate */
        char resolved[PATH_MAX];
        if (ctx->payload == NULL) {
            return xrootd_send_error(ctx, c, kXR_ArgMissing, "no path given");
        }
        if (!xrootd_resolve_path_write(c->log, &conf->root,
                                       (const char *) ctx->payload,
                                       resolved, sizeof(resolved))) {
            /* Try existing-file resolve too */
            if (!xrootd_resolve_path(c->log, &conf->root,
                                     (const char *) ctx->payload,
                                     resolved, sizeof(resolved))) {
                xrootd_log_access(ctx, c, "TRUNCATE", (char *) ctx->payload,
                                  detail, 0, kXR_NotFound, "file not found", 0);
                XROOTD_OP_ERR(ctx, XROOTD_OP_TRUNCATE);
                return xrootd_send_error(ctx, c, kXR_NotFound, "file not found");
            }
        }
        rc = truncate(resolved, (off_t) length);
        if (rc != 0) {
            xrootd_log_access(ctx, c, "TRUNCATE", resolved, detail,
                              0, kXR_IOError, strerror(errno), 0);
            XROOTD_OP_ERR(ctx, XROOTD_OP_TRUNCATE);
            return xrootd_send_error(ctx, c, kXR_IOError, strerror(errno));
        }
        xrootd_log_access(ctx, c, "TRUNCATE", resolved, detail,
                          1, 0, NULL, 0);
    } else {
        /* Handle-based truncate */
        int idx = (int)(unsigned char) req->fhandle[0];
        if (idx < 0 || idx >= XROOTD_MAX_FILES || ctx->files[idx].fd < 0) {
            xrootd_log_access(ctx, c, "TRUNCATE", "-", detail,
                              0, kXR_FileNotOpen, "invalid file handle", 0);
            XROOTD_OP_ERR(ctx, XROOTD_OP_TRUNCATE);
            return xrootd_send_error(ctx, c, kXR_FileNotOpen,
                                     "invalid file handle");
        }
        rc = ftruncate(ctx->files[idx].fd, (off_t) length);
        if (rc != 0) {
            xrootd_log_access(ctx, c, "TRUNCATE", ctx->files[idx].path, detail,
                              0, kXR_IOError, strerror(errno), 0);
            XROOTD_OP_ERR(ctx, XROOTD_OP_TRUNCATE);
            return xrootd_send_error(ctx, c, kXR_IOError, strerror(errno));
        }
        xrootd_log_access(ctx, c, "TRUNCATE", ctx->files[idx].path, detail,
                          1, 0, NULL, 0);
    }

    XROOTD_OP_OK(ctx, XROOTD_OP_TRUNCATE);
    return xrootd_send_ok(ctx, c, NULL, 0);
}

/*
 * kXR_mkdir — create a directory.
 *
 * options[0] bit kXR_mkdirpath (0x01): create parent directories too.
 * mode field: Unix permission bits.
 */
static ngx_int_t
xrootd_handle_mkdir(xrootd_ctx_t *ctx, ngx_connection_t *c,
                     ngx_stream_xrootd_srv_conf_t *conf)
{
    ClientMkdirRequest *req = (ClientMkdirRequest *) ctx->hdr_buf;
    char     resolved[PATH_MAX];
    mode_t   mode;
    int      recursive;

    if (ctx->payload == NULL || ctx->cur_dlen == 0) {
        return xrootd_send_error(ctx, c, kXR_ArgMissing, "no path given");
    }

    recursive = (req->options[0] & kXR_mkdirpath) ? 1 : 0;
    mode      = ntohs(req->mode) & 0777;
    if (mode == 0) {
        mode = 0755;
    }

    /*
     * Resolve the target path.  For recursive mkdir intermediate directories
     * do not exist yet, so we use xrootd_resolve_path_noexist (no realpath).
     * For a single-level mkdir the parent must exist, so use the write resolver.
     */
    if (recursive) {
        if (!xrootd_resolve_path_noexist(c->log, &conf->root,
                                          (const char *) ctx->payload,
                                          resolved, sizeof(resolved))) {
            xrootd_log_access(ctx, c, "MKDIR", (char *) ctx->payload, "-",
                              0, kXR_NotFound, "invalid path", 0);
            XROOTD_OP_ERR(ctx, XROOTD_OP_MKDIR);
            return xrootd_send_error(ctx, c, kXR_NotFound, "invalid path");
        }
    } else {
        if (!xrootd_resolve_path_write(c->log, &conf->root,
                                       (const char *) ctx->payload,
                                       resolved, sizeof(resolved))) {
            xrootd_log_access(ctx, c, "MKDIR", (char *) ctx->payload, "-",
                              0, kXR_NotFound, "invalid path", 0);
            XROOTD_OP_ERR(ctx, XROOTD_OP_MKDIR);
            return xrootd_send_error(ctx, c, kXR_NotFound, "invalid path");
        }
    }

    if (recursive) {
        if (xrootd_mkdir_recursive(resolved, mode) != 0 && errno != EEXIST) {
            xrootd_log_access(ctx, c, "MKDIR", resolved, "-",
                              0, kXR_IOError, strerror(errno), 0);
            XROOTD_OP_ERR(ctx, XROOTD_OP_MKDIR);
            return xrootd_send_error(ctx, c, kXR_IOError, strerror(errno));
        }
    } else {
        if (mkdir(resolved, mode) != 0) {
            int err = errno;
            if (err == EEXIST) {
                /* Not an error — directory already exists */
            } else if (err == EACCES) {
                xrootd_log_access(ctx, c, "MKDIR", resolved, "-",
                                  0, kXR_NotAuthorized, "permission denied", 0);
                XROOTD_OP_ERR(ctx, XROOTD_OP_MKDIR);
                return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                         "permission denied");
            } else {
                xrootd_log_access(ctx, c, "MKDIR", resolved, "-",
                                  0, kXR_IOError, strerror(err), 0);
                XROOTD_OP_ERR(ctx, XROOTD_OP_MKDIR);
                return xrootd_send_error(ctx, c, kXR_IOError, strerror(err));
            }
        }
    }

    xrootd_log_access(ctx, c, "MKDIR", resolved, "-", 1, 0, NULL, 0);
    XROOTD_OP_OK(ctx, XROOTD_OP_MKDIR);
    return xrootd_send_ok(ctx, c, NULL, 0);
}

/*
 * kXR_rm — remove a file.
 *
 * Path is in the payload.  Does not remove directories (use kXR_rmdir).
 */
static ngx_int_t
xrootd_handle_rm(xrootd_ctx_t *ctx, ngx_connection_t *c,
                  ngx_stream_xrootd_srv_conf_t *conf)
{
    char resolved[PATH_MAX];

    if (ctx->payload == NULL || ctx->cur_dlen == 0) {
        return xrootd_send_error(ctx, c, kXR_ArgMissing, "no path given");
    }

    /* File must exist for rm — use standard resolve */
    if (!xrootd_resolve_path(c->log, &conf->root,
                              (const char *) ctx->payload,
                              resolved, sizeof(resolved))) {
        xrootd_log_access(ctx, c, "RM", (char *) ctx->payload, "-",
                          0, kXR_NotFound, "file not found", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_RM);
        return xrootd_send_error(ctx, c, kXR_NotFound, "file not found");
    }

    if (unlink(resolved) != 0) {
        int err = errno;
        if (err == EACCES || err == EPERM) {
            xrootd_log_access(ctx, c, "RM", resolved, "-",
                              0, kXR_NotAuthorized, "permission denied", 0);
            XROOTD_OP_ERR(ctx, XROOTD_OP_RM);
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "permission denied");
        }
        xrootd_log_access(ctx, c, "RM", resolved, "-",
                          0, kXR_IOError, strerror(err), 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_RM);
        return xrootd_send_error(ctx, c, kXR_IOError, strerror(err));
    }

    xrootd_log_access(ctx, c, "RM", resolved, "-", 1, 0, NULL, 0);
    XROOTD_OP_OK(ctx, XROOTD_OP_RM);
    return xrootd_send_ok(ctx, c, NULL, 0);
}

/*
 * kXR_rmdir — remove an empty directory.
 *
 * Path is in the payload.  Fails with kXR_NotFound if path doesn't exist,
 * kXR_FSError (ENOTEMPTY) if the directory is not empty.
 */
static ngx_int_t
xrootd_handle_rmdir(xrootd_ctx_t *ctx, ngx_connection_t *c,
                    ngx_stream_xrootd_srv_conf_t *conf)
{
    char resolved[PATH_MAX];

    if (ctx->payload == NULL || ctx->cur_dlen == 0) {
        return xrootd_send_error(ctx, c, kXR_ArgMissing, "no path given");
    }

    if (!xrootd_resolve_path(c->log, &conf->root,
                              (const char *) ctx->payload,
                              resolved, sizeof(resolved))) {
        xrootd_log_access(ctx, c, "RMDIR", (char *) ctx->payload, "-",
                          0, kXR_NotFound, "directory not found", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_RMDIR);
        return xrootd_send_error(ctx, c, kXR_NotFound, "directory not found");
    }

    if (rmdir(resolved) != 0) {
        int err = errno;
        if (err == ENOTEMPTY || err == EEXIST) {
            xrootd_log_access(ctx, c, "RMDIR", resolved, "-",
                              0, kXR_FSError, "directory not empty", 0);
            XROOTD_OP_ERR(ctx, XROOTD_OP_RMDIR);
            return xrootd_send_error(ctx, c, kXR_FSError,
                                     "directory not empty");
        }
        if (err == EACCES || err == EPERM) {
            xrootd_log_access(ctx, c, "RMDIR", resolved, "-",
                              0, kXR_NotAuthorized, "permission denied", 0);
            XROOTD_OP_ERR(ctx, XROOTD_OP_RMDIR);
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "permission denied");
        }
        if (err == ENOTDIR) {
            xrootd_log_access(ctx, c, "RMDIR", resolved, "-",
                              0, kXR_NotFile, "not a directory", 0);
            XROOTD_OP_ERR(ctx, XROOTD_OP_RMDIR);
            return xrootd_send_error(ctx, c, kXR_NotFile, "not a directory");
        }
        xrootd_log_access(ctx, c, "RMDIR", resolved, "-",
                          0, kXR_IOError, strerror(err), 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_RMDIR);
        return xrootd_send_error(ctx, c, kXR_IOError, strerror(err));
    }

    xrootd_log_access(ctx, c, "RMDIR", resolved, "-", 1, 0, NULL, 0);
    XROOTD_OP_OK(ctx, XROOTD_OP_RMDIR);
    return xrootd_send_ok(ctx, c, NULL, 0);
}

/*
 * kXR_mv — rename/move a file or directory.
 *
 * Payload layout (from XrdClFileSystem.cc):
 *   header.arg1len = source.length()   ← byte count, no trailing NUL
 *   payload        = src[arg1len] + ' ' (0x20) + dst[...]
 *
 * The separator is a single ASCII space — NOT a null byte.  arg1len does
 * NOT include any terminator.  The destination runs to the end of dlen.
 *
 * Both paths must be inside the server root; rename(2) is used, so cross-
 * device moves return EXDEV.
 */
static ngx_int_t
xrootd_handle_mv(xrootd_ctx_t *ctx, ngx_connection_t *c,
                 ngx_stream_xrootd_srv_conf_t *conf)
{
    ClientMvRequest *req = (ClientMvRequest *) ctx->hdr_buf;
    char src_resolved[PATH_MAX];
    char dst_resolved[PATH_MAX];
    char src_buf[PATH_MAX];      /* null-terminated copy of source path */
    int16_t  src_len;
    const char *src_path, *dst_path;

    if (ctx->payload == NULL || ctx->cur_dlen == 0) {
        return xrootd_send_error(ctx, c, kXR_ArgMissing, "no paths given");
    }

    /*
     * Wire format (from XrdClFileSystem.cc):
     *   arg1len = source.length()       (NOT including any terminator)
     *   dlen    = src.length() + dst.length() + 1
     *   payload = src[arg1len] + ' ' + dst[...]
     * The separator between source and destination is a single space (0x20).
     */
    src_len = (int16_t) ntohs((uint16_t) req->arg1len);
    if (src_len <= 0 || (uint32_t)(src_len + 1) >= ctx->cur_dlen) {
        return xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                 "invalid arg1len for mv");
    }

    src_path = (const char *) ctx->payload;
    /* Separator byte at src_len must be a space */
    if (ctx->payload[src_len] != ' ') {
        return xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                 "mv payload separator not a space");
    }
    dst_path = (const char *) ctx->payload + src_len + 1;

    /* Copy source path into a null-terminated buffer for resolve */
    if (src_len >= (int16_t) sizeof(src_buf)) {
        return xrootd_send_error(ctx, c, kXR_ArgTooLong, "source path too long");
    }
    ngx_memcpy(src_buf, src_path, src_len);
    src_buf[src_len] = '\0';

    if (!xrootd_resolve_path(c->log, &conf->root, src_buf,
                              src_resolved, sizeof(src_resolved))) {
        xrootd_log_access(ctx, c, "MV", src_buf, "-",
                          0, kXR_NotFound, "source not found", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_MV);
        return xrootd_send_error(ctx, c, kXR_NotFound, "source not found");
    }

    if (!xrootd_resolve_path_write(c->log, &conf->root, dst_path,
                                    dst_resolved, sizeof(dst_resolved))) {
        xrootd_log_access(ctx, c, "MV", src_buf, "-",
                          0, kXR_NotFound, "invalid destination path", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_MV);
        return xrootd_send_error(ctx, c, kXR_NotFound,
                                 "invalid destination path");
    }

    if (rename(src_resolved, dst_resolved) != 0) {
        int err = errno;
        if (err == EACCES || err == EPERM) {
            xrootd_log_access(ctx, c, "MV", src_resolved, "-",
                              0, kXR_NotAuthorized, "permission denied", 0);
            XROOTD_OP_ERR(ctx, XROOTD_OP_MV);
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "permission denied");
        }
        xrootd_log_access(ctx, c, "MV", src_resolved, "-",
                          0, kXR_IOError, strerror(err), 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_MV);
        return xrootd_send_error(ctx, c, kXR_IOError, strerror(err));
    }

    xrootd_log_access(ctx, c, "MV", src_resolved, dst_resolved, 1, 0, NULL, 0);
    XROOTD_OP_OK(ctx, XROOTD_OP_MV);
    return xrootd_send_ok(ctx, c, NULL, 0);
}

/*
 * kXR_chmod — change the permission bits of a file or directory.
 *
 * The header's mode field carries the Unix permission bits (9 bits).
 * Path is in the payload.
 */
static ngx_int_t
xrootd_handle_chmod(xrootd_ctx_t *ctx, ngx_connection_t *c,
                    ngx_stream_xrootd_srv_conf_t *conf)
{
    ClientChmodRequest *req = (ClientChmodRequest *) ctx->hdr_buf;
    char    resolved[PATH_MAX];
    mode_t  mode;

    if (ctx->payload == NULL || ctx->cur_dlen == 0) {
        return xrootd_send_error(ctx, c, kXR_ArgMissing, "no path given");
    }

    mode = ntohs(req->mode) & 0777;
    if (mode == 0) {
        mode = 0644;  /* sensible default if client sends 0 */
    }

    if (!xrootd_resolve_path(c->log, &conf->root,
                              (const char *) ctx->payload,
                              resolved, sizeof(resolved))) {
        xrootd_log_access(ctx, c, "CHMOD", (char *) ctx->payload, "-",
                          0, kXR_NotFound, "path not found", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_CHMOD);
        return xrootd_send_error(ctx, c, kXR_NotFound, "path not found");
    }

    if (chmod(resolved, mode) != 0) {
        int err = errno;
        if (err == EACCES || err == EPERM) {
            xrootd_log_access(ctx, c, "CHMOD", resolved, "-",
                              0, kXR_NotAuthorized, "permission denied", 0);
            XROOTD_OP_ERR(ctx, XROOTD_OP_CHMOD);
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "permission denied");
        }
        xrootd_log_access(ctx, c, "CHMOD", resolved, "-",
                          0, kXR_IOError, strerror(err), 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_CHMOD);
        return xrootd_send_error(ctx, c, kXR_IOError, strerror(err));
    }

    xrootd_log_access(ctx, c, "CHMOD", resolved, "-", 1, 0, NULL, 0);
    XROOTD_OP_OK(ctx, XROOTD_OP_CHMOD);
    return xrootd_send_ok(ctx, c, NULL, 0);
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
/* All other infotypes return kXR_Unsupported.                         */
/*                                                                     */
/* Adler32 algorithm:                                                  */
/*   A_0 = 1, B_0 = 0                                                 */
/*   For each byte b: A += b; B += A;  (mod 65521)                    */
/*   Result = (B << 16) | A                                            */
/* ------------------------------------------------------------------ */

/*
 * Compute adler32 of a file identified by an already-resolved path.
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

    fd = open(path, O_RDONLY);
    if (fd < 0) {
        ngx_log_error(NGX_LOG_ERR, log, errno,
                      "xrootd: adler32 open(\"%s\") failed", path);
        return 0xFFFFFFFF;
    }

    for (;;) {
        n = read(fd, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR) continue;
            ngx_log_error(NGX_LOG_ERR, log, errno,
                          "xrootd: adler32 read(\"%s\") failed", path);
            close(fd);
            return 0xFFFFFFFF;
        }
        if (n == 0) break;

        for (ssize_t i = 0; i < n; i++) {
            A = (A + buf[i]) % MOD;
            B = (B + A)      % MOD;
        }
    }

    close(fd);
    return (B << 16) | A;
}

static ngx_int_t
xrootd_handle_query(xrootd_ctx_t *ctx, ngx_connection_t *c,
                    ngx_stream_xrootd_srv_conf_t *conf)
{
    ClientQueryRequest *req = (ClientQueryRequest *) ctx->hdr_buf;
    uint16_t infotype = ntohs(req->infotype);

    /* ---- kXR_Qcksum (3): adler32 by path or open handle ---- */
    if (infotype == kXR_Qcksum) {
        char     resolved[PATH_MAX];
        uint32_t cksum;
        char     resp[64];

        if (ctx->cur_dlen > 0 && ctx->payload != NULL) {
            /* Path-based checksum */
            char pathbuf[XROOTD_MAX_PATH + 1];
            xrootd_strip_cgi((const char *) ctx->payload,
                             pathbuf, sizeof(pathbuf));

            if (!xrootd_resolve_path(c->log, &conf->root,
                                     pathbuf, resolved, sizeof(resolved))) {
                xrootd_log_access(ctx, c, "QUERY", pathbuf, "cksum",
                                  0, kXR_NotFound, "file not found", 0);
                XROOTD_OP_ERR(ctx, XROOTD_OP_QUERY_CKSUM);
                return xrootd_send_error(ctx, c, kXR_NotFound,
                                         "file not found");
            }

            cksum = xrootd_adler32_file(resolved, c->log);
            if (cksum == 0xFFFFFFFF) {
                xrootd_log_access(ctx, c, "QUERY", resolved, "cksum",
                                  0, kXR_IOError, "read error", 0);
                XROOTD_OP_ERR(ctx, XROOTD_OP_QUERY_CKSUM);
                return xrootd_send_error(ctx, c, kXR_IOError,
                                         "checksum computation failed");
            }

        } else {
            /* Handle-based checksum */
            int idx = (int)(unsigned char) req->fhandle[0];
            if (idx < 0 || idx >= XROOTD_MAX_FILES
                        || ctx->files[idx].fd < 0) {
                XROOTD_OP_ERR(ctx, XROOTD_OP_QUERY_CKSUM);
                return xrootd_send_error(ctx, c, kXR_FileNotOpen,
                                         "invalid file handle");
            }
            ngx_cpystrn((u_char *) resolved,
                        (u_char *) ctx->files[idx].path,
                        sizeof(resolved));
            cksum = xrootd_adler32_file(resolved, c->log);
            if (cksum == 0xFFFFFFFF) {
                XROOTD_OP_ERR(ctx, XROOTD_OP_QUERY_CKSUM);
                return xrootd_send_error(ctx, c, kXR_IOError,
                                         "checksum computation failed");
            }
        }

        /* Response format: "adler32 <8-hex-digits>\0" */
        snprintf(resp, sizeof(resp), "adler32 %08x", (unsigned int) cksum);

        xrootd_log_access(ctx, c, "QUERY", resolved, "cksum", 1, 0, NULL, 0);
        XROOTD_OP_OK(ctx, XROOTD_OP_QUERY_CKSUM);
        return xrootd_send_ok(ctx, c, resp, (uint32_t)(strlen(resp) + 1));
    }

    /* ---- kXR_Qspace (5): storage space for xrootd_root ---- */
    if (infotype == kXR_Qspace) {
        struct statvfs  vfs;
        char            resp[256];
        unsigned long long total, free_bytes, used_bytes;

        /* statvfs on the configured root directory */
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

        while (*p) {
            nl = strchr(p, '\n');
            size_t keylen = nl ? (size_t)(nl - p) : strlen(p);
            char key[128];
            if (keylen >= sizeof(key)) keylen = sizeof(key) - 1;
            memcpy(key, p, keylen);
            key[keylen] = '\0';

            int n;
            if (strcmp(key, "chksum") == 0) {
                n = snprintf(resp + pos, sizeof(resp) - pos,
                             "chksum=adler32\n");
            } else if (strcmp(key, "readv") == 0) {
                n = snprintf(resp + pos, sizeof(resp) - pos, "readv=1\n");
            } else {
                n = snprintf(resp + pos, sizeof(resp) - pos, "%s=0\n", key);
            }
            if (n > 0) pos += (size_t) n;
            if (pos >= sizeof(resp) - 1) break;
            p = nl ? nl + 1 : p + keylen;
        }
        if (pos == 0) {
            /* no keys requested — return empty ok */
            return xrootd_send_ok(ctx, c, NULL, 0);
        }
        return xrootd_send_ok(ctx, c, resp, (uint32_t) pos);
    }

    /* All other query types: not implemented */
    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: kXR_query unsupported infotype=%d",
                   (int) infotype);
    return xrootd_send_error(ctx, c, kXR_Unsupported,
                             "query type not supported");
}

/* kXR_endsess — client wants to end the session gracefully */
static ngx_int_t
xrootd_handle_endsess(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: kXR_endsess received");
    xrootd_on_disconnect(ctx, c);
    xrootd_close_all_files(ctx);
    /* Acknowledge, then the client will close the TCP connection */
    return xrootd_send_ok(ctx, c, NULL, 0);
}

/* kXR_stat — stat by path or by open file handle */
static ngx_int_t
xrootd_handle_stat(xrootd_ctx_t *ctx, ngx_connection_t *c,
                   ngx_stream_xrootd_srv_conf_t *conf)
{
    ClientStatRequest *req = (ClientStatRequest *) ctx->hdr_buf;
    struct stat        st;
    char               resolved[PATH_MAX];
    char               body[256];
    ngx_flag_t         is_vfs;
    const char        *reqpath = NULL;

    is_vfs = (req->options & kXR_vfs) ? 1 : 0;

    if (ctx->cur_dlen > 0 && ctx->payload != NULL) {
        /* Path-based stat */
        reqpath = (const char *) ctx->payload;

        if (!xrootd_resolve_path(c->log, &conf->root,
                                 reqpath, resolved, sizeof(resolved))) {
            xrootd_log_access(ctx, c, "STAT", reqpath, "-",
                              0, kXR_NotFound, "file not found", 0);
            XROOTD_OP_ERR(ctx, XROOTD_OP_STAT);
            return xrootd_send_error(ctx, c, kXR_NotFound,
                                     "file not found");
        }

        if (stat(resolved, &st) != 0) {
            xrootd_log_access(ctx, c, "STAT", reqpath, "-",
                              0, kXR_NotFound, strerror(errno), 0);
            XROOTD_OP_ERR(ctx, XROOTD_OP_STAT);
            return xrootd_send_error(ctx, c, kXR_NotFound,
                                     "file not found");
        }
    } else {
        /* Handle-based stat: fhandle[0] is our slot index */
        int idx = (int)(unsigned char) req->fhandle[0];

        if (idx < 0 || idx >= XROOTD_MAX_FILES
                || ctx->files[idx].fd < 0) {
            xrootd_log_access(ctx, c, "STAT", "-", "-",
                              0, kXR_FileNotOpen, "invalid file handle", 0);
            XROOTD_OP_ERR(ctx, XROOTD_OP_STAT);
            return xrootd_send_error(ctx, c, kXR_FileNotOpen,
                                     "invalid file handle");
        }

        resolved[0] = '\0';
        ngx_cpystrn((u_char *) resolved,
                    (u_char *) ctx->files[idx].path,
                    sizeof(resolved));

        if (fstat(ctx->files[idx].fd, &st) != 0) {
            xrootd_log_access(ctx, c, "STAT", resolved, "-",
                              0, kXR_IOError, strerror(errno), 0);
            XROOTD_OP_ERR(ctx, XROOTD_OP_STAT);
            return xrootd_send_error(ctx, c, kXR_IOError, strerror(errno));
        }
    }

    xrootd_make_stat_body(&st, is_vfs, body, sizeof(body));

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: kXR_stat ok: %s", body);

    /* Log the stat — use resolved path for handle-based stats */
    xrootd_log_access(ctx, c, "STAT",
                      (reqpath && reqpath[0]) ? reqpath : resolved,
                      is_vfs ? "vfs" : "-",
                      1, 0, NULL, 0);
    XROOTD_OP_OK(ctx, XROOTD_OP_STAT);

    return xrootd_send_ok(ctx, c, body, (uint32_t)(strlen(body) + 1));
}

/* kXR_open — open a file for reading or writing.
 *
 * Read flags (always accepted):
 *   kXR_open_read  — open for reading (default if no write flag set)
 *
 * Write flags (only when xrootd_allow_write is on):
 *   kXR_new        — create file; fail if it exists (O_CREAT|O_EXCL)
 *   kXR_delete     — create or truncate (O_CREAT|O_TRUNC)
 *   kXR_open_updt  — open existing for read+write (O_RDWR)
 *   kXR_open_apnd  — open for append (O_WRONLY|O_APPEND)
 *   kXR_open_wrto  — write-only (combine with kXR_new or kXR_delete)
 *   kXR_mkpath     — create parent directories before opening
 */
static ngx_int_t
xrootd_handle_open(xrootd_ctx_t *ctx, ngx_connection_t *c,
                   ngx_stream_xrootd_srv_conf_t *conf)
{
    ClientOpenRequest *req = (ClientOpenRequest *) ctx->hdr_buf;
    uint16_t           options;
    uint16_t           mode_bits;
    char               resolved[PATH_MAX];
    char               clean_path[PATH_MAX];  /* path with CGI query stripped */
    int                idx, fd, oflags;
    int                is_write;
    ServerOpenBody     body;
    struct stat        st;
    char               statbuf[256];
    u_char            *buf;
    size_t             bodylen, total;
    ngx_flag_t         want_stat;

    options   = ntohs(req->options);
    mode_bits = ntohs(req->mode);
    want_stat = (options & kXR_retstat) ? 1 : 0;

    /* Determine whether this is a write-mode open */
    is_write = (options & (kXR_new | kXR_delete | kXR_open_updt |
                           kXR_open_wrto | kXR_open_apnd)) ? 1 : 0;

    if (is_write && !conf->allow_write) {
        xrootd_log_access(ctx, c, "OPEN",
                          ctx->payload ? (char *) ctx->payload : "-", "wr",
                          0, kXR_fsReadOnly, "read-only server", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_OPEN_WR);
        return xrootd_send_error(ctx, c, kXR_fsReadOnly,
                                 "this is a read-only server");
    }

    if (ctx->payload == NULL || ctx->cur_dlen == 0) {
        xrootd_log_access(ctx, c, "OPEN", "-",
                          is_write ? "wr" : "rd",
                          0, kXR_ArgMissing, "no path given", 0);
        XROOTD_OP_ERR(ctx, is_write ? XROOTD_OP_OPEN_WR : XROOTD_OP_OPEN_RD);
        return xrootd_send_error(ctx, c, kXR_ArgMissing, "no path given");
    }

    /* Strip XRootD CGI query string ("?oss.asize=N" etc.) from the path.
     * xrdcp and other clients append these for metadata; they are not part
     * of the filesystem path. */
    xrootd_strip_cgi((const char *) ctx->payload, clean_path, sizeof(clean_path));

    /* Resolve the path.
     * For read opens the file must already exist (realpath check).
     * For write opens with kXR_mkpath the parent dirs may not exist yet,
     * so use xrootd_resolve_path_noexist; otherwise use the write resolver
     * which requires the parent to exist. */
    if (!is_write) {
        if (!xrootd_resolve_path(c->log, &conf->root,
                                 clean_path, resolved, sizeof(resolved))) {
            xrootd_log_access(ctx, c, "OPEN", clean_path, "rd",
                              0, kXR_NotFound, "file not found", 0);
            XROOTD_OP_ERR(ctx, XROOTD_OP_OPEN_RD);
            return xrootd_send_error(ctx, c, kXR_NotFound, "file not found");
        }

        /* Reject opening a directory as a file */
        {
            struct stat st;
            if (stat(resolved, &st) == 0 && S_ISDIR(st.st_mode)) {
                xrootd_log_access(ctx, c, "OPEN", clean_path, "rd",
                                  0, kXR_isDirectory, "is a directory", 0);
                XROOTD_OP_ERR(ctx, XROOTD_OP_OPEN_RD);
                return xrootd_send_error(ctx, c, kXR_isDirectory,
                                         "is a directory");
            }
        }
    } else {
        int ok;
        if (options & kXR_mkpath) {
            /* Parent dirs may not exist yet — validate without realpath */
            ok = xrootd_resolve_path_noexist(c->log, &conf->root,
                                              clean_path, resolved,
                                              sizeof(resolved));
        } else {
            ok = xrootd_resolve_path_write(c->log, &conf->root,
                                           clean_path, resolved,
                                           sizeof(resolved));
        }
        if (!ok) {
            xrootd_log_access(ctx, c, "OPEN", clean_path, "wr",
                              0, kXR_NotFound, "invalid path", 0);
            XROOTD_OP_ERR(ctx, XROOTD_OP_OPEN_WR);
            return xrootd_send_error(ctx, c, kXR_NotFound, "invalid path");
        }

        /* Create parent directories if kXR_mkpath is set */
        if (options & kXR_mkpath) {
            char  parent[PATH_MAX];
            char *slash;
            ngx_cpystrn((u_char *) parent, (u_char *) resolved, sizeof(parent));
            slash = strrchr(parent, '/');
            if (slash && slash > parent) {
                *slash = '\0';
                /* mode 0755 for new directories */
                xrootd_mkdir_recursive(parent, 0755);
            }
        }
    }

    /* Build the OS open flags from XRootD options.
     *
     * XRootD separates the access mode from the creation/truncation action:
     *   kXR_open_updt  → O_RDWR (read+write access)
     *   kXR_open_apnd  → O_WRONLY|O_APPEND
     *   kXR_open_wrto  → O_WRONLY
     *   kXR_new        → O_CREAT (create if not exists)
     *   kXR_delete     → O_TRUNC (truncate to zero if exists)
     *
     * These flags are independent and can all be set simultaneously.
     * xrdcp typically sends kXR_new|kXR_delete|kXR_open_updt|kXR_mkpath
     * which means "create or overwrite, open for read+write".
     */
    if (!is_write) {
        oflags = O_RDONLY | O_NOCTTY;
    } else {
        /* Step 1: access mode */
        if (options & kXR_open_updt) {
            oflags = O_RDWR;
        } else if (options & kXR_open_apnd) {
            oflags = O_WRONLY | O_APPEND;
        } else {
            oflags = O_WRONLY;
        }

        /* Step 2: creation / truncation modifiers.
         *
         * kXR_new alone   → O_CREAT|O_EXCL  (fail if file exists)
         * kXR_new|kXR_delete → O_CREAT|O_TRUNC  (create or overwrite)
         * kXR_delete alone → O_CREAT|O_TRUNC
         */
        if (options & kXR_new) {
            oflags |= O_CREAT;
            if (!(options & kXR_delete)) {
                oflags |= O_EXCL;   /* fail if already exists */
            }
        }
        if (options & kXR_delete) {
            oflags |= O_CREAT | O_TRUNC;
        }

        oflags |= O_NOCTTY;
    }

    /* Convert XRootD mode bits (Unix permission bits in low 9 bits) */
    mode_t create_mode = (mode_bits & 0777);
    if (create_mode == 0) {
        create_mode = 0644;   /* sensible default if client sends 0 */
    }

    /* Allocate a file handle slot */
    idx = xrootd_alloc_fhandle(ctx);
    if (idx < 0) {
        xrootd_log_access(ctx, c, "OPEN", resolved,
                          is_write ? "wr" : "rd",
                          0, kXR_ServerError, "too many open files", 0);
        XROOTD_OP_ERR(ctx, is_write ? XROOTD_OP_OPEN_WR : XROOTD_OP_OPEN_RD);
        return xrootd_send_error(ctx, c, kXR_ServerError,
                                 "too many open files");
    }

    fd = open(resolved, oflags, create_mode);
    if (fd < 0) {
        int err = errno;
        const char *mode_str = is_write ? "wr" : "rd";
        if (err == ENOENT || err == ENOTDIR) {
            xrootd_log_access(ctx, c, "OPEN", resolved, mode_str,
                              0, kXR_NotFound, "file not found", 0);
            XROOTD_OP_ERR(ctx, is_write ? XROOTD_OP_OPEN_WR : XROOTD_OP_OPEN_RD);
            return xrootd_send_error(ctx, c, kXR_NotFound,
                                     "file not found");
        }
        if (err == EEXIST) {
            xrootd_log_access(ctx, c, "OPEN", resolved, mode_str,
                              0, kXR_FileLocked, "file already exists", 0);
            XROOTD_OP_ERR(ctx, is_write ? XROOTD_OP_OPEN_WR : XROOTD_OP_OPEN_RD);
            return xrootd_send_error(ctx, c, kXR_FileLocked,
                                     "file already exists");
        }
        if (err == EACCES) {
            xrootd_log_access(ctx, c, "OPEN", resolved, mode_str,
                              0, kXR_NotAuthorized, "permission denied", 0);
            XROOTD_OP_ERR(ctx, is_write ? XROOTD_OP_OPEN_WR : XROOTD_OP_OPEN_RD);
            return xrootd_send_error(ctx, c, kXR_NotAuthorized,
                                     "permission denied");
        }
        xrootd_log_access(ctx, c, "OPEN", resolved, mode_str,
                          0, kXR_IOError, strerror(err), 0);
        XROOTD_OP_ERR(ctx, is_write ? XROOTD_OP_OPEN_WR : XROOTD_OP_OPEN_RD);
        return xrootd_send_error(ctx, c, kXR_IOError, strerror(err));
    }

    ctx->files[idx].fd       = fd;
    ctx->files[idx].writable = is_write;
    ngx_cpystrn((u_char *) ctx->files[idx].path,
                (u_char *) resolved,
                sizeof(ctx->files[idx].path));

    /*
     * If the client set kXR_retstat, include a stat string in the open
     * response so the client doesn't need to issue a separate kXR_stat.
     *
     * Both kXR_open retstat and standalone kXR_stat use the same wire order:
     *   "<id> <size> <flags> <mtime>\0"
     *
     * The client's ServerOpenBody handler reads the stat string starting
     * immediately after the 12-byte ServerOpenBody, using the same parser
     * as standalone kXR_stat responses (StatInfo chunks[1]=size, [2]=flags).
     */
    statbuf[0] = '\0';
    if (want_stat) {
        if (fstat(fd, &st) == 0) {
            /* Format: "<id> <size> <flags> <mtime>\0" — size before flags. */
            int stat_flags = 0;
            if (st.st_mode & (S_IRUSR | S_IRGRP | S_IROTH)) {
                stat_flags |= kXR_readable;
            }
            if (st.st_mode & (S_IWUSR | S_IWGRP | S_IWOTH)) {
                stat_flags |= kXR_writable;
            }
            snprintf(statbuf, sizeof(statbuf), "%llu %lld %d %ld",
                     (unsigned long long) st.st_ino,
                     (long long) st.st_size,
                     stat_flags,
                     (long) st.st_mtime);
        } else {
            want_stat = 0;   /* couldn't stat; skip gracefully */
        }
    }

    ngx_log_debug4(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: kXR_open handle=%d path=%s mode=%s retstat=%d",
                   idx, resolved, is_write ? "wr" : "rd", (int) want_stat);

    /*
     * Build response: 8-byte header + 12-byte ServerOpenBody
     * + optional NUL-terminated stat string (when kXR_retstat set).
     */
    bodylen = sizeof(ServerOpenBody);
    if (want_stat) {
        bodylen += strlen(statbuf) + 1;   /* include the NUL */
    }

    total = XRD_RESPONSE_HDR_LEN + bodylen;
    buf   = ngx_palloc(c->pool, total);
    if (buf == NULL) {
        close(fd);
        ctx->files[idx].fd = -1;
        return NGX_ERROR;
    }

    xrootd_build_resp_hdr(ctx->cur_streamid, kXR_ok,
                           (uint32_t) bodylen,
                           (ServerResponseHdr *) buf);

    /*
     * fhandle[0] = our slot index; bytes 1-3 are zero.
     * The client will echo these 4 bytes in subsequent kXR_read/close.
     */
    ngx_memzero(&body, sizeof(body));
    body.fhandle[0] = (u_char) idx;
    body.cpsize     = 0;    /* no compression */
    ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN, &body, sizeof(body));

    if (want_stat) {
        size_t slen = strlen(statbuf) + 1;
        ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN + sizeof(ServerOpenBody),
                   statbuf, slen);
    }

    ctx->files[idx].bytes_read    = 0;
    ctx->files[idx].bytes_written = 0;
    ctx->files[idx].open_time     = ngx_current_msec;

    xrootd_log_access(ctx, c, "OPEN", resolved,
                      is_write ? "wr" : "rd", 1, 0, NULL, 0);
    XROOTD_OP_OK(ctx, is_write ? XROOTD_OP_OPEN_WR : XROOTD_OP_OPEN_RD);

    return xrootd_queue_response(ctx, c, buf, total);
}

/* ------------------------------------------------------------------ */
/* kXR_readv — scatter-gather / vector read                            */
/*                                                                     */
/* The payload is an array of readahead_list structs (16 bytes each).  */
/* Each struct specifies an open file handle, a byte offset, and the   */
/* number of bytes requested (rlen).  Segments may reference different  */
/* open handles.                                                        */
/*                                                                     */
/* Response: for each segment, a readahead_list header (fhandle +      */
/* actual rlen + offset) followed immediately by rlen bytes of data.   */
/* All segments are concatenated into one body.  Large responses are   */
/* split into kXR_oksofar chunks (same scheme as kXR_read).            */
/*                                                                     */
/* A short read (hit EOF) sets rlen to the actual bytes read in the    */
/* response header for that segment.  Zero-length segments are echoed  */
/* back with rlen=0.  An invalid file handle aborts the entire request. */
/* ------------------------------------------------------------------ */
static ngx_int_t
xrootd_handle_readv(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    readahead_list               *segs;
    ngx_stream_xrootd_srv_conf_t *conf =
        ngx_stream_get_module_srv_conf((ngx_stream_session_t *)(c->data), ngx_stream_xrootd_module);
    size_t           n_segs, i;
    u_char          *databuf;
    size_t           max_rsp;

/* Hard cap for the total readv response (256 MiB). */
#define XROOTD_MAX_READV_TOTAL  (256u * 1024u * 1024u)

    /* Validate payload: must be a non-empty, whole multiple of segment size */
    if (ctx->payload == NULL || ctx->cur_dlen == 0 ||
        (ctx->cur_dlen % XROOTD_READV_SEGSIZE) != 0) {
        XROOTD_OP_ERR(ctx, XROOTD_OP_READV);
        return xrootd_send_error(ctx, c, kXR_ArgInvalid,
                                 "malformed readv request");
    }

    segs   = (readahead_list *) ctx->payload;
    n_segs = ctx->cur_dlen / XROOTD_READV_SEGSIZE;

    /* --- First pass: validate all handles and compute max response size --- */
    max_rsp = 0;
    for (i = 0; i < n_segs; i++) {
        int      idx  = (int)(unsigned char) segs[i].fhandle[0];
        uint32_t rlen = (uint32_t) ntohl((uint32_t) segs[i].rlen);

        if (idx < 0 || idx >= XROOTD_MAX_FILES || ctx->files[idx].fd < 0) {
            XROOTD_OP_ERR(ctx, XROOTD_OP_READV);
            return xrootd_send_error(ctx, c, kXR_FileNotOpen,
                                     "invalid file handle in readv");
        }

        if (rlen > XROOTD_READ_MAX) { rlen = XROOTD_READ_MAX; }
        max_rsp += XROOTD_READV_SEGSIZE + rlen;

        if (max_rsp > XROOTD_MAX_READV_TOTAL) {
            XROOTD_OP_ERR(ctx, XROOTD_OP_READV);
            return xrootd_send_error(ctx, c, kXR_ArgTooLong,
                                     "readv total would exceed server limit");
        }
    }

    /* Allocate response body buffer (max size) and pre-fill headers */
    databuf = ngx_palloc(c->pool, max_rsp);
    if (databuf == NULL) { return NGX_ERROR; }

    /* Pre-fill readahead_list headers with fhandle and offset (BE).
     * rlen fields are left for the thread to patch after pread(). */
    {
        u_char *p = databuf;
        for (i = 0; i < n_segs; i++) {
            uint32_t rlen = (uint32_t) ntohl((uint32_t) segs[i].rlen);
            if (rlen > XROOTD_READ_MAX) { rlen = XROOTD_READ_MAX; }

            ngx_memcpy(p, segs[i].fhandle, 4);
            /* rlen field (p+4) will be patched by thread/sync path */
            uint32_t rlen_be = htonl(rlen);
            ngx_memcpy(p + 4, &rlen_be, 4);   /* requested rlen, thread patches actual */
            ngx_memcpy(p + 8, &segs[i].offset, 8);

            p += XROOTD_READV_SEGSIZE + rlen;  /* skip to next segment's header */
        }
    }

#if (NGX_THREADS)
    if (conf->thread_pool != NULL) {
        ngx_thread_task_t       *task;
        xrootd_readv_aio_t      *t;
        xrootd_readv_seg_desc_t *seg_descs;

        /* Allocate per-segment descriptors */
        seg_descs = ngx_palloc(c->pool,
                               n_segs * sizeof(xrootd_readv_seg_desc_t));
        if (seg_descs == NULL) { return NGX_ERROR; }

        /* Fill segment descriptors, pointing into databuf */
        {
            u_char *p = databuf;
            for (i = 0; i < n_segs; i++) {
                uint32_t rlen = (uint32_t) ntohl((uint32_t) segs[i].rlen);
                if (rlen > XROOTD_READ_MAX) { rlen = XROOTD_READ_MAX; }

                seg_descs[i].fd          = ctx->files[(int)(unsigned char)segs[i].fhandle[0]].fd;
                seg_descs[i].handle_idx  = (int)(unsigned char) segs[i].fhandle[0];
                seg_descs[i].offset      = (off_t)(int64_t) be64toh((uint64_t) segs[i].offset);
                seg_descs[i].rlen        = rlen;
                seg_descs[i].hdr_rlen_ptr = p + 4;   /* rlen field in header */
                seg_descs[i].data_ptr    = p + XROOTD_READV_SEGSIZE;

                p += XROOTD_READV_SEGSIZE + rlen;
            }
        }

        task = ngx_thread_task_alloc(c->pool, sizeof(xrootd_readv_aio_t));
        if (task == NULL) { return NGX_ERROR; }

        t = task->ctx;
        t->c           = c;
        t->ctx         = ctx;
        t->n_segs      = n_segs;
        t->segs        = seg_descs;
        t->databuf     = databuf;
        t->bytes_total = 0;
        t->rsp_total   = 0;
        t->io_error    = 0;
        t->streamid[0] = ctx->cur_streamid[0];
        t->streamid[1] = ctx->cur_streamid[1];

        task->handler       = xrootd_readv_aio_thread;
        task->event.handler = xrootd_readv_aio_done;
        task->event.data    = task;

        if (ngx_thread_task_post(conf->thread_pool, task) == NGX_OK) {
            ctx->state = XRD_ST_AIO;
            return NGX_OK;
        }
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "xrootd: thread_task_post failed, falling back to sync readv");
    }
#endif /* NGX_THREADS */

    /* --- Synchronous path: pread each segment in the event loop --- */
    {
        size_t  bytes_total = 0;
        size_t  rsp_total;
        u_char *p   = databuf;
        u_char *rspbuf;
        size_t  rsp_size;

        for (i = 0; i < n_segs; i++) {
            int      idx    = (int)(unsigned char) segs[i].fhandle[0];
            int64_t  offset = (int64_t) be64toh((uint64_t) segs[i].offset);
            uint32_t rlen   = (uint32_t) ntohl((uint32_t) segs[i].rlen);
            ssize_t  nread  = 0;

            if (rlen > XROOTD_READ_MAX) { rlen = XROOTD_READ_MAX; }

            u_char *rlen_field = p + 4;
            p += XROOTD_READV_SEGSIZE;

            if (rlen > 0) {
                nread = pread(ctx->files[idx].fd, p, (size_t) rlen, (off_t) offset);
                if (nread < 0) {
                    XROOTD_OP_ERR(ctx, XROOTD_OP_READV);
                    return xrootd_send_error(ctx, c, kXR_IOError, "readv I/O error");
                }
                if ((uint32_t) nread < rlen) {
                    XROOTD_OP_ERR(ctx, XROOTD_OP_READV);
                    return xrootd_send_error(ctx, c, kXR_IOError, "readv past EOF");
                }
            }

            uint32_t actual_rlen_be = htonl((uint32_t) nread);
            ngx_memcpy(rlen_field, &actual_rlen_be, 4);

            p           += (size_t) nread;
            bytes_total += (size_t) nread;
        }

        rsp_total = (size_t)(p - databuf);

        {
            char detail[64];
            snprintf(detail, sizeof(detail), "%zu_segs", n_segs);
            xrootd_log_access(ctx, c, "READV", "-", detail, 1, 0, NULL, bytes_total);
        }
        XROOTD_OP_OK(ctx, XROOTD_OP_READV);
        ctx->session_bytes += bytes_total;

        rspbuf = xrootd_build_readv_response(ctx, c, databuf, rsp_total, &rsp_size);
        if (rspbuf == NULL) { return NGX_ERROR; }

        return xrootd_queue_response(ctx, c, rspbuf, rsp_size);
    }
}


/* kXR_read — read file data
 *
 * Protocol semantics: a kXR_ok response with fewer bytes than rlen means
 * EOF — the client will NOT re-request the remainder.  kXR_oksofar means
 * "this chunk is part of the answer; more follows".
 *
 * When the requested rlen > XROOTD_READ_MAX we must chunk the response:
 * all but the final 8B+data chunk carry kXR_oksofar; the last carries
 * kXR_ok.  We build the entire interleaved response in one pool buffer and
 * issue a single xrootd_queue_response, avoiding state-machine re-entrancy.
 */
static ngx_int_t
xrootd_handle_read(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    ClientReadRequest            *req  = (ClientReadRequest *) ctx->hdr_buf;
    ngx_stream_xrootd_srv_conf_t *conf =
        ngx_stream_get_module_srv_conf((ngx_stream_session_t *)(c->data), ngx_stream_xrootd_module);
    int      idx;
    int64_t  offset;
    size_t   rlen;
    u_char  *databuf;
    ssize_t  nread;
    size_t   data_total;
    size_t   rsp_total;
    u_char  *rspbuf;

    idx    = (int)(unsigned char) req->fhandle[0];
    offset = (int64_t) be64toh((uint64_t) req->offset);
    rlen   = (size_t)(uint32_t) ntohl((uint32_t) req->rlen);

    if (idx < 0 || idx >= XROOTD_MAX_FILES || ctx->files[idx].fd < 0) {
        xrootd_log_access(ctx, c, "READ", "-", "-",
                          0, kXR_FileNotOpen, "invalid file handle", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_READ);
        return xrootd_send_error(ctx, c, kXR_FileNotOpen,
                                 "invalid file handle");
    }

    if (rlen == 0) {
        XROOTD_OP_OK(ctx, XROOTD_OP_READ);
        return xrootd_send_ok(ctx, c, NULL, 0);
    }

    if (rlen > XROOTD_READ_MAX * 16) {
        rlen = XROOTD_READ_MAX * 16;   /* 64 MB hard cap */
    }

    databuf = ngx_palloc(c->pool, rlen);
    if (databuf == NULL) {
        return NGX_ERROR;
    }

#if (NGX_THREADS)
    /* Async path: post pread() to the thread pool */
    if (conf->thread_pool != NULL) {
        ngx_thread_task_t  *task;
        xrootd_read_aio_t  *t;

        task = ngx_thread_task_alloc(c->pool, sizeof(xrootd_read_aio_t));
        if (task == NULL) {
            return NGX_ERROR;
        }

        t = task->ctx;
        t->c          = c;
        t->ctx        = ctx;
        t->conf       = conf;
        t->fd         = ctx->files[idx].fd;
        t->handle_idx = idx;
        t->offset     = (off_t) offset;
        t->rlen       = rlen;
        t->databuf    = databuf;
        t->nread      = -1;
        t->io_errno   = 0;
        t->streamid[0] = ctx->cur_streamid[0];
        t->streamid[1] = ctx->cur_streamid[1];

        task->handler       = xrootd_read_aio_thread;
        task->event.handler = xrootd_read_aio_done;
        task->event.data    = task;

        if (ngx_thread_task_post(conf->thread_pool, task) != NGX_OK) {
            ngx_log_error(NGX_LOG_WARN, c->log, 0,
                          "xrootd: thread_task_post failed, falling back to sync read");
            goto sync_read;
        }

        ctx->state = XRD_ST_AIO;
        return NGX_OK;
    }

sync_read:
#endif /* NGX_THREADS */

    /* Synchronous path: pread() in the event loop worker */
    nread = pread(ctx->files[idx].fd, databuf, rlen, (off_t) offset);
    if (nread < 0) {
        ngx_pfree(c->pool, databuf);
        xrootd_log_access(ctx, c, "READ", ctx->files[idx].path, "-",
                          0, kXR_IOError, strerror(errno), 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_READ);
        return xrootd_send_error(ctx, c, kXR_IOError, strerror(errno));
    }

    data_total = (size_t) nread;

    ctx->files[idx].bytes_read += data_total;
    ctx->session_bytes         += data_total;

    {
        char read_detail[64];
        snprintf(read_detail, sizeof(read_detail), "%lld+%zu",
                 (long long) offset, rlen);
        xrootd_log_access(ctx, c, "READ", ctx->files[idx].path,
                          read_detail, 1, 0, NULL, data_total);
        XROOTD_OP_OK(ctx, XROOTD_OP_READ);
    }

    rspbuf = xrootd_build_read_response(ctx, c, databuf, data_total, &rsp_total);
    ngx_pfree(c->pool, databuf);   /* copied into rspbuf; no longer needed */

    if (rspbuf == NULL) {
        return NGX_ERROR;
    }

    {
        ngx_int_t rc = xrootd_queue_response_base(ctx, c, rspbuf, rsp_total, rspbuf);
        if (ctx->state != XRD_ST_SENDING) {
            ngx_pfree(c->pool, rspbuf);
        }
        return rc;
    }
}

/* kXR_close — close an open file handle */
static ngx_int_t
xrootd_handle_close(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    ClientCloseRequest *req = (ClientCloseRequest *) ctx->hdr_buf;
    int idx = (int)(unsigned char) req->fhandle[0];

    if (idx < 0 || idx >= XROOTD_MAX_FILES || ctx->files[idx].fd < 0) {
        xrootd_log_access(ctx, c, "CLOSE", "-", "-",
                          0, kXR_FileNotOpen, "invalid file handle", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_CLOSE);
        return xrootd_send_error(ctx, c, kXR_FileNotOpen,
                                 "invalid file handle");
    }

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: kXR_close handle=%d", idx);

    /* Log before freeing so we still have the path and byte counters.
     * detail = average throughput for the transfer ("%.2fMB/s").
     * bytes  = total data bytes transferred (read or written). */
    {
        char       close_detail[64];
        size_t     br  = ctx->files[idx].bytes_read;
        size_t     bw  = ctx->files[idx].bytes_written;
        size_t     btotal = (bw > 0) ? bw : br;
        ngx_msec_t dur = ngx_current_msec - ctx->files[idx].open_time;

        if (btotal > 0 && dur > 0) {
            double mbps = (double) btotal / (double) dur / 1000.0;
            snprintf(close_detail, sizeof(close_detail), "%.2fMB/s", mbps);
        } else {
            snprintf(close_detail, sizeof(close_detail), "-");
        }

        xrootd_log_access(ctx, c, "CLOSE", ctx->files[idx].path, close_detail,
                          1, 0, NULL, btotal);
    }

    xrootd_free_fhandle(ctx, idx);
    XROOTD_OP_OK(ctx, XROOTD_OP_CLOSE);

    return xrootd_send_ok(ctx, c, NULL, 0);
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
static ngx_int_t
xrootd_handle_dirlist(xrootd_ctx_t *ctx, ngx_connection_t *c,
                      ngx_stream_xrootd_srv_conf_t *conf)
{
    ClientDirlistRequest *req = (ClientDirlistRequest *) ctx->hdr_buf;
    u_char                options;
    char                  resolved[PATH_MAX];
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

    if (ctx->payload == NULL || ctx->cur_dlen == 0) {
        xrootd_log_access(ctx, c, "DIRLIST", "-", "-",
                          0, kXR_ArgMissing, "no path given", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_DIRLIST);
        return xrootd_send_error(ctx, c, kXR_ArgMissing, "no path given");
    }

    if (!xrootd_resolve_path(c->log, &conf->root,
                             (const char *) ctx->payload,
                             resolved, sizeof(resolved))) {
        xrootd_log_access(ctx, c, "DIRLIST", (char *) ctx->payload, "-",
                          0, kXR_NotFound, "directory not found", 0);
        XROOTD_OP_ERR(ctx, XROOTD_OP_DIRLIST);
        return xrootd_send_error(ctx, c, kXR_NotFound, "directory not found");
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

    /* We write entries starting after the response header (filled last) */
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

        /* Skip . and .. — XRootD clients do not expect them */
        if (name[0] == '.' && (name[1] == '\0' ||
            (name[1] == '.' && name[2] == '\0'))) {
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

            chunk_pos = 0;
        }

        /* Append the entry name */
        ngx_memcpy(data + chunk_pos, name, nlen);
        chunk_pos += nlen;
        data[chunk_pos++] = '\n';

        /* Optionally append stat info — use fstatat to avoid path concat */
        if (want_stat) {
            struct stat entry_st;
            if (fstatat(dirfd(dp), name, &entry_st, AT_SYMLINK_NOFOLLOW)
                    == 0) {
                size_t slen;
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

/* ================================================================== */
/*  Response builders                                                   */
/* ================================================================== */

/*
 * xrootd_build_resp_hdr — fill in an 8-byte ServerResponseHdr.
 */
static void
xrootd_build_resp_hdr(const u_char *streamid, uint16_t status,
                      uint32_t dlen, ServerResponseHdr *out)
{
    out->streamid[0] = streamid[0];
    out->streamid[1] = streamid[1];
    out->status      = htons(status);
    out->dlen        = htonl(dlen);
}

/*
 * xrootd_crc32c — software CRC32c (Castagnoli polynomial 0x1EDC6F41).
 *
 * Used to compute the integrity field in kXR_status responses for
 * kXR_pgwrite.  The client verifies this before accepting the response.
 *
 * Algorithm: table-driven, reflected form of CRC32c.
 */
static uint32_t
xrootd_crc32c(const void *buf, size_t len)
{
    static const uint32_t tbl[256] = {
        /* Generated from polynomial 0x82F63B78 (reflected CRC32c / Castagnoli) */
        /* Verified: CRC32c("123456789") == 0xE3069283 */
        0x00000000u, 0xF26B8303u, 0xE13B70F7u, 0x1350F3F4u,
        0xC79A971Fu, 0x35F1141Cu, 0x26A1E7E8u, 0xD4CA64EBu,
        0x8AD958CFu, 0x78B2DBCCu, 0x6BE22838u, 0x9989AB3Bu,
        0x4D43CFD0u, 0xBF284CD3u, 0xAC78BF27u, 0x5E133C24u,
        0x105EC76Fu, 0xE235446Cu, 0xF165B798u, 0x030E349Bu,
        0xD7C45070u, 0x25AFD373u, 0x36FF2087u, 0xC494A384u,
        0x9A879FA0u, 0x68EC1CA3u, 0x7BBCEF57u, 0x89D76C54u,
        0x5D1D08BFu, 0xAF768BBCu, 0xBC267848u, 0x4E4DFB4Bu,
        0x20BD8EDEu, 0xD2D60DDDu, 0xC186FE29u, 0x33ED7D2Au,
        0xE72719C1u, 0x154C9AC2u, 0x061C6936u, 0xF477EA35u,
        0xAA64D611u, 0x580F5512u, 0x4B5FA6E6u, 0xB93425E5u,
        0x6DFE410Eu, 0x9F95C20Du, 0x8CC531F9u, 0x7EAEB2FAu,
        0x30E349B1u, 0xC288CAB2u, 0xD1D83946u, 0x23B3BA45u,
        0xF779DEAEu, 0x05125DADu, 0x1642AE59u, 0xE4292D5Au,
        0xBA3A117Eu, 0x4851927Du, 0x5B016189u, 0xA96AE28Au,
        0x7DA08661u, 0x8FCB0562u, 0x9C9BF696u, 0x6EF07595u,
        0x417B1DBCu, 0xB3109EBFu, 0xA0406D4Bu, 0x522BEE48u,
        0x86E18AA3u, 0x748A09A0u, 0x67DAFA54u, 0x95B17957u,
        0xCBA24573u, 0x39C9C670u, 0x2A993584u, 0xD8F2B687u,
        0x0C38D26Cu, 0xFE53516Fu, 0xED03A29Bu, 0x1F682198u,
        0x5125DAD3u, 0xA34E59D0u, 0xB01EAA24u, 0x42752927u,
        0x96BF4DCCu, 0x64D4CECFu, 0x77843D3Bu, 0x85EFBE38u,
        0xDBFC821Cu, 0x2997011Fu, 0x3AC7F2EBu, 0xC8AC71E8u,
        0x1C661503u, 0xEE0D9600u, 0xFD5D65F4u, 0x0F36E6F7u,
        0x61C69362u, 0x93AD1061u, 0x80FDE395u, 0x72966096u,
        0xA65C047Du, 0x5437877Eu, 0x4767748Au, 0xB50CF789u,
        0xEB1FCBADu, 0x197448AEu, 0x0A24BB5Au, 0xF84F3859u,
        0x2C855CB2u, 0xDEEEDFB1u, 0xCDBE2C45u, 0x3FD5AF46u,
        0x7198540Du, 0x83F3D70Eu, 0x90A324FAu, 0x62C8A7F9u,
        0xB602C312u, 0x44694011u, 0x5739B3E5u, 0xA55230E6u,
        0xFB410CC2u, 0x092A8FC1u, 0x1A7A7C35u, 0xE811FF36u,
        0x3CDB9BDDu, 0xCEB018DEu, 0xDDE0EB2Au, 0x2F8B6829u,
        0x82F63B78u, 0x709DB87Bu, 0x63CD4B8Fu, 0x91A6C88Cu,
        0x456CAC67u, 0xB7072F64u, 0xA457DC90u, 0x563C5F93u,
        0x082F63B7u, 0xFA44E0B4u, 0xE9141340u, 0x1B7F9043u,
        0xCFB5F4A8u, 0x3DDE77ABu, 0x2E8E845Fu, 0xDCE5075Cu,
        0x92A8FC17u, 0x60C37F14u, 0x73938CE0u, 0x81F80FE3u,
        0x55326B08u, 0xA759E80Bu, 0xB4091BFFu, 0x466298FCu,
        0x1871A4D8u, 0xEA1A27DBu, 0xF94AD42Fu, 0x0B21572Cu,
        0xDFEB33C7u, 0x2D80B0C4u, 0x3ED04330u, 0xCCBBC033u,
        0xA24BB5A6u, 0x502036A5u, 0x4370C551u, 0xB11B4652u,
        0x65D122B9u, 0x97BAA1BAu, 0x84EA524Eu, 0x7681D14Du,
        0x2892ED69u, 0xDAF96E6Au, 0xC9A99D9Eu, 0x3BC21E9Du,
        0xEF087A76u, 0x1D63F975u, 0x0E330A81u, 0xFC588982u,
        0xB21572C9u, 0x407EF1CAu, 0x532E023Eu, 0xA145813Du,
        0x758FE5D6u, 0x87E466D5u, 0x94B49521u, 0x66DF1622u,
        0x38CC2A06u, 0xCAA7A905u, 0xD9F75AF1u, 0x2B9CD9F2u,
        0xFF56BD19u, 0x0D3D3E1Au, 0x1E6DCDEEu, 0xEC064EEDu,
        0xC38D26C4u, 0x31E6A5C7u, 0x22B65633u, 0xD0DDD530u,
        0x0417B1DBu, 0xF67C32D8u, 0xE52CC12Cu, 0x1747422Fu,
        0x49547E0Bu, 0xBB3FFD08u, 0xA86F0EFCu, 0x5A048DFFu,
        0x8ECEE914u, 0x7CA56A17u, 0x6FF599E3u, 0x9D9E1AE0u,
        0xD3D3E1ABu, 0x21B862A8u, 0x32E8915Cu, 0xC083125Fu,
        0x144976B4u, 0xE622F5B7u, 0xF5720643u, 0x07198540u,
        0x590AB964u, 0xAB613A67u, 0xB831C993u, 0x4A5A4A90u,
        0x9E902E7Bu, 0x6CFBAD78u, 0x7FAB5E8Cu, 0x8DC0DD8Fu,
        0xE330A81Au, 0x115B2B19u, 0x020BD8EDu, 0xF0605BEEu,
        0x24AA3F05u, 0xD6C1BC06u, 0xC5914FF2u, 0x37FACCF1u,
        0x69E9F0D5u, 0x9B8273D6u, 0x88D28022u, 0x7AB90321u,
        0xAE7367CAu, 0x5C18E4C9u, 0x4F48173Du, 0xBD23943Eu,
        0xF36E6F75u, 0x0105EC76u, 0x12551F82u, 0xE03E9C81u,
        0x34F4F86Au, 0xC69F7B69u, 0xD5CF889Du, 0x27A40B9Eu,
        0x79B737BAu, 0x8BDCB4B9u, 0x988C474Du, 0x6AE7C44Eu,
        0xBE2DA0A5u, 0x4C4623A6u, 0x5F16D052u, 0xAD7D5351u,
    };

    const uint8_t *p   = (const uint8_t *) buf;
    uint32_t       crc = 0xFFFFFFFFu;

    while (len--) {
        crc = (crc >> 8) ^ tbl[(crc ^ *p++) & 0xFF];
    }
    return crc ^ 0xFFFFFFFFu;
}

/*
 * xrootd_send_pgwrite_status — send a kXR_status response for kXR_pgwrite.
 *
 * This is required because the xrdcp v5 client uses ServerResponseV2 to
 * parse the pgwrite response body and will crash if given a plain kXR_ok
 * (8 bytes) instead of the full 32-byte kXR_status response.
 *
 * Wire format (32 bytes):
 *   [ServerResponseHdr 8B]          status=kXR_status, dlen=24
 *   [ServerResponseBody_Status 16B] crc32c + streamID + requestid +
 *                                   resptype + reserved + dlen=0
 *   [ServerResponseBody_pgWrite 8B] write_offset (big-endian)
 */
static ngx_int_t
xrootd_send_pgwrite_status(xrootd_ctx_t *ctx, ngx_connection_t *c,
                           int64_t write_offset)
{
    ServerStatusResponse_pgWrite *rsp;
    uint32_t crc;
    /* CRC covers everything from &bdy.streamID to end (28 bytes) */
    size_t   crc_len = sizeof(rsp->bdy) - sizeof(rsp->bdy.crc32c)
                       + sizeof(rsp->pgw);   /* 12 + 8 = 20 */

    rsp = ngx_palloc(c->pool, sizeof(*rsp));
    if (rsp == NULL) {
        return NGX_ERROR;
    }

    /* Header */
    rsp->hdr.streamid[0] = ctx->cur_streamid[0];
    rsp->hdr.streamid[1] = ctx->cur_streamid[1];
    rsp->hdr.status      = htons(kXR_status);
    rsp->hdr.dlen        = htonl((uint32_t)(sizeof(rsp->bdy) + sizeof(rsp->pgw)));

    /* Status body — crc32c filled last */
    rsp->bdy.streamID[0] = ctx->cur_streamid[0];
    rsp->bdy.streamID[1] = ctx->cur_streamid[1];
    rsp->bdy.requestid   = (kXR_char)(kXR_pgwrite - kXR_1stRequest);
    rsp->bdy.resptype    = 0;   /* kXR_FinalResult */
    ngx_memzero(rsp->bdy.reserved, sizeof(rsp->bdy.reserved));
    rsp->bdy.dlen        = htonl(0);   /* no bad pages */

    /* pgWrite body: last file offset written (big-endian) */
    rsp->pgw.offset = (kXR_int64) htobe64((uint64_t) write_offset);

    /* CRC32c over [streamID .. end of pgw] */
    crc = xrootd_crc32c(&rsp->bdy.streamID[0], crc_len);
    rsp->bdy.crc32c = htonl(crc);

    return xrootd_queue_response(ctx, c, (u_char *) rsp, sizeof(*rsp));
}

/*
 * xrootd_send_ok — build and queue a kXR_ok response.
 * body may be NULL (dlen == 0) for requests with no response payload.
 */
static ngx_int_t
xrootd_send_ok(xrootd_ctx_t *ctx, ngx_connection_t *c,
               const void *body, uint32_t bodylen)
{
    size_t    total = XRD_RESPONSE_HDR_LEN + bodylen;
    u_char   *buf   = ngx_palloc(c->pool, total);

    if (buf == NULL) {
        return NGX_ERROR;
    }

    xrootd_build_resp_hdr(ctx->cur_streamid, kXR_ok, bodylen,
                           (ServerResponseHdr *) buf);

    if (bodylen > 0 && body != NULL) {
        ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN, body, bodylen);
    }

    return xrootd_queue_response(ctx, c, buf, total);
}

/*
 * xrootd_send_error — build and queue a kXR_error response.
 *
 * Wire layout: 8-byte header | errnum(4) | errmsg(N+1)
 */
static ngx_int_t
xrootd_send_error(xrootd_ctx_t *ctx, ngx_connection_t *c,
                  uint16_t errcode, const char *msg)
{
    size_t   msglen, bodylen, total;
    u_char  *buf;

    msglen  = strlen(msg) + 1;          /* include NUL */
    bodylen = sizeof(kXR_int32) + msglen;
    total   = XRD_RESPONSE_HDR_LEN + bodylen;

    buf = ngx_palloc(c->pool, total);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    xrootd_build_resp_hdr(ctx->cur_streamid, kXR_error, (uint32_t) bodylen,
                           (ServerResponseHdr *) buf);

    /* errnum in network byte order */
    uint32_t ecode = htonl(errcode);
    ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN, &ecode, sizeof(ecode));
    ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN + sizeof(ecode), msg, msglen);

    ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: sending error %d: %s", (int) errcode, msg);

    return xrootd_queue_response(ctx, c, buf, total);
}

/* ================================================================== */
/*  Access logging                                                      */
/* ================================================================== */

/*
 * xrootd_log_access — write one line to the XRootD access log.
 *
 * Called from each request handler immediately before returning so every
 * client-visible operation — successful or failed — appears in the log.
 *
 * Log line format (modelled on nginx's HTTP combined log):
 *
 *   <ip> <auth> "<identity>" [<timestamp>] "<verb> <path> <detail>" \
 *   <status> <bytes> <ms>ms ["<errmsg>"]
 *
 * Parameters:
 *   verb     — operation name in UPPER CASE: OPEN READ STAT DIRLIST
 *              CLOSE LOGIN AUTH PING
 *   path     — resolved filesystem path, or "-" for operations with no path
 *   detail   — operation-specific context:
 *                OPEN    "rd" (read-only; write ops are rejected before here)
 *                READ    "offset+len" (e.g. "0+4194304"), requested values
 *                LOGIN   the username from ClientLoginRequest
 *                AUTH    auth protocol ("gsi")
 *                others  "-"
 *   xrd_ok   — non-zero on success, zero on error
 *   errcode  — XRootD error code (kXR_NotFound etc.) when xrd_ok==0, else 0
 *   errmsg   — human-readable error description when xrd_ok==0, else NULL
 *   bytes    — file data bytes transferred in the response (0 for non-data ops)
 *
 * The function is a no-op when access_log_fd == NGX_INVALID_FILE (i.e. the
 * xrootd_access_log directive was not set for this server block).
 *
 * Thread / worker safety: the file is opened O_APPEND so each write(2) up
 * to PIPE_BUF (4096 bytes on Linux) is atomic.  All log lines fit well
 * within that limit.
 */
static void
xrootd_log_access(xrootd_ctx_t *ctx, ngx_connection_t *c,
    const char *verb, const char *path, const char *detail,
    ngx_uint_t xrd_ok, uint16_t errcode, const char *errmsg, size_t bytes)
{
    ngx_stream_xrootd_srv_conf_t  *conf;
    ngx_msec_int_t                 duration_ms;
    char                           line[2048];
    int                            n;
    const char                    *authmethod, *identity;
    char                           client_ip[INET6_ADDRSTRLEN + 8]; /* "[addr]:port" */
    ngx_time_t                    *tp;
    struct tm                      tm;
    char                           timebuf[64];
    char                           errbuf[64];   /* "ERR:NNNN" when no message */

    conf = ngx_stream_get_module_srv_conf(ctx->session, ngx_stream_xrootd_module);

    if (conf->access_log_fd == NGX_INVALID_FILE) {
        return;
    }

    /* ---- Who -------------------------------------------------------- */

    /* Client IP: addr_text is an ngx_str_t (length + pointer, not NUL-terminated).
     * Copy into a local buffer so we can safely pass it to snprintf as "%s". */
    if (c->addr_text.len > 0 && c->addr_text.len < sizeof(client_ip)) {
        ngx_memcpy(client_ip, c->addr_text.data, c->addr_text.len);
        client_ip[c->addr_text.len] = '\0';
    } else {
        client_ip[0] = '-';
        client_ip[1] = '\0';
    }

    /* Auth method and identity */
    if (conf->auth == XROOTD_AUTH_GSI) {
        authmethod = "gsi";
        identity   = (ctx->dn[0] != '\0') ? ctx->dn : "-";
    } else {
        authmethod = "anon";
        identity   = "-";
    }

    /* ---- When ------------------------------------------------------- */

    /*
     * Use ngx_timeofday() (already cached by nginx's event loop) for the
     * current second, formatted exactly like nginx's HTTP access log.
     */
    tp = ngx_timeofday();
    ngx_libc_localtime(tp->sec, &tm);
    strftime(timebuf, sizeof(timebuf), "%d/%b/%Y:%H:%M:%S %z", &tm);

    /* ---- How long --------------------------------------------------- */

    duration_ms = (ngx_msec_int_t)(ngx_current_msec - ctx->req_start);
    if (duration_ms < 0) {
        duration_ms = 0;
    }

    /* ---- Status ----------------------------------------------------- */

    /*
     * On error, build a short status token.  If the caller provided a
     * human-readable message, that appears in the final quoted field.
     * If not, include the numeric XRootD error code so the log is still
     * actionable without the message.
     */
    if (!xrd_ok && errmsg == NULL) {
        snprintf(errbuf, sizeof(errbuf), "code:%u", (unsigned) errcode);
        errmsg = errbuf;
    }

    /* ---- Assemble --------------------------------------------------- */

    if (xrd_ok) {
        n = snprintf(line, sizeof(line),
            "%s %s \"%s\" [%s] \"%s %s %s\" OK %zu %dms\n",
            client_ip,
            authmethod,
            identity,
            timebuf,
            verb,
            path   ? path   : "-",
            detail ? detail : "-",
            bytes,
            (int) duration_ms);
    } else {
        n = snprintf(line, sizeof(line),
            "%s %s \"%s\" [%s] \"%s %s %s\" ERR %zu %dms \"%s\"\n",
            client_ip,
            authmethod,
            identity,
            timebuf,
            verb,
            path   ? path   : "-",
            detail ? detail : "-",
            bytes,
            (int) duration_ms,
            errmsg);
    }

    if (n > 0 && (size_t) n < sizeof(line)) {
        (void) ngx_write_fd(conf->access_log_fd, line, (size_t) n);
    }
}

/* ================================================================== */
/*  Helpers                                                             */
/* ================================================================== */

/*
 * xrootd_resolve_path_noexist
 *
 * Like xrootd_resolve_path_write but does NOT require any component of the
 * path to exist — suitable for recursive mkdir where no intermediate directory
 * has been created yet.
 *
 * Security: rejects any path component that is exactly ".." to prevent
 * traversal.  The root is trusted (set via nginx config directive).
 *
 * Returns 1 on success (resolved[] filled), 0 on failure.
 */
static int
xrootd_resolve_path_noexist(ngx_log_t *log, const ngx_str_t *root,
                              const char *reqpath, char *resolved, size_t resolvsz)
{
    char        combined[PATH_MAX * 2];
    const char *p;
    int         n;

    /* Strip leading slashes */
    while (*reqpath == '/') {
        reqpath++;
    }

    if (*reqpath == '\0') {
        return 0;   /* empty or root-only path not allowed */
    }

    /* Scan for ".." components — any found is a traversal attempt */
    p = reqpath;
    while (*p) {
        const char *seg_end = strchr(p, '/');
        size_t      seg_len = seg_end ? (size_t)(seg_end - p) : strlen(p);

        if (seg_len == 2 && p[0] == '.' && p[1] == '.') {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "xrootd: path traversal attempt: %s", reqpath);
            return 0;
        }
        if (seg_end == NULL) {
            break;
        }
        p = seg_end + 1;
    }

    n = snprintf(combined, sizeof(combined), "%.*s/%s",
                 (int) root->len, (char *) root->data, reqpath);
    if (n < 0 || (size_t) n >= sizeof(combined)) {
        ngx_log_error(NGX_LOG_WARN, log, 0, "xrootd: path too long");
        return 0;
    }

    if ((size_t) n >= resolvsz) {
        return 0;
    }

    ngx_cpystrn((u_char *) resolved, (u_char *) combined, resolvsz);
    return 1;
}

/*
 * xrootd_resolve_path
 *
 * Combine `root` and `reqpath` into a canonical absolute path,
 * then verify the result is still inside `root` (path traversal guard).
 *
 * Returns 1 on success (resolved[] filled), 0 on failure (not found,
 * traversal attempt, or overflow).
 */
static int
xrootd_resolve_path(ngx_log_t *log, const ngx_str_t *root,
                    const char *reqpath, char *resolved, size_t resolvsz)
{
    char combined[PATH_MAX * 2];
    char canonical[PATH_MAX];
    int  n;

    /* Strip leading slashes from reqpath to avoid // in combined */
    while (*reqpath == '/') {
        reqpath++;
    }

    n = snprintf(combined, sizeof(combined), "%.*s/%s",
                 (int) root->len, (char *) root->data, reqpath);

    if (n < 0 || (size_t) n >= sizeof(combined)) {
        ngx_log_error(NGX_LOG_WARN, log, 0, "xrootd: path too long");
        return 0;
    }

    if (realpath(combined, canonical) == NULL) {
        /* File does not exist (or is a dangling symlink) */
        return 0;
    }

    /* Ensure the resolved path starts with root (+ '/' or end-of-string) */
    if (strncmp(canonical, (char *) root->data, root->len) != 0) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd: path traversal attempt: %s", canonical);
        return 0;
    }

    if (canonical[root->len] != '\0' && canonical[root->len] != '/') {
        /* The root matched a prefix but not a directory boundary */
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd: path traversal attempt: %s", canonical);
        return 0;
    }

    n = snprintf(resolved, resolvsz, "%s", canonical);
    if (n < 0 || (size_t) n >= resolvsz) {
        return 0;
    }

    return 1;
}

/*
 * xrootd_strip_cgi — remove XRootD CGI query string from a path.
 *
 * XRootD clients may append "?key=value" opaque parameters to paths
 * (e.g. "?oss.asize=<bytes>" to declare the expected upload size).
 * These are not part of the filesystem path and must be stripped before
 * any realpath()/open() call.
 *
 * Copies `in` to `out`, truncating at the first '?' character.
 */
static void
xrootd_strip_cgi(const char *in, char *out, size_t outsz)
{
    const char *q = strchr(in, '?');
    size_t      len;

    if (q != NULL) {
        len = (size_t)(q - in);
    } else {
        len = strlen(in);
    }

    if (len >= outsz) {
        len = outsz - 1;
    }

    memcpy(out, in, len);
    out[len] = '\0';
}

/*
 * xrootd_resolve_path_write
 *
 * Like xrootd_resolve_path but designed for write operations where the
 * target file may not yet exist.  Resolves the *parent directory* with
 * realpath(), verifies it is inside root, then appends the basename to
 * form the full target path.
 *
 * Returns 1 on success (resolved[] filled), 0 on failure.
 */
static int
xrootd_resolve_path_write(ngx_log_t *log, const ngx_str_t *root,
                           const char *reqpath, char *resolved, size_t resolvsz)
{
    char  combined[PATH_MAX * 2];
    char  parent_buf[PATH_MAX * 2];
    char  parent_canon[PATH_MAX];
    char *slash;
    const char *base;
    int   n;

    /* Strip leading slashes */
    while (*reqpath == '/') {
        reqpath++;
    }

    n = snprintf(combined, sizeof(combined), "%.*s/%s",
                 (int) root->len, (char *) root->data, reqpath);
    if (n < 0 || (size_t) n >= sizeof(combined)) {
        ngx_log_error(NGX_LOG_WARN, log, 0, "xrootd: path too long");
        return 0;
    }

    /* Split into parent directory and basename */
    ngx_cpystrn((u_char *) parent_buf, (u_char *) combined, sizeof(parent_buf));
    slash = strrchr(parent_buf, '/');
    if (slash == NULL || slash == parent_buf) {
        return 0;
    }
    base  = slash + 1;
    *slash = '\0';

    if (*base == '\0') {
        /* Trailing slash — directory target, not a file */
        return 0;
    }

    /* Resolve the parent — it must exist and be inside root */
    if (realpath(parent_buf, parent_canon) == NULL) {
        return 0;
    }

    if (strncmp(parent_canon, (char *) root->data, root->len) != 0) {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd: path traversal attempt in write: %s", parent_canon);
        return 0;
    }
    if (parent_canon[root->len] != '\0' && parent_canon[root->len] != '/') {
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "xrootd: path traversal attempt in write: %s", parent_canon);
        return 0;
    }

    n = snprintf(resolved, resolvsz, "%s/%s", parent_canon, base);
    if (n < 0 || (size_t) n >= resolvsz) {
        return 0;
    }

    return 1;
}

/*
 * xrootd_mkdir_recursive — create a directory and all missing parent dirs.
 *
 * Like "mkdir -p path".  Returns 0 on success (including if the final
 * directory already existed), -1 on error with errno set.
 */
static int
xrootd_mkdir_recursive(const char *path, mode_t mode)
{
    char  tmp[PATH_MAX];
    char *p;
    int   n;

    n = snprintf(tmp, sizeof(tmp), "%s", path);
    if (n < 0 || (size_t) n >= sizeof(tmp)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    /* Remove trailing slash */
    if (n > 0 && tmp[n - 1] == '/') {
        tmp[n - 1] = '\0';
    }

    for (p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, mode) != 0 && errno != EEXIST) {
                return -1;
            }
            *p = '/';
        }
    }

    if (mkdir(tmp, mode) != 0 && errno != EEXIST) {
        return -1;
    }

    return 0;
}

/*
 * xrootd_alloc_fhandle — find a free slot in the open file table.
 * Returns slot index (0..XROOTD_MAX_FILES-1) or -1 if none available.
 */
static int
xrootd_alloc_fhandle(xrootd_ctx_t *ctx)
{
    int i;
    for (i = 0; i < XROOTD_MAX_FILES; i++) {
        if (ctx->files[i].fd < 0) {
            return i;
        }
    }
    return -1;
}

/* xrootd_free_fhandle — close and release a file handle slot */
static void
xrootd_free_fhandle(xrootd_ctx_t *ctx, int idx)
{
    if (idx >= 0 && idx < XROOTD_MAX_FILES && ctx->files[idx].fd >= 0) {
        close(ctx->files[idx].fd);
        ctx->files[idx].fd      = -1;
        ctx->files[idx].path[0] = '\0';
    }
}

/* xrootd_close_all_files — called on connection teardown */
static void
xrootd_close_all_files(xrootd_ctx_t *ctx)
{
    int i;
    for (i = 0; i < XROOTD_MAX_FILES; i++) {
        xrootd_free_fhandle(ctx, i);
    }
}

/*
 * xrootd_on_disconnect — called at every connection teardown point.
 *
 * Logs a CLOSE line for any files the client left open (connection dropped
 * before sending kXR_close), then writes a DISCONNECT summary line with the
 * total bytes transferred and average session throughput.
 *
 * Must be called before xrootd_close_all_files() so the file paths and byte
 * counts are still available.
 */
static void
xrootd_on_disconnect(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    int        i;
    ngx_msec_t now = ngx_current_msec;

    /* Signal thread-pool completion handlers that the connection is gone.
     * Any in-flight AIO task will see this and skip response delivery. */
    ctx->destroyed = 1;

    /* Decrement active connection counter and accumulate byte totals */
    if (ctx->metrics) {
        ngx_atomic_fetch_add(&ctx->metrics->connections_active, (ngx_atomic_int_t) -1);
        ngx_atomic_fetch_add(&ctx->metrics->bytes_rx_total,
                             (ngx_atomic_int_t) ctx->session_bytes_written);
        ngx_atomic_fetch_add(&ctx->metrics->bytes_tx_total,
                             (ngx_atomic_int_t) ctx->session_bytes);
    }

    /* Log any files that were left open without a client-sent kXR_close.
     * These represent transfers that were interrupted mid-flight. */
    for (i = 0; i < XROOTD_MAX_FILES; i++) {
        if (ctx->files[i].fd < 0) {
            continue;   /* slot already free */
        }

        /* Temporarily point req_start at the file open time so that the
         * duration field in the log line reflects the open→disconnect span. */
        ctx->req_start = ctx->files[i].open_time;

        {
            char   detail[64];
            size_t btotal = ctx->files[i].bytes_written > 0
                            ? ctx->files[i].bytes_written
                            : ctx->files[i].bytes_read;
            ngx_msec_t dur = now - ctx->files[i].open_time;

            if (btotal > 0 && dur > 0) {
                double mbps = (double) btotal / (double) dur / 1000.0;
                snprintf(detail, sizeof(detail), "interrupted %.2fMB/s", mbps);
            } else {
                snprintf(detail, sizeof(detail), "interrupted");
            }

            xrootd_log_access(ctx, c, "CLOSE", ctx->files[i].path, detail,
                              0, kXR_Cancelled, "connection lost", btotal);
        }
    }

    /* Write the DISCONNECT summary line only if the client actually logged in.
     * Pre-login disconnects (e.g. port-scanner probes) are not worth logging. */
    if (!ctx->logged_in) {
        return;
    }

    {
        char       detail[128];
        ngx_msec_t sess_dur = now - ctx->session_start;
        size_t     total    = ctx->session_bytes + ctx->session_bytes_written;

        if (total > 0 && sess_dur > 0) {
            double mbps = (double) total / (double) sess_dur / 1000.0;
            if (ctx->session_bytes_written > 0) {
                snprintf(detail, sizeof(detail),
                         "rx=%.2fMB/s tx=%.2fMB/s",
                         (double) ctx->session_bytes / (double) sess_dur / 1000.0,
                         (double) ctx->session_bytes_written / (double) sess_dur / 1000.0);
            } else {
                snprintf(detail, sizeof(detail), "%.2fMB/s", mbps);
            }
        } else {
            snprintf(detail, sizeof(detail), "-");
        }

        /* Use session_start for the duration field so the log shows total
         * session duration rather than the last request's processing time. */
        ctx->req_start = ctx->session_start;

        xrootd_log_access(ctx, c, "DISCONNECT", "-", detail,
                          1, 0, NULL, total);
    }
}

/*
 * xrootd_make_stat_body — format a kXR_stat response body as ASCII.
 *
 * Format: "<id> <size> <flags> <mtime>\0"
 *
 *   id     = inode number (used by the client as a cache key)
 *   size   = file size in bytes
 *   flags  = XStatRespFlags bitmask (kXR_isDir, kXR_readable, kXR_other, ...)
 *   mtime  = Unix timestamp of last modification
 *
 * GOTCHA: The field order is size-then-flags, NOT flags-then-size.
 * This is verified in XrdClXRootDResponses.cc ParseServerResponse():
 *   chunks[0] = id
 *   chunks[1] = size   ← size is second
 *   chunks[2] = flags  ← flags is third
 *   chunks[3] = mtime
 *
 * Swapping size and flags causes the client to interpret directory flags
 * (e.g. kXR_isDir=4096) as the file size and the actual file size (e.g. 24)
 * as flags — producing wrong StatInfo values throughout the client.
 *
 * For VFS (filesystem-level) stat the format is the same but id=0 and
 * size reports available space (st_blocks * 512).
 */
static void
xrootd_make_stat_body(const struct stat *st, ngx_flag_t is_vfs,
                      char *out, size_t outsz)
{
    int flags = 0;

    if (is_vfs) {
        /*
         * VFS stat: reports filesystem-level space rather than a file's size.
         * id=0, size = st_blocks*512 (available space proxy), flags=readable.
         * Same wire order: "<id> <size> <flags> <mtime>".
         */
        snprintf(out, outsz, "0 %lld %d %ld",
                 (long long) st->st_blocks * 512,   /* "free" space proxy */
                 kXR_readable,
                 (long) st->st_mtime);
        return;
    }

    if (S_ISDIR(st->st_mode)) {
        flags |= kXR_isDir;
    } else if (!S_ISREG(st->st_mode)) {
        flags |= kXR_other;
    }

    if (st->st_mode & (S_IRUSR | S_IRGRP | S_IROTH)) {
        flags |= kXR_readable;
    }

    /* We are a read-only server; never advertise writable.
     * Wire format: "<id> <size> <flags> <mtime>" — size comes BEFORE flags.
     * (Verified against XRootD source: XrdClXRootDResponses.cc ParseServerResponse) */
    snprintf(out, outsz, "%llu %lld %d %ld",
             (unsigned long long) st->st_ino,
             (long long) st->st_size,
             flags,
             (long) st->st_mtime);
}
