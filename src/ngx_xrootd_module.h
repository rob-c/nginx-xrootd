#pragma once

/*
 * ngx_xrootd_module.h
 *
 * Shared internal header for the nginx XRootD stream module.
 * Included by all .c files in the module.
 *
 * Maintainer map for non-XRootD specialists:
 *   - connection.c owns nginx event wiring and the byte-accumulation state
 *     machine.  It parses complete request headers/payloads into xrootd_ctx_t.
 *   - handshake.c owns the initial client hello and the opcode dispatcher.
 *     Look there first when adding or changing an XRootD request type.
 *   - session.c owns protocol/login/auth-advertisement/liveness requests.
 *   - read_handlers.c owns file-handle lifecycle: stat/open/read/readv/close.
 *   - query.c owns kXR_query (checksum, space, config queries).
 *   - dirlist.c owns kXR_dirlist (directory listing with optional dStat).
 *   - write_handlers.c owns storage mutation: write/pgwrite/sync/truncate/
 *     mkdir/rm/rmdir/mv/chmod.
 *   - path.c is the only place that should translate untrusted client paths
 *     into canonical paths under xrootd_root.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/xattr.h>
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

/* VOMS support is loaded at runtime via dlopen; no compile-time header needed */

#include "xrootd_protocol.h"
#include "ngx_xrootd_metrics.h"
#include "ngx_xrootd_token.h"

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

/*
 * Maximum kXR_prepare payload.  XrdCl sends a newline-separated list of paths
 * here; allow a moderately sized batch without growing the receive buffer used
 * for ordinary path operations.
 */
#define XROOTD_MAX_PREPARE_PAYLOAD  (64 * 1024)

/*
 * Maximum kXR_auth payload.  GSI certificate chains with VOMS attribute
 * certificates can reach 8-10 KB depending on the CA chain depth.
 */
#define XROOTD_MAX_AUTH_PAYLOAD   (16 * 1024)

/* TCP receive buffer (sized to hold the largest expected request) */
#define XROOTD_RECV_BUF      (XROOTD_MAX_PATH + XRD_REQUEST_HDR_LEN + 64)

/*
 * Maximum immediate send_chain continuations before yielding through nginx's
 * posted-event queue.  This keeps large sendfile responses moving without
 * forcing a fresh epoll_wait after each partial chain advance, while still
 * giving other ready connections a chance to run.
 */
#define XROOTD_SEND_CHAIN_SPIN_MAX  16

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
    XRD_ST_HANDSHAKE,     /* accumulating the 20-byte client hello  */
    XRD_ST_REQ_HEADER,    /* accumulating a 24-byte request header  */
    XRD_ST_REQ_PAYLOAD,   /* accumulating dlen bytes of payload     */
    XRD_ST_SENDING,       /* draining a large pending write buffer  */
    XRD_ST_AIO,           /* async file I/O posted to thread pool   */
    XRD_ST_TLS_HANDSHAKE, /* kXR_ableTLS: TLS accept in progress    */
    XRD_ST_UPSTREAM,      /* upstream redirector query in progress  */
} xrootd_state_t;

/* Opaque upstream context — defined in ngx_xrootd_upstream.c */
typedef struct xrootd_upstream_s xrootd_upstream_t;

/* Opaque CMS heartbeat context — defined in ngx_xrootd_cms_heartbeat.c */
typedef struct ngx_xrootd_cms_ctx_s ngx_xrootd_cms_ctx_t;

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
    int        readable;           /* 1 if opened with read permission      */
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

    /*
     * Session auth state.  XRootD separates kXR_login from real auth: login
     * establishes a server-issued session id, while auth_done means the
     * configured auth mode has actually completed.  Most file opcodes require
     * both flags.
     */
    u_char     sessid[XROOTD_SESSION_ID_LEN];
    ngx_flag_t logged_in;    /* kXR_login received */
    ngx_flag_t auth_done;    /* authentication completed */
    char       dn[512];      /* authenticated subject DN (GSI), or empty */
    char       primary_vo[128];
    char       vo_list[512];

    /* Open file table; index 0..XROOTD_MAX_FILES-1 is the handle number */
    xrootd_file_t  files[XROOTD_MAX_FILES];

    /* Pending write queue (one buffer at a time) */
    u_char    *wbuf;          /* allocated from pool */
    size_t     wbuf_len;
    size_t     wbuf_pos;
    u_char    *wbuf_base;     /* base of wbuf allocation */

    /* Pending chain send (used by read/readv vectored response path) */
    ngx_chain_t *wchain;
    u_char      *wchain_base; /* optional data buffer to free after send */

    /*
     * Reusable response workspace for read-heavy sessions.  The stream state
     * machine never parses the next request while a chain response is pending,
     * so read/readv can safely retain and reuse these pool allocations instead
     * of growing the connection pool on every transfer chunk.
     */
    u_char      *read_scratch;
    size_t       read_scratch_size;
    u_char      *read_hdr_scratch;
    size_t       read_hdr_scratch_size;

    /* GSI handshake state */
    EVP_PKEY  *gsi_dh_key;   /* freed after kXGC_cert processing */

    /*
     * Token authentication state.  The dispatcher decides whether a session is
     * authenticated; individual write/open handlers check token scopes against
     * the canonical target path when a token-authenticated session mutates
     * storage.
     */
    int                   token_auth;  /* 1 if authenticated via bearer token */
    int                   token_scope_count;
    xrootd_token_scope_t  token_scopes[XROOTD_MAX_TOKEN_SCOPES];

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

    /* kXR_ableTLS: set after sending a protocol response with kXR_haveTLS;
     * cleared once the TLS handshake completes successfully. */
    ngx_uint_t                  tls_pending;

    /* Active upstream query, or NULL if none in progress. */
    xrootd_upstream_t          *upstream;

    /*
     * kXR_sigver: HMAC-SHA256 request signing (GSI sessions only).
     *
     * signing_key is SHA-256(DH shared secret), set at end of GSI kXGC_cert.
     * sigver_pending is set when kXR_sigver arrives; the next dispatch verifies
     * the HMAC against the buffered 24-byte header (and optional payload) before
     * routing the request.  last_seqno guards against replays.
     */
    u_char     signing_key[32];     /* HMAC-SHA256 key from DH exchange */
    int        signing_active;      /* 1 when signing_key is valid */
    uint64_t   last_seqno;          /* last accepted sigver seqno */

    int        sigver_pending;      /* 1 if next dispatch must verify */
    uint16_t   sigver_expectrid;    /* opcode the pending signature covers */
    uint64_t   sigver_seqno;        /* seqno from the pending sigver */
    int        sigver_nodata;       /* 1 = payload excluded from HMAC */
    u_char     sigver_hmac[32];     /* expected HMAC bytes */

} xrootd_ctx_t;

/* ------------------------------------------------------------------ */
/* Module configuration                                                 */
/* ------------------------------------------------------------------ */

#define XROOTD_AUTH_NONE   0   /* no authentication required (anonymous) */
#define XROOTD_AUTH_GSI    1   /* GSI/x509 authentication required       */
#define XROOTD_AUTH_TOKEN  2   /* Bearer token (JWT/WLCG) authentication */
#define XROOTD_AUTH_BOTH   3   /* Accept either GSI or token auth        */

typedef struct {
    ngx_str_t  path;
    ngx_str_t  vo;
    char       resolved[PATH_MAX];
} xrootd_vo_rule_t;

typedef struct {
    ngx_str_t  path;
    char       resolved[PATH_MAX];
} xrootd_group_rule_t;

typedef struct {
    ngx_str_t  prefix;   /* normalized policy-style prefix (NUL-terminated) */
    ngx_str_t  host;     /* backend host (text) */
    uint16_t   port;     /* backend port */
} xrootd_manager_map_t;

typedef struct {
    ngx_flag_t  enable;

    /* CMS heartbeat/manager registration */
    ngx_str_t    cms_manager;       /* original host:port directive value */
    ngx_addr_t  *cms_addr;          /* resolved manager address */
    ngx_str_t    cms_paths;         /* exported path list, or empty for root */
    time_t       cms_interval;      /* heartbeat interval seconds */
    ngx_xrootd_cms_ctx_t *cms_ctx;  /* runtime event/peer state */

    ngx_str_t   root;
    ngx_uint_t  auth;

    /* GSI certificate paths */
    ngx_str_t   certificate;
    ngx_str_t   certificate_key;
    ngx_str_t   trusted_ca;
    ngx_str_t   vomsdir;
    ngx_str_t   voms_cert_dir;
    ngx_str_t   crl;              /* xrootd_crl /path/to/file_or_dir     */
    time_t      crl_reload;       /* xrootd_crl_reload interval (sec), 0=off */

    ngx_array_t *vo_rules;
    ngx_array_t *group_rules;
    ngx_array_t *manager_map; /* xrootd_manager_map_t entries */

    /* Loaded OpenSSL objects */
    X509        *gsi_cert;
    EVP_PKEY    *gsi_key;
    X509_STORE  *gsi_store;
    uint32_t     gsi_ca_hash;

    /* CRL reload timer (heap-allocated in init_process) */
    ngx_event_t *crl_timer;

    /* Write support */
    ngx_flag_t   allow_write;

    /* Token (JWT/WLCG) authentication */
    ngx_str_t   token_jwks;       /* xrootd_token_jwks /path/to/jwks.json  */
    ngx_str_t   token_issuer;     /* xrootd_token_issuer "https://..."     */
    ngx_str_t   token_audience;   /* xrootd_token_audience "nginx-xrootd"  */

    /* Loaded JWKS keys (populated at postconfiguration) */
    xrootd_jwks_key_t  jwks_keys[XROOTD_MAX_JWKS_KEYS];
    int                 jwks_key_count;

    /* Access logging */
    ngx_str_t    access_log;
    ngx_fd_t     access_log_fd;

    /* Prometheus metrics */
    ngx_int_t    metrics_slot;

    /* Upstream XRootD redirector (xrootd_upstream host:port) */
    ngx_str_t    upstream_host;    /* NUL-terminated hostname or IP             */
    uint16_t     upstream_port;    /* TCP port                                  */

    /* kXR_ableTLS in-protocol TLS upgrade */
    ngx_flag_t   tls;              /* xrootd_tls on|off                          */
    ngx_ssl_t   *tls_ctx;          /* SSL context; populated at postconfiguration */

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
ngx_int_t ngx_stream_xrootd_init_process(ngx_cycle_t *cycle);
ngx_int_t ngx_xrootd_metrics_shm_init(ngx_shm_zone_t *shm_zone, void *data);
ngx_int_t xrootd_rebuild_gsi_store(ngx_stream_xrootd_srv_conf_t *xcf,
    ngx_log_t *log);
/* PKI consistency checks invoked at startup/postconfiguration. */
ngx_int_t xrootd_check_pki_consistency_stream(ngx_log_t *log,
    ngx_stream_xrootd_srv_conf_t *xcf);
char *xrootd_conf_set_require_vo(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
char *xrootd_conf_set_inherit_parent_group(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

/* xrootd manager map directive parser */
char *xrootd_conf_set_manager_map(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

/* CMS heartbeat directive parser */
char *xrootd_conf_set_cms_manager(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

/* xrootd upstream redirector directive parser */
char *xrootd_conf_set_upstream(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

/* ngx_xrootd_connection.c */
void ngx_stream_xrootd_handler(ngx_stream_session_t *s);
void ngx_stream_xrootd_recv(ngx_event_t *rev);
void ngx_stream_xrootd_send(ngx_event_t *wev);
void xrootd_tls_handshake_done(ngx_connection_t *c);
ngx_int_t xrootd_schedule_read_resume(ngx_connection_t *c);
ngx_int_t xrootd_schedule_write_resume(ngx_connection_t *c);
ngx_int_t xrootd_queue_response_base(xrootd_ctx_t *ctx, ngx_connection_t *c,
    u_char *buf, size_t len, u_char *base);
ngx_int_t xrootd_queue_response(xrootd_ctx_t *ctx, ngx_connection_t *c,
    u_char *buf, size_t len);
ngx_int_t xrootd_queue_response_chain(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_chain_t *cl, u_char *base);
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
ngx_int_t xrootd_handle_sigver(xrootd_ctx_t *ctx, ngx_connection_t *c);

/* ngx_xrootd_gsi.c */
int gsi_find_bucket(const u_char *payload, size_t plen,
    uint32_t target_type, const u_char **data_out, size_t *len_out);
STACK_OF(X509) *xrootd_gsi_parse_x509(xrootd_ctx_t *ctx, ngx_connection_t *c);
ngx_int_t xrootd_handle_auth(xrootd_ctx_t *ctx, ngx_connection_t *c);

/* ngx_xrootd_token.c — see ngx_xrootd_token.h for types and API */

/* ngx_xrootd_read_handlers.c — file-handle lifecycle: stat/open/read/readv/close */
ngx_int_t xrootd_handle_stat(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);
ngx_int_t xrootd_handle_open(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);
ngx_int_t xrootd_handle_read(xrootd_ctx_t *ctx, ngx_connection_t *c);
ngx_int_t xrootd_handle_readv(xrootd_ctx_t *ctx, ngx_connection_t *c);
ngx_int_t xrootd_handle_pgread(xrootd_ctx_t *ctx, ngx_connection_t *c);
ngx_int_t xrootd_handle_locate(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);
ngx_int_t xrootd_handle_statx(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);
ngx_int_t xrootd_handle_close(xrootd_ctx_t *ctx, ngx_connection_t *c);

/* ngx_xrootd_query.c — kXR_query: checksum (adler32, md5, sha1, sha256), */
/*                        space, config, stats, xattr, finfo, fsinfo queries */
ngx_int_t xrootd_handle_query(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);

/* ngx_xrootd_query.c — kXR_prepare staging/cache hint */
ngx_int_t xrootd_handle_prepare(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);

/* manager map lookup helper (longest-prefix match) */
const xrootd_manager_map_t *xrootd_find_manager_map(const char *reqpath,
    ngx_array_t *map);

/* ngx_xrootd_fattr.c — kXR_fattr: file extended attributes */
ngx_int_t xrootd_handle_fattr(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);

/* ngx_xrootd_dirlist.c — kXR_dirlist: directory listing with optional dStat */
ngx_int_t xrootd_handle_dirlist(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);

/* ngx_xrootd_write_handlers.c */
ngx_int_t xrootd_handle_write(xrootd_ctx_t *ctx, ngx_connection_t *c);
ngx_int_t xrootd_handle_pgwrite(xrootd_ctx_t *ctx, ngx_connection_t *c);
ngx_int_t xrootd_handle_writev(xrootd_ctx_t *ctx, ngx_connection_t *c);
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
ngx_int_t xrootd_send_redirect(xrootd_ctx_t *ctx, ngx_connection_t *c,
    const char *host, uint16_t port);
ngx_int_t xrootd_send_wait(xrootd_ctx_t *ctx, ngx_connection_t *c,
    uint32_t seconds);
ngx_int_t xrootd_send_waitresp(xrootd_ctx_t *ctx, ngx_connection_t *c);
ngx_int_t xrootd_send_pgwrite_status(xrootd_ctx_t *ctx,
    ngx_connection_t *c, int64_t write_offset);
void xrootd_build_pgread_status(xrootd_ctx_t *ctx, int64_t file_offset,
    uint32_t total_with_crcs, ServerStatusResponse_pgRead *out);
uint32_t xrootd_crc32c(const void *buf, size_t len);

/* ngx_xrootd_path.c */
size_t xrootd_sanitize_log_string(const char *in, char *out, size_t outsz);
ngx_int_t xrootd_normalize_policy_path(ngx_pool_t *pool, const ngx_str_t *src,
    ngx_str_t *dst);
ngx_array_t *xrootd_merge_arrays(ngx_conf_t *cf, ngx_array_t *parent,
    ngx_array_t *child, size_t element_size);
ngx_int_t xrootd_finalize_vo_rules(ngx_log_t *log, const ngx_str_t *root,
    ngx_array_t *rules);
ngx_int_t xrootd_finalize_group_rules(ngx_log_t *log, const ngx_str_t *root,
    ngx_array_t *rules);
const xrootd_vo_rule_t *xrootd_find_vo_rule(const char *resolved_path,
    ngx_array_t *rules);
const xrootd_group_rule_t *xrootd_find_group_rule(const char *resolved_path,
    ngx_array_t *rules);
ngx_flag_t xrootd_vo_list_contains(const char *vo_list, const char *required_vo);
ngx_int_t xrootd_check_vo_acl(ngx_log_t *log, const char *resolved_path,
    ngx_array_t *vo_rules, const char *vo_list);
ngx_int_t xrootd_apply_parent_group_policy_fd(ngx_log_t *log, int fd,
    const char *path, ngx_array_t *rules);
ngx_int_t xrootd_apply_parent_group_policy_path(ngx_log_t *log,
    const char *path, ngx_array_t *rules);
int  xrootd_resolve_path_noexist(ngx_log_t *log, const ngx_str_t *root,
    const char *reqpath, char *resolved, size_t resolvsz);
int  xrootd_resolve_path(ngx_log_t *log, const ngx_str_t *root,
    const char *reqpath, char *resolved, size_t resolvsz);
int  xrootd_resolve_path_write(ngx_log_t *log, const ngx_str_t *root,
    const char *reqpath, char *resolved, size_t resolvsz);
int  xrootd_extract_path(ngx_log_t *log, const u_char *payload,
    size_t payload_len, char *out, size_t outsz, ngx_flag_t strip_cgi);
int  xrootd_mkdir_recursive(const char *path, mode_t mode);
int  xrootd_mkdir_recursive_policy(const char *path, mode_t mode,
    ngx_log_t *log, ngx_array_t *rules);
void xrootd_strip_cgi(const char *in, char *out, size_t outsz);
void xrootd_make_stat_body(const struct stat *st, ngx_flag_t is_vfs,
    char *out, size_t outsz);
void xrootd_log_access(xrootd_ctx_t *ctx, ngx_connection_t *c,
    const char *verb, const char *path, const char *detail,
    ngx_uint_t xrd_ok, uint16_t errcode, const char *errmsg, size_t bytes);

/* ngx_xrootd_upstream.c — outbound XRootD redirector client */
ngx_int_t xrootd_upstream_start(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf);
void xrootd_upstream_cleanup(xrootd_upstream_t *up);

/* ngx_xrootd_cms_heartbeat.c — CMS manager heartbeat/registration */
void ngx_xrootd_cms_start(ngx_cycle_t *cycle,
    ngx_stream_xrootd_srv_conf_t *conf);

/* ngx_xrootd_voms.c — runtime VOMS via dlopen(libvomsapi.so.1) */
ngx_int_t  xrootd_voms_init(ngx_log_t *log);
ngx_flag_t xrootd_voms_available(void);
ngx_int_t  xrootd_extract_voms_info(ngx_log_t *log, X509 *leaf,
    STACK_OF(X509) *chain, const ngx_str_t *vomsdir,
    const ngx_str_t *cert_dir, char *primary_vo, size_t primary_vo_sz,
    char *vo_list, size_t vo_list_sz);

/* ngx_xrootd_aio.c — AIO response builders (used by read/write handlers) */
u_char *xrootd_build_read_response(xrootd_ctx_t *ctx, ngx_connection_t *c,
    u_char *databuf, size_t data_total, size_t *rsp_total_out);
u_char *xrootd_build_readv_response(xrootd_ctx_t *ctx, ngx_connection_t *c,
    u_char *databuf, size_t rsp_total, size_t *out_size);
ngx_chain_t *xrootd_build_chunked_chain(xrootd_ctx_t *ctx,
    ngx_connection_t *c, u_char *databuf, size_t data_total);
ngx_chain_t *xrootd_build_sendfile_chain(xrootd_ctx_t *ctx,
    ngx_connection_t *c, int fd, const char *path, off_t offset,
    size_t data_total, u_char **base_out);
u_char *xrootd_get_read_scratch(xrootd_ctx_t *ctx, ngx_connection_t *c,
    size_t need);
u_char *xrootd_get_read_header_scratch(xrootd_ctx_t *ctx,
    ngx_connection_t *c, size_t need);
void xrootd_release_read_buffer(xrootd_ctx_t *ctx, ngx_connection_t *c,
    u_char *buf);

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

/*
 * xrootd_pgread_aio_t — async kXR_pgread context.
 *
 * scratch layout: [0 .. rlen-1] = flat file data read by thread;
 *                 [rlen .. rlen+out_size-1] = interleaved data+CRC written by thread.
 * The completion callback builds the chain from scratch + rlen.
 */
typedef struct {
    ngx_connection_t              *c;
    xrootd_ctx_t                  *ctx;
    int       fd;
    int       handle_idx;
    off_t     offset;
    size_t    rlen;       /* requested bytes; flat portion size in scratch */
    u_char   *scratch;    /* single alloc: flat data then interleaved output */
    size_t    out_size;   /* interleaved bytes written (set by thread) */
    u_char    streamid[2];
    ssize_t   nread;      /* actual pread return (set by thread) */
    int       io_errno;
} xrootd_pgread_aio_t;

void xrootd_aio_resume(ngx_connection_t *c);
void xrootd_read_aio_done(ngx_event_t *ev);
void xrootd_write_aio_done(ngx_event_t *ev);
void xrootd_readv_aio_done(ngx_event_t *ev);
void xrootd_pgread_aio_done(ngx_event_t *ev);
void xrootd_read_aio_thread(void *data, ngx_log_t *log);
void xrootd_write_aio_thread(void *data, ngx_log_t *log);
void xrootd_readv_aio_thread(void *data, ngx_log_t *log);
void xrootd_pgread_aio_thread(void *data, ngx_log_t *log);
#endif
