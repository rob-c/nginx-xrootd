/*
 * ngx_xrootd_metrics.h
 *
 * Shared memory layout for Prometheus-style metrics exposed by the
 * nginx-xrootd stream module.  One slot per server block (up to
 * XROOTD_METRICS_MAX_SERVERS).  Both the stream module and the HTTP
 * metrics module reference this header.
 */

#ifndef NGX_XROOTD_METRICS_H
#define NGX_XROOTD_METRICS_H

#include <ngx_core.h>

/* Hard cap on exported stream listeners sharing the metrics zone. */
#define XROOTD_METRICS_MAX_SERVERS  16

/*
 * Operation indices — order must match xrootd_op_names[] in
 * ngx_http_xrootd_metrics_module.c.
 *
 * The stream side increments op_ok/op_err by these numeric slots; the HTTP
 * exporter later turns the same slot number back into a Prometheus label.
 * That means this list is effectively a small ABI between the two modules.
 */
#define XROOTD_OP_LOGIN     0
#define XROOTD_OP_AUTH      1
#define XROOTD_OP_STAT      2
#define XROOTD_OP_OPEN_RD   3
#define XROOTD_OP_OPEN_WR   4
#define XROOTD_OP_READ      5
#define XROOTD_OP_WRITE     6
#define XROOTD_OP_SYNC      7
#define XROOTD_OP_CLOSE     8
#define XROOTD_OP_DIRLIST   9
#define XROOTD_OP_MKDIR    10
#define XROOTD_OP_RMDIR    11
#define XROOTD_OP_RM       12
#define XROOTD_OP_MV       13
#define XROOTD_OP_CHMOD    14
#define XROOTD_OP_TRUNCATE    15
#define XROOTD_OP_PING        16
#define XROOTD_OP_QUERY_CKSUM 17  /* kXR_query / kXR_QChecksum */
#define XROOTD_OP_QUERY_SPACE 18  /* kXR_query / kXR_QSpace    */
#define XROOTD_OP_READV       19  /* kXR_readv                 */
/* Number of entries in op_ok[] / op_err[] and xrootd_op_names[]. */
#define XROOTD_NOPS           20

/*
 * Per-server counter block.  Lives in shared memory; accessed by all
 * worker processes.  All integer fields are ngx_atomic_t so workers
 * can increment them without locks.
 *
 * auth[] and port are written once at config init time (before workers
 * fork) so no locking is needed for them.
 */
typedef struct {
    /* Connection and traffic counters exported as Prometheus counters/gauges. */
    ngx_atomic_t  connections_total;       /* connections accepted (lifetime) */
    ngx_atomic_t  connections_active;      /* currently open connections      */
    ngx_atomic_t  bytes_rx_total;          /* bytes received (write payloads) */
    ngx_atomic_t  bytes_tx_total;          /* bytes sent (read data)          */

    /* Indexed by XROOTD_OP_*; success/error are kept separate for export. */
    ngx_atomic_t  op_ok [XROOTD_NOPS];    /* successful ops by index         */
    ngx_atomic_t  op_err[XROOTD_NOPS];    /* failed ops by index             */

    /*
     * Identity for the listener bound to this slot.
     * The stream module assigns one slot per enabled server during startup.
     */
    ngx_uint_t    port;                    /* TCP listen port (0 = unknown)   */
    char          auth[8];                 /* "anon\0" or "gsi\0"             */
    ngx_uint_t    in_use;                  /* 1 = slot has been assigned      */
} ngx_xrootd_srv_metrics_t;

/*
 * Root shared-memory object stored in ngx_xrootd_shm_zone->data.
 * A fixed-size array keeps indexing simple and avoids extra allocation once
 * workers are running.
 */
typedef struct {
    ngx_xrootd_srv_metrics_t  servers[XROOTD_METRICS_MAX_SERVERS];
} ngx_xrootd_metrics_t;

/*
 * Global pointer to the shared zone — set by the stream module during
 * postconfiguration; read by the HTTP metrics module at request time.
 */
extern ngx_shm_zone_t *ngx_xrootd_shm_zone;

#endif /* NGX_XROOTD_METRICS_H */
