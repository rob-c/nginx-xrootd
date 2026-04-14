/*
 * xrootd_protocol.h
 *
 * Wire-format constants and packed structs for the XRootD root:// protocol.
 *
 * Sources:
 *   xrootd/xrootd  src/XProtocol/XProtocol.hh  (canonical C++ header)
 *   dcache/xrootd4j                              (Java reference impl)
 *   go-hep/hep     xrdproto/                    (Go reference impl)
 *   XRootD Protocol Specification v5.2.0
 *
 * All multi-byte integers on the wire are big-endian (network byte order).
 * Use htonl/ntohl/htons/ntohs when reading/writing these structs.
 */

#ifndef XROOTD_PROTOCOL_H
#define XROOTD_PROTOCOL_H

#include <stdint.h>

/* ------------------------------------------------------------------ */
/* Primitive types (matching XProtocol.hh)                             */
/* ------------------------------------------------------------------ */

typedef uint8_t   kXR_char;
typedef uint16_t  kXR_unt16;
typedef uint32_t  kXR_unt32;
typedef int16_t   kXR_int16;
typedef int32_t   kXR_int32;
typedef int64_t   kXR_int64;

/* ------------------------------------------------------------------ */
/* Protocol version and port                                            */
/* ------------------------------------------------------------------ */

#define XROOTD_DEFAULT_PORT     1094
#define kXR_PROTOCOLVERSION     0x00000520u   /* current (5.2.0) */
#define kXR_PROTOCOLVERSION_3   0x00000300u   /* stable v3 */

/* Initial handshake magic — fifth field of the client's 20-byte hello */
#define ROOTD_PQ                2012   /* 0x7DC */

/* Server type (msgval in server handshake response) */
#define kXR_LBalServer          0      /* load-balancer / redirector */
#define kXR_DataServer          1      /* data server (us) */

/* ------------------------------------------------------------------ */
/* Fixed wire sizes                                                     */
/* ------------------------------------------------------------------ */

#define XRD_HANDSHAKE_LEN       20     /* client → server, initial hello */
#define XRD_HANDSHAKE_RSP_LEN   12     /* server → client, initial hello */
#define XRD_REQUEST_HDR_LEN     24     /* every request starts with this */
#define XRD_RESPONSE_HDR_LEN    8      /* every response starts with this */
#define XRD_FHANDLE_LEN         4      /* opaque file handle */
#define XROOTD_SESSION_ID_LEN   16     /* opaque session id */

/* ------------------------------------------------------------------ */
/* Request IDs (kXR_*)                                                  */
/* ------------------------------------------------------------------ */

#define kXR_auth        3000
#define kXR_query       3001
#define kXR_chmod       3002
#define kXR_close       3003
#define kXR_dirlist     3004
#define kXR_gpfile      3005
#define kXR_protocol    3006
#define kXR_login       3007
#define kXR_mkdir       3008
#define kXR_mv          3009
#define kXR_open        3010
#define kXR_ping        3011
#define kXR_chkpoint    3012
#define kXR_read        3013
#define kXR_rm          3014
#define kXR_rmdir       3015
#define kXR_sync        3016
#define kXR_stat        3017
#define kXR_set         3018
#define kXR_write       3019
#define kXR_prepare     3021
#define kXR_statx       3022
#define kXR_endsess     3023
#define kXR_bind        3024
#define kXR_readv       3025
#define kXR_locate      3027
#define kXR_truncate    3028
#define kXR_sigver      3029
#define kXR_pgread      3030
#define kXR_pgwrite     3026
#define kXR_writev      3031

/* ------------------------------------------------------------------ */
/* Response status codes                                               */
/* ------------------------------------------------------------------ */

#define kXR_ok          0        /* success */
#define kXR_oksofar     4000     /* partial — more packets follow */
#define kXR_attn        4001     /* unsolicited server notification */
#define kXR_authmore    4002     /* auth needs another round-trip */
#define kXR_error       4003     /* error; body = errnum[4] + errmsg */
#define kXR_redirect    4004     /* redirect; body = port[4] + host */
#define kXR_wait        4005     /* retry after N seconds */
#define kXR_waitresp    4006     /* async result is coming */
#define kXR_status      4007     /* extended status with CRC32C */

/* ------------------------------------------------------------------ */
/* Error codes (carried in kXR_error response errnum field)            */
/* ------------------------------------------------------------------ */

#define kXR_ArgInvalid      3000
#define kXR_ArgMissing      3001
#define kXR_ArgTooLong      3002
#define kXR_FileLocked      3003
#define kXR_FileNotOpen     3004
#define kXR_FSError         3005
#define kXR_InvalidRequest  3006
#define kXR_IOError         3007
#define kXR_NoMemory        3008
#define kXR_NoSpace         3009
#define kXR_NotAuthorized   3010
#define kXR_NotFound        3011
#define kXR_ServerError     3012
#define kXR_Unsupported     3013
#define kXR_noserver        3014
#define kXR_NotFile         3015
#define kXR_isDirectory     3016
#define kXR_Cancelled       3017
#define kXR_ItExists        3018
#define kXR_ChkSumErr       3019
#define kXR_inProgress      3020
#define kXR_overQuota       3021
#define kXR_Overloaded      3024
#define kXR_fsReadOnly      3025
#define kXR_AttrNotFound    3027
#define kXR_TLSRequired     3028
#define kXR_AuthFailed      3030
#define kXR_Impossible      3031
#define kXR_Conflict        3032

/* ------------------------------------------------------------------ */
/* Open option flags (options field in kXR_open, uint16)               */
/* ------------------------------------------------------------------ */

#define kXR_compress    0x0001
#define kXR_delete      0x0002
#define kXR_force       0x0004
#define kXR_new         0x0008
#define kXR_open_read   0x0010
#define kXR_open_updt   0x0020
#define kXR_async       0x0040
#define kXR_refresh     0x0080
#define kXR_mkpath      0x0100
#define kXR_open_apnd   0x0200
#define kXR_retstat     0x0400   /* include stat info in open response */
#define kXR_replica     0x0800
#define kXR_posc        0x1000
#define kXR_nowait      0x2000
#define kXR_seqio       0x4000
#define kXR_open_wrto   0x8000

/* ------------------------------------------------------------------ */
/* Stat response flags                                                  */
/* ------------------------------------------------------------------ */

#define kXR_file        0     /* regular file (no bit set) */
#define kXR_xset        1     /* executable / searchable   */
#define kXR_isDir       2     /* is a directory            */
#define kXR_other       4     /* neither file nor dir      */
#define kXR_offline     8     /* file is not online        */
#define kXR_readable    16    /* read access permitted     */
#define kXR_writable    32    /* write access permitted    */
#define kXR_poscpend    64    /* POSC file, not yet closed */
#define kXR_bkpexist    128   /* a backup copy exists      */

/* ------------------------------------------------------------------ */
/* Protocol response flags (server capability bits)                    */
/* ------------------------------------------------------------------ */

#define kXR_isServer    0x00000001u   /* we are a data server */
#define kXR_isManager   0x00000002u   /* we are a manager/redirector */
#define kXR_haveTLS     0x80000000u
#define kXR_gotoTLS     0x40000000u
#define kXR_tlsLogin    0x04000000u

/* ------------------------------------------------------------------ */
/* Login capver / ability flags                                         */
/* ------------------------------------------------------------------ */

#define kXR_asyncap     0x80   /* client is async-capable */
#define kXR_vermask     0x3F   /* version bits in capver byte */
#define kXR_ver003      3      /* XRootD v3 stable client */
#define kXR_ver005      5      /* TLS-capable client */

/* Stat request options */
#define kXR_vfs         1      /* stat the VFS, not the file */

/* Dirlist options */
#define kXR_dstat       0x02   /* include per-entry stat info */
#define kXR_online      0x01   /* only online entries */

/* ------------------------------------------------------------------ */
/* Packed wire structures                                               */
/* All integers are network byte order; use htonl/ntohl to access.     */
/* ------------------------------------------------------------------ */

#pragma pack(push, 1)

/*
 * ClientInitHandShake — 20 bytes sent by the client on connect.
 *
 * Validate: third==0, fourth==htonl(4), fifth==htonl(ROOTD_PQ==2012).
 */
typedef struct {
    kXR_int32  first;    /* 0x00000000 */
    kXR_int32  second;   /* 0x00000000 */
    kXR_int32  third;    /* 0x00000000 */
    kXR_int32  fourth;   /* htonl(4)   */
    kXR_int32  fifth;    /* htonl(2012 = ROOTD_PQ) */
} ClientInitHandShake;   /* 20 bytes */

/*
 * ServerInitHandShake — 12 bytes sent by the server in response.
 * NOTE: this is NOT in standard response-header format. It is its own
 * special framing (msglen + protover + msgval).
 */
typedef struct {
    kXR_unt32  msglen;   /* htonl(8): 8 more bytes follow */
    kXR_unt32  protover; /* server protocol version       */
    kXR_unt32  msgval;   /* kXR_LBalServer=0 or kXR_DataServer=1 */
} ServerInitHandShake;   /* 12 bytes */

/* ------------------------------------------------------------------ */
/* Standard request header — shared by every request (24 bytes)        */
/* ------------------------------------------------------------------ */

typedef struct {
    kXR_char   streamid[2];  /* client-chosen, echoed in response */
    kXR_unt16  requestid;    /* one of the kXR_* constants        */
    kXR_char   body[16];     /* request-specific parameters       */
    kXR_int32  dlen;         /* payload length following header   */
} ClientRequestHdr;          /* 24 bytes; payload follows inline  */

/* ------------------------------------------------------------------ */
/* Standard response header — shared by every response (8 bytes)       */
/* ------------------------------------------------------------------ */

typedef struct {
    kXR_char   streamid[2];  /* echoed from request */
    kXR_unt16  status;       /* kXR_ok / kXR_error / ... */
    kXR_int32  dlen;         /* response body length */
} ServerResponseHdr;         /* 8 bytes; body follows inline */

/* ------------------------------------------------------------------ */
/* kXR_protocol (3006)                                                  */
/* ------------------------------------------------------------------ */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;    /* kXR_protocol */
    kXR_int32  clientpv;     /* client protocol version */
    kXR_char   flags;        /* kXR_secreqs, kXR_ableTLS, etc. */
    kXR_char   expect;       /* kXR_ExpLogin = 0x03            */
    kXR_char   reserved[10];
    kXR_int32  dlen;         /* 0 */
} ClientProtocolRequest;     /* 24 bytes */

typedef struct {
    kXR_int32  pval;         /* server protocol version */
    kXR_int32  flags;        /* kXR_isServer | ... */
} ServerProtocolBody;        /* 8 bytes, dlen=8 */

/* ------------------------------------------------------------------ */
/* kXR_login (3007)                                                     */
/* ------------------------------------------------------------------ */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;    /* kXR_login */
    kXR_int32  pid;          /* client process ID */
    kXR_char   username[8];  /* null-padded username */
    kXR_char   ability2;     /* extended ability flags */
    kXR_char   ability;      /* ability flags */
    kXR_char   capver;       /* version | kXR_asyncap */
    kXR_char   reserved;
    kXR_int32  dlen;         /* length of auth token payload */
} ClientLoginRequest;        /* 24 bytes */

typedef struct {
    kXR_char   sessid[XROOTD_SESSION_ID_LEN];  /* 16 opaque bytes */
    /* optional: security info follows if dlen > 16 */
} ServerLoginBody;

/* ------------------------------------------------------------------ */
/* kXR_open (3010)                                                      */
/* ------------------------------------------------------------------ */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;    /* kXR_open */
    kXR_unt16  mode;         /* POSIX permission bits (e.g. 0644 = 0x01B4) */
    kXR_unt16  options;      /* kXR_open_read | kXR_retstat | ... */
    kXR_unt16  optiont;      /* extended open flags */
    kXR_char   reserved[6];
    kXR_char   fhtemplt[4];  /* file handle template (usually 0) */
    kXR_int32  dlen;         /* length of path payload */
    /* null-terminated path follows as payload */
} ClientOpenRequest;         /* 24 bytes */

typedef struct {
    kXR_char   fhandle[4];   /* opaque file handle for subsequent ops */
    kXR_int32  cpsize;       /* compression page size (0 = uncompressed) */
    kXR_char   cptype[4];    /* compression type (e.g. "adl\0") */
    /* if kXR_retstat set: ASCII stat string follows */
} ServerOpenBody;            /* 12 bytes minimum */

/* ------------------------------------------------------------------ */
/* kXR_read (3013)                                                      */
/* ------------------------------------------------------------------ */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;    /* kXR_read */
    kXR_char   fhandle[4];   /* file handle from open */
    kXR_int64  offset;       /* byte offset to read from */
    kXR_int32  rlen;         /* bytes to read */
    kXR_int32  dlen;         /* 0 for basic read */
} ClientReadRequest;         /* 24 bytes */
/* Response body: raw file bytes, dlen bytes */

/* ------------------------------------------------------------------ */
/* kXR_stat (3017)                                                      */
/* ------------------------------------------------------------------ */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;    /* kXR_stat */
    kXR_char   options;      /* kXR_vfs or 0 */
    kXR_char   reserved[7];
    kXR_unt32  wants;        /* 0 */
    kXR_char   fhandle[4];   /* 0 if path-based stat, else open handle */
    kXR_int32  dlen;         /* path length (0 if using fhandle) */
    /* null-terminated path follows as payload */
} ClientStatRequest;         /* 24 bytes */
/*
 * Response body: ASCII string (null-terminated):
 *   "<id> <flags> <size> <modtime>"
 * e.g. "1234567 16 65536 1700000000"
 */

/* ------------------------------------------------------------------ */
/* kXR_close (3003)                                                     */
/* ------------------------------------------------------------------ */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;    /* kXR_close */
    kXR_char   fhandle[4];   /* file handle to close */
    kXR_char   reserved[12];
    kXR_int32  dlen;         /* 0 */
} ClientCloseRequest;        /* 24 bytes */

/* ------------------------------------------------------------------ */
/* kXR_ping (3011)                                                      */
/* ------------------------------------------------------------------ */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;    /* kXR_ping */
    kXR_char   reserved[16];
    kXR_int32  dlen;         /* 0 */
} ClientPingRequest;         /* 24 bytes */

/* ------------------------------------------------------------------ */
/* kXR_dirlist (3004)                                                   */
/* ------------------------------------------------------------------ */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;    /* kXR_dirlist */
    kXR_char   reserved[15];
    kXR_char   options;      /* kXR_dstat | kXR_online */
    kXR_int32  dlen;         /* path length */
    /* null-terminated path follows as payload */
} ClientDirlistRequest;      /* 24 bytes */
/*
 * Response body: newline-separated entries (null-terminated at end):
 *   "name\n[id flags size mtime\n]..."
 * Last chunk uses kXR_ok; intermediate chunks use kXR_oksofar.
 */

/* ------------------------------------------------------------------ */
/* kXR_endsess (3023)                                                   */
/* ------------------------------------------------------------------ */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;    /* kXR_endsess */
    kXR_char   sessid[16];   /* session to terminate */
    kXR_int32  dlen;         /* 0 */
} ClientEndsessRequest;      /* 24 bytes */

/* ------------------------------------------------------------------ */
/* Error response body                                                  */
/* ------------------------------------------------------------------ */

typedef struct {
    kXR_int32  errnum;         /* one of kXR_* error codes above */
    char       errmsg[1];      /* null-terminated, variable length */
} ServerErrorBody;

/* ------------------------------------------------------------------ */
/* Redirect response body                                               */
/* ------------------------------------------------------------------ */

typedef struct {
    kXR_int32  port;
    char       host[1];        /* null-terminated hostname */
} ServerRedirectBody;

#pragma pack(pop)

#endif /* XROOTD_PROTOCOL_H */
