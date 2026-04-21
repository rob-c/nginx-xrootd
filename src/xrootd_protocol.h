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

/*
 * These aliases mirror the upstream protocol header names so the request and
 * response structs below can stay visually close to the published spec.
 */
typedef uint8_t   kXR_char;
typedef uint16_t  kXR_unt16;
typedef uint32_t  kXR_unt32;
typedef uint64_t  kXR_unt64;
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

/*
 * These sizes are used throughout the parser when advancing between the fixed
 * header and the optional payload that follows it.
 */
#define XRD_HANDSHAKE_LEN       20     /* client → server, initial hello */
#define XRD_HANDSHAKE_RSP_LEN   12     /* server → client, initial hello */
#define XRD_REQUEST_HDR_LEN     24     /* every request starts with this */
#define XRD_RESPONSE_HDR_LEN    8      /* every response starts with this */
#define XRD_FHANDLE_LEN         4      /* opaque file handle */
#define XROOTD_SESSION_ID_LEN   16     /* opaque session id */

/* ------------------------------------------------------------------ */
/* Request IDs (kXR_*)                                                  */
/* ------------------------------------------------------------------ */

/* Numeric opcodes carried in ClientRequestHdr.requestid. */
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
#define kXR_fattr       3020
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
/*                                                                      */
/* These are combined into an integer and sent as a decimal string.    */
/*                                                                      */
/* kXR_stat / kXR_open retstat / kXR_dirlist dStat wire format:        */
/*   "<id> <size> <flags> <mtime>\0"                                   */
/* Field order: size comes BEFORE flags (not the other way around).    */
/* Swapping them causes the client to misinterpret kXR_isDir (2) or   */
/* kXR_readable (16) as the file size.                                 */
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
/* Protocol request flags (client capability bits in kXR_protocol)    */
/* ------------------------------------------------------------------ */

#define kXR_secreqs     0x01u   /* client wants security-protocol list */
#define kXR_ableTLS     0x02u   /* client can upgrade to in-protocol TLS */
#define kXR_wantTLS     0x04u   /* client requires TLS (must upgrade) */

/* ------------------------------------------------------------------ */
/* Protocol response flags (server capability bits)                    */
/* ------------------------------------------------------------------ */

#define kXR_isServer    0x00000001u   /* we are a data server */
#define kXR_isManager   0x00000002u   /* we are a manager/redirector */
#define kXR_haveTLS     0x80000000u   /* server can accept kXR_ableTLS upgrade */
#define kXR_gotoTLS     0x40000000u   /* client must upgrade now */
#define kXR_tlsLogin    0x04000000u   /* login exchange requires TLS */

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
#define kXR_dstat       0x02   /* include per-entry stat info; see note below */
#define kXR_online      0x01   /* only online entries */

/* Prepare request options */
#define kXR_cancel      0x01   /* cancel a prepare request */
#define kXR_notify      0x02   /* notify client when prepare finishes */
#define kXR_noerrs      0x04   /* suppress per-path missing-file failures */
#define kXR_stage       0x08   /* stage files to online storage */
#define kXR_wmode       0x10   /* prepare for write access */
#define kXR_coloc       0x20   /* request colocated replicas */
#define kXR_fresh       0x40   /* require fresh cached copy */
#define kXR_usetcp      0x80   /* notification port uses TCP */

/* Prepare extended options (optionX field) */
#define kXR_evict       0x0001 /* evict cached data when supported */

/*
 * kXR_dstat wire format note:
 *
 * When kXR_dstat is set the server MUST prepend the 10-byte sentinel
 *   ".\n0 0 0 0\n"
 * to the response body before any real entries.  The XRootD client checks
 * for the 9-byte prefix ".\n0 0 0 0" (DirectoryList::dStatPrefix) and only
 * enters stat-pairing mode if it is present.  Without it the client treats
 * every newline-delimited line (including stat lines) as a plain filename.
 *
 * Body layout (after the lead-in):
 *   "<name1>\n<id1> <size1> <flags1> <mtime1>\n"   ← pair
 *   "<name2>\n<id2> <size2> <flags2> <mtime2>\n"   ← pair
 *   ...
 * The final '\n' is replaced by '\0' (NUL-terminator).
 * Intermediate kXR_oksofar chunks do NOT carry the lead-in or a NUL;
 * they are raw newline-delimited data that the client accumulates.
 */

/* ------------------------------------------------------------------ */
/* Packed wire structures                                               */
/* All integers are network byte order; use htonl/ntohl to access.     */
/* ------------------------------------------------------------------ */

/*
 * The protocol structs must match the on-the-wire byte layout exactly; any
 * compiler-inserted padding would corrupt request parsing immediately.
 */
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
 * ServerInitHandShake — legacy 12-byte server handshake response.
 *
 * This is NOT standard ServerResponseHdr framing — it has its own layout:
 *   msglen[4] + protover[4] + msgval[4]
 *
 * DO NOT USE for XRootD v5 clients.  v5 clients send handshake + kXR_protocol
 * as a single 44-byte segment and expect EACH server reply to be a standard
 * 8-byte ServerResponseHdr + body.  Sending this old 12-byte frame parses as
 * status=0x0008 / dlen=1312, causing the client to stall.
 *
 * This struct is kept for reference only.  The module responds to the
 * handshake with a standard ServerResponseHdr{streamid={0,0}, status=kXR_ok,
 * dlen=8} followed by 8 bytes of protover+msgval.
 */
typedef struct {
    kXR_unt32  msglen;   /* htonl(8): 8 more bytes follow */
    kXR_unt32  protover; /* server protocol version       */
    kXR_unt32  msgval;   /* kXR_LBalServer=0 or kXR_DataServer=1 */
} ServerInitHandShake;   /* 12 bytes — legacy, not used */

/* ------------------------------------------------------------------ */
/* Standard request header — shared by every request (24 bytes)        */
/* ------------------------------------------------------------------ */

typedef struct {
    kXR_char   streamid[2];  /* client-chosen, echoed in response */
    kXR_unt16  requestid;    /* one of the kXR_* constants        */
    kXR_char   body[16];     /* request-specific parameters       */
    /* Number of payload bytes immediately following this 24-byte header. */
    kXR_int32  dlen;         /* payload length following header   */
} ClientRequestHdr;          /* 24 bytes; payload follows inline  */

/* ------------------------------------------------------------------ */
/* Standard response header — shared by every response (8 bytes)       */
/* ------------------------------------------------------------------ */

typedef struct {
    kXR_char   streamid[2];  /* echoed from request */
    kXR_unt16  status;       /* kXR_ok / kXR_error / ... */
    /* Number of response-body bytes following the 8-byte response header. */
    kXR_int32  dlen;         /* response body length */
} ServerResponseHdr;         /* 8 bytes; body follows inline */

/*
 * kXR_status (4007) extended response — used for kXR_pgwrite and kXR_pgread.
 * The server sends kXR_status instead of kXR_ok; the body carries a
 * ServerResponseBody_Status (16 bytes) with a CRC32c integrity field,
 * followed by the request-specific body (ServerResponseBody_pgWrite, 8 bytes).
 *
 * Wire layout for kXR_pgwrite success (no bad pages), 32 bytes total:
 *   [ServerResponseHdr 8B] status=kXR_status, dlen=24
 *   [ServerResponseBody_Status 16B] crc32c, streamID, requestid, resptype,
 *                                   reserved, dlen=0 (no bad pages)
 *   [ServerResponseBody_pgWrite 8B] offset (last written)
 */

#define kXR_1stRequest  3000  /* base for requestid encoding in Status body */

typedef struct {
    kXR_unt32  crc32c;     /* CRC32c of everything from &streamID to end */
    kXR_char   streamID[2];/* echo of request streamid                   */
    kXR_char   requestid;  /* requestcode - kXR_1stRequest               */
    kXR_char   resptype;   /* 0=kXR_FinalResult, 1=kXR_PartialResult     */
    kXR_char   reserved[4];
    kXR_int32  dlen;       /* size of bad-page list (0 = no bad pages)   */
} ServerResponseBody_Status;   /* 16 bytes */

typedef struct {
    kXR_int64  offset;     /* file offset of written data                */
} ServerResponseBody_pgWrite;  /* 8 bytes */

/* Full kXR_status response for pgwrite (sent as one contiguous buffer) */
typedef struct {
    ServerResponseHdr          hdr; /* status=kXR_status, dlen=24       */
    ServerResponseBody_Status  bdy;
    ServerResponseBody_pgWrite pgw;
} ServerStatusResponse_pgWrite; /* 32 bytes */

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
    /* Path bytes follow the header; many clients include a trailing NUL in dlen. */
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
/* kXR_prepare (3021)                                                  */
/* ------------------------------------------------------------------ */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;    /* kXR_prepare */
    kXR_char   options;      /* kXR_stage, kXR_cancel, kXR_notify, ... */
    kXR_char   prty;         /* request priority */
    kXR_unt16  port;         /* notification port when kXR_notify is set */
    kXR_unt16  optionX;      /* extended prepare flags, e.g. kXR_evict */
    kXR_char   reserved[10];
    kXR_int32  dlen;         /* newline-separated paths or cancel token */
} ClientPrepareRequest;      /* 24 bytes */

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
    /* Either this handle is set, or dlen points at a path payload, but not both. */
    kXR_char   fhandle[4];   /* 0 if path-based stat, else open handle */
    kXR_int32  dlen;         /* path length (0 if using fhandle) */
    /* null-terminated path follows as payload */
} ClientStatRequest;         /* 24 bytes */
/*
 * Response body: ASCII string (null-terminated):
 *   "<id> <size> <flags> <modtime>"
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
/* kXR_pgwrite (3026) — paged write with per-page CRC32 checksums      */
/* ------------------------------------------------------------------ */

/*
 * Payload format: pages of kXR_pgPageSZ (4096) bytes each followed by a
 * 4-byte big-endian CRC32 checksum.  The last page may be shorter than
 * 4096 bytes but still has a 4-byte checksum appended.
 *
 * Layout per page: [ data[0..N-1] ][ crc32_be[4] ]
 * where N = 4096 for full pages, or (total_file_data % 4096) for the last.
 */
#define XRD_PGWRITE_PAGESZ  4096
#define XRD_PGWRITE_CKSZ    4    /* sizeof(uint32_t) CRC32 */
#define XRD_PGWRITE_UNITSZ  (XRD_PGWRITE_PAGESZ + XRD_PGWRITE_CKSZ)

typedef struct {
    kXR_char  streamid[2];
    kXR_unt16 requestid;    /* kXR_pgwrite */
    kXR_char  fhandle[4];   /* file handle from open */
    kXR_int64 offset;       /* file byte offset for first page */
    kXR_char  pathid;       /* path ID (0 = primary) */
    kXR_char  reqflags;     /* kXR_pgRetry (0x01) or 0 */
    kXR_char  reserved[2];
    /* Total bytes of interleaved data+CRC payload, not just pure file data. */
    kXR_int32 dlen;         /* total payload length (pages + checksums) */
    /* payload: interleaved page data and 4-byte CRC32 checksums */
} ClientPgWriteRequest;     /* 24 bytes */

/* ------------------------------------------------------------------ */
/* kXR_write (3019)                                                     */
/* ------------------------------------------------------------------ */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;    /* kXR_write */
    kXR_char   fhandle[4];   /* file handle from open */
    kXR_int64  offset;       /* byte offset to write at */
    kXR_char   pathid;       /* path ID (0 for primary) */
    kXR_char   reserved[3];
    kXR_int32  dlen;         /* number of data bytes in payload */
    /* payload: raw file data, dlen bytes */
} ClientWriteRequest;        /* 24 bytes */

/* ------------------------------------------------------------------ */
/* kXR_sync (3016)                                                      */
/* ------------------------------------------------------------------ */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;    /* kXR_sync */
    kXR_char   fhandle[4];   /* file handle to sync */
    kXR_char   reserved[12];
    kXR_int32  dlen;         /* 0 */
} ClientSyncRequest;         /* 24 bytes */

/* ------------------------------------------------------------------ */
/* kXR_truncate (3028)                                                  */
/* ------------------------------------------------------------------ */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;    /* kXR_truncate */
    kXR_char   fhandle[4];   /* file handle (if dlen==0) */
    kXR_int64  offset;       /* target file length */
    kXR_char   reserved[4];
    /* Handle-based truncate uses dlen=0; path-based truncate supplies a path. */
    kXR_int32  dlen;         /* path length (if path-based), or 0 for handle-based */
    /* null-terminated path follows as payload when dlen > 0 */
} ClientTruncateRequest;     /* 24 bytes */

/* ------------------------------------------------------------------ */
/* kXR_mkdir (3008)                                                     */
/* ------------------------------------------------------------------ */

/* kXR_mkdirpath option flag: create parent directories */
#define kXR_mkdirpath  0x01

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;    /* kXR_mkdir */
    kXR_char   options[1];   /* kXR_mkdirpath (0x01) to create parents */
    kXR_char   reserved[13];
    kXR_unt16  mode;         /* POSIX permission bits */
    kXR_int32  dlen;         /* path length */
    /* null-terminated path follows as payload */
} ClientMkdirRequest;        /* 24 bytes */

/* ------------------------------------------------------------------ */
/* kXR_rm (3014)                                                        */
/* ------------------------------------------------------------------ */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;    /* kXR_rm */
    kXR_char   reserved[16];
    kXR_int32  dlen;         /* path length */
    /* null-terminated path follows as payload */
} ClientRmRequest;           /* 24 bytes */

/* ------------------------------------------------------------------ */
/* kXR_rmdir (3015)                                                     */
/* ------------------------------------------------------------------ */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;    /* kXR_rmdir */
    kXR_char   reserved[16];
    kXR_int32  dlen;         /* path length */
    /* null-terminated path follows as payload */
} ClientRmdirRequest;        /* 24 bytes */

/* ------------------------------------------------------------------ */
/* kXR_mv (3009)                                                        */
/* ------------------------------------------------------------------ */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;    /* kXR_mv */
    kXR_char   reserved[14];
    /* Length of the first path so the receiver can split src and dst safely. */
    kXR_int16  arg1len;      /* byte length of source path in payload */
    kXR_int32  dlen;         /* total payload length (src + '\0' + dst) */
    /* payload: source path (arg1len bytes, null-terminated) followed
     *          immediately by dest path (null-terminated) */
} ClientMvRequest;           /* 24 bytes */

/* ------------------------------------------------------------------ */
/* kXR_chmod (3002)                                                     */
/* ------------------------------------------------------------------ */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;    /* kXR_chmod */
    kXR_char   reserved[14];
    kXR_unt16  mode;         /* POSIX permission bits */
    kXR_int32  dlen;         /* path length */
    /* null-terminated path follows as payload */
} ClientChmodRequest;        /* 24 bytes */

/* ------------------------------------------------------------------ */
/* kXR_readv (3025) — scatter-gather / vector read                     */
/* ------------------------------------------------------------------ */

/*
 * Each entry in the kXR_readv request payload describes one read segment.
 * The response body is the same structure (with actual rlen filled in)
 * followed immediately by rlen bytes of file data, repeated N times.
 * The server therefore has to preserve the per-segment headers while filling
 * in the data area behind them.
 *
 * Wire sizes (all big-endian):
 *   fhandle  4 bytes  open file handle (same as kXR_open response)
 *   rlen     4 bytes  requested / actual byte count
 *   offset   8 bytes  file byte offset
 *   -------- 16 bytes per segment
 *
 * Max elements: XrdProto::maxRvecsz = 16384 / 16 = 1024 per request.
 * Source: XProtocol.hh  struct readahead_list / read_list
 */
typedef struct {
    kXR_char   fhandle[4];  /* open file handle from kXR_open              */
    kXR_int32  rlen;        /* request: bytes wanted; response: bytes given */
    kXR_int64  offset;      /* file byte offset                             */
} readahead_list;           /* 16 bytes; network byte order                 */

#define XROOTD_READV_SEGSIZE  16    /* sizeof(readahead_list) */
#define XROOTD_READV_MAXSEGS  1024  /* XrdProto::maxRvecsz                 */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;   /* kXR_readv */
    kXR_char   reserved[15];
    kXR_char   pathid;      /* 0 for primary path */
    /* Payload is a packed array of readahead_list entries. */
    kXR_int32  dlen;        /* N * sizeof(readahead_list) */
    /* payload: N readahead_list structs */
} ClientReadVRequest;       /* 24 bytes */

/* ------------------------------------------------------------------ */
/* kXR_query (3001)                                                     */
/* ------------------------------------------------------------------ */

/*
 * Query type codes (infotype field in ClientQueryRequest).
 * Source: XProtocol.hh enum XQueryType (kXR_Q* constants).
 * These are the values that xrdcp v5 and the XRootD Python client send.
 */
#define kXR_QStats      1   /* server statistics (text)                  */
#define kXR_QPrep       2   /* prepare queue status                      */
#define kXR_Qcksum      3   /* compute file checksum by path or handle   */
#define kXR_Qxattr      4   /* extended attributes                       */
#define kXR_Qspace      5   /* storage space information (oss.* text)    */
#define kXR_Qckscan     6   /* checksum cancel / scan                    */
#define kXR_Qconfig     7   /* server configuration items (text)         */
#define kXR_Qvisa       8   /* visa string                               */
#define kXR_QFinfo      9   /* file information                          */
#define kXR_QFSinfo    10   /* filesystem information                    */
#define kXR_Qopaque    16   /* opaque string (path-attached)             */
#define kXR_Qopaquf    32   /* opaque string (file-attached)             */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;   /* kXR_query */
    kXR_unt16  infotype;    /* one of kXR_Q* above                       */
    kXR_char   reserved1[2];
    /* Handle is used for handle-based queries; otherwise dlen supplies a path. */
    kXR_char   fhandle[4];  /* open file handle (for handle-based queries) */
    kXR_char   reserved2[8];
    kXR_int32  dlen;        /* path length (0 for handle-based queries)  */
    /* null-terminated path follows as payload when dlen > 0             */
} ClientQueryRequest;       /* 24 bytes */

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
    /* errmsg is variable-length storage beginning here, including the trailing NUL. */
    char       errmsg[1];      /* null-terminated, variable length */
} ServerErrorBody;

/* ------------------------------------------------------------------ */
/* Redirect response body                                               */
/* ------------------------------------------------------------------ */

typedef struct {
    kXR_int32  port;
    /* host bytes start here and continue until the terminating NUL. */
    char       host[1];        /* null-terminated hostname */
} ServerRedirectBody;

/* ------------------------------------------------------------------ */
/* kXR_pgread (3030) — paged read with per-page CRC32c checksums       */
/* ------------------------------------------------------------------ */

#define kXR_pgPageSZ    4096
#define kXR_pgPageBL    12
#define kXR_pgUnitSZ    (kXR_pgPageSZ + 4)
#define kXR_pgRetry     0x01
#define kXR_AnyPath     0xff

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;      /* kXR_pgread */
    kXR_char   fhandle[4];
    kXR_int64  offset;
    kXR_int32  rlen;
    kXR_int32  dlen;           /* 0, 1 (pathid), or 2 (pathid+reqflags) */
} ClientPgReadRequest;         /* 24 bytes */

typedef struct {
    kXR_char   pathid;         /* kXR_AnyPath = 0xff = server chooses */
    kXR_char   reqflags;       /* kXR_pgRetry = 0x01 */
} ClientPgReadReqArgs;

typedef struct {
    kXR_int64  offset;         /* file offset of first byte of returned data */
} ServerResponseBody_pgRead;   /* 8 bytes */

typedef struct {
    ServerResponseHdr          hdr;
    ServerResponseBody_Status  bdy;
    ServerResponseBody_pgRead  pgr;
} ServerStatusResponse_pgRead; /* 32 bytes; interleaved data+crc follows */

/* ------------------------------------------------------------------ */
/* kXR_writev (3031) — scatter-gather / vector write                   */
/* ------------------------------------------------------------------ */

#define kXR_wv_doSync       0x01
#define XROOTD_WRITEV_SEGSIZE   16      /* sizeof(write_list)          */
#define XROOTD_WRITEV_MAXSEGS   1024    /* XrdProto::maxWvecsz         */

typedef struct {
    kXR_char   fhandle[4];
    kXR_int32  wlen;
    kXR_int64  offset;
} write_list;                  /* 16 bytes; network byte order */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;      /* kXR_writev */
    kXR_char   options;        /* kXR_wv_doSync = 0x01 */
    kXR_char   reserved[15];
    kXR_int32  dlen;
} ClientWriteVRequest;         /* 24 bytes */

/* ------------------------------------------------------------------ */
/* kXR_locate (3027) — file replica location query                     */
/* ------------------------------------------------------------------ */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;      /* kXR_locate */
    kXR_unt16  options;        /* kXR_refresh, kXR_compress, ... */
    kXR_char   reserved[14];
    kXR_int32  dlen;
} ClientLocateRequest;         /* 24 bytes */

/* Response body: space-separated "XY<host:port>" tokens, NUL-terminated.
 * X = S (server online) | M (manager) | s/m (pending)
 * Y = r (read-only) | w (read-write) */

/* ------------------------------------------------------------------ */
/* kXR_sigver (3029) — request signing verification                    */
/* ------------------------------------------------------------------ */

#define kXR_SHA256_sig   0x01
#define kXR_HashMask_sig 0x0f
#define kXR_rsaKey_sig   0x80
#define kXR_nodata_sig   0x01   /* payload was not hashed */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;      /* kXR_sigver */
    kXR_unt16  expectrid;      /* opcode of the NEXT (signed) request */
    kXR_char   version;        /* kXR_Ver_00 = 0 */
    kXR_char   flags;          /* kXR_nodata_sig = 0x01 */
    kXR_unt64  seqno;          /* monotonically increasing sequence number */
    kXR_char   crypto;         /* kXR_SHA256_sig | kXR_rsaKey_sig */
    kXR_char   rsvd2[3];
    kXR_int32  dlen;
} ClientSigverRequest;         /* 24 bytes */

/* ------------------------------------------------------------------ */
/* kXR_statx (3022) — multi-path stat                                  */
/* ------------------------------------------------------------------ */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;      /* kXR_statx */
    kXR_char   options;        /* kXR_vfs or 0 */
    kXR_char   reserved[11];
    kXR_char   fhandle[4];
    kXR_int32  dlen;
} ClientStatxRequest;          /* 24 bytes */

/* Response body: NUL-separated stat lines; one line per path:
 *   "<id> <size> <flags> <mtime>\n"  (last entry ends with \0) */

/* ------------------------------------------------------------------ */
/* kXR_fattr (3020) — file extended attributes                         */
/* ------------------------------------------------------------------ */

/* Subcodes (subcode field) */
#define kXR_fattrDel    0   /* delete named attributes                   */
#define kXR_fattrGet    1   /* retrieve named attributes                 */
#define kXR_fattrList   2   /* enumerate all attributes                  */
#define kXR_fattrSet    3   /* write named attributes                    */
#define kXR_fattrMaxSC  3   /* highest valid subcode                     */

/* Limits */
#define kXR_faMaxVars   16      /* max attributes per request            */
#define kXR_faMaxNlen   248     /* max attribute name length             */
#define kXR_faMaxVlen   65536   /* max attribute value length            */

/* Options field bits */
#define kXR_fa_isNew    0x01    /* set: attribute must not already exist */
#define kXR_fa_aData    0x10    /* list: include attribute values        */

typedef struct {
    kXR_char   streamid[2];
    kXR_unt16  requestid;   /* kXR_fattr */
    kXR_char   fhandle[4];  /* open file handle (0 if path-based)        */
    kXR_char   subcode;     /* one of kXR_fattrDel/Get/List/Set above    */
    kXR_char   numattr;     /* number of attributes in request (0 for list) */
    kXR_char   options;     /* kXR_fa_isNew | kXR_fa_aData               */
    kXR_char   reserved[9];
    kXR_int32  dlen;
    /*
     * Payload layout for path-based (payload[0] != 0):
     *   [path\0][nvec][vvec]
     *
     * Payload layout for handle-based (payload[0] == 0 or dlen == 0):
     *   [0x00][nvec][vvec]   or   (empty for list with dlen=0)
     *
     * nvec entry: [kXR_unt16 = 0x0000][name\0]   (numattr entries)
     * vvec entry: [kXR_int32 vlen BE][value]      (numattr entries, set only)
     */
} ClientFattrRequest;    /* 24 bytes */

#pragma pack(pop)

/* ================================================================== */
/*  GSI (x509) Authentication Wire Constants                           */
/*  Source: xrootd/xrootd src/XrdSecgsi/XrdSecProtocolgsi.hh          */
/*          and src/XrdSut/XrdSutBuffer.hh                             */
/* ================================================================== */

/*
 * GSI handshake step numbers.
 * Server sends steps in the kXGS_* range; client in kXGC_* range.
 * Steps are carried as the first 4-byte big-endian field in every
 * XrdSutBuffer after the null-terminated protocol name ("gsi\0").
 */
#define kXGS_init       2000    /* server → client: initial exchange    */
#define kXGS_cert       2001    /* server → client: server cert + DH    */
#define kXGS_pxyreq     2002    /* server → client: proxy request       */
#define kXGC_certreq    1000    /* client → server: cert request        */
#define kXGC_cert       1001    /* client → server: client cert + DH    */
#define kXGC_sigpxy     1002    /* client → server: signed proxy        */

/*
 * XrdSutBucket type codes (kXRS_*).
 * Every bucket on the wire is [type:4B BE][len:4B BE][data:len].
 * A bucket with type=kXRS_none signals end-of-message.
 * Parsing therefore runs as a length-delimited loop until the terminator is
 * seen or the enclosing auth payload is exhausted.
 */
#define kXRS_none           0       /* terminator bucket                 */
#define kXRS_inactive       1       /* skipped during serialisation      */
#define kXRS_cryptomod   3000       /* crypto module name ("ssl")        */
#define kXRS_main        3001       /* inner/encrypted main buffer       */
#define kXRS_puk         3004       /* server DH public key blob         */
#define kXRS_cipher      3005       /* DH public params / ciphertext     */
#define kXRS_rtag        3006       /* random challenge tag              */
#define kXRS_signed_rtag 3007       /* signed random tag                 */
#define kXRS_user        3008       /* username string                   */
#define kXRS_version     3014       /* protocol version (int32)          */
#define kXRS_clnt_opts   3019       /* client option flags (int32)       */
#define kXRS_x509        3022       /* X.509 certificate (PEM text)      */
#define kXRS_issuer_hash 3023       /* CA subject name hash (uint32)     */
#define kXRS_cipher_alg  3025       /* supported cipher algorithms       */
#define kXRS_md_alg      3026       /* supported digest algorithms       */

/*
 * GSI protocol version sent in kXRS_version bucket.
 * 20100 = 2.01.00
 */
#define kXGSI_VERSION    20100

#endif /* XROOTD_PROTOCOL_H */
