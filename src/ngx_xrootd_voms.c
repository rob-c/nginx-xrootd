/*
 * ngx_xrootd_voms.c
 *
 * Runtime VOMS support via dlopen(3).
 *
 * Loads libvomsapi.so.1 at startup and resolves the handful of C API
 * symbols we need (VOMS_Init, VOMS_Retrieve, VOMS_Destroy, …).
 * If the library is absent the module still starts; VO-based access
 * control simply becomes unavailable.
 *
 * Target: EL9 / voms-2.1.3 (libvomsapi.so.1).  The struct layouts
 * below are ABI-compatible with that release.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#include <dlfcn.h>
#include <string.h>
#include <limits.h>

#include <openssl/x509.h>

#include "ngx_xrootd_module.h"

/* ------------------------------------------------------------------ */
/*  ABI-compatible struct definitions (voms-2.1.3 / EL9)              */
/* ------------------------------------------------------------------ */

/*
 * Only the fields we dereference are given meaningful types; the rest
 * are void* placeholders so the byte offsets stay correct.
 */

struct voms_data_item {
    char *group;
    char *role;
    char *cap;
};

struct voms_entry {
    int    siglen;
    char  *signature;
    char  *user;
    char  *userca;
    char  *server;
    char  *serverca;
    char  *voname;          /* VO name — the field we need                 */
    char  *uri;
    char  *date1;
    char  *date2;
    int    type;
    struct voms_data_item **std;
    char  *custom;
    int    datalen;
    int    version;
    char **fqan;            /* FQANs — the other field we need             */
    char  *serial;
    /* remaining (AC *ac, X509 *holder) are opaque to us */
    void  *ac;
    void  *holder;
};

struct voms_data {
    char  *cdir;
    char  *vdir;
    struct voms_entry **data;   /* NULL-terminated array of results */
    char  *workvo;
    char  *extra_data;
    int    volen;
    int    extralen;
    void  *real;
};

/* Error codes from voms_apic.h */
#define VOMS_VERR_NOEXT   5
#define VOMS_VERR_NODATA  11

/* Retrieval mode */
#define VOMS_RECURSE_CHAIN 0

/* ------------------------------------------------------------------ */
/*  Function-pointer typedefs                                         */
/* ------------------------------------------------------------------ */

typedef struct voms_data *(*fn_VOMS_Init_t)(char *voms, char *cert);
typedef int  (*fn_VOMS_Retrieve_t)(X509 *cert, STACK_OF(X509) *chain,
                                    int how, struct voms_data *vd, int *error);
typedef void (*fn_VOMS_Destroy_t)(struct voms_data *vd);
typedef char *(*fn_VOMS_ErrorMessage_t)(struct voms_data *vd, int error,
                                         char *buf, int len);

/* ------------------------------------------------------------------ */
/*  Module-level state (set once, read-only afterwards)               */
/* ------------------------------------------------------------------ */

static void                   *voms_handle;    /* dlopen handle      */
static fn_VOMS_Init_t          p_VOMS_Init;
static fn_VOMS_Retrieve_t      p_VOMS_Retrieve;
static fn_VOMS_Destroy_t       p_VOMS_Destroy;
static fn_VOMS_ErrorMessage_t  p_VOMS_ErrorMessage;

static ngx_flag_t              voms_loaded;    /* 1 once dlopen OK   */


/* ------------------------------------------------------------------ */
/*  Public query: is libvomsapi available?                            */
/* ------------------------------------------------------------------ */

ngx_flag_t
xrootd_voms_available(void)
{
    return voms_loaded;
}


/* ------------------------------------------------------------------ */
/*  Initialisation: dlopen + dlsym                                    */
/* ------------------------------------------------------------------ */

ngx_int_t
xrootd_voms_init(ngx_log_t *log)
{
    if (voms_loaded) {
        return NGX_OK;
    }

    voms_handle = dlopen("libvomsapi.so.1", RTLD_NOW | RTLD_LOCAL);
    if (voms_handle == NULL) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0,
                      "xrootd: libvomsapi.so.1 not found (%s) — "
                      "VOMS VO ACL enforcement disabled",
                      dlerror());
        return NGX_DECLINED;
    }

    /* Clear any prior dlerror */
    (void) dlerror();

#define LOAD_SYM(ptr, name)                                            \
    do {                                                               \
        *(void **) (&(ptr)) = dlsym(voms_handle, #name);              \
        if ((ptr) == NULL) {                                           \
            ngx_log_error(NGX_LOG_ERR, log, 0,                        \
                          "xrootd: dlsym(%s) failed: %s",             \
                          #name, dlerror());                           \
            dlclose(voms_handle);                                      \
            voms_handle = NULL;                                        \
            return NGX_ERROR;                                          \
        }                                                              \
    } while (0)

    LOAD_SYM(p_VOMS_Init,         VOMS_Init);
    LOAD_SYM(p_VOMS_Retrieve,     VOMS_Retrieve);
    LOAD_SYM(p_VOMS_Destroy,      VOMS_Destroy);
    LOAD_SYM(p_VOMS_ErrorMessage, VOMS_ErrorMessage);

#undef LOAD_SYM

    voms_loaded = 1;

    ngx_log_error(NGX_LOG_NOTICE, log, 0,
                  "xrootd: libvomsapi.so.1 loaded — "
                  "VOMS VO ACL enforcement available");
    return NGX_OK;
}


/* ------------------------------------------------------------------ */
/*  Internal helpers (moved from ngx_xrootd_path.c)                   */
/* ------------------------------------------------------------------ */

static ngx_flag_t
xrootd_append_vo_token(char *primary_vo, size_t primary_vo_sz,
                       char *vo_list, size_t vo_list_sz, const char *vo)
{
    size_t list_len;
    size_t vo_len;

    if (vo == NULL || vo[0] == '\0') {
        return 1;
    }

    if (xrootd_vo_list_contains(vo_list, vo)) {
        return 1;
    }

    vo_len = strlen(vo);
    list_len = strlen(vo_list);

    if (list_len == 0) {
        if (vo_len + 1 > vo_list_sz || vo_len + 1 > primary_vo_sz) {
            return 0;
        }

        ngx_cpystrn((u_char *) vo_list, (u_char *) vo, vo_list_sz);
        ngx_cpystrn((u_char *) primary_vo, (u_char *) vo, primary_vo_sz);
        return 1;
    }

    if (list_len + 1 + vo_len + 1 > vo_list_sz) {
        return 0;
    }

    vo_list[list_len++] = ',';
    ngx_memcpy(vo_list + list_len, vo, vo_len);
    vo_list[list_len + vo_len] = '\0';
    return 1;
}


static ngx_flag_t
xrootd_fqan_to_vo(const char *fqan, char *vo, size_t vo_sz)
{
    const char *start;
    const char *end;
    size_t      len;

    if (fqan == NULL || fqan[0] != '/') {
        return 0;
    }

    start = fqan + 1;
    end = strchr(start, '/');
    if (end == NULL || end == start) {
        return 0;
    }

    len = (size_t) (end - start);
    if (len + 1 > vo_sz) {
        return 0;
    }

    ngx_memcpy(vo, start, len);
    vo[len] = '\0';
    return 1;
}


/*
 * Iterate the VOMS API result and collect VO names into primary_vo/vo_list.
 */
static ngx_int_t
xrootd_collect_voms_vos(struct voms_data *vd,
                        char *primary_vo, size_t primary_vo_sz,
                        char *vo_list, size_t vo_list_sz)
{
    struct voms_entry **entry;

    if (vd->data == NULL) {
        return NGX_DECLINED;
    }

    for (entry = vd->data; *entry != NULL; entry++) {
        char **fqan;
        char   derived_vo[128];

        if ((*entry)->voname != NULL && (*entry)->voname[0] != '\0') {
            if (!xrootd_append_vo_token(primary_vo, primary_vo_sz,
                                        vo_list, vo_list_sz,
                                        (*entry)->voname)) {
                return NGX_ERROR;
            }
        }

        if ((*entry)->fqan == NULL) {
            continue;
        }

        for (fqan = (*entry)->fqan; *fqan != NULL; fqan++) {
            if (!xrootd_fqan_to_vo(*fqan, derived_vo, sizeof(derived_vo))) {
                continue;
            }

            if (!xrootd_append_vo_token(primary_vo, primary_vo_sz,
                                        vo_list, vo_list_sz,
                                        derived_vo)) {
                return NGX_ERROR;
            }
        }
    }

    return (vo_list != NULL && vo_list[0] != '\0') ? NGX_OK : NGX_DECLINED;
}


/* ------------------------------------------------------------------ */
/*  Public: extract VOMS VO membership from a cert chain              */
/* ------------------------------------------------------------------ */

ngx_int_t
xrootd_extract_voms_info(ngx_log_t *log, X509 *leaf, STACK_OF(X509) *chain,
                         const ngx_str_t *vomsdir, const ngx_str_t *cert_dir,
                         char *primary_vo, size_t primary_vo_sz,
                         char *vo_list, size_t vo_list_sz)
{
    struct voms_data *vd;
    STACK_OF(X509)  *voms_chain = NULL;
    char             vomsdir_buf[PATH_MAX];
    char             cert_dir_buf[PATH_MAX];
    char             errbuf[512];
    int              error = 0;
    ngx_int_t        rc = NGX_DECLINED;

    if (!voms_loaded) {
        return NGX_DECLINED;
    }

    if (leaf == NULL || vomsdir == NULL || cert_dir == NULL
        || vomsdir->len == 0 || cert_dir->len == 0)
    {
        return NGX_DECLINED;
    }

    if (vomsdir->len >= sizeof(vomsdir_buf)
        || cert_dir->len >= sizeof(cert_dir_buf))
    {
        return NGX_ERROR;
    }

    ngx_memcpy(vomsdir_buf, vomsdir->data, vomsdir->len);
    vomsdir_buf[vomsdir->len] = '\0';
    ngx_memcpy(cert_dir_buf, cert_dir->data, cert_dir->len);
    cert_dir_buf[cert_dir->len] = '\0';

    if (primary_vo != NULL && primary_vo_sz > 0) {
        primary_vo[0] = '\0';
    }
    if (vo_list != NULL && vo_list_sz > 0) {
        vo_list[0] = '\0';
    }

    vd = p_VOMS_Init(vomsdir_buf, cert_dir_buf);
    if (vd == NULL) {
        return NGX_ERROR;
    }

    if (chain != NULL && sk_X509_num(chain) > 0) {
        voms_chain = sk_X509_dup(chain);
        if (voms_chain == NULL) {
            p_VOMS_Destroy(vd);
            return NGX_ERROR;
        }

        if (sk_X509_num(voms_chain) > 0
            && X509_cmp(sk_X509_value(voms_chain, 0), leaf) == 0)
        {
            sk_X509_delete(voms_chain, 0);
        }
    }

    if (!p_VOMS_Retrieve(leaf, voms_chain, VOMS_RECURSE_CHAIN, vd, &error)) {
        if (error != VOMS_VERR_NOEXT && error != VOMS_VERR_NODATA) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "xrootd: VOMS extraction failed: %s",
                          p_VOMS_ErrorMessage(vd, error, errbuf,
                                              (int) sizeof(errbuf)));
            rc = NGX_ERROR;
        }
    } else {
        rc = xrootd_collect_voms_vos(vd, primary_vo, primary_vo_sz,
                                     vo_list, vo_list_sz);
    }

    if (voms_chain != NULL) {
        sk_X509_free(voms_chain);
    }
    p_VOMS_Destroy(vd);
    return rc;
}
