#ifndef NGX_XROOTD_CMS_HEARTBEAT_H
#define NGX_XROOTD_CMS_HEARTBEAT_H

#include "ngx_xrootd_module.h"

void ngx_xrootd_cms_start(ngx_cycle_t *cycle,
    ngx_stream_xrootd_srv_conf_t *conf);

#endif /* NGX_XROOTD_CMS_HEARTBEAT_H */
