/*
 * Copyright (c) 2014-2016 Cesanta Software Limited
 * All rights reserved
 */

#include "mgos_rpc.h"

#include "mg_rpc_channel_http.h"
#include "mg_rpc_channel_ws.h"

#include "mgos_config.h"
#include "mgos_debug.h"
#include "mgos_debug_hal.h"
#include "mgos_hal.h"
#if defined(MGOS_HAVE_HTTP_SERVER) && MGOS_ENABLE_RPC_CHANNEL_HTTP
#include "mgos_http_server.h"
#endif
#include "mgos_mongoose.h"
#include "mgos_net.h"
#include "mgos_sys_config.h"
#include "mgos_utils.h"
#include "mgos_timers.h"
#ifdef MGOS_HAVE_WIFI
#include "mgos_wifi.h"
#endif

#define HTTP_URI_PREFIX "/rpc"

static struct mg_rpc *s_global_mg_rpc;

void mg_rpc_net_ready(enum mgos_net_event ev,
                      const struct mgos_net_event_data *ev_data, void *arg) {
  if (ev != MGOS_NET_EV_IP_ACQUIRED) return;
  struct mg_rpc_channel *ch = (struct mg_rpc_channel *) arg;
  ch->ch_connect(ch);
  (void) ev_data;
}

struct mg_rpc_cfg *mgos_rpc_cfg_from_sys(const struct sys_config *scfg) {
  struct mg_rpc_cfg *ccfg = (struct mg_rpc_cfg *) calloc(1, sizeof(*ccfg));
  mgos_conf_set_str(&ccfg->id, scfg->device.id);
  mgos_conf_set_str(&ccfg->psk, scfg->device.password);
  ccfg->max_queue_length = scfg->rpc.max_queue_length;
  ccfg->default_out_channel_idle_close_timeout =
      scfg->rpc.default_out_channel_idle_close_timeout;
  return ccfg;
}

#if defined(MGOS_HAVE_HTTP_SERVER) && MGOS_ENABLE_RPC_CHANNEL_HTTP
static void mgos_rpc_http_handler(struct mg_connection *nc, int ev,
                                  void *ev_data, void *user_data) {
  if (ev == MG_EV_HTTP_REQUEST) {
    /* Create and add the channel to mg_rpc */
    struct mg_rpc_channel *ch = mg_rpc_channel_http(nc);
    struct http_message *hm = (struct http_message *) ev_data;
    size_t prefix_len = sizeof(HTTP_URI_PREFIX) - 1;
    mg_rpc_add_channel(mgos_rpc_get_global(), mg_mk_str(""), ch,
                       true /* is_trusted */);

    /*
     * Handle the request. If there is method name after /rpc,
     * then body is only args.
     * If there isn't, then body is entire frame.
     */
    if (hm->uri.len - prefix_len > 1) {
      struct mg_str method = mg_mk_str_n(hm->uri.p + prefix_len + 1 /* / */,
                                         hm->uri.len - prefix_len - 1);
      mg_rpc_channel_http_recd_parsed_frame(nc, ch, method, hm->body);
    } else {
      mg_rpc_channel_http_recd_frame(nc, ch, hm->body);
    }
  } else if (ev == MG_EV_WEBSOCKET_HANDSHAKE_REQUEST) {
/* Allow handshake to proceed */
#if MGOS_ENABLE_RPC_CHANNEL_WS
    if (!get_cfg()->rpc.ws.enable)
#endif
    {
      mg_http_send_error(nc, 503, "WS is disabled");
    }
#if MGOS_ENABLE_RPC_CHANNEL_WS
  } else if (ev == MG_EV_WEBSOCKET_HANDSHAKE_DONE) {
    struct mg_rpc_channel *ch = mg_rpc_channel_ws_in(nc);
    mg_rpc_add_channel(mgos_rpc_get_global(), mg_mk_str(""), ch,
                       true /* is_trusted */);
    ch->ev_handler(ch, MG_RPC_CHANNEL_OPEN, NULL);
#endif
  }

  (void) user_data;
}
#endif /* defined(MGOS_HAVE_HTTP_SERVER) && MGOS_ENABLE_RPC_CHANNEL_HTTP */

#if MGOS_ENABLE_SYS_SERVICE
static void mgos_sys_reboot_handler(struct mg_rpc_request_info *ri,
                                    void *cb_arg, struct mg_rpc_frame_info *fi,
                                    struct mg_str args) {
  if (!fi->channel_is_trusted) {
    mg_rpc_send_errorf(ri, 403, "unauthorized");
    ri = NULL;
    return;
  }
  int delay_ms = 100;
  json_scanf(args.p, args.len, ri->args_fmt, &delay_ms);
  if (delay_ms < 0) {
    mg_rpc_send_errorf(ri, 400, "invalid delay value");
    ri = NULL;
    return;
  }
  mgos_system_restart_after(delay_ms);
  mg_rpc_send_responsef(ri, NULL);
  ri = NULL;
  (void) cb_arg;
}

static void mgos_sys_get_info_handler(struct mg_rpc_request_info *ri,
                                      void *cb_arg,
                                      struct mg_rpc_frame_info *fi,
                                      struct mg_str args) {
  if (!fi->channel_is_trusted) {
    mg_rpc_send_errorf(ri, 403, "unauthorized");
    ri = NULL;
    return;
  }

  const struct sys_ro_vars *v = get_ro_vars();
  struct mgos_net_ip_info ip_info;
  memset(&ip_info, 0, sizeof(ip_info));
#ifdef MGOS_HAVE_WIFI
  char *status = mgos_wifi_get_status_str();
  char *ssid = mgos_wifi_get_connected_ssid();
  char sta_ip[16], ap_ip[16];
  memset(sta_ip, 0, sizeof(sta_ip));
  memset(ap_ip, 0, sizeof(ap_ip));
  if (mgos_net_get_ip_info(MGOS_NET_IF_TYPE_WIFI, MGOS_NET_IF_WIFI_STA,
                           &ip_info)) {
    mgos_net_ip_to_str(&ip_info.ip, sta_ip);
  }
  if (mgos_net_get_ip_info(MGOS_NET_IF_TYPE_WIFI, MGOS_NET_IF_WIFI_AP,
                           &ip_info)) {
    mgos_net_ip_to_str(&ip_info.ip, ap_ip);
  }
#endif
#ifdef MGOS_HAVE_ETHERNET
  char eth_ip[16];
  memset(eth_ip, 0, sizeof(eth_ip));
  if (mgos_net_get_ip_info(MGOS_NET_IF_TYPE_ETHERNET, 0, &ip_info)) {
    mgos_net_ip_to_str(&ip_info.ip, eth_ip);
  }
#endif
  (void) ip_info;

  mg_rpc_send_responsef(
      ri,
      "{app: %Q, fw_version: %Q, fw_id: %Q, mac: %Q, "
      "arch: %Q, uptime: %lu, "
      "ram_size: %u, ram_free: %u, ram_min_free: %u, "
      "fs_size: %u, fs_free: %u"
#ifdef MGOS_HAVE_WIFI
      ",wifi: {sta_ip: %Q, ap_ip: %Q, status: %Q, ssid: %Q}"
#endif
#ifdef MGOS_HAVE_ETHERNET
      ",eth: {ip: %Q}"
#endif
      "}",
      MGOS_APP, v->fw_version, v->fw_id, v->mac_address, v->arch,
      (unsigned long) mgos_uptime(), mgos_get_heap_size(),
      mgos_get_free_heap_size(), mgos_get_min_free_heap_size(),
      mgos_get_fs_size(), mgos_get_free_fs_size()
#ifdef MGOS_HAVE_WIFI
                              ,
      sta_ip, ap_ip, status == NULL ? "" : status, ssid == NULL ? "" : ssid
#endif
#ifdef MGOS_HAVE_ETHERNET
      ,
      eth_ip
#endif
      );

#ifdef MGOS_HAVE_WIFI
  free(ssid);
  free(status);
#endif

  (void) cb_arg;
  (void) args;
  (void) fi;
}

static void mgos_sys_set_debug_handler(struct mg_rpc_request_info *ri,
                                       void *cb_arg,
                                       struct mg_rpc_frame_info *fi,
                                       struct mg_str args) {
  char *udp_log_addr = NULL, *filter = NULL;
  int error_code = 0, level = _LL_MIN;
  const char *error_msg = NULL;

  if (!fi->channel_is_trusted) {
    mg_rpc_send_errorf(ri, 403, "unauthorized");
    ri = NULL;
    return;
  }

  json_scanf(args.p, args.len, ri->args_fmt, &udp_log_addr, &level, &filter);

#if MGOS_ENABLE_DEBUG_UDP
  if (udp_log_addr != NULL &&
      mgos_debug_udp_init(udp_log_addr) != MGOS_INIT_OK) {
    error_code = 400;
    error_msg = "invalid udp_log_addr";
  }
#else
  if (udp_log_addr != NULL) {
    error_code = 501;
    error_msg = "MGOS_ENABLE_DEBUG_UDP is not enabled";
  }
#endif

  if (filter != NULL) {
    cs_log_set_filter(filter);
  }

  if (level > _LL_MIN && level < _LL_MAX) {
    cs_log_set_level((enum cs_log_level) level);
  } else if (level != _LL_MIN) {
    error_code = 400;
    error_msg = "invalid level";
  }

  mg_rpc_send_errorf(ri, error_code, error_msg);
  free(udp_log_addr);
  free(filter);

  (void) cb_arg;
  (void) args;
  (void) fi;
}
#endif

bool mgos_rpc_common_init(void) {
  const struct sys_config_rpc *sccfg = &get_cfg()->rpc;
  if (!sccfg->enable) return true;
  struct mg_rpc_cfg *ccfg = mgos_rpc_cfg_from_sys(get_cfg());
  struct mg_rpc *c = mg_rpc_create(ccfg);

#if MGOS_ENABLE_RPC_CHANNEL_WS
  if (sccfg->ws.server_address != NULL && sccfg->ws.enable) {
    struct mg_rpc_channel_ws_out_cfg chcfg;
    mgos_rpc_channel_ws_out_cfg_from_sys(get_cfg(), &chcfg);
    struct mg_rpc_channel *ch = mg_rpc_channel_ws_out(mgos_get_mgr(), &chcfg);
    if (ch == NULL) {
      return false;
    }
    mg_rpc_add_channel(c, mg_mk_str(MG_RPC_DST_DEFAULT), ch,
                       false /* is_trusted */);
    mgos_net_add_event_handler(mg_rpc_net_ready, ch);
  }
#endif /* MGOS_ENABLE_RPC_CHANNEL_WS */

#if defined(MGOS_HAVE_HTTP_SERVER) && MGOS_ENABLE_RPC_CHANNEL_HTTP
  mgos_register_http_endpoint(HTTP_URI_PREFIX, mgos_rpc_http_handler, NULL);
#endif

  mg_rpc_add_list_handler(c);
  s_global_mg_rpc = c;

#if MGOS_ENABLE_SYS_SERVICE
  mg_rpc_add_handler(c, "Sys.Reboot", "{delay_ms: %d}", mgos_sys_reboot_handler,
                     NULL);
  mg_rpc_add_handler(c, "Sys.GetInfo", "", mgos_sys_get_info_handler, NULL);
  mg_rpc_add_handler(c, "Sys.SetDebug",
                     "{udp_log_addr: %Q, level: %d, filter:%Q}",
                     mgos_sys_set_debug_handler, NULL);
#endif

  return true;
}

#if MGOS_ENABLE_RPC_CHANNEL_WS
void mgos_rpc_channel_ws_out_cfg_from_sys(
    const struct sys_config *cfg, struct mg_rpc_channel_ws_out_cfg *chcfg) {
  const struct sys_config_rpc_ws *wscfg = &cfg->rpc.ws;
  chcfg->server_address = mg_mk_str(wscfg->server_address);
#if MG_ENABLE_SSL
  chcfg->ssl_ca_file = mg_mk_str(wscfg->ssl_ca_file);
  chcfg->ssl_client_cert_file = mg_mk_str(wscfg->ssl_client_cert_file);
  chcfg->ssl_server_name = mg_mk_str(wscfg->ssl_server_name);
#endif
  chcfg->reconnect_interval_min = wscfg->reconnect_interval_min;
  chcfg->reconnect_interval_max = wscfg->reconnect_interval_max;
}
#endif /* MGOS_ENABLE_RPC_CHANNEL_WS */

struct mg_rpc *mgos_rpc_get_global(void) {
  return s_global_mg_rpc;
};

/* Adding handlers {{{ */

/*
 * Data for the FFI-able wrapper
 */
struct mgos_rpc_req_eh_data {
  /* FFI-able callback and its user_data */
  mgos_rpc_eh_t cb;
  void *cb_arg;
};

static void mgos_rpc_req_oplya(struct mg_rpc_request_info *ri, void *cb_arg,
                               struct mg_rpc_frame_info *fi,
                               struct mg_str args) {
  struct mgos_rpc_req_eh_data *oplya_arg =
      (struct mgos_rpc_req_eh_data *) cb_arg;

  /*
   * FFI expects strings to be null-terminated, so we have to reallocate
   * `mg_str`s.
   *
   * TODO(dfrank): implement a way to ffi strings via pointer + length
   */

  char *args2 = calloc(1, args.len + 1 /* null-terminate */);
  char *src = calloc(1, ri->src.len + 1 /* null-terminate */);

  memcpy(args2, args.p, args.len);
  memcpy(src, ri->src.p, ri->src.len);

  oplya_arg->cb(ri, args2, src, oplya_arg->cb_arg);

  free(src);
  free(args2);

  (void) fi;
}

void mgos_rpc_add_handler(const char *method, mgos_rpc_eh_t cb, void *cb_arg) {
  /* NOTE: it won't be freed */
  struct mgos_rpc_req_eh_data *oplya_arg = calloc(1, sizeof(*oplya_arg));
  oplya_arg->cb = cb;
  oplya_arg->cb_arg = cb_arg;

  mg_rpc_add_handler(s_global_mg_rpc, method, "", mgos_rpc_req_oplya,
                     oplya_arg);
}

bool mgos_rpc_send_response(struct mg_rpc_request_info *ri,
                            const char *response_json) {
  return !!mg_rpc_send_responsef(ri, "%s", response_json);
}

/* }}} */

/* Calling {{{ */

/*
 * Data for the FFI-able wrapper
 */
struct mgos_rpc_call_eh_data {
  /* FFI-able callback and its user_data */
  mgos_rpc_result_cb_t cb;
  void *cb_arg;
};

static void mgos_rpc_call_oplya(struct mg_rpc *c, void *cb_arg,
                                struct mg_rpc_frame_info *fi,
                                struct mg_str result, int error_code,
                                struct mg_str error_msg) {
  struct mgos_rpc_call_eh_data *oplya_arg =
      (struct mgos_rpc_call_eh_data *) cb_arg;

  /*
   * FFI expects strings to be null-terminated, so we have to reallocate
   * `mg_str`s.
   *
   * TODO(dfrank): implement a way to ffi strings via pointer + length
   */

  char *result2 = calloc(1, result.len + 1 /* null-terminate */);
  char *error_msg2 = calloc(1, error_msg.len + 1 /* null-terminate */);

  memcpy(result2, result.p, result.len);
  memcpy(error_msg2, error_msg.p, error_msg.len);

  oplya_arg->cb(result2, error_code, error_msg2, oplya_arg->cb_arg);

  free(error_msg2);
  free(result2);

  free(oplya_arg);

  (void) c;
  (void) fi;
}

bool mgos_rpc_call(const char *dst, const char *method, const char *args_json,
                   mgos_rpc_result_cb_t cb, void *cb_arg) {
  /* It will be freed in mgos_rpc_call_oplya() */
  struct mgos_rpc_call_eh_data *oplya_arg = calloc(1, sizeof(*oplya_arg));
  oplya_arg->cb = cb;
  oplya_arg->cb_arg = cb_arg;

  struct mg_rpc_call_opts opts;
  opts.dst = mg_mk_str(dst);

  const char *fmt = (strcmp(args_json, "null") != 0 ? "%s" : NULL);

  return mg_rpc_callf(s_global_mg_rpc, mg_mk_str(method), mgos_rpc_call_oplya,
                      oplya_arg, &opts, fmt, args_json);
}

/* }}} */
