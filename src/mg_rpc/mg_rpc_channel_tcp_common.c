/*
 * Copyright (c) 2014-2017 Cesanta Software Limited
 * All rights reserved
 */

#include "mg_rpc_channel_tcp_common.h"

char *mg_rpc_channel_tcp_get_info(struct mg_connection *c) {
  char buf[100] = {0}, *s = NULL;
  if (c != NULL) {
    int flags = MG_SOCK_STRINGIFY_IP | MG_SOCK_STRINGIFY_REMOTE;
    mg_conn_addr_to_str(c, buf, sizeof(buf), flags);
    s = strdup(buf);
  }
  return s;
}
