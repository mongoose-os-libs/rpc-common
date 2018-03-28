/*
 * Copyright (c) 2014-2016 Cesanta Software Limited
 * All rights reserved
 */

#ifndef CS_FW_SRC_MGOS_MG_RPC_H_
#define CS_FW_SRC_MGOS_MG_RPC_H_

#include "mg_rpc.h"
#include "mg_rpc_channel_ws.h"

#include "frozen.h"

#include "mgos_event.h"
#include "mgos_features.h"
#include "mgos_init.h"
#include "mgos_sys_config.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

bool mgos_rpc_common_init(void);
struct mg_rpc *mgos_rpc_get_global(void);
struct mg_rpc_cfg *mgos_rpc_cfg_from_sys(const struct mgos_config *scfg);
void mgos_rpc_channel_ws_out_cfg_from_sys(
    const struct mgos_config *scfg, struct mg_rpc_channel_ws_out_cfg *chcfg);

/* FFI-able signature of the function that receives RPC request */
typedef void (*mgos_rpc_eh_t)(struct mg_rpc_request_info *ri, const char *args,
                              const char *src, void *user_data);

/* FFI-able signature of the function that receives response to a request. */
typedef void (*mgos_rpc_result_cb_t)(const char *result, int error_code,
                                     const char *error_msg, void *cb_arg);

/*
 * FFI-able function to add an RPC handler
 */
void mgos_rpc_add_handler(const char *method, mgos_rpc_eh_t cb, void *cb_arg);

/* FFI-able function to send response from an RPC handler */
bool mgos_rpc_send_response(struct mg_rpc_request_info *ri,
                            const char *response_json);

/* FFI-able function to perform an RPC call */
bool mgos_rpc_call(const char *dst, const char *method, const char *args_json,
                   mgos_rpc_result_cb_t cb, void *cb_arg);

/* Print system info JSON object. Return number of bytes written. */
int mgos_print_sys_info(struct json_out *out);

/* RPC events */
#define MGOS_RPC_EVENT_BASE MGOS_EVENT_BASE('R', 'P', 'C')

/* In the comment, the type of `void *ev_data` is specified */
enum mgos_rpc_event {
  MGOS_RPC_EV_CHANNEL_OPEN = MGOS_RPC_EVENT_BASE, /* struct mg_str *dst */
  MGOS_RPC_EV_CHANNEL_CLOSED,                     /* struct mg_str *dst */
};

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* CS_FW_SRC_MGOS_MG_RPC_H_ */
