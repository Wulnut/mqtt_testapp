#ifndef CTS_CLIENT_H
#define CTS_CLIENT_H

#include "cts.h"
#define _GUN_SOURCE

#include "cJSON.h"
#include <libubox/uloop.h>
#include <mosquitto.h>

#define MAX_LINE_LEN 1024
#define CONFIG_PATH  "../conf/ini.conf"
#define CER_PATH     "../conf/zxykey.cer"
#define DEFAULT_ADDR "101.227.231.138"
#define DEFAULT_PORT "18080"

#define TEST 0

#define GET_PARAM(param, json, name, t)                            \
    cJSON *param = cJSON_GetObjectItem(json, name);                \
    if (param == NULL) {                                           \
        set_err(RESULT_EXECUTE_FAILED, "'%s' not found\n", name);  \
        goto done;                                                 \
    }                                                              \
    if ((param->type & 0xFF) != t) {                               \
        set_err(RESULT_EXECUTE_FAILED, "'%s' type worng\n", name); \
        goto done;                                                 \
    }

#define set_err(r, fmt, ...)          \
    do {                              \
        cc.result = r;                \
        ULOG_ERR(fmt, ##__VA_ARGS__); \
    } while (0)

typedef struct cts_client {
    char                 addr[64];
    char                 port[8];
    int                  retry_num;
    struct mosquitto    *mosq;
    struct uloop_fd      mosquitto_ufd;
    struct uloop_timeout connect_timer;
    cts_result_t         result;
} cts_client_t;

extern cts_client_t cc;

void cc_init();
void cc_run();
void cc_done();

#endif