#ifndef CTS_CLIENT_H
#define CTS_CLIENT_H

#include "cts.h"
#include <stdint.h>
#define _GUN_SOURCE

#include <libubox/uloop.h>
#include <mosquitto.h>

#define PCAP_ERRBUF_SIZE 1024;
#define MAX_DNS_REQUESTS 20
#define MAX_LINE_LEN     1024
#define CONFIG_PATH      "../conf/ini.conf"
#define CER_PATH         "../conf/zxykey.cer"
#define DEFAULT_ADDR     "101.227.231.138"
#define DEFAULT_PORT     "18080"

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

#define MAC_ARG(p) p[0], p[1], p[2], p[3], p[4], p[5]
#define IP_ARG(p)  p[0], p[1], p[2], p[3]

typedef struct cts_client {
    char                 addr[64];
    char                 port[8];
    int                  retry_num;
    struct mosquitto    *mosq;
    struct uloop_fd      mosquitto_ufd;
    struct uloop_timeout connect_timer;
    cts_result_t         result;
} cts_client_t;

struct dnshdr {
    uint16_t id; // Identification number
    // Flags
    u_char rd    :1; // Recursion Desired
    u_char tc    :1; // Truncated Message
    u_char aa    :1; // Authoritative Answer
    u_char opcode:4; // Purpose of message
    u_char qr    :1; // Query/Response flag

    u_char rcode:4; // Response code
    u_char cd   :1; // Checking Disabled
    u_char ad   :1; // Authenticated Data
    u_char z    :1; // Reserved
    u_char ra   :1; // Recursion Available

    uint16_t q_count;    // Number of question entries
    uint16_t ans_count;  // Number of answer entries
    uint16_t auth_count; // Number of authority entries
    uint16_t add_count;  // Number of resource entries
};

struct dnsq {
    uint16_t qclass;
    uint16_t qtype;
};

struct dnsr {
    u_char      *name;     // 域名
    uint16_t     type;     // 类型（例如，A, MX, CNAME）
    uint16_t     Class;    // 类
    unsigned int ttl;      // 生存时间
    uint16_t     data_len; // 数据长度
    u_char      *rdata;    // 资源数据
};

typedef struct {
    char   dns_request[256];
    time_t timestamp;
} DNS_request;

extern cts_client_t cc;

void cc_init();
void cc_run();
void cc_done();

#endif