#ifndef CTS_CLIENT_H
#define CTS_CLIENT_H

#include <libubox/uloop.h>
#include <mosquitto.h>

typedef struct cts_client
{
    int                  retry_num;
    struct mosquitto*    mosq;
    struct uloop_fd      mosquitto_ufd;
    struct uloop_timeout connect_timer;
} cts_client_t;

void cc_init();
void cc_run();
void cc_done();

#endif