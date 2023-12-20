#include "cts_client.h"
#include <libubox/uloop.h>
#include <mosquitto.h>
#include <stdio.h>

cts_client_t cc;

static void on_connect(struct mosquitto *mosq, void *obj, int rc) {
    if (rc) {
        printf("Error with result code: %d\n", rc);
        // 处理连接失败的情况
    } else {
        printf("Connected to MQTT broker\n");
        // 连接成功后的操作，例如订阅主题等
    }
}

static void on_message(struct mosquitto *mosq, void *obj, const struct mosquitto_message *msg) {
    if (msg->payload) {
        printf("Received message on topic %s: %s\n", msg->topic, (char *)msg->payload);
    }
}

void mosquitto_fd_handler(struct uloop_fd *u, unsigned int events) {
    int fd = mosquitto_socket(cc.mosq);
    if (fd == -1) return;

    // 调用 mosquitto_loop 来处理事件
    mosquitto_loop_read(cc.mosq, 1);
    mosquitto_loop_write(cc.mosq, 1);
    mosquitto_loop_misc(cc.mosq);
}

static void cc_connect()
{
    int fd = 0;
    uloop_timeout_cancel(&cc.connect_timer);

    cc.mosq = mosquitto_new(NULL, true, NULL);
    if (!cc.mosq) {
        printf("Error: Out of memeory.\n");
        return;
    }

    mosquitto_connect_callback_set(cc.mosq, on_connect);
    mosquitto_message_callback_set(cc.mosq, on_message);

    if (mosquitto_connect(cc.mosq, "111.111.111.111", 18080, 30)) {
        printf("Unable to connect\n");
        return;
    }

    if ((fd = mosquitto_socket(cc.mosq)) >= 0) {
        cc.mosquitto_ufd.fd = fd;
        cc.mosquitto_ufd.cb = mosquitto_fd_handler;
        uloop_fd_add(&cc.mosquitto_ufd, ULOOP_READ | ULOOP_WRITE);
    }
}

static void connect_cb(struct uloop_timeout* timeout)
{
    cc_connect();
}

void cc_init()
{
    if (mosquitto_lib_init() < 0) { printf("mosquitto lib init failed\n"); }

    cc.connect_timer.cb = connect_cb;
}

void cc_run()
{
    cc_connect();
}

void cc_done()
{
    mosquitto_disconnect(cc.mosq);
    mosquitto_destroy(cc.mosq);
    mosquitto_lib_cleanup();
}