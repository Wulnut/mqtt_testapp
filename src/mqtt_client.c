#include "mqtt_client.h"
#include "cJSON.h"
#include "log.h"
#include "util.h"
#include <MQTTAsync.h>
#include <MQTTClient.h>
#include <MQTTClientPersistence.h>
#include <MQTTReasonCodes.h>
#include <alloca.h>
#include <bits/pthreadtypes.h>
#include <mosquitto.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if 1
static mqtt_info_t* mqtt_info;

static void on_send_failure(void* context, MQTTAsync_failureData* response)
{
    MQTTAsync                   client = (MQTTAsync)context;
    MQTTAsync_disconnectOptions opts   = MQTTAsync_disconnectOptions_initializer;
    int                         rc     = 0;

    printf("Message send failed token %d error code %d\n", response->token, response->code);
    opts.context = &client;
    if ((rc = MQTTAsync_disconnect(client, &opts)) != MQTTASYNC_SUCCESS) {
        log_error("Failed to start disconnect %s, return code %d\n", MQTTAsync_strerror(rc), rc);
    }
}

static void on_send(void* context, MQTTAsync_successData* response)
{
    log_info("(testapp) -> Message with token value %d delivery confirmed", response->token);
}

static void on_connect(void* context, MQTTAsync_successData* response)
{

    MQTTAsync                 client = (MQTTAsync)context;
    MQTTAsync_responseOptions opts   = MQTTAsync_responseOptions_initializer;
    MQTTAsync_message         pubmsg = MQTTAsync_message_initializer;
    int                       rc     = 0;

    log_info("Successful connection");

    pubmsg.payload    = cJSON_PrintUnformatted(mqtt_info->command[1]);
    pubmsg.payloadlen = strlen(cJSON_PrintUnformatted(mqtt_info->command[1]));
    pubmsg.qos        = 0;
    pubmsg.retained   = 0;

    opts.onSuccess = on_send;
    opts.onFailure = on_send_failure;
    opts.context   = client;

    if ((rc = MQTTAsync_sendMessage(client, mqtt_info->query, &pubmsg, &opts)) !=
        MQTTASYNC_SUCCESS) {
        log_error("Failed to send message");
    }
    else {
        log_debug("send message");
    }

    log_info("Successful reconnection");

    if ((rc = MQTTAsync_subscribe(client, mqtt_info->query_res, 0, &opts)) != MQTTASYNC_SUCCESS) {
        log_error("Failed to subscribe topic: %s", mqtt_info->query_res);
    }
    else {
        log_debug("Successful subscribe topic: %s", mqtt_info->query_res);
    }

    if ((rc = MQTTAsync_subscribe(client, mqtt_info->cmd_res, 0, &opts)) != MQTTASYNC_SUCCESS) {
        log_error("Failed to subscribe topic: %s", mqtt_info->cmd_res);
    }
    else {
        log_debug("Successful subscribe topic: %s", mqtt_info->cmd_res);
    }

    if ((rc = MQTTAsync_subscribe(client, mqtt_info->plugin_res, 0, &opts)) != MQTTASYNC_SUCCESS) {
        log_error("Failed to subscribe topic: %s", mqtt_info->plugin_res);
    }
    else {
        log_debug("Successful subscribe topic: %s", mqtt_info->plugin_res);
    }

    if ((rc = MQTTAsync_subscribe(client, mqtt_info->report, 0, &opts)) != MQTTASYNC_SUCCESS) {
        log_error("Failed to subscribe topic: %s", mqtt_info->report);
    }
    else {
        log_debug("Successful subscribe topic: %s", mqtt_info->report);
    }

    if ((rc = MQTTAsync_subscribe(client, mqtt_info->report_rt, 0, &opts)) != MQTTASYNC_SUCCESS) {
        log_error("Failed to subscribe topic: %s", mqtt_info->report_rt);
    }
    else {
        log_debug("Successful subscribe topic: %s", mqtt_info->report_rt);
    }

    if ((rc = MQTTAsync_subscribe(client, mqtt_info->report_res, 0, &opts)) != MQTTASYNC_SUCCESS) {
        log_error("Failed to subscribe topic: %s", mqtt_info->report_res);
    }
    else {
        log_debug("%lu Successful subscribe topic: %s", pthread_self(), mqtt_info->report_res);
    }
}


static void on_connect_failure(void* context, MQTTAsync_failureData* response)
{
    log_info("Failure connected, rc %d", response ? response->code : 0);
}

#endif

#if 1
static int on_message(void* context, char* topic, int topic_len, MQTTAsync_message* message)
{

    char* payload = message->payload;

    memcpy(payload, (char*)message->payload, message->payloadlen);

    log_debug("(testapp) <- Message receive payload: %s, topic: %s", payload, topic);

    // sprintf(topic, "%s/res", topic);

    log_debug("(testapp) -> publish: %s\n", topic);

    return 1;
}

static void conn_lost(void* context, char* cause)
{

    MQTTAsync                client    = (MQTTAsync)context;
    MQTTAsync_connectOptions conn_opts = MQTTAsync_connectOptions_initializer;
    int                      rc        = 0;

    log_error("Connection lost cause: %s", cause);
    log_error("Reconnecting");

    conn_opts.keepAliveInterval = 30;
    conn_opts.cleansession      = 1;

    if ((rc = MQTTAsync_connect(client, &conn_opts)) != MQTTCLIENT_SUCCESS) {
        log_error("Failed to start connect, return code %d", rc);
    }
}

static void on_reconnect(void* context, char* cause)
{
    int                       rc     = 0;
    MQTTAsync                 client = (MQTTAsync)context;
    MQTTAsync_responseOptions opts   = MQTTAsync_responseOptions_initializer;
    MQTTAsync_message         pubmsg = MQTTAsync_message_initializer;

    pubmsg.payload    = cJSON_PrintUnformatted(mqtt_info->command[1]);
    pubmsg.payloadlen = strlen(cJSON_PrintUnformatted(mqtt_info->command[1]));
    pubmsg.qos        = 0;
    pubmsg.retained   = 0;

    opts.onSuccess = on_send;
    opts.onFailure = on_send_failure;
    opts.context   = client;

    if ((rc = MQTTAsync_sendMessage(client, mqtt_info->query, &pubmsg, &opts)) !=
        MQTTASYNC_SUCCESS) {
        log_error("Failed to send message %s(%d)", MQTTAsync_strerror(rc), rc);
    }
    else {
        log_debug("%lu send message", pthread_self());
    }
}

#endif

#if 1

void mqtt_run(mqtt_info_t* info)
{

    log_info("mqtt_run");

    int rc    = 0;
    mqtt_info = info;
    MQTTAsync                client;
    MQTTAsync_connectOptions conn_opts = MQTTAsync_connectOptions_initializer;
    MQTTAsync_SSLOptions     ssl_opts  = MQTTAsync_SSLOptions_initializer;

    if ((rc = MQTTAsync_create(
             &client, mqtt_info->host, mqtt_info->id, MQTTCLIENT_PERSISTENCE_NONE, NULL)) !=
        MQTTASYNC_SUCCESS) {
        log_error("%d MQTTAsync_create to create %s(%d)", __LINE__, MQTTAsync_strerror(rc), rc);
    }

    if ((rc = MQTTAsync_setCallbacks(client, NULL, conn_lost, on_message, NULL)) !=
        MQTTASYNC_SUCCESS) {
        log_error("%d Failed to set callback %s(%d)", __LINE__, MQTTAsync_strerror(rc), rc);
    }

    conn_opts.MQTTVersion        = MQTTVERSION_3_1_1;
    conn_opts.keepAliveInterval  = 60;
    conn_opts.cleansession       = 1;
    conn_opts.automaticReconnect = 1;
    conn_opts.minRetryInterval   = 2;
    conn_opts.maxRetryInterval   = 365 * 24 * 60 * 60;

    ssl_opts.enableServerCertAuth = 1;
    ssl_opts.trustStore           = SSL_PATH;
    ssl_opts.sslVersion           = MQTT_SSL_VERSION_TLS_1_2;

    conn_opts.ssl       = &ssl_opts;
    conn_opts.onSuccess = on_connect;
    conn_opts.onFailure = on_connect_failure;
    conn_opts.context   = client;

    if ((rc = MQTTAsync_setConnected(client, client, on_reconnect)) != MQTTASYNC_SUCCESS) {
        log_error("%d Failed to setconnect %s(%d)", __LINE__, MQTTAsync_strerror(rc), rc);
    }

    if ((rc = MQTTAsync_connect(client, &conn_opts)) != MQTTASYNC_SUCCESS) {
        log_error("%d Failed to connect %s(%d)", __LINE__, MQTTAsync_strerror(rc), rc);
    }
    else {
        log_info("%lu connect to MQTT Broker!", pthread_self());
    }
}

#endif

#if 0

mqtt_info_t* info_t;

void on_connect(struct mosquitto* mosq, void* obj, int reason_code)
{
    int   rc         = 0;
    int   payloadlen = strlen(cJSON_PrintUnformatted(info_t->command[1]));
    char* payload    = cJSON_PrintUnformatted(info_t->command[1]);

    log_info("on_connect: %s payload: %s(%d)",
             mosquitto_connack_string(reason_code),
             payload,
             payloadlen);
    if (reason_code != 0) {
        mosquitto_disconnect(mosq);
    }

    rc = mosquitto_subscribe(mosq, NULL, info_t->query_res, 0);
    if (rc != MOSQ_ERR_SUCCESS) {
        log_error("Error subscribing: %s\n", mosquitto_strerror(rc));
        mosquitto_disconnect(mosq);
    }

    rc = mosquitto_subscribe(mosq, NULL, info_t->cmd_res, 0);
    if (rc != MOSQ_ERR_SUCCESS) {
        log_error("Error subscribing: %s\n", mosquitto_strerror(rc));
        mosquitto_disconnect(mosq);
    }

    rc = mosquitto_subscribe(mosq, NULL, info_t->report, 0);
    if (rc != MOSQ_ERR_SUCCESS) {
        log_error("Error subscribing: %s\n", mosquitto_strerror(rc));
        mosquitto_disconnect(mosq);
    }

    rc = mosquitto_subscribe(mosq, NULL, info_t->report_res, 0);
    if (rc != MOSQ_ERR_SUCCESS) {
        log_error("Error subscribing: %s\n", mosquitto_strerror(rc));
        mosquitto_disconnect(mosq);
    }

    rc = mosquitto_subscribe(mosq, NULL, info_t->report_rt, 0);
    if (rc != MOSQ_ERR_SUCCESS) {
        log_error("Error subscribing: %s\n", mosquitto_strerror(rc));
        mosquitto_disconnect(mosq);
    }

    rc = mosquitto_publish(mosq, NULL, info_t->query, payloadlen, payload, 0, 0);
    if (rc != MOSQ_ERR_SUCCESS) {
        log_error("Error publishing: %s\n", mosquitto_strerror(rc));
        mosquitto_disconnect(mosq);
    }
}

// 当客户端收到消息时调用回调该函数
void on_message(struct mosquitto* mosq, void* obj, const struct mosquitto_message* msg)
{
    // 打印有效载荷
    log_info("%s %d %s", msg->topic, msg->qos, (char*)msg->payload);
}

void on_log(struct mosquitto* mosq, void* obj, int rc, const char* s)
{
    log_info("[%lu]%s", pthread_self(), s);
}

void mqtt_run(mqtt_info_t* info)
{
    int               rc   = 0;
    struct mosquitto* mosq = NULL;
    info_t                 = info;

    mosq = mosquitto_new(info->id, true, NULL);

    if (mosq == NULL) {

        log_error("create client failed ....");
    }

    if ((rc = mosquitto_tls_set(mosq, SSL_PATH, NULL, NULL, NULL, NULL)) != MOSQ_ERR_SUCCESS) {

        log_error("Failed to mosquitto_tls_set: %s (%d)", mosquitto_strerror(rc), rc);
    }

    if ((rc = mosquitto_tls_opts_set(mosq, 0, "tlsv1.2", NULL)) != MOSQ_ERR_SUCCESS) {

        log_error("Failed to mosquitto_tls_opts_set: %s (%d)", mosquitto_strerror(rc), rc);
    }

    mosquitto_connect_callback_set(mosq, on_connect);
    mosquitto_log_callback_set(mosq, on_log);
    mosquitto_message_callback_set(mosq, on_message);

    if ((rc = mosquitto_connect(mosq, info->address, atoi(info->port), 30)) !=
        MOSQ_ERR_SUCCESS) {

        log_error("Failed to connect: %s (%d)\n", mosquitto_strerror(rc), rc);
    }

    if ((rc = mosquitto_loop_start(mosq)) != MOSQ_ERR_SUCCESS) {

        log_error("Failed to mosquitto loop start: %s (%d)\n", mosquitto_strerror(rc), rc);

        mosquitto_disconnect(mosq);
        mosquitto_destroy(mosq);
        mosquitto_lib_cleanup();
    }
}

#endif