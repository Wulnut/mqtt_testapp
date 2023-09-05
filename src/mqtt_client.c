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

#if 0
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
    log_info("(testapp) -> Message with token value %d delivery confirmed\n", response->token);
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

    // MQTTAsync                 client = (MQTTAsync)context;
    // MQTTAsync_responseOptions opts   = MQTTAsync_responseOptions_initializer;
    // int                       rc     = 0;

    // log_info("Successful reconnection");

    // if ((rc = MQTTAsync_subscribe(client, mqtt_info->query_res, 0, &opts)) != MQTTASYNC_SUCCESS) {
    //     log_error("Failed to subscribe topic: %s", mqtt_info->query_res);
    // }
    // else {
    //     log_debug("Successful subscribe topic: %s", mqtt_info->query_res);
    // }

    // if ((rc = MQTTAsync_subscribe(client, mqtt_info->cmd_res, 0, &opts)) != MQTTASYNC_SUCCESS) {
    //     log_error("Failed to subscribe topic: %s", mqtt_info->cmd_res);
    // }
    // else {
    //     log_debug("Successful subscribe topic: %s", mqtt_info->cmd_res);
    // }

    // if ((rc = MQTTAsync_subscribe(client, mqtt_info->plugin_res, 0, &opts)) != MQTTASYNC_SUCCESS) {
    //     log_error("Failed to subscribe topic: %s", mqtt_info->plugin_res);
    // }
    // else {
    //     log_debug("Successful subscribe topic: %s", mqtt_info->plugin_res);
    // }

    // if ((rc = MQTTAsync_subscribe(client, mqtt_info->report, 0, &opts)) != MQTTASYNC_SUCCESS) {
    //     log_error("Failed to subscribe topic: %s", mqtt_info->report);
    // }
    // else {
    //     log_debug("Successful subscribe topic: %s", mqtt_info->report);
    // }

    // if ((rc = MQTTAsync_subscribe(client, mqtt_info->report_rt, 0, &opts)) != MQTTASYNC_SUCCESS) {
    //     log_error("Failed to subscribe topic: %s", mqtt_info->report_rt);
    // }
    // else {
    //     log_debug("Successful subscribe topic: %s", mqtt_info->report_rt);
    // }

    // if ((rc = MQTTAsync_subscribe(client, mqtt_info->report_res, 0, &opts)) != MQTTASYNC_SUCCESS) {
    //     log_error("Failed to subscribe topic: %s", mqtt_info->report_res);
    // }
    // else {
    //     log_debug("%lu Successful subscribe topic: %s", pthread_self(), mqtt_info->report_res);
    // }
}


static void on_connect_failure(void* context, MQTTAsync_failureData* response)
{
    log_info("Failure connected, rc %d", response ? response->code : 0);
}

#endif

#if 0
static int on_message(void* context, char* topic, int topic_len, MQTTAsync_message* message)
{

    char* payload = message->payload;

    memcpy(payload, (char*)message->payload, message->payloadlen);

    log_debug("(testapp) <- Message receive payload: %s, topic: %s\n", payload, topic);

    sprintf(topic, "%s/res", topic);

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
    // int                       rc     = 0;
    // MQTTAsync                 client = (MQTTAsync)context;
    // MQTTAsync_responseOptions opts   = MQTTAsync_responseOptions_initializer;
    // MQTTAsync_message         pubmsg = MQTTAsync_message_initializer;

    // pubmsg.payload    = cJSON_PrintUnformatted(mqtt_info->command[1]);
    // pubmsg.payloadlen = strlen(cJSON_PrintUnformatted(mqtt_info->command[1]));
    // pubmsg.qos        = 0;
    // pubmsg.retained   = 0;

    // opts.onSuccess = on_send;
    // opts.onFailure = on_send_failure;
    // opts.context   = client;

    // if ((rc = MQTTAsync_sendMessage(client, mqtt_info->query, &pubmsg, &opts)) !=
    //     MQTTASYNC_SUCCESS) {
    //     log_error("Failed to send message %s(%d)", MQTTAsync_strerror(rc), rc);
    // }
    // else {
        log_debug("%lu send message", pthread_self());
    // }
}

#endif

#if 0

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
static void MQTT_subscribe(MQTTClient client, mqtt_info_t* info)
{
    int rc = 0;

    if ((rc = MQTTClient_subscribe(client, info->report, 0)) != MQTTCLIENT_SUCCESS) {
        log_error("Failed to subscribe, return code: %s(%d)", MQTTClient_strerror(rc), rc);
    }
    else {
        log_info("Successful subscribe the topic: %s", info->report);
    }

    if ((rc = MQTTClient_subscribe(client, info->report_rt, 0)) != MQTTCLIENT_SUCCESS) {
        log_error("Failed to subscribe, return code: %s(%d)", MQTTClient_strerror(rc), rc);
    }
    else {
        log_info("Successful subscribe the topic: %s", info->report_rt);
    }

    if ((rc = MQTTClient_subscribe(client, info->report_res, 0)) != MQTTCLIENT_SUCCESS) {
        log_error("Failed to subscribe, return code: %s(%d)", MQTTClient_strerror(rc), rc);
    }
    else {
        log_info("Successful subscribe the topic: %s", info->report_res);
    }

    if ((rc = MQTTClient_subscribe(client, info->cmd_res, 0)) != MQTTCLIENT_SUCCESS) {
        log_error("Failed to subscribe, return code: %s(%d)", MQTTClient_strerror(rc), rc);
    }
    else {
        log_info("Successful subscribe the topic: %s", info->cmd_res);
    }

    if ((rc = MQTTClient_subscribe(client, info->query_res, 0)) != MQTTCLIENT_SUCCESS) {
        log_error("Failed to subscribe, return code: %s(%d)", MQTTClient_strerror(rc), rc);
    }
    else {
        log_info("Successful subscribe the topic: %s", info->query_res);
    }

    if ((rc = MQTTClient_subscribe(client, info->plugin_res, 0)) != MQTTCLIENT_SUCCESS) {
        log_error("Failed to subscribe, return code: %s(%d)", MQTTClient_strerror(rc), rc);
    }
    else {
        log_info("Successful subscribe the topic: %s", info->plugin_res);
    }
}

static void MQTT_publish(MQTTClient client, mqtt_info_t* info)
{
    int                      rc     = 0;
    MQTTClient_message       pubmsg = MQTTClient_message_initializer;
    MQTTClient_deliveryToken token;

    pubmsg.payload    = cJSON_PrintUnformatted(info->command[1]);
    pubmsg.payloadlen = strlen(cJSON_PrintUnformatted(info->command[1]));
    pubmsg.qos        = 0;
    pubmsg.retained   = 0;

    if ((rc = MQTTClient_publishMessage(client, info->query, &pubmsg, &token)) !=
        MQTTCLIENT_SUCCESS) {
        log_error("Failed to publish message: %s(%d)", MQTTClient_strerror(rc), rc);
    }
    else {
        log_info("Successful published: %s, topicname: %s", pubmsg.payload, info->query);
    }

    rc = MQTTClient_waitForCompletion(client, token, 100000);
    log_info("Message with delivery token %d delivered", token);
}

static void delivery_complete(void* context, MQTTClient_deliveryToken dt)
{
    printf("publish topic success, token  %d \n", dt);
}

void mqtt_run(mqtt_info_t* info)
{
    log_info("mqtt run");

    int                       rc = 0;
    int                       ch = 0;
    MQTTClient                client;
    MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer;
    MQTTClient_SSLOptions     ssl_opts  = MQTTClient_SSLOptions_initializer;

    log_debug("id: %s", info->id);

    if ((rc =
             MQTTClient_create(&client, info->host, info->id, MQTTCLIENT_PERSISTENCE_NONE, NULL)) !=
        MQTTCLIENT_SUCCESS) {
        log_error("Failed to create client, return code: %s(%d)", MQTTClient_strerror(rc), rc);
    }

    if ((rc = MQTTClient_setCallbacks(client, NULL, conn_lost, on_message, delivery_complete)) !=
        MQTTCLIENT_SUCCESS) {
        log_error("Failed to callbacks, return code: %s(%d)", MQTTClient_strerror(rc), rc);
    }

    conn_opts.MQTTVersion       = MQTTVERSION_3_1_1;
    conn_opts.keepAliveInterval = 30;
    conn_opts.cleansession      = 1;

    //  ssl_opts.verify               = 1; // verify开启就无法单向认证
    ssl_opts.enableServerCertAuth = 1;
    ssl_opts.trustStore           = SSL_PATH;
    ssl_opts.sslVersion           = MQTT_SSL_VERSION_TLS_1_2;

    conn_opts.ssl = &ssl_opts;

    if ((rc = MQTTClient_connect(client, &conn_opts)) != MQTTCLIENT_SUCCESS) {
        log_error("Failed to connect, return code: %s(%d)", MQTTClient_strerror(rc), rc);
    }

    MQTT_subscribe(client, info);

    MQTT_publish(client, info);

    printf("\nPress Q or q + <Enter> to quite\n");
    do {
        ch = getchar();
    } while (ch != 'Q' && ch != 'q');

    if ((rc = MQTTClient_disconnect(client, 10000)) != MQTTCLIENT_SUCCESS) {
        log_error("Failed to disconnect, return %d(%s)", MQTTClient_strerror(rc), rc);
    }

    MQTTClient_destroy(&client);
}
#endif

#if 1

void mqtt_run(mqtt_info_t* info)
{
   int rc = 0;
   struct mosquitto *mosq = NULL; 

   mosq = mosquitto_new(info->id, true, NULL);

   	if (mosq == NULL) {

		log_error("create client failed .... \n");

	}

	if ((rc = mosquitto_tls_set(mosq, SSL_PATH, NULL, NULL, NULL, NULL)) != MOSQ_ERR_SUCCESS) {

		log_error("Failed to mosquitto_tls_set: %s (%d)\n", mosquitto_strerror(rc), rc);

	}

	if ((rc = mosquitto_tls_opts_set(mosq, 0, "tlsv1.2", NULL)) != MOSQ_ERR_SUCCESS) {

		log_error("Failed to mosquitto_tls_opts_set: %s (%d)\n", mosquitto_strerror(rc), rc);

	}

    if ((rc = mosquitto_connect_async(mosq, info->address, atoi(info->port), 30)) != MOSQ_ERR_SUCCESS) {

		log_error("Failed to connect: %s (%d)\n", mosquitto_strerror(rc), rc);
		
	}
}

#endif