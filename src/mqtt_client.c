#include "mqtt_client.h"
#include "cJSON.h"
#include "log.h"
#include <MQTTAsync.h>
#include <MQTTClient.h>
#include <MQTTClientPersistence.h>
#include <stdlib.h>
#include <string.h>

#if 0
static void on_connect(void *context, MQTTAsync_successData *response) { 

   MQTTAsync client = (MQTTAsync) context;
   MQTTAsync_responseOptions opts = MQTTAsync_responseOptions_initializer;
	int rc = 0;

   log_info("Successful connection\n");

   if ((rc = MQTTAsync_subscribe(client, info->query_res, 0, &opts)) != MQTTASYNC_SUCCESS) {
		log_error("Failed to subscribe topic: %s\n", info->query_res);
	} else {
		log_debug("Successful subscribe topic: %s\n", info->query_res);
	}

	if ((rc = MQTTAsync_subscribe(client, info->cmd_res, 0, &opts)) != MQTTASYNC_SUCCESS) {
		log_error("Failed to subscribe topic: %s\n", info->cmd_res);
	} else {
		log_debug("Successful subscribe topic: %s\n", info->cmd_res);
	}

	if ((rc = MQTTAsync_subscribe(client, info->plugin_res, 0, &opts)) != MQTTASYNC_SUCCESS) {
		log_error("Failed to subscribe topic: %s\n", info->plugin_res);
	} else {
		log_debug("Successful subscribe topic: %s\n", info->plugin_res);
	}

   if ((rc = MQTTAsync_subscribe(client, info->report, 0, &opts)) != MQTTASYNC_SUCCESS) {
      log_error("Failed to subscribe topic: %s\n", info->report);
   } else {
      log_debug("Successful subscribe topic: %s\n", info->report);
   }

   if ((rc = MQTTAsync_subscribe(client, info->report, 0, &opts)) != MQTTASYNC_SUCCESS) {
      log_error("Failed to subscribe topic: %s\n", info->report);
   } else {
      log_debug("Successful subscribe topic: %s\n", info->report);
   }

   if ((rc = MQTTAsync_subscribe(client, info->report_res, 0, &opts)) != MQTTASYNC_SUCCESS) {
      log_error("Failed to subscribe topic: %s\n", info->report_res);
   } else {
      log_debug("Successful subscribe topic: %s\n", info->report_res);
   }
}


static void on_connect_failure (void *context, MQTTAsync_failureData* response) {

   log_info("Failure connected, rc %d", response ? response->code : 0);
   
}

#endif

static int on_message(void* context, char* topic, int topic_len, MQTTClient_message* message)
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

    if ((rc = MQTTAsync_connect(client, &conn_opts)) != MQTTASYNC_SUCCESS) {
        log_error("Failed to start connect, return code %d", rc);
    }
}

#if 0
void mqtt_run(mqtt_info_t *info) {

   log_info("mqtt_run");

   int rc = 0;
   MQTTAsync client;
   MQTTAsync_connectOptions conn_opts = MQTTAsync_connectOptions_initializer;
   MQTTAsync_SSLOptions ssl_opts = MQTTAsync_SSLOptions_initializer;

   if ((rc = MQTTAsync_create(&client, info->host, info->id,
       MQTTCLIENT_PERSISTENCE_NONE, NULL)) != MQTTASYNC_SUCCESS) 
   {
      log_error("%d MQTTAsync_create to create %s(%d)", __LINE__, MQTTAsync_strerror(rc), rc);
   }

   if ((rc = MQTTAsync_setCallbacks(client, NULL, conn_lost, on_message, NULL)) != MQTTASYNC_SUCCESS) {
      log_error("%d Failed to set callback %s(%d)", __LINE__, MQTTAsync_strerror(rc), rc);
   }

   conn_opts.MQTTVersion = MQTTVERSION_3_1_1;
   conn_opts.keepAliveInterval= 20;
   conn_opts.cleansession = 1;

   ssl_opts.verify = 1;
   ssl_opts.enableServerCertAuth = 1;
   ssl_opts.trustStore = SSL_PATH;
   ssl_opts.sslVersion = MQTT_SSL_VERSION_TLS_1_2;

   conn_opts.ssl = &ssl_opts;
   conn_opts.onSuccess = on_connect;
   conn_opts.onFailure = on_connect_failure;
   conn_opts.context = client;

   if ((rc = MQTTAsync_connect(client, &conn_opts)) != MQTTASYNC_SUCCESS) {
      log_error("%d Failed to connect %s(%d)", __LINE__, MQTTAsync_strerror(rc), rc);
   } else {
      log_info("connect to MQTT Broker!");
   }

   while (1);

}

#endif

void mqtt_run(mqtt_info_t* info)
{
    log_info("mqtt run");

    int                       rc = 0;
    MQTTClient                client;
    MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer;
    MQTTClient_SSLOptions     ssl_opts  = MQTTClient_SSLOptions_initializer;

    if ((rc =
             MQTTClient_create(&client, info->host, info->id, MQTTCLIENT_PERSISTENCE_NONE, NULL)) !=
        MQTTCLIENT_SUCCESS) {
        log_error("Failed to create client, return code: %s(%d)", MQTTClient_strerror(rc), rc);
    }

    if ((rc = MQTTClient_setCallbacks(client, NULL, conn_lost, on_message, NULL)) !=
        MQTTCLIENT_SUCCESS) {
        log_error("Failed to callbacks, return code: %s(%d)", MQTTClient_strerror(rc), rc);
    }

    conn_opts.MQTTVersion       = MQTTVERSION_3_1_1;
    conn_opts.keepAliveInterval = 20;
    conn_opts.cleansession      = 1;

    ssl_opts.verify               = 1;
    ssl_opts.enableServerCertAuth = 1;
    ssl_opts.trustStore           = SSL_PATH;
    ssl_opts.sslVersion           = MQTT_SSL_VERSION_TLS_1_2;

    conn_opts.ssl = &ssl_opts;

    if ((rc = MQTTClient_connect(client, &conn_opts)) != MQTTCLIENT_SUCCESS) {
        log_error("Failed to connect, return code: %s(%d)", MQTTClient_strerror(rc), rc);
    }

    if ((rc = MQTTClient_subscribe(client, info->report, 0)) != MQTTCLIENT_SUCCESS) {
        log_error("Failed to subscribe, return code: %s(%d)", MQTTClient_strerror(rc), rc);
    }

    MQTTClient_destroy(&client);
}