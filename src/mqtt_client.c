#include <MQTTAsync.h>
#include <MQTTClient.h>
#include <MQTTClientPersistence.h>
#include <stdlib.h>
#include <string.h>
#include "mqtt_client.h"
#include "log.h"
#include "cJSON.h"

mqtt_info_t *info;

// static void on_connect(void *context, MQTTAsync_successData *response) { 

//    MQTTAsync_responseOptions opts = MQTTAsync_responseOptions_initializer;
// 	int rc = 0;

//    log_info("Successful connection\n");

//    if ((rc = MQTTAsync_subscribe(info->client, info->query_res, 0, &opts)) != MQTTASYNC_SUCCESS) {
// 		log_error("Failed to subscribe topic: %s\n", info->query_res);
// 	} else {
// 		log_debug("Successful subscribe topic: %s\n", info->query_res);
// 	}

// 	if ((rc = MQTTAsync_subscribe(info->client, info->cmd_res, 0, &opts)) != MQTTASYNC_SUCCESS) {
// 		log_error("Failed to subscribe topic: %s\n", info->cmd_res);
// 	} else {
// 		log_debug("Successful subscribe topic: %s\n", info->cmd_res);
// 	}

// 	if ((rc = MQTTAsync_subscribe(info->client, info->plugin_res, 0, &opts)) != MQTTASYNC_SUCCESS) {
// 		log_error("Failed to subscribe topic: %s\n", info->plugin_res);
// 	} else {
// 		log_debug("Successful subscribe topic: %s\n", info->plugin_res);
// 	}

//    if ((rc = MQTTAsync_subscribe(info->client, info->report, 0, &opts)) != MQTTASYNC_SUCCESS) {
//       log_error("Failed to subscribe topic: %s\n", info->report);
//    } else {
//       log_debug("Successful subscribe topic: %s\n", info->report);
//    }

//    if ((rc = MQTTAsync_subscribe(info->client, info->report, 0, &opts)) != MQTTASYNC_SUCCESS) {
//       log_error("Failed to subscribe topic: %s\n", info->report);
//    } else {
//       log_debug("Successful subscribe topic: %s\n", info->report);
//    }

//    if ((rc = MQTTAsync_subscribe(info->client, info->report_res, 0, &opts)) != MQTTASYNC_SUCCESS) {
//       log_error("Failed to subscribe topic: %s\n", info->report_res);
//    } else {
//       log_debug("Successful subscribe topic: %s\n", info->report_res);
//    }
// }


// static void on_connect_failure (void *context, MQTTAsync_failureData* response) {

//    log_info("Failure connected, rc %d", response ? response->code : 0);
   
// }

static int on_message (void *context, char *topic, int topic_len, MQTTClient_message *message) {

    char* payload = message->payload;

    memcpy (payload, (char *)message->payload, message->payloadlen);

    log_debug ("(testapp) <- Message receive payload: %s, topic: %s\n", payload, topic);

    sprintf (topic, "%s/res", topic);
     
    log_debug ("(testapp) -> publish: %s\n", topic);

    MQTTClient_freeMessage(&message);
    MQTTClient_free(topic);

    return 1;
}

static void conn_lost(void *context, char *cause) {
	MQTTAsync client = (MQTTAsync)context;
	MQTTAsync_connectOptions conn_opts = MQTTAsync_connectOptions_initializer;
	int rc = 0;

	log_error("Connection lost cause: %s", cause);
	log_error("Reconnecting");

	conn_opts.keepAliveInterval = 30;
	conn_opts.cleansession = 1;

	if ((rc = MQTTAsync_connect(client, &conn_opts)) != MQTTASYNC_SUCCESS) {
		log_error("Failed to start connect, return code %d", rc);
	}
}

// void mqtt_run(mqtt_info_t *mit) {

//    log_info("mqtt_run");

//    info = mit;
//    int rc = 0;

//    MQTTAsync_connectOptions conn_opts = MQTTAsync_connectOptions_initializer;
//    MQTTAsync_SSLOptions ssl_opts = MQTTAsync_SSLOptions_initializer;
//    // MQTTAsync_message pubmsg = MQTTAsync_message_initializer;
//    // MQTTAsync_responseOptions pub_opts = MQTTAsync_responseOptions_initializer;

//    conn_opts.MQTTVersion = MQTTVERSION_3_1_1;
//    conn_opts.keepAliveInterval= 20;
//    conn_opts.cleansession = 1;

//    ssl_opts.verify = 1;
//    ssl_opts.enableServerCertAuth = 1;
//    ssl_opts.trustStore = SSL_PATH;
//    ssl_opts.sslVersion = MQTT_SSL_VERSION_TLS_1_2;

//    conn_opts.ssl = &ssl_opts;
//    conn_opts.onSuccess = on_connect;
//    conn_opts.onFailure = on_connect_failure;
//    conn_opts.context = info->client;

//    if ((rc = MQTTAsync_create(&(info->client), info->host, info->id,
//        MQTTCLIENT_PERSISTENCE_NONE, NULL)) != MQTTASYNC_SUCCESS) 
//    {
//       log_error("%d MQTTAsync_create to create %s(%d)", __LINE__, MQTTAsync_strerror(rc), rc);
//    }

//    if ((rc = MQTTAsync_setCallbacks(info->client, NULL, conn_lost, on_message, NULL)) != MQTTASYNC_SUCCESS) {
//       log_error("%d Failed to set callback %s(%d)", __LINE__, MQTTAsync_strerror(rc), rc);
//    }

//    if ((rc = MQTTAsync_connect(info->client, &conn_opts)) != MQTTASYNC_SUCCESS) {
//       log_error("%d Failed to connect %s(%d)", __LINE__, MQTTAsync_strerror(rc), rc);
//    } else {
//       log_info("connect to MQTT Broker!");
//    }

//    while (1);

// }

void mqtt_run(mqtt_info_t *mit)
{
   log_trace("here");
   int rc = 0;
   MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer;
   MQTTClient_SSLOptions ssl_opts = MQTTClient_SSLOptions_initializer;

   conn_opts.MQTTVersion = MQTTVERSION_3_1_1;
   conn_opts.keepAliveInterval= 20;
   conn_opts.cleansession = 1;

   ssl_opts.verify = 1;
   ssl_opts.enableServerCertAuth = 1;
   ssl_opts.trustStore = SSL_PATH;
   ssl_opts.sslVersion = MQTT_SSL_VERSION_TLS_1_2;

   conn_opts.ssl = &ssl_opts;
log_trace("here");
   if ((rc = MQTTClient_create(&info->mqtt, info->host, info->id, 
         MQTTCLIENT_PERSISTENCE_NONE, NULL)) != MQTTCLIENT_SUCCESS)
   {
      log_error("Failed to create client, return code: %s(%d)", MQTTClient_strerror(rc), rc);
   }
log_trace("here");
   if ((rc = MQTTClient_setCallbacks(info->mqtt, NULL, conn_lost, on_message, NULL)) != MQTTCLIENT_SUCCESS) {
      log_error("Failed to callbacks, return code: %s(%d)", MQTTClient_strerror(rc), rc);
   }
log_trace("here");
   if ((rc = MQTTClient_connect(info->mqtt, &conn_opts)) != MQTTCLIENT_SUCCESS) {
      log_error("Failed to connect, return code: %s(%d)", MQTTClient_strerror(rc), rc);
   }
log_trace("here");
   if ((rc = MQTTClient_subscribe(info->mqtt, info->report, 0)) != MQTTCLIENT_SUCCESS) {
      log_error("Failed to subscribe, return code: %s(%d)", MQTTClient_strerror(rc), rc);
   }


}