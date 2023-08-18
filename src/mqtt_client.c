#include <MQTTAsync.h>
#include <stdlib.h>
#include <string.h>
#include "mqtt_client.h"
#include "log.h"
#include "cJSON.h"

mqtt_info_t *info;

static void on_connect (void *context, MQTTAsync_successData* response) {
    
    log_info("Successful connected");

    //TODO
}

static void on_connect_failure (void *context, MQTTAsync_failureData* response) {

   log_info("Failure connected");
   
   //TODO
}

static int on_message (void *context, char *topic, int topic_len, MQTTAsync_message *message) {

    char* payload = message->payload;

    memcpy (payload, (char *)message->payload, message->payloadlen);

    log_debug ("(CTS) <- Message receive payload: %s, topic: %s\n", payload, topic);

    sprintf (topic, "%s/res", topic);
     
    log_debug ("(CTS) -> publish: %s\n", topic);

    MQTTAsync_freeMessage(&message);
    MQTTAsync_free(topic);

    return 1;
}

void mqtt_run(mqtt_info_t *mit) {

   log_info("mqtt_run");

   info = mit;
   int rc = 0;

   MQTTAsync_connectOptions conn_opts = MQTTAsync_connectOptions_initializer;
   MQTTAsync_SSLOptions ssl_opts = MQTTAsync_SSLOptions_initializer;
//    MQTTAsync_message pubmsg = MQTTAsync_message_initializer;

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
   conn_opts.context = info->client;

   if ((rc = MQTTAsync_create(&(info->client), info->address, info->id,
       MQTTCLIENT_PERSISTENCE_NONE, NULL)) != MQTTASYNC_SUCCESS) 
   {
      log_error("%d MQTTAsync_create to create %s(%d)", __LINE__, MQTTAsync_strerror(rc), rc);
   }

   MQTTAsync_setCallbacks(info->client, NULL, NULL, on_message, NULL);

   if ((rc = MQTTAsync_connect(info->client, &conn_opts)) != MQTTASYNC_SUCCESS) {
      log_error("%d Failed to connect %s(%d)", __LINE__, MQTTAsync_strerror(rc), rc);
   } else {
      log_debug("connect to MQTT Broker!");
   }

}