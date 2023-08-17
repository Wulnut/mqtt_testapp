#include <mosquitto.h>
#include <stdlib.h>
#include <string.h>
#include "mqtt_client.h"
#include "log.h"
#include "cJSON.h"

mqtt_info_t *client;

static void on_log (struct mosquitto *mosq, void *userdata, int level, const char *str) {

    log_info("[mosquitto log]: %s\n", str);

}

static void on_connect (struct mosquitto *mosq, void *obj, int rc) {
    
    log_info("Successful connecttion\n");

    //TODO
}

static void on_message (struct mosquitto *mosq, void *userdata, const struct mosquitto_message *message) {

    char* payload = (char *)calloc(message->payloadlen + 1, sizeof (char));
    char* topic   = NULL;

    memcpy (payload, (char *)message->payload, message->payloadlen);

    log_debug ("(CTS) <- Message receive payload: %s, topic: %s\n", payload, message->topic);

    sprintf (topic, "%s/res", message->topic);
    
    //TODO utask_set();
     
    log_debug ("(CTS) -> publish: %s\n", topic);
}

void mqtt_run(mqtt_info_t *mit) {

   log_info("mqtt_run");

   client = mit;
   int rc = 0;

    client->mosq = mosquitto_new(mit->id, true, NULL);

    if (client->mosq == NULL) {

        log_error("create mosquitto client error...\n");

        mosquitto_lib_cleanup();
    }

    if ((rc = mosquitto_tls_set(client->mosq, SSL_PATH, NULL, NULL, NULL, NULL)) != MOSQ_ERR_SUCCESS) {

		log_error("Failed to mosquitto_tls_set: %s (%d)\n", mosquitto_strerror(rc), rc);

		mosquitto_lib_cleanup();
	}

	if ((rc = mosquitto_tls_opts_set(client->mosq, 0, "tlsv1.2", NULL)) != MOSQ_ERR_SUCCESS) {

		log_error("Failed to mosquitto_tls_opts_set: %s (%d)\n", mosquitto_strerror(rc), rc);

		mosquitto_lib_cleanup();
	}

    if ((rc = mosquitto_username_pw_set(client->mosq, mit->id, mit->passowrd)) != MOSQ_ERR_SUCCESS) {

        log_error("Failed to %s: %s(%d)", __func__, mosquitto_strerror(rc), rc);

        mosquitto_lib_cleanup();
    }

    mosquitto_log_callback_set(client->mosq, on_log);
    mosquitto_connect_callback_set(client->mosq, on_connect);
    mosquitto_message_callback_set(client->mosq, on_message);

    // TODO
    if ((rc = mosquitto_connect_async(client->mosq, client->address, atoi(client->port), 60)) != MOSQ_ERR_SUCCESS) {

        log_error("Failed to connect: %s (%d)", mosquitto_strerror(rc), rc);

        mosquitto_disconnect(client->mosq);
        mosquitto_destroy(client->mosq);
        mosquitto_lib_cleanup();
   }

    if ((rc = mosquitto_loop_start(client->mosq)) != MOSQ_ERR_SUCCESS) {

        log_error("Failed to mosquitto loop start: %s (%d)", mosquitto_strerror(rc), rc);

        mosquitto_disconnect(client->mosq);
        mosquitto_loop_stop(client->mosq, 1);
        mosquitto_destroy(client->mosq);
        mosquitto_lib_cleanup();
   }
}