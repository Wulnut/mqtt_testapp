#include <MQTTAsync.h>
#include "mqtt_client.h"
#include "log.h"
#include "cJSON.h"

static void on_connect (void *context, MQTTAsync_successData *reponse) {
    
    MQTTAsync *client = (MQTTAsync)context;
    MQTTAsync_responseOptions opts = MQTTAsync_responseOptions_initializer;
    MQTTAsync_message pubmsg = MQTTAsync_message_initializer;

    // TODO
}

static void on_connect_failure (void *context, MQTTAsync_failureData *response) {
    log_error("Connect failed reponse is %s, rc %d\n", response->message, response ? response->code : 0);
}

static MQTTAsync_connectOptions configure_conn_opts(mqtt_info_t *mit) {

    MQTTAsync_connectOptions conn_opts = MQTTAsync_connectOptions_initializer;

    conn_opts.MQTTVersion = MQTTVERSION_3_1_1;
    conn_opts.keepAliveInterval = 30;
    conn_opts.cleansession = 1;

    conn_opts.onSuccess = on_connect;
    conn_opts.onFailure = on_connect_failure;
    conn_opts.context = mit;

    conn_opts.automaticReconnect = 1;
    conn_opts.minRetryInterval = 2;
    conn_opts.maxRetryInterval = 365 * 24 * 60 * 60;

    return conn_opts;
}

static MQTTAsync_SSLOptions configure_ssl_opts() {

    MQTTAsync_SSLOptions ssl_opts = MQTTAsync_SSLOptions_initializer;

	ssl_opts.enableServerCertAuth = 1;
	ssl_opts.trustStore = SSL_PATH;
	ssl_opts.sslVersion = MQTT_SSL_VERSION_TLS_1_2;

	return ssl_opts;

}

void mqtt_run(mqtt_info_t *mit) {

   log_info("connect");

   mqtt_info_t *info_t = mit;

}