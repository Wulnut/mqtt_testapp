#include <MQTTAsync.h>
#include "mqtt_client.h"

static MQTTAsync_connectOptions configure_conn_opts() {

    MQTTAsync_connectOptions conn_opts = MQTTAsync_connectOptions_initializer;

    conn_opts.MQTTVersion = MQTTVERSION_3_1_1;
    conn_opts.keepAliveInterval = 30;
    conn_opts.cleansession = 1;

    conn_opts.onSuccess;
    conn_opts.onFailure;
    conn_opts.context;

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