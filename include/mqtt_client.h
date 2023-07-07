#ifndef MQTT_CLIENT
#define MQTT_CLIENT

#include <MQTTAsync.h>

#define SSL_PAHT "./conf/server.crt"

static MQTTAsync_SSLOptions configure_ssl_opts();
static MQTTAsync_connectOptions configure_conn_opts();

#endif MQTT_CLIENT