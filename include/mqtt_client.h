#ifndef MQTT_CLIENT
#define MQTT_CLIENT

#include <MQTTAsync.h>

#define SSL_PATH "./conf/server.crt"

typedef struct cts_mqtt_client {
	MQTTAsync mqtt_client;
	char query[128];
	char query_res[128];
	char cmd[128];
	char cmd_res[128];
	char plugin[128];
	char plugin_res[128];
	char report[128];
	char report_res[128];
	char report_rt[128];
	char passowrd[128];
	char username[128];
    char host[128];
} mqtt_info_t;

static MQTTAsync_SSLOptions configure_ssl_opts();
static MQTTAsync_connectOptions configure_conn_opts();

void mqtt_run();

#endif MQTT_CLIENT