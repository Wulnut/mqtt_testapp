#ifndef MQTT_CLIENT
#define MQTT_CLIENT

#include <mosquitto.h>

#define SSL_PATH "./conf/server.crt"

typedef struct cts_mqtt_client {
	struct mosquitto *mosq;
	char id[32];
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

void mqtt_run();

#endif //MQTT_CLIENT