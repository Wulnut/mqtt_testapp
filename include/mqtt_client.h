#ifndef MQTT_CLIENT
#define MQTT_CLIENT

#include "cJSON.h"
#include <MQTTAsync.h>
#include <mosquitto.h>

#define SSL_PATH "../conf/zxykey.cer"

typedef struct cts_mqtt_client {
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
	char test[128];
	char test_res[128];
	char passowrd[2048];
	char username[128];
    char address[128];
	char port[32];
	char host[128];
	cJSON *command[128];
	int cmd_counts;
	MQTTAsync *client;
} mqtt_info_t;

void mqtt_run(mqtt_info_t *info);

#endif //MQTT_CLIENT