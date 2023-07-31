#include "util.h"
#include "log.h"
#include "mqtt_client.h"
#include <mosquitto.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int count;
char buff[MAXSIZE];
char *lable = "\\/\\-\\/";

void progress_bar(int flag) {

    if (flag == 1) count ++;

    printf("[%-39s][%c][%.1f%%]\r", buff, lable[count % 4], (count + 1) * 2.5);

    fflush(stdout);

    buff[count] = '>';
}

void config_init(mqtt_info_t *mit) {

   log_info("testapp init start\n"); 

    FILE *fp = NULL;
    char line[MAX_LINE_LEN];

    memset(line, '\0', MAX_LINE_LEN);

    fp = fopen(CONFIG_PATH, "r");

    if (fp == NULL) {
        log_error("test.conf open failed!\n");
        goto err;
    }

    while (fgets(line, MAX_LINE_LEN, fp) != NULL) {

        char key[MAX_LINE_LEN], value[MAX_LINE_LEN];
        memset(key, '\0', MAX_LINE_LEN);
        memset(value, '\0', MAX_LINE_LEN);

        if (line[0] == '#' || (line[0] == '/' && line[1] == '/') || line[0] == '\0') {
            continue;
        }

        if (sscanf(line, "%[^=] = %[^\n]", key, value) != 2) {
            continue;
        } 

        for (int i = strlen(key) - 1; i >= 0 && key[i] == ' '; --i) {
            key[i] = '\0';
        }

        if (strcmp(key, "host") == 0) {

            sscanf(value, "%63[^:]:%7s", mit->address, mit->port);

            log_debug("host: %s:%s\n", value, mit->address, mit->port);

        }
    }

err:
    fclose(fp);
}

void mqtt_init(mqtt_info_t * mit) {

    int rc = 0;

    struct mosquitto *mosq = NULL;

    mosq = mosquitto_new(mit->id, true, NULL);

    if (mosq == NULL) {

        log_error("create mosquitto client error...\n");

        mosquitto_lib_cleanup();
    }

    if ((rc = mosquitto_tls_set(mosq, SSL_PATH, NULL, NULL, NULL, NULL)) != MOSQ_ERR_SUCCESS) {

		log_error("Failed to mosquitto_tls_set: %s (%d)\n", mosquitto_strerror(rc), rc);

		mosquitto_lib_cleanup();
	}

	if ((rc = mosquitto_tls_opts_set(mosq, 0, "tlsv1.2", NULL)) != MOSQ_ERR_SUCCESS) {

		log_error("Failed to mosquitto_tls_opts_set: %s (%d)\n", mosquitto_strerror(rc), rc);

		mosquitto_lib_cleanup();
	}

    mit->mosq = mosq;
}

void testapp_init(mqtt_info_t *mit) {

    config_init(mit);

    mqtt_init(mit);

}
