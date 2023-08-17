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

   log_info("testapp init start"); 

    FILE *fp = NULL;
    char line[MAX_LINE_LEN];

    memset(line, '\0', MAX_LINE_LEN);

    fp = fopen(CONFIG_PATH, "r");

    if (fp == NULL) {
        log_error("test.conf open failed!\n");
        goto err;
    }

    while (fgets(line, MAX_LINE_LEN, fp) != NULL) {

        char key[MAX_LINE_LEN], value[MAX_LINE_LEN], tmp[MAX_LINE_LEN];
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

            sscanf(value, "%63[^:]:%7s", tmp, mit->port);

            if (sprintf(mit->address, "ssl://%s", tmp) < 0) {
                log_error("address error\n");
            }

            log_debug("%s %s:%s", __func__, mit->address, mit->port);
        }

        if (strcmp(key, "id") == 0) {

            strncpy(mit->id, value, strlen(value) + 1);

            log_debug("%s id:%s", __func__, mit->id);
        }

        if (strcmp(key, "pwd") == 0) {

            strncpy(mit->passowrd, value, strlen(value) + 1);

            log_debug("%s pwd:%s", __func__, mit->passowrd);
        }
    }

err:
    fclose(fp);
}
