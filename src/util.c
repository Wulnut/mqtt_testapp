#include "util.h"
#include "log.h"
#include "mqtt_client.h"
#include <stdio.h>

mqtt_info_t mit;

void progress_bar(int flag) {

    if (flag == 1) count ++;

    printf("[%-39s][%c][%.1f%%]\r", buff, lable[count % 4], (count + 1) * 2.5);

    fflush(stdout);

    buff[count] = '>';
}

void testapp_init() {

   log_info("testapp init start\n"); 

    FILE *fp = NULL;
    char line[MAX_LINE_LEN];

    memset(line, '\0', MAX_LINE_LEN);

    fp = open(CONFIG_PATH, "r");

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
            strncpy(mit.host, value, strlen(mit.host) + 1);
            log_debug("host: %s\n", mit.host);
        }
    }

   fclose(fp); 

err:
    fclose(fp);
    exit(0);
}

void testapp_run() {

    mqtt_run();

}