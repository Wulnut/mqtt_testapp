#ifndef UTIL_H
#define UTIL_H

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "cJSON.h"
#include "mqtt_client.h"

#define MAXSIZE 30
#define MAX_LINE_LEN 1024
#define CONFIG_PATH "../conf/test.conf"
#define HUWEI_PATH "../conf/huawei.conf"
#define TIANYI_PATH "../conf/tianyi.conf"
char test_conf[128]; // test conf file
char conf_path[128]; // mqtt conf file
char filename[128];

typedef struct test {
    int success;
    int error;
    int intput_total;
    int output_total;
    cJSON *result[128];
}test_t;

void progress_bar(int flag);

void config_init(mqtt_info_t *info);
void process_signal_init(void);
void opt_init(int argc, char **argv);
int read_test_conf(mqtt_info_t *info, char *path);
int read_result_conf(char *path);
int execute_cmd(const char *command, char **result);
int payload_check(char *payload, char *topic, int idx);
int get_json_int(cJSON *json, char *key, int default_value);
char *get_json_str(cJSON *json, char *key);
void log_write(char *line);

#endif