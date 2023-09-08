#ifndef UTIL_H
#define UTIL_H

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "mqtt_client.h"

#define MAXSIZE 30
#define MAX_LINE_LEN 1024
#define CONFIG_PATH "../conf/test.conf"
#define HUWEI_PATH "../conf/huawei.conf"
#define TIANYI_PATH "../conf/tianyi.conf"
char test_conf[128]; // test conf file
char conf_path[128]; // mqtt conf file

void progress_bar(int flag);

void config_init(mqtt_info_t *info);
void process_signal_init(void);
void opt_init(int argc, char **argv);
int read_test_conf(mqtt_info_t *info, char *path);
int execute_cmd(const char *command, char **result);

#endif