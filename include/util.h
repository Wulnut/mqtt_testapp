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
char test_conf[128];

typedef struct opt {
    int t;
    int h;
    int z;
} opt_t;

void progress_bar(int flag);

void config_init(mqtt_info_t *mit);
void process_signal_init(void);
void opt_init(int argc, char **argv, opt_t *opts);

#endif