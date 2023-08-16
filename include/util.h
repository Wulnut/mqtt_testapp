#ifndef UTIL_H
#define UTIL_H

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "mqtt_client.h"

#define MAXSIZE 30
#define MAX_LINE_LEN 1024
#define CONFIG_PATH "../conf/test.conf"

void progress_bar(int flag);

void config_init(mqtt_info_t *mit);

#endif