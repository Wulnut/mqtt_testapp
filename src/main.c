#include <mosquitto.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "log.h"
#include "util.h"

mqtt_info_t mit;

int main() { 

    log_set_level(LOG_TRACE);

    config_init(&mit);

    mqtt_run(&mit);

    return 0;
}