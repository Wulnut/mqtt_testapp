#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "log.h"
#include "util.h"

mqtt_info_t mit;

int main() { 

    log_set_level(LOG_FATAL);

    log_info("Hello World\n");

    testapp_init(&mit);

    testapp_run(&mit);

    return 0;
}