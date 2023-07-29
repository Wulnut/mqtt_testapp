#include <mosquitto.h>
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

    mqtt_run();

   if (mosquitto_loop_start(mit.mosq) != MOSQ_ERR_SUCCESS) {

        log_info("Failed to mosquitto loop start: %s\n");

        mosquitto_disconnect(mit.mosq);
        mosquitto_loop_stop(mit.mosq, 1);
        mosquitto_destroy(mit.mosq);
        mosquitto_lib_cleanup();
   }

    return 0;
}