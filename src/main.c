#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "log.h"
#include "util.h"

mqtt_info_t mit;

int main(int argc, char **argv) { 

    log_set_level(LOG_TRACE);

    process_signal_init();

    opt_init(argc, argv);

    config_init(&mit);

    read_test_conf(&mit, "../conf/tianyi.conf");

    mqtt_run(&mit);

    return 0;
}