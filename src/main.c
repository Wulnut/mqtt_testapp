#include "log.h"
#include "util.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>

mqtt_info_t mqtt_info;

int main(int argc, char** argv)
{

    log_set_level(LOG_TRACE);

    process_signal_init();

    opt_init(argc, argv);

    config_init(&mqtt_info);

    read_test_conf(&mqtt_info, "../conf/tianyi.conf");

    mqtt_run(&mqtt_info);

    while (1);

    return 0;
}