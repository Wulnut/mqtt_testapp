#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "log.h"
#include "util.h"

mqtt_info_t mit;

int main(int argc, char **argv) { 
    int rc = 0;

    log_set_level(LOG_TRACE);

    process_signal_init();

    opt_init(argc, argv);

    config_init(&mit);

   rc = read_test_conf(&mit, "../conf/tianyi.conf");

   log_debug("rc: %d", rc);

    // mqtt_run(&mit);

    return 0;
}