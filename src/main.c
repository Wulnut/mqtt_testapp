#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "log.h"
#include "util.h"

mqtt_info_t mit;
opt_t g_opt;

int main(int argc, char **argv) { 

    log_set_level(LOG_TRACE);

    process_signal_init();

    //BUG
    opt_init(argc, argv, &g_opt);

    config_init(&mit);

    // mqtt_run(&mit);

    return 0;
}