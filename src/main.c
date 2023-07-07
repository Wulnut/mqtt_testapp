#include <stdio.h>
#include "log.h"

int main() { 

    log_set_level(LOG_INFO);

    log_info("Hello World\n");

    return 0;
}