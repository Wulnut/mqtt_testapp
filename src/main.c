#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "log.h"
#include "util.h"

int main() { 

    log_set_level(LOG_INFO);

    log_info("Hello World\n");

    return 0;
}