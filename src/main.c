#include "cts_client.h"
#include <libubox/uloop.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char** argv)
{

    uloop_init();

    cc_init();

    uloop_run();

    cc_run();

    uloop_done();

    cc_done();

    return 0;
}