#include "cts_client.h"

int main(int argc, char **argv)
{

    uloop_init();

    cc_init();

    uloop_run();

    cc_run();

    uloop_done();

    cc_done();

    return 0;
}