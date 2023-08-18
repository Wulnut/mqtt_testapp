#include "util.h"
#include "log.h"
#include "mqtt_client.h"
#include <mosquitto.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

int count;
char buff[MAXSIZE];
char *lable = "\\/\\-\\/";

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

void progress_bar(int flag) {

    if (flag == 1) count ++;

    printf("[%-39s][%c][%.1f%%]\r", buff, lable[count % 4], (count + 1) * 2.5);

    fflush(stdout);

    buff[count] = '>';
}

void config_init(mqtt_info_t *mit) {

   log_info("testapp init start"); 

    FILE *fp = NULL;
    char line[MAX_LINE_LEN];

    memset(line, '\0', MAX_LINE_LEN);

    fp = fopen(CONFIG_PATH, "r");

    if (fp == NULL) {
        log_error("test.conf open failed!\n");
        goto err;
    }

    while (fgets(line, MAX_LINE_LEN, fp) != NULL) {

        char key[MAX_LINE_LEN], value[MAX_LINE_LEN], tmp[MAX_LINE_LEN];
        memset(key, '\0', MAX_LINE_LEN);
        memset(value, '\0', MAX_LINE_LEN);

        if (line[0] == '#' || (line[0] == '/' && line[1] == '/') || line[0] == '\0') {
            continue;
        }

        if (sscanf(line, "%[^=] = %[^\n]", key, value) != 2) {
            continue;
        } 

        for (int i = strlen(key) - 1; i >= 0 && key[i] == ' '; --i) {
            key[i] = '\0';
        }

        if (strcmp(key, "host") == 0) {

            sscanf(value, "%63[^:]:%7s", tmp, mit->port);

            if (sprintf(mit->address, "ssl://%s", tmp) < 0) {
                log_error("address error");
            }

            if (sprintf(mit->host, "%s:%s", mit->address, mit->port) < 0) {
                log_error("host error");
            }

            log_debug("%s %s", __func__, mit->host);
        }

        if (strcmp(key, "id") == 0) {

            strncpy(mit->id, value, strlen(value) + 1);

            log_debug("%s id:%s", __func__, mit->id);
        }
    }

err:
    fclose(fp);
}

int signals[31] = {
    SIGHUP,  SIGINT,    SIGQUIT, SIGILL,   SIGTRAP,   SIGABRT,
    SIGIOT,  SIGBUS,    SIGFPE,  SIGKILL,  SIGUSR1,   SIGSEGV,
    SIGUSR2, SIGPIPE,   SIGALRM, SIGTERM,  16, SIGCONT,
    SIGSTOP, SIGTSTP,   SIGTTIN, SIGTTOU,  SIGURG,    SIGXCPU,
    SIGXFSZ, SIGVTALRM, SIGPROF, SIGWINCH, SIGIO,     SIGPWR,
    SIGSYS,
};

void process_exit_cb(int __noused)
{
    log_debug("process receive signal:%d\n", __noused);
    switch (__noused) {
        case SIGQUIT:
            exit(EXIT_FAILURE);

        case SIGTERM:
            exit(EXIT_FAILURE);

        case SIGINT:
            exit(EXIT_FAILURE);

        case SIGHUP:
            exit(EXIT_FAILURE);

        case SIGSEGV:
            exit(EXIT_FAILURE);

        case SIGKILL:
            exit(EXIT_FAILURE);

        case SIGABRT:
            exit(EXIT_FAILURE);

        case 16:
            exit(EXIT_FAILURE);

        case SIGILL:
            exit(EXIT_FAILURE);

        default:
            break;
    }
}

void process_signal_init(void)
{
    for (int i = 0; i < ARRAY_SIZE(signals); i++) {
        signal(signals[i], process_exit_cb);
    }
}

void opt_init(int argc, char **argv, opt_t *opts)
{
    // BUG
    if (argc == 1) {
        printf("\n Usage:\n");
        printf(" testapp COMMAND\n");
        puts(" ");
        printf("Commands:\n");
        printf("%-10s %s\n", "t", "tianyi");
        printf("%-10s %s\n", "h", "huawei");
        printf("%-10s %s\n", "z", "zte");

        exit(1);
    }

    opt_t *g_opt = opts;
	int opt = -1;

	while ((opt = getopt(argc, argv, "t:h:z:")) != -1) {
		switch (opt) {

			case 't':
				g_opt->t = 1;

				break;

			case 'h':
				g_opt->h = 1;

				break;

			case 'z':
				g_opt->z = 1;

				break;
		}
	}
}
