#include "common.h"
#include <time.h>
#include <stdio.h>
#include <sys/stat.h>
#include <stdarg.h>

#define LOG_FILE "../bin/mqtt_testapp.log"
#define LOG_FILE_SIZE 32768

void ulog(const char *priority, const char *fmt, ...)
{
    va_list         ap;
    struct timespec ts;
    struct tm       tm;
    FILE           *f;
    struct stat     s;

    clock_gettime(CLOCK_REALTIME, &ts);
    localtime_r(&ts.tv_sec, &tm);

    f = fopen(LOG_FILE, "a+");

    if (!stat(LOG_FILE, &s) && s.st_size > LOG_FILE_SIZE) {
        if (f) {
            fclose(f);
        }

        rename(LOG_FILE, LOG_FILE ".old");
        f = fopen(LOG_FILE, "a+");
    }

    if (f) {
        fprintf(f, "%04d-%02d-%02d %02d:%02d:%02d.%03ld [%s] ", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                tm.tm_hour, tm.tm_min, tm.tm_sec, ts.tv_nsec / 1000000, priority);

        va_start(ap, fmt);
        vfprintf(f, fmt, ap);
        va_end(ap);

        fclose(f);
    }

    fprintf(stderr, "%04d-%02d-%02d %02d:%02d:%02d.%03ld [%s] ", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
            tm.tm_hour, tm.tm_min, tm.tm_sec, ts.tv_nsec / 1000000, priority);

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}