#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#define ULOG_ERR(fmt, ...)   ulog("ERROR", fmt, ##__VA_ARGS__)
#define ULOG_WARN(fmt, ...)  ulog("WARN", fmt, ##__VA_ARGS__)
#define ULOG_INFO(fmt, ...)  ulog("INFO", fmt, ##__VA_ARGS__)
#define ULOG_DEBUG(fmt, ...) ulog("DEBUG", fmt, ##__VA_ARGS__)
#define ULOG_MARK()          ulog("DEBUG", "%s %d\n", __FUNCTION__, __LINE__)

#define _free(x)         \
    do {                 \
        if (x != NULL) { \
            free(x);     \
            x = NULL;    \
        }                \
    } while (0)

void  ulog(const char *priority, const char *fmt, ...);
char *_itoa(int64_t i);

#endif