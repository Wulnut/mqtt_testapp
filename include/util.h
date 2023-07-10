#ifndef UTIL_H
#define UTIL_H

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define MAXSIZE 30
#define MAX_LINE_LEN 1024
#define CONFIG_PATH "./conf/test.conf"

int count;
char buff[MAXSIZE];
char *lable = "\\/\\-\\/";

void progress_bar(int flag);

void testapp_init();
void testapp_run();

#endif