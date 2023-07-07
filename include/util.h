#ifndef UTIL_H
#define UTIL_H

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define MAXSIZE 30

int count;
char buff[MAXSIZE];
char *lable = "\\/\\-\\/";

void progress_bar(int flag);

#endif