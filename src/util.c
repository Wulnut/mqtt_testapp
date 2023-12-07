#include "util.h"
#include "cJSON.h"
#include "log.h"
#include "mqtt_client.h"
#include <bits/types/FILE.h>
#include <mosquitto.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int           count;
char          buff[MAXSIZE];
char*         lable = "\\/\\-\\/";
static test_t testapps;

#ifndef ARRAY_SIZE
#    define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

int signals[31] = {
    SIGHUP,  SIGINT,    SIGQUIT, SIGILL,   SIGTRAP, SIGABRT, SIGIOT,  SIGBUS,
    SIGFPE,  SIGKILL,   SIGUSR1, SIGSEGV,  SIGUSR2, SIGPIPE, SIGALRM, SIGTERM,
    16,      SIGCONT,   SIGSTOP, SIGTSTP,  SIGTTIN, SIGTTOU, SIGURG,  SIGXCPU,
    SIGXFSZ, SIGVTALRM, SIGPROF, SIGWINCH, SIGIO,   SIGPWR,  SIGSYS,
};

void progress_bar(int flag)
{

    if (flag == 1) count++;

    printf("[%-39s][%c][%.1f%%]\r", buff, lable[count % 4], (count + 1) * 2.5);

    fflush(stdout);

    buff[count] = '>';
}

void config_init(mqtt_info_t* info)
{
    log_info("testapp init start");

    time_t     t;     // 声明一个time_t类型的变量t
    struct tm* tmp;   // 声明一个指向struct tm的指针tmp

    t   = time(NULL);      // 获取当前的系统时间
    tmp = localtime(&t);   // 将time_t类型转换为struct tm类型，以本地时区表示

    FILE* fp = NULL;
    char  line[MAX_LINE_LEN];

    memset(line, '\0', MAX_LINE_LEN);

    if (tmp == NULL) {
        log_error("localtime");
    }

    if (strftime(filename, sizeof(filename), "../conf/result_%Y%m%d_%H%M%S.log", tmp) == 0) {
        log_error("strftime returned 0");
    }

#if 0
    fp = fopen(CONFIG_PATH, "r");
#endif
    fp = fopen(CONFIG_PATH, "r");
    log_info("read conf file: %s", CONFIG_PATH);

    if (fp == NULL) {
        log_error("test.conf open failed!\n");
        goto err;
    }

    while (fgets(line, MAX_LINE_LEN, fp) != NULL) {

        char key[MAX_LINE_LEN], value[MAX_LINE_LEN], tmp[MAX_LINE_LEN], *ptr;
        memset(key, '\0', MAX_LINE_LEN);
        memset(value, '\0', MAX_LINE_LEN);

        ptr = strchr(line, '\r');
        if (ptr) *ptr = '\0';

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

            sscanf(value, "%63[^:]:%7s", tmp, info->port);
#if 1
            if (sprintf(info->address, "mqtts://%s", tmp) < 0) {
                log_error("address error");
            }
#endif
            // if (sprintf(info->address, "%s", tmp) < 0) {
            //     log_error("address error");
            // }

            if (sprintf(info->host, "%s:%s", info->address, info->port) < 0) {
                log_error("host error");
            }

            log_debug("%s %s", __func__, info->host);
            continue;
        }

        if (strcmp(key, "id") == 0) {

            strncpy(info->id, value, strlen(value) + 1);

            log_debug("%s id:%s", __func__, info->id);
            continue;
        }

        if (strcmp(key, "username") == 0) {

            strncpy(info->username, value, strlen(value) + 1);

            log_debug("%s username:%s", __func__, info->username);
            continue;
        }

        if (strcmp(key, "password") == 0) {

            strncpy(info->passowrd, value, strlen(value) + 1);

            log_debug("%s password:%s, value:%s", __func__, info->passowrd, value);
        }
    }

err:
    fclose(fp);
}

void process_exit_cb(int __noused)
{
    log_debug("process receive signal:%d\n", __noused);
    switch (__noused) {
    case SIGQUIT: exit(EXIT_FAILURE);

    case SIGTERM: exit(EXIT_FAILURE);

    case SIGINT: exit(EXIT_FAILURE);

    case SIGHUP: exit(EXIT_FAILURE);

    case SIGSEGV: exit(EXIT_FAILURE);

    case SIGKILL: exit(EXIT_FAILURE);

    case SIGABRT: exit(EXIT_FAILURE);

    case 16: exit(EXIT_FAILURE);

    case SIGILL: exit(EXIT_FAILURE);

    default: break;
    }
}

void process_signal_init(void)
{
    for (int i = 0; i < ARRAY_SIZE(signals); i++) {
        signal(signals[i], process_exit_cb);
    }
}

void opt_init(int argc, char** argv)
{
    if (argc == 1 || argc > 3) goto err;

    strncpy(conf_path, argv[1], sizeof(conf_path));
    strncpy(test_conf, argv[2], sizeof(test_conf));

    return;

err:
    printf(" Usage: \n");
    printf("\t testapp conf_path test_path\n");
    printf(" description: \n");
    printf("\t conf_path: mqtt configuration file\n");
    printf("\t test_path: mqtt topic name and json commands file\n");
    exit(1);
}

int read_test_conf(mqtt_info_t* info, char* path)
{
    log_info("read test conf: %s", path);

    int   i  = 0;
    FILE* fp = NULL;
    char  line[MAX_LINE_LEN];

    memset(line, '\0', sizeof(line));

    fp = fopen(path, "r");

    if (fp == NULL) {

        log_error("%s open failed!", path);

        return -1;
    }

    while (fgets(line, MAX_LINE_LEN, fp) != NULL) {

        char key[MAX_LINE_LEN], value[MAX_LINE_LEN], *ptr;
        memset(key, '\0', MAX_LINE_LEN);
        memset(value, '\0', MAX_LINE_LEN);

        if (line[0] == '#' || (line[0] == '/' && line[1] == '/') || line[0] == '\0') {
            continue;
        }

        ptr = strchr(line, '\r');
        if (ptr) *ptr = '\0';

        if (strstr(line, "mac") != NULL) {

            info->command[i] = cJSON_Parse(line);

            if (info->command[i] == NULL) {

                log_error("command read failed\n");

                return -2;
            }

            log_debug("command[%d]: %s", i + 1, cJSON_PrintUnformatted(info->command[i]));

            ++i;
        }

        info->cmd_counts      = i;
        testapps.intput_total = i;

        if (sscanf(line, "%[^=] = %[^\n]", key, value) != 2) {
            continue;
        }

        for (int i = strlen(key) - 1; i >= 0 && key[i] == ' '; --i) {
            key[i] = '\0';
        }

        if (strcmp(key, "cmd") == 0) {

            strncpy(info->cmd, value, strlen(value) + 1);

            log_debug("cmd: %s", info->cmd);
            continue;
        }

        if (strcmp(key, "cmd_res") == 0) {

            strncpy(info->cmd_res, value, strlen(value) + 1);

            log_debug("cmd_res: %s", info->cmd_res);
            continue;
        }

        if (strcmp(key, "plugin") == 0) {

            strncpy(info->plugin, value, strlen(value) + 1);

            log_debug("plugin: %s", info->plugin);
            continue;
        }

        if (strcmp(key, "plugin_res") == 0) {

            strncpy(info->plugin_res, value, strlen(value) + 1);

            log_debug("plugin_res: %s", info->plugin_res);
            continue;
        }

        if (strcmp(key, "query") == 0) {

            strncpy(info->query, value, strlen(value) + 1);

            log_debug("query: %s", info->query);
            continue;
        }

        if (strcmp(key, "query_res") == 0) {

            strncpy(info->query_res, value, strlen(value) + 1);

            log_debug("query_res: %s", info->query_res);
            continue;
        }

        if (strcmp(key, "report") == 0) {

            strncpy(info->report, value, strlen(value) + 1);

            log_debug("report: %s", info->report);
            continue;
        }

        if (strcmp(key, "report_res") == 0) {

            strncpy(info->report_res, value, strlen(value) + 1);

            log_debug("report_res: %s", info->report_res);
            continue;
        }

        if (strcmp(key, "report_rt") == 0) {

            strncpy(info->report_rt, value, strlen(value) + 1);

            log_debug("report_rt: %s", info->report_rt);
            continue;
        }

        if (strcmp(key, "test") == 0) {

            strncpy(info->test, value, strlen(value) + 1);

            log_debug("test: %s", info->test);
            continue;
        }

        if (strcmp(key, "test_res") == 0) {

            strncpy(info->test_res, value, strlen(value) + 1);

            log_debug("test_res: %s", info->test_res);
        }
    }

    return 1;
}

int read_result_conf(char* path)
{
    log_info("read test conf: %s", path);

    int   i  = 0;
    FILE* fp = NULL;
    char  line[MAX_LINE_LEN];

    memset(line, '\0', sizeof(line));

    fp = fopen(path, "r");

    if (fp == NULL) {

        log_error("%s open failed!", path);

        return -1;
    }

    while (fgets(line, MAX_LINE_LEN, fp) != NULL) {

        char key[MAX_LINE_LEN], value[MAX_LINE_LEN], *ptr;
        memset(key, '\0', MAX_LINE_LEN);
        memset(value, '\0', MAX_LINE_LEN);

        if (line[0] == '#' || (line[0] == '/' && line[1] == '/') || line[0] == '\0') {
            continue;
        }

        ptr = strchr(line, '\r');
        if (ptr) *ptr = '\0';

        if (strstr(line, "mac") != NULL) {

            testapps.result[i] = cJSON_Parse(line);

            if (testapps.result[i] == NULL) {

                log_error("command read failed\n");

                return -2;
            }

            log_debug("result[%d]: %s", i + 1, cJSON_PrintUnformatted(testapps.result[i]));

            ++i;
        }

        testapps.output_total = i;
    }

    return 1;
}

int execute_cmd(const char* command, char** result)
{
    char* res;
    char  buf[1024];
    FILE* fp = NULL;

    res = (char*)malloc(1024 * sizeof(char));

    if ((fp = popen(command, "r")) == NULL) {
        log_error("popen error!");
        return -1;
    }

    while (fgets(buf, sizeof buf, fp)) {
        strcat(res, buf);
    }

    pclose(fp);
    log_debug("result: \n%s", res);

    *result = res;

    return 1;
}

static int is_valid_json(const char* str)
{
    cJSON* json = cJSON_Parse(str);

    if (json == NULL) {

        cJSON_Delete(json);

        return 1;
    }

    return 0;
}

#if 0
static int json_equal(cJSON* json_1, cJSON* json_2)
{
    if (!json_1 || !json_2) return 0;
    // 检查两个JSON对象的类型是否相同
    if (json_1->type != json_2->type) return 0;

    switch (json_1->type) {
    case cJSON_Object:
    {
        cJSON* child1 = json_1->child;
        cJSON* child2 = json_2->child;
        while (child1 && child2) {
            if (!json_equal(child1, child2)) return 0;
            child1 = child1->next;
            child2 = child2->next;
        }
        // 确保两个对象都遍历完
        if (child1 || child2) return 0;
        break;
    }
    case cJSON_Array:
    {
        cJSON* child1 = json_1->child;
        cJSON* child2 = json_2->child;
        while (child1 && child2) {
            if (!json_equal(child1, child2)) return 0;
            child1 = child1->next;
            child2 = child2->next;
        }
        if (child1 || child2) return 0;
        break;
    }
    case cJSON_String:
        if (strcmp(json_1->valuestring, json_2->valuestring) != 0) return 0;
        break;
    case cJSON_Number:
        if (json_1->valuedouble != json_2->valuedouble) return 0;
        break;
    case cJSON_True:
    case cJSON_False:
    case cJSON_NULL: break;   // 已经通过type检查
    default: return 0;        // 未知类型
    }

    return 1;
}

int payload_check(char* payload, char* topic, int idx)
{
    int    count = idx;
    cJSON* json  = NULL;

    if (payload == NULL && topic == NULL && testapps.result[count] == NULL) return 0;

    if (is_valid_json(payload)) return -1;

    json = cJSON_Parse(payload);

    if (json_equal(json, testapps.result[count])) return -2;

    return 1;
}
#endif

int get_json_int(cJSON* json, char* key, int default_value)
{
    cJSON* value = cJSON_GetObjectItem(json, key);

    if (cJSON_IsNumber(value)) {
        return value->valueint;
    }

    return default_value;
}

char* get_json_str(cJSON* json, char* key)
{
    cJSON* value = cJSON_GetObjectItem(json, key);

    if (cJSON_IsString(value)) {
        return value->valuestring;
    }

    return NULL;
}

int payload_check(char* payload, char* topic, int idx)
{
    int    count  = idx;
    int    result = 0;
    cJSON* json   = NULL;

    if (payload == NULL && topic == NULL && testapps.result[count] == NULL) return 0;

    if (is_valid_json(payload)) return -1;

    json = cJSON_Parse(payload);

    result = get_json_int(json, "result", -2);

    if (result != 0) return result;

    return 1;
}

void log_write(char* line)
{
    FILE* file = NULL;

    file = fopen(filename, "a+");

    if (file == NULL) {
        log_error("result.log file open error");
    }

    fprintf(file, "%s\n", line);

    fclose(file);
}
