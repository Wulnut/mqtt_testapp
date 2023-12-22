#include "cts_handler_gw.h"
#include "cJSON.h"
#include "common.h"
#include "cts.h"
#include "cts_client.h"
#include <__stddef_size_t.h>
#include <curl/curl.h>
#include <curl/easy.h>
#include <stdlib.h>
#include <string.h>

size_t curl_write(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    return fwrite(ptr, size, nmemb, stream);
}

static int get_download_file(char *url)
{
    FILE              *fp           = NULL;
    char               filename[30] = "";
    char              *property     = NULL;
    CURL              *curl         = NULL;
    CURLcode           res;
    struct curl_slist *header_list = NULL;
    memset(&res, 0, sizeof(res));

    // TODO generate authorization

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    if (!curl)
        return 0;

    fp = fopen(filename, "w");
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_URL, fp);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);

    header_list = curl_slist_append(header_list, property);
    res         = curl_easy_perform(curl);

    fclose(fp);
    curl_easy_cleanup(curl);

    return 1;
}

static void handle_plugin_cmd(cJSON *msg)
{
    ULOG_MARK();

    cJSON *cmd    = NULL;
    cJSON *plugid = NULL;
    cJSON *url    = NULL;
    cJSON *param  = NULL;
    char  *strval = NULL;
    char  *errmsg = NULL;
    int    ret    = -1;
    int    id     = 0;

    cmd    = cJSON_GetObjectItem(msg, "cmd");
    plugid = cJSON_GetObjectItem(msg, "pluginId");

    if (!cJSON_IsString(cmd)) {
        set_err(RESULT_CANNOT_EXECUTE, "invalid cmd");
        goto done;
    }

    if (!cJSON_IsNumber(plugid)) {
        set_err(RESULT_CANNOT_EXECUTE, "invalid plugin id");
        goto done;
    }

    strval = cJSON_GetStringValue(cmd);
    id     = cJSON_GetNumberValue(plugid);

    if (strcmp(strval, "install") == 0) {

        url = cJSON_GetObjectItem(msg, "url");

        if (!cJSON_IsString(url)) {
            set_err(RESULT_CANNOT_EXECUTE, "invalid url");
            goto done;
        }

        if (get_download_file(url->valuestring) == 0) {
            set_err(RESULT_EXECUTE_FAILED, "invalid url");
        }

        // ret = ctcap_install_app(cJSON_GetStringValue(url), id, (GAsyncReadyCallback)app_install_cb, NULL);

        if (ret != 0) {
            set_err(RESULT_EXECUTE_FAILED, "plugin install failed");
            goto done;
        }
    }
    else if (strcmp(strval, "unInstall") == 0) {

        // ret = ctcap_uninstall_app(id, &errmsg);

        if (ret != 0) {
            set_err(RESULT_EXECUTE_FAILED, errmsg ? errmsg : "plugin uninstall failed");

            if (errmsg) {
                free(errmsg);
            }

            goto done;
        }
    }
    else if (strcmp(strval, "stop") == 0) {

        // ret = ctcap_stop_app(id, &errmsg);

        if (ret != 0) {
            set_err(RESULT_EXECUTE_FAILED, errmsg ? errmsg : "plugin stop failed");

            if (errmsg) {
                free(errmsg);
            }

            goto done;
        }
    }
    else if (strcmp(strval, "run") == 0) {

        // ret = ctcap_run_app(id, &errmsg);

        if (ret != 0) {
            set_err(RESULT_EXECUTE_FAILED, errmsg ? errmsg : "plugin run failed");

            if (errmsg) {
                free(errmsg);
            }

            goto done;
        }
    }
    else if (strcmp(strval, "set") == 0) {

        param = cJSON_GetObjectItem(msg, "param");

        if (!cJSON_IsString(param)) {
            set_err(RESULT_CANNOT_EXECUTE, "invalid param");
            goto done;
        }

        // char *result = ctcap_app_postmsg(id, cJSON_GetStringValue(param), &errmsg);
        char *result = NULL;

        if (result == NULL) {
            set_err(RESULT_EXECUTE_FAILED, errmsg ? errmsg : "plugin set failed");

            if (errmsg) {
                free(errmsg);
            }

            goto done;
        }

        ULOG_DEBUG("retmsg: %s\n", result);
        free(result);
    }

done:
    // bundle_msg(bundle, msg);
}