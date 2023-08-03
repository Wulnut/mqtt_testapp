#include "util.h"
#include "log.h"
#include "mqtt_client.h"
#include "cJSON.h"
#include <mosquitto.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int count;
char buff[MAXSIZE];
char *lable = "\\/\\-\\/";


/*
code 1008 information
成功返回0，失败返回非0
*/
static int parsing_1008_information(cJSON *retparse)
{
	cJSON *cjson_mac = cJSON_GetObjectItem(retparse,"mac");
	cJSON *cjson_array_query_res = cJSON_GetObjectItem(retparse,"query_res");

	if (cjson_mac != NULL)
	{
		/*TODO*/
	}
	else 
	{
		log_error("mac failed.");
		return -1;
	}

	if (cjson_array_query_res != NULL)
	{
		int array_query_res_len = cJSON_GetArraySize(cjson_array_query_res);
		if(array_query_res_len > 0)
		{
			int i = 0;
			for (; i < array_query_res_len; i++)
			{
				cJSON *cjson_array_value = cJSON_GetArrayItem(cjson_array_query_res,i);
				if(cjson_array_value != NULL)
				{
					cJSON *cjson_array_data = cJSON_GetObjectItem(cjson_array_value,"data");
					cJSON *cjson_name = cJSON_GetObjectItem (cjson_array_value,"name");
					if(cjson_name != NULL)
					{
						/*TODO*/
					}
					else
					{
						log_error("query_res -> name failed.");
						return -1;
					}

					if(cjson_array_data != NULL)
					{
						cJSON * cjson_devName = cJSON_GetObjectItem(cjson_array_data,"devName");
						cJSON * cjson_devType = cJSON_GetObjectItem(cjson_array_data,"devType");
						cJSON * cjson_devManufacturer = cJSON_GetObjectItem(cjson_array_data,"devManufacturer");
						cJSON * cjson_devModel = cJSON_GetObjectItem(cjson_array_data,"devModel");
						cJSON * cjson_devSeriesNumber = cJSON_GetObjectItem(cjson_array_data,"devSeriesNumber");
						cJSON * cjson_devMac = cJSON_GetObjectItem(cjson_array_data,"devMac");
						cJSON * cjson_devVersion = cJSON_GetObjectItem(cjson_array_data,"devVersion");
						cJSON * cjson_softwareVersion = cJSON_GetObjectItem(cjson_array_data,"softwareVersion");
						cJSON * cjson_deviceId = cJSON_GetObjectItem(cjson_array_data,"deviceId");
						cJSON * cjson_wanIp = cJSON_GetObjectItem(cjson_array_data,"wanIp");
						cJSON * cjson_lanIp = cJSON_GetObjectItem(cjson_array_data,"lanIp");
						cJSON * cjson_protocolVer = cJSON_GetObjectItem(cjson_array_data,"protocolVer");
						if(cjson_devName != NULL)
						{
							/*TODO*/
						}
						else
						{
							log_error("query_res -> data -> devName failed.");
							return -1;
						}

						if(cjson_devType != NULL)
						{
							/*TODO*/
						}
						else
						{
							log_error("query_res -> data -> devType failed.");
							return -1;
						}

						if(cjson_devManufacturer != NULL)
						{
							/*TODO*/
						}
						else
						{
							log_error("query_res -> data -> devManufacturer failed.");
							return -1;
						}
						
						if(cjson_devModel != NULL)
						{
							/*TODO*/
						}
						else
						{
							log_error("query_res -> data -> devModel failed.");
							return -1;
						}
						
						if(cjson_devSeriesNumber != NULL)
						{
							/*TODO*/
						}
						else
						{
							log_error("query_res -> data -> devSeriesNumber failed.");
							return -1;
						}

						if(cjson_devMac != NULL)
						{
							/*TODO*/
						}
						else
						{
							log_error("query_res -> data -> devMac] failed.");
							return -1;
						}

						if(cjson_devVersion != NULL)
						{
							/*TODO*/
						}
						else
						{
							log_error("query_res -> data -> devVersion failed.");
							return -1;
						}

						if(cjson_softwareVersion != NULL)
						{
							/*TODO*/
						}
						else
						{
							log_error("query_res -> data -> softwareVersion failed.");
							return -1;
						}

						if(cjson_deviceId != NULL)
						{
							/*TODO*/
						}
						else
						{
							log_error("query_res -> data -> deviceId failed.");
							return -1;
						}

						if(cjson_wanIp != NULL)
						{
							/*TODO*/
						}
						else
						{
							log_error("query_res -> data -> wanIp failed.");
							return -1;
						}

						if(cjson_lanIp != NULL)
						{
							/*TODO*/
						}
						else
						{
							log_error("query_res -> data -> lanIp failed.");
							return -1;
						}

						if(cjson_protocolVer != NULL)
						{
							/*TODO*/
						}
						else
						{
							log_error("query_res -> data -> protocolVer failed.");
							return -1;
						}
					
					}
					else
					{
						log_error("query_res -> data failed.");
						return -1;
					}
				}
				else
				{
					log_error("query_res index %d failed.",i);
					return -1;
				}
			}
		}
		else
		{
			log_error("query_res failed.");
			return -1;
		}
	}
	else 
	{
		log_error("query_res failed.");
		return -1;
	}
	return 0;
}

/*
code 1008 version
成功返回0，失败返回非0
*/
static int parsing_1008_version(cJSON *retparse)
{
	cJSON *cjson_mac = cJSON_GetObjectItem(retparse,"mac");
	cJSON *cjson_array_query_res = cJSON_GetObjectItem(retparse,"query_res");
	if (cjson_mac != NULL)
	{
		/*TODO*/
	}
	else 
	{
		log_error("mac failed.");
		return -1;
	}
	if (cjson_array_query_res != NULL)
	{
		int array_query_res_len = cJSON_GetArraySize(cjson_array_query_res);
		if(array_query_res_len > 0)
		{
			int i = 0;
			for (; i < array_query_res_len; i++)
			{
				cJSON *cjson_array_value = cJSON_GetArrayItem(cjson_array_query_res,i);
				if(cjson_array_value != NULL)
				{
					cJSON *cjson_array_data = cJSON_GetObjectItem(cjson_array_value,"data");
					cJSON *cjson_name = cJSON_GetObjectItem (cjson_array_value,"name");
					if(cjson_name != NULL)
					{
						/*TODO*/
					}
					else
					{
						log_error("query_res -> name failed.");
						return -1;
					}

					if(cjson_array_data != NULL)
					{

						cJSON * cjson_devVersion = cJSON_GetObjectItem(cjson_array_data,"devVersion");
						cJSON * cjson_softwareVersion = cJSON_GetObjectItem(cjson_array_data,"softwareVersion");
						if(cjson_devVersion != NULL)
						{
							/*TODO*/
						}
						else
						{
							log_error("query_res -> data -> devVersion failed.");
							return -1;
						}

						if(cjson_softwareVersion != NULL)
						{
							/*TODO*/
						}
						else
						{
							log_error("query_res -> data -> softwareVersion failed.");
							return -1;
						}

					}
					else
					{
						log_error("query_res -> data failed.");
						return -1;
					}
				}
				else
				{
					log_error("query_res index %d failed.",i);
					return -1;
				}
			}
		}
		else
		{
			log_error("query_res failed.");
			return -1;
		}
	}
	else 
	{
		log_error("query_res failed.");
		return -1;
	}
	return 0;
}

/*解析返回的json数据，retbuf为需要解析的json数据
成功返回0，失败返回非0*/
int returned_message_is_correct(const char *retbuf)
{
	int iret = 0;
	cJSON* cjson_retparse = NULL;
	if(retbuf == NULL)
	{
		iret = -1;
		log_error("retbuf failed.");
		goto end;
	}
	cjson_retparse = cJSON_Parse(retbuf);
	if(cjson_retparse != NULL)
	{
		cJSON* cjson_code = cJSON_GetObjectItem(cjson_retparse,"code");
		cJSON *cjson_result = cJSON_GetObjectItem(cjson_retparse,"result");
		cJSON *cjson_sequence = cJSON_GetObjectItem(cjson_retparse,"sequence");
		cJSON *cjson_deviceId = cJSON_GetObjectItem(cjson_retparse,"deviceId");

		if (cjson_result != NULL)
		{
			/*TODO*/
		}
		else 
		{
			iret = -1;
			log_error(" result failed.");
			goto end;
		}

		if (cjson_deviceId != NULL)
		{
			/*TODO*/
		}
		else 
		{
			iret = -1;
			log_error(" deviceId failed.");
			goto end;
		}

		if(cjson_code != NULL)
		{
			/*TODO*/
		}
		else 
		{
			iret = -1;
			log_error(" code failed.");
			goto end;
		}

		if(cjson_sequence != NULL)
		{
			char *csequence = cJSON_GetStringValue(cjson_sequence); 

			if (strcmp("7092707747896377344",csequence) == 0 || strcmp("7092707844008853504",csequence) == 0)
			{
				
			}
			else if (strcmp("7092707747896377345",csequence) == 0 || strcmp("7092707844008853505",csequence) == 0)
			{
				/*code 1008 information*/
				if(parsing_1008_information(cjson_retparse))
				{
					iret = -1;
					log_error(" parsing_1008_information(cjson_retparse) failed.");
					goto end;
				}
			}
			else if (strcmp("7092707747896377346",csequence) == 0 || strcmp("7092707844008853506",csequence) == 0)
			{
				/*code 1008 version*/
				if(parsing_1008_version(cjson_retparse))
				{
					iret = -1;
					log_error(" parsing_1008_information(cjson_retparse) failed.");
					goto end;
				}

			}
			else if (strcmp("7092707747896377347",csequence) == 0 || strcmp("7092707844008853507",csequence) == 0)
			{
			}
			else if (strcmp("7092707747896377348",csequence) == 0 || strcmp("7092707844008853508",csequence) == 0)
			{
			}
			else if (strcmp("7092707747896377349",csequence) == 0 || strcmp("7092707844008853509",csequence) == 0)
			{
			}
			else if (strcmp("7092707747896377350",csequence) == 0 || strcmp("7092707844008853510",csequence) == 0)
			{
			}
			else if (strcmp("7092707747896377351",csequence) == 0 || strcmp("7092707844008853511",csequence) == 0)
			{
			}
			else if (strcmp("7092707747896377352",csequence) == 0 || strcmp("7092707844008853512",csequence) == 0)
			{
			}
			else if (strcmp("7092707747896377353",csequence) == 0 || strcmp("7092707844008853513",csequence) == 0)
			{
			}
			else if (strcmp("7092707747896377354",csequence) == 0 || strcmp("7092707844008853514",csequence) == 0)
			{
			}
			else if (strcmp("7092707747896377355",csequence) == 0 || strcmp("7092707844008853515",csequence) == 0)
			{
			}
			else if (strcmp("7092707747896377356",csequence) == 0 || strcmp("7092707844008853516",csequence) == 0)
			{
			}
			else if (strcmp("7092707747896377357",csequence) == 0 || strcmp("7092707844008853517",csequence) == 0)
			{
			}
			else if (strcmp("7092707747896377358",csequence) == 0 || strcmp("7092707844008853518",csequence) == 0)
			{
			}
			else if (strcmp("7092707747896377359",csequence) == 0 || strcmp("7092707844008853519",csequence) == 0)
			{
			}
			else if (strcmp("7092707747896377360",csequence) == 0 || strcmp("7092707844008853520",csequence) == 0)
			{
			}
			else if (strcmp("7092707747896377361",csequence) == 0 || strcmp("7092707844008853521",csequence) == 0)
			{
			}
			else if (strcmp("7092707747896377362",csequence) == 0 || strcmp("7092707844008853522",csequence) == 0)
			{
			}
			else if (strcmp("7092707747896377363",csequence) == 0 || strcmp("7092707844013047808",csequence) == 0)
			{
			}
			else if (strcmp("7092707747896377364",csequence) == 0 || strcmp("7092707844013047809",csequence) == 0)
			{
			}
			else if (strcmp("7092707747896377365",csequence) == 0 || strcmp("7092707844013047810",csequence) == 0)
			{
			}
			else if (strcmp("7092707747896377366",csequence) == 0 || strcmp("7092707844013047811",csequence) == 0)
			{
			}
			else if (strcmp("7092707747896377367",csequence) == 0 || strcmp("7092707844013047812",csequence) == 0)
			{
			}
			else if (strcmp("7092707747896377368",csequence) == 0 || strcmp("7092707844013047813",csequence) == 0)
			{
			}
			else if (strcmp("7092707747896377369",csequence) == 0 || strcmp("7092707844013047814",csequence) == 0)
			{
			}
			else if (strcmp("7092707747896377370",csequence) == 0 || strcmp("7092707844013047815",csequence) == 0)
			{
			}
			else if (strcmp("7092707747896377371",csequence) == 0 || strcmp("7092707844013047816",csequence) == 0)
			{
			}
			else if (strcmp("7092707747896377372",csequence) == 0 || strcmp("7092707844013047817",csequence) == 0)
			{
			}
			else if (strcmp("7092707747896377373",csequence) == 0 || strcmp("7092707844013047818",csequence) == 0)
			{
			}
			else if (strcmp("7092707747896377374",csequence) == 0 || strcmp("7092707844013047819",csequence) == 0)
			{
			}
			else if (strcmp("7092707747896377375",csequence) == 0 || strcmp("7092707844013047820",csequence) == 0)
			{
			}
			else if (strcmp("7092707747896377376",csequence) == 0 || strcmp("7092707844013047821",csequence) == 0)
			{
			}
			else if (strcmp("7092707747896377377",csequence) == 0 || strcmp("7092707844013047822",csequence) == 0)
			{
			}
			else if (strcmp("7092707747896377378",csequence) == 0 || strcmp("7092707844013047823",csequence) == 0)
			{
			}
			else if (strcmp("7092707747896377379",csequence) == 0 || strcmp("7092707844013047824",csequence) == 0)
			{
			}
			else if (strcmp("7092707747896377380",csequence) == 0 || strcmp("7092707844013047825",csequence) == 0)
			{
			}
			else if (strcmp("7092707747896377381",csequence) == 0 || strcmp("7092707844013047826",csequence) == 0)
			{
			}
			else if (strcmp("7092707747896377382",csequence) == 0 || strcmp("7092707844013047827",csequence) == 0)
			{
			}
			else if (strcmp("7092707747896377383",csequence) == 0 || strcmp("7092707844013047828",csequence) == 0)
			{
			}
			else
			{
				log_error("sequence failed.");
				iret = -1;
				goto end;
			}
		}
		else
		{
			log_error("sequence failed.");
			iret = -1;
			goto end;
		}
			
	}
	else
	{
		iret = -1;
		log_error(" cJSON_Parse(retbuf) failed.");
	}

end:
	cJSON_Delete(cjson_retparse);
	return iret;
}



void progress_bar(int flag) {

    if (flag == 1) count ++;

    printf("[%-39s][%c][%.1f%%]\r", buff, lable[count % 4], (count + 1) * 2.5);

    fflush(stdout);

    buff[count] = '>';
}

void config_init(mqtt_info_t *mit) {

   log_info("testapp init start\n"); 

    FILE *fp = NULL;
    char line[MAX_LINE_LEN];

    memset(line, '\0', MAX_LINE_LEN);

    fp = fopen(CONFIG_PATH, "r");

    if (fp == NULL) {
        log_error("test.conf open failed!\n");
        //goto err;
		return;
    }

    while (fgets(line, MAX_LINE_LEN, fp) != NULL) {

        char key[MAX_LINE_LEN], value[MAX_LINE_LEN];
        memset(key, '\0', MAX_LINE_LEN);
        memset(value, '\0', MAX_LINE_LEN);

        if (line[0] == '#' || (line[0] == '/' && line[1] == '/') || line[0] == '\0' || line[0] == '\r' ||  line[0] == '\n' ) {
            continue;
        }
        if (sscanf(line, "%[^=] = %[^\n]", key, value) == 2)
		{
			for (int i = strlen(key) - 1; i >= 0 && key[i] == ' '; --i) 
			{
				key[i] = '\0';
			}
			if (strcmp(key, "host") == 0) 
			{
				//sscanf(value, "%63[^:]:%7s", mit->address, mit->port);
				//log_debug("host: %s:%s\n", value, mit->address, mit->port);
				sscanf(value, "ssl://%63[^:]:%7s", mit->address, mit->port);
				log_debug("host: %s:%s\n", mit->address, mit->port);
			}
			continue;
		} 
		cJSON *cjson_data = cJSON_Parse(line);
		if(cjson_data != NULL)
		{
			/*TODO*/
            
            /*returned_message_is_correct(buf);*/
		}
		else{
			log_error("cjson failed : %s\n",line);
		}
		
    }

err:
    fclose(fp);
}

void mqtt_init(mqtt_info_t * mit) {

    int rc = 0;

    struct mosquitto *mosq = NULL;

    mosq = mosquitto_new(mit->id, true, NULL);

    if (mosq == NULL) {

        log_error("create mosquitto client error...\n");

        mosquitto_lib_cleanup();
    }

    if ((rc = mosquitto_tls_set(mosq, SSL_PATH, NULL, NULL, NULL, NULL)) != MOSQ_ERR_SUCCESS) {

		log_error("Failed to mosquitto_tls_set: %s (%d)\n", mosquitto_strerror(rc), rc);

		mosquitto_lib_cleanup();
	}

	if ((rc = mosquitto_tls_opts_set(mosq, 0, "tlsv1.2", NULL)) != MOSQ_ERR_SUCCESS) {

		log_error("Failed to mosquitto_tls_opts_set: %s (%d)\n", mosquitto_strerror(rc), rc);

		mosquitto_lib_cleanup();
	}

    mit->mosq = mosq;
}

void testapp_init(mqtt_info_t *mit) {

    config_init(mit);

    mqtt_init(mit);

}
