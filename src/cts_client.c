#include "cts_client.h"
#include <libubox/list.h>
#include <libubox/uloop.h>
#include <mosquitto.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

cts_client_t     cc;
DNS_request      dns_requests[MAX_DNS_REQUESTS];
int              dns_request_count = 0;
struct list_head session;

static void cc_retry_conn();

static void on_connect(struct mosquitto *mosq, void *obj, int rc)
{
    if (rc) {
        printf("Error with result code: %d\n", rc);
        // 处理连接失败的情况
    }
    else {
        printf("Connected to MQTT broker\n");
        // 连接成功后的操作，例如订阅主题等
    }
}

static void on_message(struct mosquitto *mosq, void *obj, const struct mosquitto_message *msg)
{
    if (msg->payload) {
        printf("Received message on topic %s: %s\n", msg->topic, (char *)msg->payload);
    }
}

static void on_log(struct mosquitto *mosq, void *userdata, int level, const char *str)
{
    printf("mosquitto log: %s\n", str);
}

#if TEST
static void mosquitto_fd_handler(struct uloop_fd *u, unsigned int events)
{
    int fd = mosquitto_socket(cc.mosq);
    if (fd == -1)
        return;
    // 调用 mosquitto_loop 来处理事件
    mosquitto_loop_read(cc.mosq, 1024);
    mosquitto_loop_write(cc.mosq, 1024);
    mosquitto_loop_misc(cc.mosq);
}
#endif

static void cc_connect()
{
    int rc = 0;
#if TEST
    int fd = 0;
#endif

    uloop_timeout_cancel(&cc.connect_timer);

    cc.mosq = mosquitto_new("mqtt_test_0x01", true, NULL);
    if (!cc.mosq) {
        printf("Error: Out of memeory.\n");
        cc_retry_conn();
    }

    mosquitto_connect_callback_set(cc.mosq, on_connect);
    mosquitto_message_callback_set(cc.mosq, on_message);
    mosquitto_log_callback_set(cc.mosq, on_log);

    if ((rc = mosquitto_tls_set(cc.mosq, CER_PATH, NULL, NULL, NULL, NULL)) != MOSQ_ERR_SUCCESS) {
        printf("Failed to mosquitto_tls_set: %s (%d)\n", mosquitto_strerror(rc), rc);
        cc_retry_conn();
    }

    if ((rc = mosquitto_tls_opts_set(cc.mosq, 0, "tlsv1.2", NULL)) != MOSQ_ERR_SUCCESS) {
        printf("Failed to mosquitto_tls_opts_set: %s(%d)\n", mosquitto_strerror(rc), rc);
        cc_retry_conn();
    }

    if ((rc = mosquitto_connect(cc.mosq, cc.addr, atoi(cc.port), 30)) != MOSQ_ERR_SUCCESS) {
        printf("Unable to connect %s(%d), %s:%s\n", mosquitto_strerror(rc), rc, cc.addr, cc.port);
        cc_retry_conn();
    }

#if TEST
    fd = mosquitto_socket(cc.mosq);
    if (fd >= 0) {
        cc.mosquitto_ufd.fd = fd;
        cc.mosquitto_ufd.cb = mosquitto_fd_handler;
        uloop_fd_add(&cc.mosquitto_ufd, ULOOP_READ | ULOOP_WRITE);
    }
#endif

    if ((rc = mosquitto_loop_start(cc.mosq)) != MOSQ_ERR_SUCCESS) {

        printf("Failed to mosquitto loop start: %s (%d)\n", mosquitto_strerror(rc), rc);

        cc_retry_conn();
    }
}

static void cc_disconnect()
{
    mosquitto_disconnect(cc.mosq);
    mosquitto_destroy(cc.mosq);
}

static void cc_reconnect(int interval)
{
    cc_disconnect();
    printf("(\"CTS\") reconnect after %ds\n", interval / 1000);
    uloop_timeout_set(&cc.connect_timer, interval);
}

static void cc_retry_conn()
{
    printf("(\"CTS\") %dth retry auth\n", ++cc.retry_num);

    if (cc.retry_num <= 3) {
        cc_reconnect(1000);
    }
    else {
        cc_reconnect(10000);
    }
}

static void check_and_report()
{
    time_t now = time(NULL);

    if (dns_request_count > MAX_DNS_REQUESTS) {
        printf("Report: Reached 20 DNS requests.\n");
        dns_request_count = 0;
        return;
    }

    if (dns_request_count > 0 && now - dns_requests[0].timestamp >= 10) {
        printf("Report: Earliest DNS request delayed over 10 seconds.\n");
        dns_request_count = 0;
        return;
    }
}

void add_dns_request(const char *request)
{
    if (dns_request_count < MAX_DNS_REQUESTS) {

        strncpy(dns_requests[dns_request_count].dns_request, request,
                sizeof(dns_requests[dns_request_count].dns_request));

        dns_requests[dns_request_count].timestamp = time(NULL);

        dns_request_count++;
    }

    check_and_report();
}

static void get_packet(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    int *id = (int *)arg;

    printf("id: %d\n", ++(*id));
    printf("Packet length: %d\n", pkthdr->len);
    printf("Number of bytes: %d\n", pkthdr->caplen);
    printf("Recieved time: %s", ctime((const time_t *)&pkthdr->ts.tv_sec));

    int i;
    for (i = 0; i < pkthdr->len; ++i) {
        printf(" %02x", packet[i]);
        if ((i + 1) % 16 == 0) {
            printf("\n");
        }
    }

    printf("\n\n");
}

static void *dns_pcap()
{
    pthread_detach(pthread_self());

    int                id                        = 0;
    pcap_t            *device                    = NULL;
    char               err_buf[PCAP_ERRBUF_SIZE] = "";
    char              *dev_interface             = NULL;
    char               filter_exp[]              = "udp port 53";
    struct bpf_program filter;
    bpf_u_int32        net = 0;

    dev_interface = pcap_lookupdev(err_buf);

    if (dev_interface == NULL)
        printf("Could not get device interface\n");

    device = pcap_open_live(dev_interface, 65535, 1, 3000, err_buf);

    if (device == NULL) {
        printf("Could not open device %s: %s\n", dev_interface, err_buf);
    }

    if (pcap_compile(device, &filter, filter_exp, 0, net) == -1)
        printf("Could not parse filter %s: %s\n", filter_exp, pcap_geterr(device));

    if (pcap_setfilter(device, &filter) == -1)
        printf("Could not install filter %s: %s\n", filter_exp, pcap_geterr(device));

    pcap_loop(device, -1, get_packet, (u_char *)&id);

    pcap_close(device);

    pthread_exit(0);
}

static void connect_cb(struct uloop_timeout *timeout) { cc_connect(); }

static int config_init()
{
    FILE *fp                  = NULL;
    char  line[MAX_LINE_LEN]  = "";
    char  key[MAX_LINE_LEN]   = "";
    char  value[MAX_LINE_LEN] = "";

    fp = fopen(CONFIG_PATH, "r");

    if (fp == NULL) {
        printf("ini.conf open failed\n");
        return 0;
    }

    while (fgets(line, 1024, fp) != NULL) {

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

        if (strcmp(key, "ip") == 0) {
            strncpy(cc.addr, value, strlen(value) + 1);
            continue;
        }

        if (strcmp(key, "port") == 0) {
            strncpy(cc.port, value, strlen(value) + 1);
        }
    }

    fclose(fp);
    return 1;
}

void cc_init()
{
    pthread_t dns;

    if (config_init() == 0)
        printf("config init failed\n");

    if (strlen(cc.addr) == 0 || strlen(cc.port) == 0) {
        strncpy(cc.addr, DEFAULT_ADDR, sizeof(DEFAULT_ADDR));
        strncpy(cc.port, DEFAULT_PORT, sizeof(DEFAULT_PORT));
    }

    if (mosquitto_lib_init() < 0)
        printf("mosquitto lib init failed\n");

    if (pthread_create(&dns, NULL, dns_pcap, (void *)0) != 0)
        printf("dns packet thread init failed\n");

    cc.retry_num        = 1;
    cc.connect_timer.cb = connect_cb;

    INIT_LIST_HEAD(&session);
}

void cc_run() { cc_connect(); }

void cc_done()
{
    mosquitto_disconnect(cc.mosq);
    mosquitto_destroy(cc.mosq);
    mosquitto_lib_cleanup();
}