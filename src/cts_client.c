#include "cts_client.h"
#include "common.h"
#include <libubox/list.h>
#include <libubox/uloop.h>
#include <mosquitto.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include <stdbool.h>
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
        ULOG_INFO("Error with result code: %d\n", rc);
        // 处理连接失败的情况
    }
    else {
        ULOG_INFO("Connected to MQTT broker\n");
        // 连接成功后的操作，例如订阅主题等
    }
}

static void on_message(struct mosquitto *mosq, void *obj, const struct mosquitto_message *msg)
{
    if (msg->payload) {
        ULOG_INFO("Received message on topic %s: %s\n", msg->topic, (char *)msg->payload);
    }
}

static void on_log(struct mosquitto *mosq, void *userdata, int level, const char *str)
{
    ULOG_INFO("mosquitto log: %s\n", str);
}

#if TEST
static void mosquitto_fd_handler(struct uloop_fd *u, unsigned int events)
{
    // ULOG_MARK();

    mosquitto_loop_misc(cc.mosq);

    if (events & ULOOP_READ) {
        // ULOG_MARK();
        mosquitto_loop_read(cc.mosq, 65535);
    }

    if (events & ULOOP_WRITE) {
        // ULOG_MARK();
        mosquitto_loop_write(cc.mosq, 65535);
    }
}
#endif

static void *cc_connect()
{
    ULOG_MARK();

    pthread_detach(pthread_self());

    int rc = 0;
#if TEST
    int fd = 0;
#endif

    uloop_timeout_cancel(&cc.connect_timer);

    cc.mosq = mosquitto_new("mqtt_test_0x01", true, NULL);
    if (!cc.mosq) {
        ULOG_DEBUG("Error: Out of memeory.\n");
        cc_retry_conn();
    }

    mosquitto_connect_callback_set(cc.mosq, on_connect);
    mosquitto_message_callback_set(cc.mosq, on_message);
    mosquitto_log_callback_set(cc.mosq, on_log);

    if ((rc = mosquitto_tls_set(cc.mosq, CER_PATH, NULL, NULL, NULL, NULL)) != MOSQ_ERR_SUCCESS) {
        ULOG_DEBUG("Failed to mosquitto_tls_set: %s (%d)\n", mosquitto_strerror(rc), rc);
        cc_retry_conn();
    }

    if ((rc = mosquitto_tls_opts_set(cc.mosq, 0, "tlsv1.2", NULL)) != MOSQ_ERR_SUCCESS) {
        ULOG_DEBUG("Failed to mosquitto_tls_opts_set: %s(%d)\n", mosquitto_strerror(rc), rc);
        cc_retry_conn();
    }

    if ((rc = mosquitto_connect(cc.mosq, cc.addr, atoi(cc.port), 30)) != MOSQ_ERR_SUCCESS) {
        ULOG_DEBUG("Unable to connect %s(%d), %s:%s\n", mosquitto_strerror(rc), rc, cc.addr, cc.port);
        cc_retry_conn();
    }

#if TEST
    fd = mosquitto_socket(cc.mosq);
    if (fd >= 0) {

        cc.mosquitto_ufd.fd         = fd;
        cc.mosquitto_ufd.cb         = mosquitto_fd_handler;
        cc.mosquitto_ufd.registered = false;
        cc.mosquitto_ufd.flags      = ULOOP_READ | ULOOP_WRITE;

        uloop_fd_add(&cc.mosquitto_ufd, ULOOP_READ | ULOOP_WRITE);
    }

    uloop_timeout_set(&cc.misc_loop_timer, 250);
#endif

    if ((rc = mosquitto_loop_start(cc.mosq)) != MOSQ_ERR_SUCCESS) {

        ULOG_DEBUG("Failed to mosquitto loop start: %s (%d)\n", mosquitto_strerror(rc), rc);

        cc_retry_conn();
    }

    pthread_exit(0);
}

static void cc_disconnect()
{
    mosquitto_disconnect(cc.mosq);
    mosquitto_destroy(cc.mosq);
}

static void cc_reconnect(int interval)
{
    cc_disconnect();
    ULOG_DEBUG("(\"CTS\") reconnect after %ds\n", interval / 1000);
    uloop_timeout_set(&cc.connect_timer, interval);
}

static void cc_retry_conn()
{
    ULOG_DEBUG("(\"CTS\") %dth retry auth\n", ++cc.retry_num);

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
        ULOG_DEBUG("Report: Reached 20 DNS requests.\n");
        dns_request_count = 0;
        return;
    }

    if (dns_request_count > 0 && now - dns_requests[0].timestamp >= 10) {
        ULOG_DEBUG("Report: Earliest DNS request delayed over 10 seconds.\n");
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
    int                       *id                = (int *)arg;
    const struct ether_header *ethernet_header   = NULL;
    const struct ip           *ip_header         = NULL;
    const struct udphdr       *udp_header        = NULL;
    const dns_header_t        *dns_header        = NULL;
    unsigned int               ip_header_length  = 0;
    unsigned int               udp_header_length = 0;

    printf("id: %d\n", ++(*id));
    printf("Packet length: %d\n", pkthdr->len);
    printf("Number of bytes: %d\n", pkthdr->caplen);
    printf("Recieved time: %s", ctime((const time_t *)&pkthdr->ts.tv_sec));

    for (int i = 0; i < pkthdr->len; ++i) {
        printf(" %02x", packet[i]);
        if ((i + 1) % 16 == 0) {
            printf("\n");
        }
    }

    // Step 1: Parse Ethernet Header
    ethernet_header = (struct ether_header *)packet;
    if (ntohs(ethernet_header->ether_type) != ETHERTYPE_IP)
        return;
    printf("\nh_dest:%02x:%02x:%02x:%02x:%02x:%02x \n", MAC_ARG(ethernet_header->ether_dhost));
    printf("h_source:%02x:%02x:%02x:%02x:%02x:%02x \n", MAC_ARG(ethernet_header->ether_shost));
    printf("h_proto:%04x\n", ntohs(ethernet_header->ether_type));

    // Step 2: Parse IP Header
    ip_header           = (struct ip *)(packet + sizeof(struct ether_header));
    ip_header_length    = ip_header->ip_hl * 4; // IP header length
    unsigned char *src  = (unsigned char *)&(ip_header->ip_src);
    unsigned char *dest = (unsigned char *)&(ip_header->ip_dst);
    printf("\nsrc ip:%d.%d.%d.%d\n", IP_ARG(src));
    printf("dest ip:%d.%d.%d.%d\n", IP_ARG(dest));
    printf("proto ip:%x", ip_header->ip_p);

    // Step 3: Parse UDP Header
    udp_header        = (struct udphdr *)(packet + sizeof(struct ether_header) + ip_header_length);
    udp_header_length = sizeof(struct udphdr);
    printf("\nsource:%d dest:%d udp_header_len:%d\n", ntohs(udp_header->uh_sport),
           ntohs(udp_header->uh_dport), udp_header_length);

    // Step 4: Get to the DNS part
    dns_header =
        (dns_header_t *)(packet + sizeof(struct ether_header) + ip_header_length + udp_header_length);
    printf("\ndns_header:%d\n", dns_header->tid);

    // Parse DNS Header and data here...
    // Extract the domain name, query type, etc.

    printf("\n\n");
}

static void *dns_pcap()
{
    pthread_detach(pthread_self());

    int                id                        = 0;
    pcap_t            *device                    = NULL;
    char               err_buf[PCAP_ERRBUF_SIZE] = "";
    char              *dev_interface             = NULL;
    char               filter_exp[]              = "port domain";
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
        ULOG_DEBUG("ini.conf open failed\n");
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
    if (config_init() == 0)
        ULOG_DEBUG("config init failed\n");

    if (strlen(cc.addr) == 0 || strlen(cc.port) == 0) {
        strncpy(cc.addr, DEFAULT_ADDR, sizeof(DEFAULT_ADDR));
        strncpy(cc.port, DEFAULT_PORT, sizeof(DEFAULT_PORT));
    }

    if (mosquitto_lib_init() < 0)
        ULOG_DEBUG("mosquitto lib init failed\n");

    cc.retry_num        = 1;
    cc.connect_timer.cb = connect_cb;

    INIT_LIST_HEAD(&session);
}

void cc_run()
{
    pthread_t dns;
    pthread_t mqtt;

    // cc_connect();

    if (pthread_create(&mqtt, NULL, cc_connect, (void *)0) != 0)
        ULOG_DEBUG("mqtt loop thread init failed\n");

    if (pthread_create(&dns, NULL, dns_pcap, (void *)0) != 0)
        ULOG_DEBUG("dns packet thread init failed\n");
}

void cc_done()
{
    mosquitto_disconnect(cc.mosq);
    mosquitto_destroy(cc.mosq);
    mosquitto_lib_cleanup();
}