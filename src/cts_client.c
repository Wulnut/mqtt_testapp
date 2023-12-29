#include "cts_client.h"
#include "common.h"
#include <arpa/inet.h>
#include <libubox/list.h>
#include <libubox/uloop.h>
#include <libubox/utils.h>
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
#include <sys/types.h>
#include <time.h>

cts_client_t     cc;
DNS_request      dns_requests[MAX_DNS_REQUESTS];
int              dns_request_count = 0;
struct list_head session;

static const dns_qtype_entry qtypes[] = {
    {1,     "A"         },
    {2,     "NS"        },
    {3,     "MD"        },
    {4,     "MF"        },
    {5,     "CNAME"     },
    {6,     "SOA"       },
    {7,     "MB"        },
    {8,     "MG"        },
    {9,     "MR"        },
    {10,    "NULL"      },
    {11,    "WKS"       },
    {12,    "RTP"       },
    {13,    "HINFO"     },
    {14,    "MINFO"     },
    {15,    "MX"        },
    {16,    "TXT"       },
    {17,    "RP"        },
    {18,    "AFSDB"     },
    {24,    "SIG"       },
    {25,    "KEY"       },
    {28,    "AAAA"      },
    {29,    "LOC"       },
    {33,    "SRV"       },
    {35,    "NAPTR"     },
    {37,    "CERT"      },
    {39,    "DNAME"     },
    {41,    "OPT"       },
    {42,    "APL"       },
    {43,    "DS"        },
    {44,    "SSHFP"     },
    {45,    "IPSECKEY"  },
    {46,    "RRSIG"     },
    {47,    "NSEC"      },
    {48,    "DNSKEY"    },
    {49,    "DHCID"     },
    {50,    "NSEC3"     },
    {51,    "NSEC3PARAM"},
    {55,    "HIP"       },
    {59,    "CDS"       },
    {60,    "CDNSKEY"   },
    {61,    "OPENPGPKEY"},
    {65,    "HTTPS"     },
    {99,    "SPF"       },
    {249,   "TKEY"      },
    {250,   "TSIG"      },
    {256,   "URI"       },
    {257,   "CAA"       },
    {32768, "TA"        },
    {32769, "DLV"       }
};

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
    ULOG_MARK();
    ULOG_DEBUG("dns_count:%d\n", dns_request_count);

    if (dns_request_count > MAX_DNS_REQUESTS) {
        ULOG_DEBUG("Report: Reached 20 DNS requests.\n");

        for (int i = 0; i < 20; ++i) {
            ULOG_DEBUG("dns: %s\n", dns_requests[i].dns_request);
        }

        dns_request_count = 0;
        return;
    }

    if (dns_request_count > 0 && now - dns_requests[0].timestamp >= 10) {
        ULOG_DEBUG("Report: Earliest DNS request delayed over 10 seconds.\n");
        ULOG_DEBUG("dns: %s\n", dns_requests[0].dns_request);
        dns_request_count = 0;
        return;
    }
}

void add_dns_request(const char *request)
{
    ULOG_MARK();
    ULOG_DEBUG("dns_count:%d\n", dns_request_count);

    if (dns_request_count < MAX_DNS_REQUESTS) {

        strncpy(dns_requests[dns_request_count].dns_request, request,
                sizeof(dns_requests[dns_request_count].dns_request));

        dns_requests[dns_request_count].timestamp = time(NULL);

        dns_request_count++;
    }

    check_and_report();
}

static void parse_dns_name(u_char *dns, u_char *buffer, char *output)
{
    int i   = 0;
    int j   = 0;
    int len = 0;

    while (buffer[i] != 0) {
        len = buffer[i];
        ++i;

        for (j = 0; j < len; ++j) {
            output[i + j - 1] = buffer[i + j];
        }

        output[i + j - 1] = '.';
        i += len;
    }

    output[i + j - 1] = '\0';
}

void parse_dns_answer(u_char *buffer, int answer_offset, int answers)
{
    int i = 0;
    ;

    for (i = 0; i < answers; i++) {
        struct dnsr rr;
        rr.name = &buffer[answer_offset]; // 指向资源记录的名称

        // 跳过域名
        while (buffer[answer_offset] != 0) {
            answer_offset++;
        }
        answer_offset++; // 跳过域名的 null 字节

        // 资源记录头部
        rr.type = ntohs(*(unsigned short *)(buffer + answer_offset));
        answer_offset += 2;
        rr.Class = ntohs(*(unsigned short *)(buffer + answer_offset));
        answer_offset += 2;
        rr.ttl = ntohl(*(unsigned int *)(buffer + answer_offset));
        answer_offset += 4;
        rr.data_len = ntohs(*(unsigned short *)(buffer + answer_offset));
        answer_offset += 2;

        // 资源数据
        rr.rdata = (unsigned char *)malloc(rr.data_len + 1);
        memcpy(rr.rdata, buffer + answer_offset, rr.data_len);
        rr.rdata[rr.data_len] = '\0'; // 如果是字符串类型的数据，确保 null 结尾
        answer_offset += rr.data_len;

        // 打印资源记录的信息
        char domain_name[256];
        parse_dns_name(buffer, rr.name, domain_name);
        printf("Resource Record: %s, Type: %d, Class: %d, TTL: %d, Data Length: %d\n", domain_name, rr.type,
               rr.Class, rr.ttl, rr.data_len);

        _free(rr.rdata);
    }
}

const char *dns_qtype_switch(uint16_t qtype)
{
    int low  = 0;
    int mid  = 0;
    int high = ARRAY_SIZE(qtypes);

    while (low <= high) {
        mid = low + (high - low) / 2;
        if (qtypes[mid].qtype < qtype) {
            low = mid + 1;
        }
        else if (qtypes[mid].qtype > qtype) {
            high = mid - 1;
        }
        else {
            return qtypes[mid].name; // 找到 qtype
        }
    }

    return "Unknown QTYPE";
}

static void get_packet(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    int                       *id                = (int *)arg;
    u_char                    *qname             = NULL;
    char                       domain_name[256]  = "";
    const char                *qtype             = NULL;
    char                       tmp[256]          = "";
    char                      *ipaddr            = NULL;
    const struct ether_header *ethernet_header   = NULL;
    const struct ip           *ip_header         = NULL;
    const struct udphdr       *udp_header        = NULL;
    const struct dnshdr       *dns_header        = NULL;
    const struct dnsq         *dns_question      = NULL;
    unsigned int               ip_header_length  = 0;
    unsigned int               udp_header_length = 0;
    unsigned int               dns_header_length = 0;

    printf("id: %d\n", ++(*id));
    printf("Packet length: %d\n", pkthdr->len);
    printf("Number of bytes: %d\n", pkthdr->caplen);
    printf("Recieved time: %s", ctime((const time_t *)&pkthdr->ts.tv_sec));

    // print frame
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
    printf("\tsrc ip:%d.%d.%d.%d\n", IP_ARG(src));
    printf("\tdest ip:%d.%d.%d.%d\n", IP_ARG(dest));
    printf("\tproto ip:%x\n", ip_header->ip_p);

    // Step 3: Parse UDP Header
    udp_header        = (struct udphdr *)(packet + sizeof(struct ether_header) + ip_header_length);
    udp_header_length = sizeof(struct udphdr);
    printf("\t\tsource:%d dest:%d udp_header_len:%d\n", ntohs(udp_header->uh_sport),
           ntohs(udp_header->uh_dport), udp_header_length);

    // Step 4: Get to the DNS part
    // Parse DNS Header and data here...
    dns_header =
        (struct dnshdr *)(packet + sizeof(struct ether_header) + ip_header_length + udp_header_length);
    dns_header_length = sizeof(struct dnshdr);
    printf("\t\t\tdns_qr:%hhu", dns_header->qr);
    printf(" dns_q:%d", ntohs(dns_header->q_count));
    printf(" dns_an:%d\n", ntohs(dns_header->ans_count));

    // Extract the domain name, query type, etc.
    if (dns_header->qr == 0) {
        qname = (u_char *)(packet + sizeof(struct ether_header) + ip_header_length + udp_header_length
                           + dns_header_length);

        parse_dns_name(NULL, qname, domain_name);
        printf("\t\t\t\tDomain name: %s", domain_name);

        dns_question = (struct dnsq *)(packet + sizeof(struct ether_header) + ip_header_length
                                       + udp_header_length + dns_header_length + (strlen(domain_name) + 1));
        qtype        = dns_qtype_switch(ntohs(dns_question->qtype));
        printf(" Query Type: %s, Query Class: %d\n", qtype, ntohs(dns_question->qclass));

        ipaddr = inet_ntoa(*(struct in_addr *)&ip_header->ip_src);

        snprintf(tmp, sizeof(tmp), "%d,%s,%s,%s;", (int)pkthdr->ts.tv_sec, domain_name, qtype, ipaddr);

        ULOG_DEBUG("Get dns %s\n", tmp);

        add_dns_request(tmp);
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