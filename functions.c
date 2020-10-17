/**
 * TODO:
 */

#include "functions.h"

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define SIZE 10

struct sockaddr_in server;
int count = 0;
int free_index = -1;

typedef struct {
    char ext_type_hex[5];
    unsigned int ext_type;
    char ext_len_hex[5];
    unsigned int ext_len;
    char *data;
} extention;

typedef struct tls_conn{
    u_int src_ip, dst_ip;
    u_int16_t src_port, dst_port;
    struct timeval time_stamp;
    double duration;
    char *sni;
    u_int packet_count;
    u_int bytes;
    u_int addr_size;
    bool server_fin;
    bool server_ack;
    bool client_ack;
    bool client_fin;
    bool last_ack;
    struct tls_conn *prev;
    struct tls_conn *next;
} tls_connection;

tls_connection *connections;


tls_connection *get_conn(const struct iphdr *ip_header, const struct tcphdr *tcp_header){
    tls_connection *pp = connections;
    while (pp != NULL){
        if ((pp->src_ip   == ip_header->saddr) &&
            (pp->dst_ip   == ip_header->daddr) &&
            (pp->src_port == tcp_header->source) &&
            (pp->dst_port == tcp_header->dest)){
            if (tcp_header->th_flags == 0x011){
                pp->client_fin = true;
                pp->client_ack = true;
            }
            // If it is really the last packet in TCP connection
            else if (pp->client_fin && pp->client_ack && pp->server_ack && pp->server_fin && (tcp_header->th_flags == 0x010)){ 
                pp->last_ack = true;
            }
            return pp;
        }
        else if ((pp->src_ip   == ip_header->daddr) &&
                (pp->dst_ip   == ip_header->saddr) &&
                (pp->src_port == tcp_header->dest) &&
                (pp->dst_port == tcp_header->source)) {
            if (tcp_header->th_flags == 0x011){
                pp->server_fin = true;
                pp->server_ack = true;
            }
            // If it is really the last packet in TCP connection
            else if (pp->client_fin && pp->client_ack && pp->server_ack && pp->server_fin && (tcp_header->th_flags == 0x010)){
                pp->last_ack = true;
            }
            return pp;
        } 
        pp = pp->next;
    }
    return NULL;
}


void insert_conn(tls_connection *conn){
    if (connections == NULL){
        conn->next = NULL;
        conn->prev = NULL;
        connections = conn;
    }
    else{        
        conn->prev = NULL;
        conn->next = connections;
        connections->prev = conn;
        connections = conn;        
    }
}


tls_connection *delete_conn(tls_connection *conn){
    tls_connection *prev = conn->prev;
    tls_connection *next = conn->next;
    if (prev != NULL){
        prev->next = next;
    }
    if (next != NULL){
        next->prev = prev;
    }
    if (strcmp("No SNI", conn->sni) != 0) {
        free(conn->sni);
    }
    free(conn);
    return next;
}


void clean_up(int dummy){
    (void)dummy;
    tls_connection *conn = connections;
    while (conn != NULL){
        conn = delete_conn(conn);
    }
    logger(2, "Cleaning up is done");
    logger(2, "Exit");
    exit(0);
}


void logger(int type, void *msg) {
    static int log_count = 0;
    time_t now;
    time(&now);
    struct tm *local = localtime(&now);
    int hours = local->tm_hour;   // get hours since midnight (0-23)
    int minutes = local->tm_min;  // get minutes passed after the hour (0-59)
    int seconds = local->tm_sec;
    static int i = 1;
    (void)i;
    tls_connection *pp;
    char *source_ip;
    char *dest_ip;
    struct tm *info;
    char tmp[80];

    switch (type) {
        case 1:
            printf("\033[0;31m%d - %02d:%02d:%02d - ERROR\033[0m: %s\n",
                   log_count, hours, minutes, seconds, (char*)msg);
            break;
        case 2:
            printf("\033[0;34m%d - %02d:%02d:%02d - LOG\033[0m: %s\n",
                   log_count, hours, minutes, seconds, (char*)msg);
            break;
        case 3:
            pp = (tls_connection*)msg;
            info = localtime(&pp->time_stamp.tv_sec);
            source_ip = (char*)malloc(pp->addr_size);
            dest_ip = (char*)malloc(pp->addr_size);

            strftime(tmp, 80, "%Y-%m-%d %X", info);
            inet_ntop(AF_INET, &(pp->src_ip), source_ip, pp->addr_size);
            inet_ntop(AF_INET, &(pp->dst_ip), dest_ip, pp->addr_size);
            #ifdef DEBUG
            fprintf(stdout,
                "------------------------------------\n"
                "               %d                   \n"
                "Timestamp: %s.%ld\n"
                "Source IP: %s,\n"
                "Source port: %d,\n"
                "Destination port: %d,\n"
                "Destination IP: %s,\n"
                "SNI: %s\n"
                "Bytes: %d,\n"
                "Packets:%d\n"
                "Duration: %.3f\n",
                i++, tmp, pp->time_stamp.tv_usec, source_ip, ntohs(pp->src_port),ntohs(pp->dst_port),
                dest_ip, pp->sni, pp->bytes, pp->packet_count,
                pp->duration);
            #else
            fprintf(stdout, "%s.%ld, %s, %d, %s, %s, %d, %d, %.3f\n",
                tmp, pp->time_stamp.tv_usec, source_ip, ntohs(pp->src_port),
                dest_ip, pp->sni, pp->bytes, pp->packet_count,
                pp->duration);
            #endif

            free(source_ip);
            free(dest_ip);
            break;
        default:
            break;
    }
    log_count++;
}

/**
 * Parse TLS headers
 *
 * @param[in] payload - whole TLS packet
 * @param[in] size - size of given packet
 *
 * @return pointer to the string with SNI
 */
void process_tls(tls_connection *pp, u_char *payload) {
    uint8_t *content_type = payload;
    char len_hex[5];

    if (*content_type >=20 && *content_type <= 23){
        u_int data_size;
        sprintf(len_hex, "%02x%02x", *(content_type + 3), *(content_type + 4));
        sscanf(len_hex, "%04x", &data_size);
        pp->bytes += data_size;
    }

    if (*content_type == 22) {
        uint8_t *handshake_type = content_type + 5;
        if (*handshake_type == 1) {
            uint8_t *session_id_len = handshake_type + 38;
            uint8_t cipher_suites_length = *(session_id_len + *session_id_len + 1) +
                                        *(session_id_len + *session_id_len + 2);
            uint8_t *compress_method_len =
                session_id_len + *session_id_len + 3 + cipher_suites_length;

            extention ext;
            unsigned int sni_length;

            // Get size of all extansions
            unsigned int all_ext_len;

            // Take pointer to the first extantion
            u_char *extenstions = compress_method_len + *compress_method_len + 3;

            sprintf(len_hex, "%02x%02x",
                    *(compress_method_len + *compress_method_len + 1),
                    *(compress_method_len + *compress_method_len + 2));
            sscanf(len_hex, "%04x", &all_ext_len);
            // Find Client Hello
            for (u_char *i = extenstions; i < (extenstions + all_ext_len);
                 i += ext.ext_len + 4) {
                sprintf(ext.ext_type_hex, "%02x%02x", *(i), *(i + 1));
                sscanf(ext.ext_type_hex, "%04x", &ext.ext_type);
                sprintf(ext.ext_len_hex, "%02x%02x", *(i + 2), *(i + 3));
                sscanf(ext.ext_len_hex, "%04x", &ext.ext_len);
                if (ext.ext_type == 0) {  // 0 - Client hello
                    sprintf(len_hex, "%02x%02x", *(i + 7), *(i + 8));
                    sscanf(len_hex, "%04x", &sni_length);
                    pp->sni = (char *)malloc(sni_length + 1);
                    snprintf(pp->sni, sni_length, "%s\n", (char *)i + 9);
                }
            }
        }
    }
}


double time_diff(struct timeval x, struct timeval y) {
    double x_ms, y_ms, diff;

    x_ms = (double)x.tv_sec * 1000000 + (double)x.tv_usec;
    y_ms = (double)y.tv_sec * 1000000 + (double)y.tv_usec;

    diff = (double)x_ms - (double)y_ms;

    return diff / 100000;
}


void packet_handler(u_char *userData, const struct pcap_pkthdr *pkt_hdr, const u_char *packet) {
    const struct ether_header *ethernet_header;
    const struct iphdr *ip_header;
    const struct tcphdr *tcp_header;
    u_char *data;

    (void)userData;

    ethernet_header = (struct ether_header *)packet;
    if (ntohs(ethernet_header->ether_type) == ETHERTYPE_IP) {
        tls_connection *conn;
        ip_header = (struct iphdr *)(packet + sizeof(struct ether_header));

        if (ip_header->protocol != IPPROTO_TCP) {
            logger(1, "Not TCP packet, skip");
            return;
        }
        logger(2, "Processing next packet");

        tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) +
                                       sizeof(struct iphdr));

        conn = get_conn(ip_header, tcp_header);
        
        if (conn == NULL){
            conn = (tls_connection*)malloc(sizeof(tls_connection));
            conn->dst_ip = ip_header->daddr;
            conn->src_ip = ip_header->saddr;
            conn->src_port = tcp_header->source;
            conn->dst_port = tcp_header->dest;
            conn->sni = "No SNI";
            conn->time_stamp = pkt_hdr->ts;
            conn->packet_count = 1;
            conn->bytes = 0;
            conn->duration = 0;
            conn->server_ack = false;
            conn->server_fin = false;
            conn->client_ack = false;
            conn->client_fin = false;
            conn->last_ack = false;
            conn->addr_size = ip_header->version == 4 ? INET_ADDRSTRLEN : INET6_ADDRSTRLEN;
                
            insert_conn(conn);
        }
        else{
            conn->packet_count++;
            conn->duration = time_diff(pkt_hdr->ts, conn->time_stamp);
            if (userData != NULL){ // It is live stream
                if (conn->last_ack){
                    logger(2, "Last packet");
                    logger(3, conn);
                    delete_conn(conn);
                }
            }
        }
        int size = sizeof(struct ethhdr) + ip_header->ihl * 4 + tcp_header->th_off * 4;
        if ((pkt_hdr->len - size) > 0){
            data = (u_char *)(packet + size);
            process_tls(conn, data);
        }
        count++;
    }
}



void *start_listen(void *p) {
    pcap_t *handler = (pcap_t *)p;
    logger(2, "Listen interface");
    struct bpf_program prog;
    const uint8_t *packet;
    struct pcap_pkthdr header;
    char err_buff[PCAP_ERRBUF_SIZE];
    connections = NULL;
    if (handler == NULL) {
        logger(1, err_buff);
    }

    if (pcap_compile(handler, &prog, "tcp port 443", 0, PCAP_NETMASK_UNKNOWN) == 1) {
        logger(1, "Filter can't be created");
        logger(1, pcap_geterr(handler));
    }

    if (pcap_setfilter(handler, &prog) == -1) {
        logger(1, "Filter can't be set");
        logger(1, err_buff);
    }

    int rc = pcap_loop(handler, -1, packet_handler, (unsigned char *)"");

    pthread_exit(NULL);
}

void *process_file(void *p) {
    char *file = (char*)p;
    struct bpf_program prog;
    char err_buff[PCAP_ERRBUF_SIZE];

    pcap_t *fp = pcap_open_offline(file, err_buff);
    if (fp == NULL) {
        logger(1, err_buff);
    }

    if (pcap_compile(fp, &prog, "tcp port 443", 0, PCAP_NETMASK_UNKNOWN) ==
        -1) {
        logger(1, "Filter can't be created");
        logger(1, pcap_geterr(fp));
    }

    if (pcap_setfilter(fp, &prog) == -1) {
        logger(1, "Filter can't be set");
        logger(1, err_buff);
    }

    logger(2, "Start processing packets");

    if (pcap_loop(fp, 0, packet_handler, NULL) < 0) {
        logger(1, pcap_geterr(fp));
    }
    
    // Print all aggregated packages
    tls_connection *conn = connections;
    while (conn != NULL){
        logger(3, conn);
        conn = delete_conn(conn);
    }

    pthread_exit(NULL);
}

pcap_t * check_iface(char *iface) {
    char err_buff[PCAP_ERRBUF_SIZE];
    pcap_t *handler = pcap_open_live(iface, 65536, 1, 0, err_buff);
    if (handler == NULL) {
        logger(1, "Couldn't open device");
        logger(1, err_buff);
        return NULL;
    }
    return handler;
}

int check_file(char *file) {
    printf("Filename: %s\n", file);
    if(access( file, F_OK ) == -1 ) {
        logger(1, "Given file does not exist");
        return 1;
    }
    return 0;
}