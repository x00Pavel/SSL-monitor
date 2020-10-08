/**
 * https://stackoverflow.com/questions/39624745/capture-only-ssl-handshake-with-tcpdump
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <stdbool.h>

#define SIZE 10

struct sockaddr_in server;
int count = 0;

typedef struct {
    char ext_type_hex[5];
    unsigned int ext_type;
    char ext_len_hex[5];
    unsigned int ext_len;
    char *data;
} extention;

typedef struct {
    u_int src_ip, dst_ip;
    // char source_ip[INET_ADDRSTRLEN], dest_ip[INET_ADDRSTRLEN];
    u_int src_port, dst_port;
    struct timeval time_stamp;
    time_t duration;
    char *sni;
    u_int packet_count;
    u_int bytes;
} tls_connection;

struct {
    int max_size;
    int current_size;
    tls_connection *connections;
} list_of_connections;

// tls_connection connections[SIZE];
void logger(int type, char *msg) {
    static int log_count = 0;
    time_t now;
    time(&now);
    struct tm *local = localtime(&now);
    int hours = local->tm_hour;   // get hours since midnight (0-23)
    int minutes = local->tm_min;  // get minutes passed after the hour (0-59)
    int seconds = local->tm_sec;
    switch (type) {
        case 1:
            printf("\033[0;31m%d - %02d:%02d:%02d - ERROR\033[0m: %s\n",
                   log_count, hours, minutes, seconds, msg);
            break;
        case 2:
            printf("\033[0;34m%d - %02d:%02d:%02d - LOG\033[0m: %s\n",
                   log_count, hours, minutes, seconds, msg);
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
void process_tls(u_char *payload) {
    uint8_t *content_type = payload;
    char len_hex[5];
    u_int data_size;
    tls_connection *pp = &list_of_connections.connections[list_of_connections.current_size - 1];

    sprintf(len_hex, "%02x%02x",
        *(content_type + 3),
        *(content_type + 4));
    sscanf(len_hex, "%04x", &data_size);
    
    pp->bytes += data_size;

    if (*content_type == 22){
        uint8_t *handshake_type = content_type + 5;
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

        if (*content_type == 22 && *handshake_type == 1) {
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
                    tls_connection *pp = &list_of_connections.connections[list_of_connections.current_size - 1];
                    pp->sni = (char *)malloc(sni_length + 1);
                    snprintf(pp->sni, sni_length, "%s\n", (char *)i + 9);
                    // strncpy(pp->sni, (const char *)i + 9, sni_length);
                }
            }
        }
    }

    // sscanf(payload,"%04x", vers);
    // sprintf(version, "%02x%02x", payload[1], payload[2]);
    // char version = (payload + 8);
    // printf("Version: %d\n", version);
    // printf("Handshake type: %x\n", handshake_type);

    // for (int i = 1; i < 3; i++){
    //     printf("%02x ", payload[i]);
    // }
    // printf("\n");
    // u_int32_t j;
    // for (u_int32_t i = 0; i < size; i = i + 16 ) {
    //     char str[17];

    //     u_int32_t len = 16;
    //     if (i + 16 >= size) {
    //         len = size - i;
    //     } //else {
    //         // printf("0x%04x ", i);
    //     // }
    //         printf("0x%04x ", i );

    //     for (j = 0; j < len; j++) {
    //         printf("%02x ", payload[i + j]);

    //         if (payload[i + j] > 32 && payload[i + j] < 127) {
    //             sprintf(str + j, "%c", payload[i + j]);
    //         } else {
    //             sprintf(str + j, ".");
    //         }
    //     }

    //     if (len != 16) {
    //         for (u_int32_t a = len; a < 16; a++) {
    //             printf("   ");
    //         }
    //     }
    //     if (i != 0 && (i + 16) % 64 == 0) {
    //         printf("%s\n\n", str);
    //     } else {
    //         printf("%s\n", str);
    //     }
    // }

    // printf("\n");
}


void packet_handler(u_char *userData, const struct pcap_pkthdr *pkt_hdr,
                    const u_char *packet) {
    const struct ether_header *ethernet_header;
    const struct iphdr *ip_header;
    const struct tcphdr *tcp_header;
    char source_ip[INET_ADDRSTRLEN], dest_ip[INET_ADDRSTRLEN];
    u_int src_port;
    u_char *data;

    (void)userData;

    logger(2, "Processing next packet");
    ethernet_header = (struct ether_header *)packet;
    if (ntohs(ethernet_header->ether_type) == ETHERTYPE_IP) {
        ip_header = (struct iphdr *)(packet + sizeof(struct ether_header));
        // output = (char*)malloc(80 + 2 * sizeof(u_int) + inet_size);
        // strftime(tmp, 80, "%Y-%m-%d\n%X", info);

        inet_ntop(AF_INET, &(ip_header->saddr), source_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->daddr), dest_ip, INET_ADDRSTRLEN);
        if (ip_header->protocol != IPPROTO_TCP) {
            logger(1, "Not TCP packet, skip");
            return;
        }
        tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) +
                                       sizeof(struct iphdr));
        src_port = ntohs(tcp_header->source);
        tls_connection *conn;
        int index = -1;
        for (int i = 0; i < list_of_connections.current_size; i++){
            conn = &list_of_connections.connections[i];
            if ((conn->src_ip == ip_header->saddr && 
                conn->dst_ip == ip_header->daddr &&
                conn->src_port == tcp_header->source &&
                conn->dst_port == tcp_header->dest) ||
                (conn->src_ip == ip_header->daddr &&
                conn->dst_ip == ip_header->saddr &&
                conn->src_port == tcp_header->dest &&
                conn->dst_port == tcp_header->source)){
                index = i;
                break;
            }
        }
        if (index != -1){
            tls_connection *pp = &list_of_connections.connections[index];
            pp->packet_count++;
            pp->duration = {pkt_hdr->ts.tv_sec - pp->time_stamp.tv_sec, pkt_hdr->ts.tv_usec - pp->time_stamp.tv_usec};
        }
        else{
            tls_connection *new_conn = malloc(sizeof(tls_connection));
            new_conn->dst_ip = ip_header->daddr;
            new_conn->src_ip = ip_header->saddr;
            new_conn->src_port = tcp_header->source;
            new_conn->dst_port = tcp_header->dest;
            new_conn->sni = NULL;
            new_conn->time_stamp = pkt_hdr->ts;
            new_conn->packet_count = 1;
            new_conn->bytes = 0;
            new_conn->duration = 0;
            list_of_connections.connections[list_of_connections.current_size] = *new_conn;
            if (list_of_connections.current_size + 1 == list_of_connections.current_size){
                list_of_connections.connections = realloc(list_of_connections.connections, sizeof(tls_connection) * SIZE);
            }
            list_of_connections.current_size++;
        }

        // int size = pkt_hdr->len - (sizeof(struct ethhdr) + ip_header->ihl * 4 +
        //                            tcp_header->th_off * 4);

        data = (u_char *)(packet + sizeof(struct ethhdr) + ip_header->ihl * 4 +
                          tcp_header->th_off * 4);
        process_tls(data);
        // fprintf(stdout, "%s.%ld, %s, %d, %s, %s\n", tmp, timestamp.tv_usec,
        //         source_ip, src_port, dest_ip, sni);
        // free(sni);
        // fprintf(stdout, "%s.%ld, %s, %d, %s\n", tmp, timestamp.tv_usec,
        // source_ip, src_port, dest_ip);
        count++;
    }
}

void *start_listen(char *iface) {
    logger(2, "Listen interface");
    pcap_t *handler = pcap_open_live(iface, 65536, 1, 0, err_buff);
    struct bpf_program prog;
    const uint8_t *packet;
    struct pcap_pkthdr header;
    if (handler == NULL) {
        logger(1, err_buff);
    }

    // "or (tcp[((tcp[12] & 0xf0) >> 2)] = 0x17))"
    if (pcap_compile(handler, &prog,
                     "tcp port 443 and ((tcp[((tcp[12] & 0xf0) >> 2)] = 0x16)",
                     0, PCAP_NETMASK_UNKNOWN) == 1) {
        logger(1, "Filter can't be created");
        logger(1, pcap_geterr(handler));
    }

    if (pcap_setfilter(handler, &prog) == -1) {
        logger(1, "Filter can't be set");
        logger(1, err_buff);
    }

    for (;;) {
        packet = pcap_next(handler, &header);
        if (packet == NULL) {
            logger(1, "Didn't grab packet");
        }
        packet_handler(NULL, &header, packet);
    }
}

void *process_file(char *file) {
    struct bpf_program prog;
    pcap_t *fp = pcap_open_offline(file, err_buff);
    if (fp == NULL) {
        logger(1, err_buff);
    }
    if (pcap_compile(fp, &prog,
                    "tcp port 443",
                    //  "tcp port 443 and ("
                    //  "(tcp[((tcp[12] & 0xf0) >> 2)] = 0x16) "
                    //  "or (tcp[((tcp[12] & 0xf0) >> 2)] = 0x17) "
                    //  "or (tcp[((tcp[12] & 0xf0) >> 2)] = 0x02) "
                    //  "or (tcp[((tcp[12] & 0xf0) >> 2)] = 0x15) "
                    //  "or (tcp[((tcp[12] & 0xf0) >> 2)] = 0x18) "
                    //  "or (tcp[((tcp[12] & 0xf0) >> 2)] = 0x14))",
                     0, PCAP_NETMASK_UNKNOWN) == -1) {
        logger(1, "Filter can't be created");
        logger(1, pcap_geterr(fp));
    }
    if (pcap_setfilter(fp, &prog) == -1) {
        logger(1, "Filter can't be set");
        logger(1, err_buff);
    }
    logger(2, "Start processing packets");
    list_of_connections.connections = (tls_connection *)malloc(SIZE * sizeof(tls_connection));
    list_of_connections.max_size = SIZE;
    list_of_connections.current_size = 0;
    if (pcap_loop(fp, 0, packet_handler, NULL) < 0) {
        logger(1, pcap_geterr(fp));
    }

    // Print all aggregated packages
    tls_connection *conn; 
    char source_ip[INET_ADDRSTRLEN], dest_ip[INET_ADDRSTRLEN];
    char tmp[80];
    struct tm *info;

    for (int i = 0; i < list_of_connections.current_size; i++){
        conn = &list_of_connections.connections[i];
        info = localtime(&conn->time_stamp.tv_sec);
        strftime(tmp, 80, "%Y-%m-%d %X", info);
        inet_ntop(AF_INET, &(conn->src_ip), source_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(conn->dst_ip), dest_ip, INET_ADDRSTRLEN);
        fprintf(stdout, "------------------------------------\n"
                        "               %d                   \n"
                        "Timestamp: %s.%ld\n"
                        "Source IP: %s,\n"
                        "Source port: %d,\n"
                        "Destination IP: %s,\n"
                        "SNI: %s\n"
                        "Bytes: %d,\n"
                        "Packets:%d\n"
                        "Duration: %d\n", 
            i + 1,
            tmp, 
            conn->time_stamp.tv_usec,
            source_ip, 
            conn->src_port, 
            dest_ip, 
            conn->sni, 
            conn->bytes, 
            conn->packet_count,
            conn->duration);
        free(conn->sni);
    }
    free(list_of_connections.connections);
    // logger(1, "Count of packets in file");
    // printf("%d\n", count);
}

int check_iface(char *iface, char *buff) {
    // TODO
    (void)buff;
    (void)iface;
    return 0;
}

int check_file(char *file, char *buff) {
    // TODO
    (void)buff;
    (void)file;
    return 0;
}