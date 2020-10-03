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

struct sockaddr_in server;

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

typedef struct 
{
    char ext_type_hex[5];
    unsigned int ext_type;
    char ext_len_hex[5];
    unsigned int ext_len;
    char *data;
} extention;


char *process_tls(u_char *payload, u_int32_t size) {
    (void)size;
    uint8_t *content_type = payload;
    uint8_t *handshake_type = content_type +  5;
    uint8_t *session_id_len =  handshake_type + 38;
    uint8_t cipher_suites_length = *(session_id_len + *session_id_len + 1) + *(session_id_len + *session_id_len + 2);
    uint8_t *compress_method_len = session_id_len + *session_id_len + 3 + cipher_suites_length;
    char len_hex[5];
    sprintf(len_hex, "%02x%02x", *(compress_method_len + *compress_method_len + 1), *(compress_method_len + *compress_method_len + 2));
    // uint8_t ext_len = *(compress_method_len + *compress_method_len + 1) + *(compress_method_len + *compress_method_len + 2);
    unsigned int all_ext_len;
    unsigned int res_len;
    sscanf(len_hex, "%04x", &all_ext_len);
    
    sprintf(len_hex, "%02x%02x", *(compress_method_len + *compress_method_len + 6), *(compress_method_len + *compress_method_len + 7));
    sscanf(len_hex, "%04x", &res_len);
    // if (*content_type == 22 && *handshake_type == 1){
    //     printf("Content type: %d\n", *content_type);
    //     printf("Handshake type: %d\n", *handshake_type);
    //     printf("Session ID length: %d\n", *session_id_len);
    //     printf("Cipher suites length: %d\n", cipher_suites_length);
    //     printf("Compression Methods length: %d\n", *compress_method_len);
    //     printf("Compression Methods length: %s\n", len_hex);
    //     printf("Extension length: %d\n", all_ext_len);

    // }
    // uint8_t *serv_name_ext = compress_method_len + *compress_method_len + 7;
    unsigned int ext_len = 0;
    u_char *extenstions = compress_method_len + *compress_method_len + 3;
    extention ext;
    for (u_char *i = extenstions; i < (extenstions + all_ext_len); i += ext.ext_len + 3){
        sprintf(ext.ext_type_hex, "%02x%02x", *(i), *(i+1));
        sscanf(ext.ext_type_hex, "%04x", &ext.ext_type);
        sprintf(ext.ext_len_hex, "%02x%02x", *(i+2), *(i+3));
        sscanf(ext.ext_len_hex, "%04x", &ext.ext_len);
        printf(
        "Extention type hex: %s\nExtention type: %d\n"
        "Extention length hex: %s\nExtention length: %d\n", 
        ext.ext_type_hex, ext.ext_type,ext.ext_len_hex, ext.ext_len);
        
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
    return "No sni";
}

void packet_handler(u_char *userData, const struct pcap_pkthdr *pkt_hdr,
                    const u_char *packet) {
    const struct ether_header *ethernet_header;
    const struct iphdr *ip_header;
    const struct tcphdr *tcp_header;
    char source_ip[INET_ADDRSTRLEN], dest_ip[INET_ADDRSTRLEN];
    u_int src_port, dst_port;
    u_char *data;
    struct timeval timestamp = pkt_hdr->ts;
    struct tm *info = localtime(&timestamp.tv_sec);
    char tmp[80];
    char output[256];

    (void)dst_port;
    (void)userData;

    logger(2, "Processing next packet");
    ethernet_header = (struct ether_header *)packet;
    if (ntohs(ethernet_header->ether_type) == ETHERTYPE_IP) {
        ip_header = (struct iphdr *)(packet + sizeof(struct ether_header));
        // output = (char*)malloc(80 + 2 * sizeof(u_int) + inet_size);
        strftime(tmp, 80, "%Y-%m-%d\n%X", info);
        inet_ntop(AF_INET, &(ip_header->saddr), source_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->daddr), dest_ip, INET_ADDRSTRLEN);
        if (ip_header->protocol != IPPROTO_TCP) {
            logger(1, "Not TCP packet, skip");
            return;
        }
        tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) +
                                       sizeof(struct iphdr));
        src_port = ntohs(tcp_header->source);
        dst_port = ntohs(tcp_header->dest);

        data = (u_char *)(packet + sizeof(struct ethhdr) + ip_header->ihl * 4 +
                          tcp_header->th_off * 4);
        int size = pkt_hdr->len - (sizeof(struct ethhdr) + ip_header->ihl * 4 +
                                   tcp_header->th_off * 4);
        char *sni = process_tls(data, size);

        // fprintf(stdout, "%s.%ld, %s, %d, %s, %s\n", tmp, timestamp.tv_usec,
        //                 source_ip, src_port, dest_ip, sni);

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
                     "tcp port 443 and (tcp[((tcp[12] & 0xf0) >> 2)] = 0x16)",
                     0, PCAP_NETMASK_UNKNOWN) == -1) {
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