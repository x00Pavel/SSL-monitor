#include <arpa/inet.h>

#include <net/ethernet.h>
#include <net/if.h>

#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <time.h>
#include <stdio.h>
#include <string.h>

#include "functions.h"


void logger(int type, char *msg){
    static int log_count = 0;
    time_t now;
    time(&now);
    struct tm *local = localtime(&now);
    int hours = local->tm_hour;	  	// get hours since midnight (0-23)
	int minutes = local->tm_min;	 	// get minutes passed after the hour (0-59)
	int seconds = local->tm_sec;
    switch (type) {
        case 1:
            printf("\033[0;31m%d - %02d:%02d:%02d - ERROR\033[0m: %s\n", log_count, hours, minutes, seconds, msg);
            break;
        case 2:
            printf("\033[0;34m%d - %02d:%02d:%02d - LOG\033[0m: %s\n", log_count, hours, minutes, seconds,msg);
            break;
        default:
            break;
    }
    log_count++;
}

void process_tls(u_char* payload){
    // printf("%s\n", payload);
}

void packet_handler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet){
    const struct ether_header* ethernet_header;
    const struct iphdr* ip_header;
    const struct tcphdr* tcp_header;
    const struct udphdr* udp_header;
    char source_ip[INET_ADDRSTRLEN], dest_ip[INET_ADDRSTRLEN];
    u_int src_port, dst_port;
    u_char *data;

    
    logger(2, "Processing next packet");
    ethernet_header = (struct ether_header*)packet;
    if (ntohs(ethernet_header->ether_type) == ETHERTYPE_IP){
        ip_header = (struct iphdr*)(packet + sizeof(struct ether_header));
        inet_ntop(AF_INET, &(ip_header->saddr), source_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->daddr), dest_ip, INET_ADDRSTRLEN);
        if (ip_header->protocol != IPPROTO_TCP) {
            logger(1, "Not TCP packet, skip");
        } 
        tcp_header = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));
        src_port = ntohs(tcp_header->source);
        dst_port = ntohs(tcp_header->dest);
        printf("%s:%d -> %s:%d\n", source_ip, src_port, dest_ip, dst_port);
        if (src_port != 443){
            logger(2, "Not TLS protocol");
            return;
        }
        data = (u_char*)(packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr));
        process_tls(data);
    }
    
}


int check_iface(char *buff){
    // TODO
    (void)buff;
    return 0;
}

int check_file(char *buff){
    // TODO
    (void)buff;
    return 0;
}