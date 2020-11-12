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
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define SIZE 10

typedef struct {
    char ext_type_hex[5];
    unsigned int ext_type;
    char ext_len_hex[5];
    unsigned int ext_len;
    char *data;
} extention;

typedef struct {
    uint8_t type_hex;
    char version_hex[5];
    unsigned int version;
    char len_hex[5];
    unsigned int len;
    char *data;
} tls_header;

typedef struct tls_conn {
    u_int src_ip, dst_ip;
    struct in6_addr ip6_src, ip6_dst;
    u_int16_t src_port, dst_port;
    struct timeval time_stamp;
    double duration;
    char *sni;
    u_int packet_count;
    u_int bytes;
    u_int addr_size;
    bool server_fin, client_fin, last_ack;
    struct tls_conn *prev, *next;
} tls_connection;

tls_connection *connections;

void logger(int type, void *msg) {
    tls_connection *pp;
    char *source_ip;
    char *dest_ip;
    struct tm *info;
    char tmp[80];
    if (type == 3) {
        pp = (tls_connection *)msg;
        // In case if SNI name is not present in connect
        // there is no reason to return is 
        // if (strcmp(pp->sni, "No SNI") != 0) {
            info = localtime(&pp->time_stamp.tv_sec);
            source_ip = (char *)malloc(pp->addr_size);
            dest_ip = (char *)malloc(pp->addr_size);
            strftime(tmp, 80, "%Y-%m-%d %X", info);
            if (pp->addr_size == INET6_ADDRSTRLEN) {
                inet_ntop(AF_INET6, &(pp->ip6_dst), source_ip, pp->addr_size);
                inet_ntop(AF_INET6, &(pp->ip6_src), dest_ip, pp->addr_size);
            } else if (pp->addr_size == INET_ADDRSTRLEN) {
                inet_ntop(AF_INET, &(pp->src_ip), source_ip, pp->addr_size);
                inet_ntop(AF_INET, &(pp->dst_ip), dest_ip, pp->addr_size);
            }
            fprintf(stdout, "%s.%06ld,%s,%d,%s,%s,%d,%d,%f\n", tmp,
                    pp->time_stamp.tv_usec, source_ip, ntohs(pp->src_port), dest_ip,
                    pp->sni, pp->bytes, pp->packet_count, pp->duration);
            free(source_ip);
            free(dest_ip);
        // }
    }
}

void insert_conn(tls_connection *conn) {
    if (connections == NULL) {
        conn->next = NULL;
        conn->prev = NULL;
        connections = conn;
    } else {
        conn->prev = NULL;
        conn->next = connections;
        connections->prev = conn;
        connections = conn;
    }
}

tls_connection *delete_conn(tls_connection *conn) {
    tls_connection *prev = conn->prev;
    tls_connection *next = conn->next;
    if (prev != NULL) {
        prev->next = next;
    } else {
        // It is the first element in the list -> need to move pointer
        connections = next;
    }
    if (next != NULL) {
        next->prev = prev;
    }

    if (strcmp("No SNI", conn->sni) != 0) {
        free(conn->sni);
    }
    free(conn);
    return next;
}

void cleanup(int dummy) {
    (void)dummy;
    tls_connection *conn = connections;
    while (conn != NULL) {
        conn = delete_conn(conn);
    }
    exit(0);
}

double time_diff(struct timeval x, struct timeval y) {
    double x_ms, y_ms, diff;

    x_ms = (double)x.tv_sec * 1000000 + (double)x.tv_usec;
    y_ms = (double)y.tv_sec * 1000000 + (double)y.tv_usec;

    diff = (double)x_ms - (double)y_ms;

    return diff / 1000000;
}

void preprocess_packet(tls_connection *pp, bool client, uint16_t fin) {
    if (fin) {
        if (client) {
            pp->client_fin = true;
        } else {
            pp->server_fin = true;
        }
    }
    // If it is really the last packet in TCP connection
    if (pp->client_fin && pp->server_fin) {
        pp->last_ack = true;
    }
    if (!pp->last_ack) {
        pp->packet_count++;
    }
}

bool cmp_ip6(struct in6_addr client_src, struct in6_addr client_dst,
             struct in6_addr server_src, struct in6_addr server_dst) {
    for (int i = 0; i < 16; ++i) {
        if (client_src.s6_addr[i] != server_src.s6_addr[i]){
            return false;
        }
        else if (client_dst.s6_addr[i] != server_dst.s6_addr[i]){
            return false;
        }
    }
    return true;
}

tls_connection *get_conn_6(const struct ip6_hdr *ip6_header,
                           const struct tcphdr *tcp_header) {
    tls_connection *pp = connections;
    while (pp != NULL) {
        if (pp->addr_size == INET6_ADDRSTRLEN) {
            if (cmp_ip6(pp->ip6_src, pp->ip6_dst, ip6_header->ip6_src,
                        ip6_header->ip6_dst)) {
                preprocess_packet(pp, true, tcp_header->fin);
                return pp;
            }
            if (cmp_ip6(pp->ip6_src, pp->ip6_dst, ip6_header->ip6_dst,
                        ip6_header->ip6_src)) {
                preprocess_packet(pp, false, tcp_header->fin);
                return pp;
            }
        }
        pp = pp->next;
    }
    return NULL;
}

tls_connection *get_conn(const struct iphdr *ip_header,
                         const struct tcphdr *tcp_header) {
    tls_connection *pp = connections;
    while (pp != NULL) {
        if ((pp->src_ip == ip_header->saddr) &&
            (pp->dst_ip == ip_header->daddr) &&
            (pp->src_port == tcp_header->source) &&
            (pp->dst_port == tcp_header->dest)) {
            preprocess_packet(pp, true, tcp_header->fin);
            return pp;
        }
        if ((pp->src_ip == ip_header->daddr) &&
            (pp->dst_ip == ip_header->saddr) &&
            (pp->src_port == tcp_header->dest) &&
            (pp->dst_port == tcp_header->source)) {
            // Set identify value of other side for reassembling
            preprocess_packet(pp, false, tcp_header->fin);
            return pp;
        }
        pp = pp->next;
    }
    return NULL;
}

/**
 * Parse TLS headers
 *
 * @param[in] payload - whole TLS packet
 * @param[in] size - size of given packet
 *
 * @return pointer to the string with SNI
 */
void process_tls(tls_connection *pp, u_char *payload, size_t size_of_data) {
    tls_header tls_header;
    for (u_char *j = payload; j < (payload + size_of_data);
         j += tls_header.len + 5) {
        tls_header.type_hex = *j;
        sprintf(tls_header.version_hex, "%02x%02x", *(j + 1), *(j + 2));
        sscanf(tls_header.version_hex, "%04x", &tls_header.version);
        sprintf(tls_header.len_hex, "%02x%02x", *(j + 3), *(j + 4));
        sscanf(tls_header.len_hex, "%04x", &tls_header.len);

        if (tls_header.type_hex == 22) {
            char len_hex[5];
            uint8_t *handshake_type = payload + 5;
            if (*handshake_type == 1) {
                uint8_t *session_id_len = handshake_type + 38;
                uint8_t cipher_suites_length =
                    *(session_id_len + *session_id_len + 1) +
                    *(session_id_len + *session_id_len + 2);
                uint8_t *compress_method_len =
                    session_id_len + *session_id_len + 3 + cipher_suites_length;

                extention ext;
                unsigned int sni_length;

                // Get size of all extansions
                unsigned int all_ext_len;

                // Take pointer to the first extantion
                u_char *extenstions =
                    compress_method_len + *compress_method_len + 3;

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
                        pp->sni = (char *)malloc(sni_length + 2);
                        snprintf(pp->sni, sni_length + 1, "%s\n",
                                 (char *)i + 9);
                        break;
                    }
                }
            }
        }

        if ((tls_header.type_hex >= 20) && (tls_header.type_hex <= 23)) {
            pp->bytes += tls_header.len;
        }
    }
}

tls_connection *create_conn(const void *ip_header, bool ipv4,
                            const struct tcphdr *tcp_header,
                            struct timeval ts) {
    const struct iphdr *ip4_header = NULL;
    const struct ip6_hdr *ip6_header = NULL;

    tls_connection *conn = (tls_connection *)malloc(sizeof(tls_connection));
    if (ipv4) {
        ip4_header = (struct iphdr *)ip_header;
        conn->addr_size = INET_ADDRSTRLEN;
        conn->dst_ip = ip4_header->daddr;
        conn->src_ip = ip4_header->saddr;
    } else {
        ip6_header = (struct ip6_hdr *)ip_header;
        conn->addr_size = INET6_ADDRSTRLEN;
        conn->ip6_src = ip6_header->ip6_src;
        conn->ip6_dst = ip6_header->ip6_dst;
    }
    conn->src_port = tcp_header->source;
    conn->dst_port = tcp_header->dest;
    conn->sni = "No SNI";
    conn->time_stamp = ts;
    conn->packet_count = 1;
    conn->bytes = 0;
    conn->duration = 0;
    conn->server_fin = false;
    conn->client_fin = false;
    conn->last_ack = false;
    return conn;
}

void packet_handler(u_char *userData, const struct pcap_pkthdr *pkt_hdr,
                    const u_char *packet) {
    const struct ether_header *ethernet_header;
    const struct iphdr *ip_header = NULL;
    const struct ip6_hdr *ip6_header = NULL;
    const struct tcphdr *tcp_header;
    u_char *data;

    (void)userData;
    ethernet_header = (struct ether_header *)packet;
    int type = ntohs(ethernet_header->ether_type);
    tls_connection *conn;
    size_t size = 0;
    if (type == ETHERTYPE_IP) {
        // Create IPv4 connection entry
        ip_header = (struct iphdr *)(packet + sizeof(struct ether_header));
        tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) +
                                       sizeof(struct iphdr));
        conn = get_conn(ip_header, tcp_header);
        size =
            sizeof(struct ethhdr) + ip_header->ihl * 4 + tcp_header->doff * 4;
        if (conn == NULL) {
            // If conenction is not present, then create a new one
            conn = create_conn(ip_header, true, tcp_header, pkt_hdr->ts);
            insert_conn(conn);
        }
    } else if (type == ETHERTYPE_IPV6) {
        // Create IPv6 connection entry
        ip6_header = (struct ip6_hdr *)(packet + sizeof(struct ether_header));

        tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) +
                                       sizeof(struct ip6_hdr));

        conn = get_conn_6(ip6_header, tcp_header);
        size = sizeof(struct ethhdr) + ip6_header->ip6_plen * 4 +
               tcp_header->doff * 4;
        if (conn == NULL) {
            // If conenction is not present, then create a new one
            conn = create_conn(ip6_header, false, tcp_header, pkt_hdr->ts);
            insert_conn(conn);
        }
    }

    if (conn->last_ack) {
        conn->duration = time_diff(pkt_hdr->ts, conn->time_stamp);
        logger(3, conn);
        delete_conn(conn);
    }

    size_t size_of_data = pkt_hdr->len - size;
    if (size_of_data > 0) {
        data = (u_char *)(packet + size);
        process_tls(conn, data, size_of_data);
    }
}

void *start_listen(void *p) {
    pcap_t *handler = (pcap_t *)p;
    logger(2, "Listen interface");
    struct bpf_program prog;
    char err_buff[PCAP_ERRBUF_SIZE];
    connections = NULL;
    if (handler == NULL) {
        logger(1, err_buff);
    }

    if (pcap_compile(handler, &prog, "tcp", 0, PCAP_NETMASK_UNKNOWN) == 1) {
        logger(1, "Filter can't be created");
        logger(1, pcap_geterr(handler));
    }

    if (pcap_setfilter(handler, &prog) == -1) {
        logger(1, "Filter can't be set");
        logger(1, err_buff);
    }

    pcap_loop(handler, -1, packet_handler, (unsigned char *)"");

    pthread_exit(NULL);
}

void *process_file(void *p) {
    char *file = (char *)p;
    struct bpf_program prog;
    char err_buff[PCAP_ERRBUF_SIZE];

    pcap_t *fp = pcap_open_offline(file, err_buff);
    if (fp == NULL) {
        logger(1, err_buff);
    }

    if (pcap_compile(fp, &prog, "tcp", 0, PCAP_NETMASK_UNKNOWN) == -1) {
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
    while (conn != NULL) {
        // logger(3, conn);
        conn = delete_conn(conn);
    }

    pthread_exit(NULL);
}

pcap_t *check_iface(char *iface) {
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
    if (access(file, F_OK) == -1) {
        logger(1, "Given file does not exist");
        return 1;
    }
    return 0;
}