/**
 * \author Pavel Yadlouski (xyadlo00)
 * \date September, 2020
 * \brief Application for SSL monitoring 
 * \file functions.h  Header file for functions.c
 */

#include <pcap.h>
#include <pthread.h>

#define PCAP_BUF_SIZE	1024
#define PCAP_SRC_FILE	2
#ifndef NI_MAXHOST
#define NI_MAXHOST 1025
#endif
typedef unsigned char u_char;
typedef unsigned int u_int; 

void packet_handler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void logger(int , void *);
pcap_t * check_iface(char*);
int check_file(char*);
void *start_listen(void *);
void *process_file(void *);
void cleanup(int dummy);