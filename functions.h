/**
 * \author Pavel Yadlouski (xyadlo00)
 * \date September, 2020
 * \brief Application for SSL monitoring 
 * \file functions.h  Header file for functions.c
 */

#include <pcap.h>

#define PCAP_BUF_SIZE	1024
#define PCAP_SRC_FILE	2
#ifndef NI_MAXHOST
#define NI_MAXHOST 1025
#endif
char *file;
char *iface;
char err_buff[PCAP_ERRBUF_SIZE];
typedef unsigned char u_char;
typedef unsigned int u_int; 

void packet_handler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void logger(int , void *);
int check_iface(char*, char *buff);
int check_file(char*, char *buff);
void *start_listen();
void *process_file();