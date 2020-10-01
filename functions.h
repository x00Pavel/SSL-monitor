#include <pcap.h>

#define PCAP_BUF_SIZE	1024
#define PCAP_SRC_FILE	2

pcap_t *fp;
char *file;
char *iface;
char err_buff[PCAP_ERRBUF_SIZE];
struct bpf_program prog;
typedef unsigned char u_char;
typedef unsigned int u_int; 

void packet_handler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void logger(int type, char *msg);
int check_iface(char *buff);
int check_file(char *buff);