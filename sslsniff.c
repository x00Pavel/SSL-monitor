#include <stdlib.h>
#include <getopt.h>

#include "functions.h"


int main(int argc, char *argv[]) {
    (void)argv;
    if (argc == 1) {
        logger(1, "Wrong number of input arguments\n");
        return 0;
    }
    logger(2, "Program started");
    
    int c;
    int rc = 0;
    // Process input arguments
    while ((c = getopt(argc, argv, "r:i:")) != -1){
        switch (c)
        {
        case 'i':
            if (optarg == NULL){
                logger (1, "No interfece is set, quite\n");
                return 0;
            }
            iface = optarg;
            rc = check_iface(err_buff);            
            if (rc != 0){
                logger(1, err_buff);
                return rc;
            }
            logger(2, "Interface is set");
            break;
        case 'r':
            if (optarg == NULL){
                printf ("No file is set, quite\n");
                return 0;
            }
            file = optarg;
            rc = check_file(err_buff);            
            if (rc != 0){
                printf("%s\n", err_buff);
                return rc;
            }
            logger(2, "File is set");
            break;
        default:
            printf("Argument for %c is ignored", c);
            break;
        }
    }
    
    fp = pcap_open_offline(file, err_buff);
    if (fp == NULL) {
	    logger(1, err_buff);
	    return 0;
    }

    logger(2, "Start processing packets");
    if (pcap_compile(fp, &prog, "proto tcp", 0, PCAP_NETMASK_UNKNOWN) == -1) {
        logger(1, "Filter can't be created");
        logger(1, pcap_geterr(fp));
    }
    if (pcap_setfilter(fp, &prog) == -1) {
        logger(1, "Filter can't be set");
        logger(1, err_buff);

    }

    if (pcap_loop(fp, 0, packet_handler, NULL) < 0) {
        logger(1, pcap_geterr(fp));
        return 0;
    }
    return 0;

}