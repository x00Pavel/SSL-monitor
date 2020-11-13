/**
 * @short Main program
 * @file sslsniff.c
 * @author Pavel Yadlouski (xadlo00)
 */ 

#include <getopt.h>
#include <stdlib.h>
#include <signal.h>

#include "functions.h"

void help(){
    fprintf(stdout,
    "Basic usage:\n\t./sslniff -r file_name.pcapng\n\t./sslniff -i interface\n\n"
    "Arguments:\n"
    "\t-r <file_name>  file in pcap/pcapng format to be aggreageted\n"
    "\t-i <interface>  network interafce to be sniffed\n"
    );
}

int main(int argc, char *argv[]) {
    (void)argv;
    if (argc == 1) {
        help();
        return 0;
    }

    signal(SIGINT, cleanup);

    int c, rc = 0;
    pthread_t tid_file = 0; 
    pthread_t tid_iface = 0; 
    pcap_t *handler = NULL;
    
    // Process input arguments
    while ((c = getopt(argc, argv, "r:i:")) != -1) {
        switch (c) {
            case 'i':
                if (optarg == NULL) {
                    logger(1, "No interfece is set, quite\n");
                    return 0;
                }
                handler = check_iface(optarg);
                if (handler == NULL) {
                    return 1;
                }
                pthread_create(&tid_iface, NULL, start_listen, handler);
                break;
            case 'r':
                if (optarg == NULL) {
                    logger(1, "No file is set, quite\n");
                    return 0;
                }
                rc = check_file(optarg);
                if (rc != 0) {
                    return rc;
                }
                pthread_create(&tid_file, NULL, process_file, optarg);
                break;
            default:
                printf("Argument for %c is ignored", c);
                break;
        }
    }
    if (tid_file != (long unsigned int)0){
        pthread_join(tid_file, NULL);
        
    }
    if (tid_iface != (long unsigned int)0){
        pthread_join(tid_iface, NULL);
    }
    return 0;
}