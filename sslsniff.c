#include <getopt.h>
#include <stdlib.h>
#include <pthread.h>

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
    logger(2, "Program started");

    int c, rc = 0;
    pthread_t *tid_file = NULL; 
    pthread_t *tid_iface = NULL;

    // Process input arguments
    while ((c = getopt(argc, argv, "r:i:")) != -1) {
        switch (c) {
            case 'i':
                if (optarg == NULL) {
                    logger(1, "No interfece is set, quite\n");
                    return 0;
                }
                rc = check_iface(optarg, err_buff);
                if (rc != 0) {
                    logger(1, err_buff);
                    return rc;
                }
                logger(2, "Interface is set");
                // pthread_create(&tid_iface, NULL, start_listen, optarg);
                break;
            case 'r':
                if (optarg == NULL) {
                    printf("No file is set, quite\n");
                    return 0;
                }
                rc = check_file(optarg, err_buff);
                if (rc != 0) {
                    printf("%s\n", err_buff);
                    return rc;
                }
                logger(2, "File is set");
                process_file(optarg);
                // pthread_create(&tid_file, NULL, process_file, optarg);
                break;
            default:
                printf("Argument for %c is ignored", c);
                break;
        }
    }
    if (tid_file != NULL){
        printf("Start her\n");
        pthread_join(*tid_file, NULL);
    }
    if (tid_iface != NULL){
        pthread_join(*tid_iface, NULL);

    }
    return 0;
}