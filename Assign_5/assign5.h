#ifndef ASSIGN5_H
#define ASSIGN5_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>
#include <string.h>
#include <time.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdint.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>

#define DEFAULT_FILTER "";

typedef struct {
    int tcp_count;
    int udp_count;
    int other_count;
    int total_packets;
    int tcp_bytes;
    int udp_bytes;
} metrics_t;


// Declare functions

void print_help();

/* used for debugging */
void print_all(char* type, u_char* ip_hdr);

/* checks if interface is in alldevs, 1: success, 0: fail */
int dev_exists(const char* interface);

void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet);

#endif