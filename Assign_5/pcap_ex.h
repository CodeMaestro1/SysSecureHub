#ifndef PCAP_EX_H
#define PCAP_EX_H

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
#include <signal.h>

#define DEFAULT_FILTER ""
#define MAX_FLOWS 8*16384 //a bit lazy but yeah
#define LOGFILE "log.txt"
#define ONLINE_OUTPUT_FILE "online_output.txt"
#define OFFLINE_OUTPUT_FILE "offline_output.txt"


typedef struct {
    int tcp_count;
    int udp_count;
    int total_packets;
    unsigned long tcp_bytes;
    unsigned long udp_bytes;
    int net_flows;
    int tcp_flows;
    int udp_flows;
    int retransmitted_tcp_count;
} metrics_t;

typedef struct {
    char ip_src[INET6_ADDRSTRLEN]; // put max size 
    char ip_dst[INET6_ADDRSTRLEN];
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
} flow_t;

typedef struct {
    flow_t key;
    unsigned int expected_seq;
    int counter; // not needed but yeah
} flow_entry_t;


// Declare functions

int is_tcp_keep_alive(struct tcphdr* tcp_header, unsigned int next_exp_seq, unsigned int packet_len);

int is_tcp_packet_retransmitted(struct tcphdr* tcp_header, flow_entry_t* flow, unsigned int packet_len);

void print_help();

/* used for debugging */
void print_all(char* type, u_char* ip_hdr);

void INThandler(int sig);

int add_flow(flow_t *key);

flow_entry_t* find_flow(flow_t *key);

/* debugging prints global array flows */ 
void print_flows();

/* checks if interface is in alldevs, 1: success, 0: fail */
int dev_exists(const char* interface);

void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet);

#endif