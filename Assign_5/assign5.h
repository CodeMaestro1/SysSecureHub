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

#define DEFAULT_FILTER "";

typedef struct {
    int tcp_count;
    int udp_count;
    int other_count;
    int total_packets;
    int tcp_bytes;
    int udp_bytes;
} metrics_t;

// struct ipv4_header {
//     uint8_t   hlen:4;			// header length 
//     uint8_t   version:4;		// version
//     uint8_t   tos;				// type of service
//     uint16_t  total_length;		// total_length
//     uint16_t  id;				// identification
//     uint16_t  flags:3;			// flags
//     uint16_t  fragoff:13;		// frag. offset
//     uint8_t   ttl;				// time to live
//     uint8_t   protocol;			// protocol
//     uint16_t  checksum;			// checksum
//     uint32_t  src_ip;			// src
//     uint32_t  dst_ip;			// dst
//     uint32_t  options[];		// options field (if hlen > 5)
// } __attribute__((__packed__)); // no padding 


// struct ipv6_header {
//     uint8_t   version:4;		// version 
//     uint8_t   traffic_class;	// traffic class
//     uint32_t  flow_label:20;	// type of service
//     uint16_t  payload_len;		// payload_length
//     uint8_t  next_header;		// next 
//     uint8_t  hop_limit;			// hop limit 
//     struct in6_addr src_ip;
//     struct in6_addr dst_ip;
// } __attribute__((__packed__)); // no padding 

// Declare functions

void print_help();

/* checks if interface is in alldevs, 1: success, 0: fail */
int dev_exists(const char* interface);

void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet);

#endif