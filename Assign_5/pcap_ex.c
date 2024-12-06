#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include "pcap_ex.h"



/* Global Variables */
// metrics struct  
metrics_t metrics = {0, 0, 0, 0, 0, 0, 0, 0, 0}; // could technically go local again, but not worth it 
// flow counter
flow_entry_t flows[MAX_FLOWS];
// log files 
FILE *logfile = NULL;
FILE *outfile = NULL;
// session handle
pcap_t* handle;

int is_tcp_keep_alive(struct tcphdr* tcp_header, unsigned int next_exp_seq, unsigned int packet_len) {
    /* Set when 
    - the segment size is zero or one, 
    - current sequence number is one byte less than the next expected sequence number, 
    - none of SYN, FIN, or RST are set.
    */

    
    unsigned int segment_size = packet_len - sizeof(struct tcphdr);
    
    if ( (segment_size == 0 || segment_size == 1) 
        && (tcp_header->th_seq == next_exp_seq - 1)
        && (!tcp_header->syn && !tcp_header->fin && !tcp_header->rst) )
    {
        return 1; // true
    }

    return 0; // false
}

int is_tcp_packet_retransmitted(struct tcphdr* tcp_header, flow_entry_t* flow, unsigned int packet_len) {
    /*
    - This is not a keepalive packet.
    - In the forward direction, the segment length is greater than zero or the SYN or FIN flag is set.
    - The next expected sequence number is greater than the current sequence number. 
    */

    unsigned int next_exp_seq = flow->expected_seq;
    unsigned int segment_size = packet_len - sizeof(struct tcphdr);

    // if it is not a keep alive packet
    if ( (is_tcp_keep_alive(tcp_header, next_exp_seq, packet_len) == 0)
         && (segment_size > 0 || (tcp_header->syn || tcp_header->fin))
         && (next_exp_seq > tcp_header->th_seq) )
    {
        return 1; // true
    }

    return 0; // false
}


/**
 * @brief Finds the index of a network flow in the flows array that matches the given key.
 *
 * This function iterates through the global `flows` array and compares each flow's key with the provided key.
 * If a match is found, the index of the matching flow is returned.
 *
 * @param key A pointer to a `flow_t` structure containing the key to search for.
 * @return The index of the matching flow in the `flows` array, or -1 if no match is found.
 */
flow_entry_t* find_flow(flow_t *key) {
    for (int i = 0; i < metrics.net_flows; i++) {
        if (strcmp(flows[i].key.ip_src, key->ip_src) == 0 &&
            strcmp(flows[i].key.ip_dst, key->ip_dst) == 0 &&
            flows[i].key.src_port == key->src_port &&
            flows[i].key.dst_port == key->dst_port &&
            flows[i].key.protocol == key->protocol) {
                return &flows[i];
        }
    }
    return NULL;
}

int add_flow(flow_t *key) {
    flow_entry_t* cur_flow = find_flow(key);
    if (cur_flow != NULL) {
        cur_flow->counter++;
        return 0; // no new flow
    } else {
        // add entry if not found 
        if (metrics.net_flows < MAX_FLOWS) {
            int num = metrics.net_flows;
            flows[num].key = *key;
            flows[num].expected_seq = 0; // init next expected seq num as 0
            flows[num].counter = 1;
            return 1; // new flow 
        } else {
            printf("MAX_FLOWS = %d reached\n", MAX_FLOWS);
            return 0; // no new flow (?)
        }
   }
}

void print_flows() {
    printf("Flow Count: %d\n", metrics.net_flows);
    for (int i = 0; i < metrics.net_flows; i++) {
        printf("Flow %d:\n", i + 1);
        printf("  Source IP: %s | ", flows[i].key.ip_src);
        printf("Destination IP: %s | ", flows[i].key.ip_dst);
        printf("Source Port: %d | ", flows[i].key.src_port);
        printf("Destination Port: %d | ", flows[i].key.dst_port);
        printf("Protocol: %d | ", flows[i].key.protocol);
        printf("Packet Count: %d\n", flows[i].counter);
        printf("----------------------------------------------------------------------------------------------------------------------------------\n");
    }
}

void INThandler(int sig) {
    // Ignore additional signals while handling this one
    signal(sig, SIG_IGN);

    if (handle != NULL) {
        pcap_breakloop(handle);
    } else { // no session active -> exit immed
        printf("\nCaught signal %d. Exiting...\n", sig);
        exit(0);
    }
}


/**
 * @brief Prints the details of various network headers based on the specified type.
 *
 * This function takes a type and a header, and prints the details of the header
 * based on the type. Supported types are "ipv4", "ipv6", "tcp", and "udp".
 *
 * @param type A string indicating the type of the header. Supported values are:
 *             - "ipv4": for IPv4 headers
 *             - "ipv6": for IPv6 headers
 *             - "tcp": for TCP headers
 *             - "udp": for UDP headers
 * @param header A pointer to the header data to be printed. The data should be
 *               cast to the appropriate structure based on the type.
 */
void print_all(char* type, u_char* header) {
    // ip headers 
    if (strcmp(type, "ipv4") == 0) {
        struct ip* ip4_hdr = (struct ip*) header;

        printf("IPv4 Header:\n");
        printf("Version: %d\n", ip4_hdr->ip_v);
        printf("Header Length: %d bytes\n", ip4_hdr->ip_hl * 4); 
        printf("Type of Service: 0x%02x\n", ip4_hdr->ip_tos); 
        printf("Total Length: %d\n", ntohs(ip4_hdr->ip_len));
        printf("Identification: 0x%04x\n", ntohs(ip4_hdr->ip_id)); 
        printf("Flags and Fragment Offset: 0x%04x\n", ntohs(ip4_hdr->ip_off)); 
        printf("Time to Live (TTL): %d\n", ip4_hdr->ip_ttl);
        printf("Protocol: %d\n", ip4_hdr->ip_p);
        printf("Checksum: 0x%04x\n", ntohs(ip4_hdr->ip_sum));
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip4_hdr->ip_src, src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &ip4_hdr->ip_dst, dst_ip, INET_ADDRSTRLEN);
        printf("Source Address: %s\n", src_ip);
        printf("Destination Address: %s\n", dst_ip);
    } 
    else if (strcmp(type, "ipv6") == 0) {
        struct ip6_hdr* ip6_header = (struct ip6_hdr*) header;

        printf("IPv6 Header:\n");
        printf("Version: %d\n", (ip6_header->ip6_vfc >> 4) & 0x0F); 
        printf("Traffic Class: 0x%02x\n", (ip6_header->ip6_vfc & 0x0F) << 4 | (ip6_header->ip6_flow >> 16)); 
        printf("Flow Label: 0x%05x\n", ip6_header->ip6_flow & 0xFFFFF); 
        printf("Payload Length: %d\n", ntohs(ip6_header->ip6_plen)); 
        printf("Next Header: %d\n", ip6_header->ip6_nxt); 
        printf("Hop Limit: %d\n", ip6_header->ip6_hlim); 
        char src_ip[INET6_ADDRSTRLEN];
        char dst_ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &ip6_header->ip6_src, src_ip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &ip6_header->ip6_dst, dst_ip, INET6_ADDRSTRLEN);
        printf("Source Address: %s\n", src_ip);
        printf("Destination Address: %s\n", dst_ip);
    }

    // tcp/udp
    if (strcmp(type, "tcp") == 0) {
        struct tcphdr* tcp_hdr = (struct tcphdr*) header;

        printf("TCP Header:\n");
        printf("Source Port: %u\n", ntohs(tcp_hdr->th_sport));
        printf("Destination Port: %u\n", ntohs(tcp_hdr->th_dport));
        printf("Sequence Number: %u\n", ntohl(tcp_hdr->th_seq));
        printf("Acknowledgment Number: %u\n", ntohl(tcp_hdr->th_ack));

        // Handling byte order for th_off and th_x2
        printf("Data Offset: %u\n", tcp_hdr->th_off);
        printf("Unused field (th_x2): %u\n", tcp_hdr->th_x2);

        // Print TCP flags
        printf("Flags: 0x%x\n", tcp_hdr->th_flags);
        printf("Flags: ");
        if (tcp_hdr->th_flags & TH_FIN) printf("FIN ");
        if (tcp_hdr->th_flags & TH_SYN) printf("SYN ");
        if (tcp_hdr->th_flags & TH_RST) printf("RST ");
        if (tcp_hdr->th_flags & TH_PUSH) printf("PUSH ");
        if (tcp_hdr->th_flags & TH_ACK) printf("ACK ");
        if (tcp_hdr->th_flags & TH_URG) printf("URG ");
        printf("\n");

        printf("Window: %u\n", ntohs(tcp_hdr->th_win));
        printf("Checksum: 0x%x\n", ntohs(tcp_hdr->th_sum));
        printf("Urgent Pointer: %u\n", ntohs(tcp_hdr->th_urp));
    } 
    else if (strcmp(type, "udp") == 0) {
        struct udphdr* udp_hdr = (struct udphdr*) header;

        printf("UDP Header:\n");
        printf("Source Port: %u\n", ntohs(udp_hdr->uh_sport));
        printf("Destination Port: %u\n", ntohs(udp_hdr->uh_dport));
        printf("UDP Length: %u\n", ntohs(udp_hdr->uh_ulen));
        printf("UDP Checksum: 0x%x\n", ntohs(udp_hdr->uh_sum));
    }
}

void packet_handler(u_char *user, const struct pcap_pkthdr* header, const u_char* packet)
{

    metrics.total_packets++;

    // log full packet 
    if (logfile != NULL) {
        fprintf(logfile, "\nPacket #%d:\n", metrics.total_packets);
        // print packet as a hexstream
        for (int i = 0; i < header->len; i++) {
            fprintf(logfile, "%02x ", packet[i]);
        }
    }

    /* Check if packet is IPV4 or IPV6 */ 
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;
    uint16_t ether_type = ntohs(eth_header->ether_type); 

    if (ether_type != ETHERTYPE_IP && ether_type != ETHERTYPE_IPV6) {
        // printf("Not IPV4 or IPV6\n");
        return;
    }

    /* Resolve IPV4/IPV6 packets */
    const u_char *ip_header;
    char ip_src[INET6_ADDRSTRLEN];
    char ip_dst[INET6_ADDRSTRLEN];
    int ip_header_len;
    uint8_t protocol;

    // IPV4
    if (ether_type == ETHERTYPE_IP) {
        struct ip* ip4_hdr = (struct ip*) (packet + sizeof(struct ether_header)); // pointer starts after ether header
        
        ip_header = (u_char*) ip4_hdr;
        ip_header_len = ip4_hdr->ip_hl * 4;
        protocol = ip4_hdr->ip_p;

        char ip_src[INET_ADDRSTRLEN];
        char ip_dst[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip4_hdr->ip_src, ip_src, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &ip4_hdr->ip_dst, ip_dst, INET_ADDRSTRLEN);

    }
    // IPV6 (ipv6 portion untested because my vm can't run ipv6 apparently - will figure out later)
    else if (ether_type == ETHERTYPE_IPV6) {
        struct ip6_hdr* ip6_header = (struct ip6_hdr*) (packet + sizeof(struct ether_header)); // pointer starts after ether header
        
        ip_header = (u_char*) ip6_header;
        ip_header_len = sizeof(struct ip6_hdr);
        protocol = ip6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt;

        char ip_src[INET6_ADDRSTRLEN];
        char ip_dst[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &ip6_header->ip6_src, ip_src, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &ip6_header->ip6_dst, ip_dst, INET6_ADDRSTRLEN);

        // print_all("ipv6", (u_char*) ip6_header); // debug 
    }

    // Resolve TCP/UDP packets 
    if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP) {
        return;
    }

    uint16_t src_port;
    uint16_t dst_port;

    if (protocol == IPPROTO_TCP) {
        struct tcphdr* tcp_header = (struct tcphdr*) (ip_header + ip_header_len);

        metrics.tcp_count++;
        metrics.tcp_bytes += ntohs(header->len); // full package len (?)

        // get needed vars
        src_port = ntohs(tcp_header->th_sport);
        dst_port = ntohs(tcp_header->th_dport);
        uint8_t tcp_hdr_len = tcp_header->th_off * 4;
        int payload_len = ntohs(header->len) - ip_header_len - tcp_hdr_len;

        // TCP Flows 
        flow_t key;
        strcpy(key.ip_src, ip_src);
        strcpy(key.ip_dst, ip_dst);
        key.src_port = src_port;
        key.dst_port = dst_port;
        key.protocol = protocol;

        if (add_flow(&key) == 1) { // if needed
            metrics.net_flows++;
            metrics.tcp_flows++;
        }
        flow_entry_t* cur_flow = find_flow(&key);

        // Retransmitted packets 
        int is_retransmitted = is_tcp_packet_retransmitted(tcp_header, cur_flow, payload_len);
        if (is_retransmitted == 0) {
            metrics.retransmitted_tcp_count++; // optional
        }

        // Update next expected seq number
        cur_flow->expected_seq = tcp_header->th_seq + payload_len;

        FILE* files[] = {stdout, outfile};
        for (int i = 0; i < 2; i++) {
            fprintf(files[i], "TCP Packet");
            if (is_retransmitted == 0) {
                fprintf(files[i], " (Retransmitted)"); // retransmition
            }
            fprintf(files[i], ":\nProtocol Number: %d\n", protocol);
            fprintf(files[i], "Source Address: %s\n", ip_src);
            fprintf(files[i], "Destination Address: %s\n", ip_dst);
            fprintf(files[i], "Source Port: %d\n", src_port);
            fprintf(files[i], "Destination Port: %d\n", dst_port);
            fprintf(files[i], "Header Length: %d bytes\n", tcp_hdr_len);
            fprintf(files[i], "Payload Length: %d bytes\n", payload_len);
            fprintf(files[i], "======================================\n");
        }

        // print_all("tcp", (u_char*) tcp_header); // debug 
    }
    else if (protocol == IPPROTO_UDP) {
        struct udphdr* udp_header = (struct udphdr*) (ip_header + ip_header_len);

        metrics.udp_count++;
        metrics.udp_bytes += ntohs(header->len); // full package len (?)

        // Extract UDP details
        src_port = ntohs(udp_header->uh_sport);
        dst_port = ntohs(udp_header->uh_dport);
        int udp_hdr_len = sizeof(struct udphdr);
        int payload_len = ntohs(header->len) - ip_header_len - udp_hdr_len;

        FILE* files[] = {stdout, outfile};
        for (int i = 0; i < 2; i++) {
            fprintf(files[i], "UDP Packet:\n");
            fprintf(files[i], "Protocol Number: %d\n", protocol);
            fprintf(files[i], "Source Address: %s\n", ip_src);
            fprintf(files[i], "Destination Address: %s\n", ip_dst);
            fprintf(files[i], "Source Port: %d\n", src_port);
            fprintf(files[i], "Destination Port: %d\n", dst_port);
            fprintf(files[i], "Header Length: %d bytes\n", udp_hdr_len);
            fprintf(files[i], "Payload Length: %d bytes\n", payload_len);
            fprintf(files[i], "======================================\n");

        }

        // UDP Flows 
        flow_t key;
        strcpy(key.ip_src, ip_src);
        strcpy(key.ip_dst, ip_dst);
        key.src_port = src_port;
        key.dst_port = dst_port;
        key.protocol = protocol;

        if (add_flow(&key) == 1) { // if needed
            metrics.net_flows++;
            metrics.udp_flows++;
        }  

        // print_all("udp", (u_char*) udp_header); // debug 
    }

}


/**
 * @brief Checks if the specified network interface exists in the list of available devices.
 * 
 * 
 * @param interface The name of the network interface to check.
 * 
 * @return 1 if the interface exists, 0 otherwise.s
 * 
 */
int dev_exists(const char* interface) {
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding alldevs | %s\n", errbuf);
        return 0;
    }

    pcap_if_t *dev = alldevs; // set to first elem in list (iter var)
    int found = 0;
    
    while (dev != NULL) {
        printf("%s\n", dev->name);
        if (strcmp(dev->name, interface) == 0) {
            found = 1;
            break;
        }
        dev = dev->next;
    }

    if (!found) {
        fprintf(stderr, "Error finding %s in alldevs\n", interface);
        return 0;
    }

    return 1; // success
} 

void print_help() {
    printf("Usage: ./pcap_ex [OPTIONS]\n");
    printf("Options:\n");
    printf("    -i <interface>    Select the network interface to monitor (e.g., eth0).\n");
    printf("    -r <file>         Specify the PCAP file to analyze (e.g., test.pcap).\n");
    printf("    -f <filter>       Apply a filter expression (e.g., \"port 8080\").\n");
    printf("    -h                Display this help message.\n");
}

int main(int argc, char *argv[]) {
    
    // signal handle to print exit 
    signal(SIGINT, INThandler);

    int opt;
    char *interface = NULL;
    char *pcap_file = NULL;
    char *filter = DEFAULT_FILTER;

    // Parse command-line options
    while ((opt = getopt(argc, argv, "i:r:f:h")) != -1) {
        switch (opt) {
            case 'i':
                if (pcap_file) {
                    fprintf(stderr, "Cannot use both -i (interface) and -r (pcap file) options simultaneously.\n");
                    return 1;
                }
                interface = optarg;
                break;
            case 'r':
                if (interface) {
                    fprintf(stderr, "Cannot use both -i (interface) and -r (pcap file) options simultaneously.\n");
                    return 1;
                }
                pcap_file = optarg;
                break;
            case 'f':
                filter = optarg;
                break;
            case 'h':
                print_help();
                return 0;
            default:
                fprintf(stderr, "Invalid option or missing argument. Use -h for help.\n");
                return 1;
        }
    }

    // error (i and r)
    if (!interface && !pcap_file) {
        fprintf(stderr, "Either -i (interface) or -r (pcap file) option must be provided.\n");
        return 1;
    }

    /* ONLINE OPEN | -i <interface> */
    if (interface) {
        /* vars */
        char errbuf[PCAP_ERRBUF_SIZE];
        /* Filter vars */
        struct bpf_program fp;
        bpf_u_int32 mask;
        bpf_u_int32 net;

        printf("Monitoring interface: %s\n", interface);

        // check if user inputted dev is in all devs
        if (dev_exists(interface) == 0) {
            return 1; // user dev not in list 
        }

        // open online 
        handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "Couldn't open device %s | %s\n", interface, errbuf);
            return 1;
        }

        // -f <filter>      
        if (filter) {
            printf("Using filter: %s\n", filter);
            
            // compile and set filter (if needed)
            if (pcap_compile(handle, &fp, filter, 0, net) == -1) {
                fprintf(stderr, "Couldn't compile | %s\n", pcap_geterr(handle));
                return 1;
            }
            if (pcap_setfilter(handle, &fp) == -1) {
                fprintf(stderr, "Couldn't set filter %s | %s\n", filter, pcap_geterr(handle));
                return 1;
            }
        }

        // open related files 
        logfile = fopen(LOGFILE, "w");
        if (!logfile) {
            perror("Error opening log file");
            return 1;
        }
        outfile = fopen(ONLINE_OUTPUT_FILE, "w");
        if (!outfile) {
            perror("Error opening online output file");
            fclose(logfile); // close log file if the other file failed to open
            return 1;
        }

        // online loop
        pcap_loop(handle, 0, packet_handler, (u_char*) &metrics);

        // continues here after ^C

        // Print statistics before exiting
        FILE* files[] = {stdout, outfile};
        for (int i = 0; i < 2; i++) {
            fprintf(files[i], "\nStats:\n");
            fprintf(files[i], "Total packets: %d\n", metrics.total_packets);
            fprintf(files[i], "Total TCP packets: %d\n", metrics.tcp_count);
            fprintf(files[i], "Total UDP packets: %d\n", metrics.udp_count);
            fprintf(files[i], "Total bytes of TCP packets: %lu\n", metrics.tcp_bytes);
            fprintf(files[i], "Total bytes of UDP packets: %lu\n", metrics.udp_bytes);
            fprintf(files[i], "Total flows: %d\n", metrics.net_flows);
            fprintf(files[i], "Total TCP flows: %d\n", metrics.tcp_flows);
            fprintf(files[i], "Total UDP flows: %d\n", metrics.udp_flows);
            fprintf(files[i], "Total TCP retransmissions: %d\n\n\n", metrics.retransmitted_tcp_count);
        }
        
        // close session 
        pcap_close(handle);

        //close files
        fclose(outfile);
        fclose(logfile);

        return 0;
    }

    /* OFFLINE OPEN | -r <file> */  
    if (pcap_file) {
        /* vars */
        char errbuf[PCAP_ERRBUF_SIZE];
        /* Filter vars */
        struct bpf_program fp;
        bpf_u_int32 mask;
        bpf_u_int32 net;

        printf("Analyzing PCAP file: %s\n", pcap_file);

        // open offline 
        handle = pcap_open_offline(pcap_file, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "Couldn't open file %s | %s\n", pcap_file, errbuf);
            return 1;
        }

        // -f <filter>      
        if (filter) {
            printf("Using filter: %s\n", filter);
            
            // compile and set filter (if needed)
            if (pcap_compile(handle, &fp, filter, 0, net) == -1) {
                fprintf(stderr, "Couldn't compile | %s\n", pcap_geterr(handle));
                return 1;
            }
            if (pcap_setfilter(handle, &fp) == -1) {
                fprintf(stderr, "Couldn't set filter %s | %s\n", filter, pcap_geterr(handle));
                return 1;
            }
        }        

        // open related files 
        outfile = fopen(OFFLINE_OUTPUT_FILE, "w");
        if (!outfile) {
            perror("Error opening offline output file");
            return 1;
        }

        // offline loop
        pcap_loop(handle, 0, packet_handler, (u_char*) &metrics);

        // continues here after ^C

        // Print statistics before exiting
        FILE* files[] = {stdout, outfile};
        for (int i = 0; i < 2; i++) {
            fprintf(files[i], "\nStats:\n");
            fprintf(files[i], "Total packets: %d\n", metrics.total_packets);
            fprintf(files[i], "Total TCP packets: %d\n", metrics.tcp_count);
            fprintf(files[i], "Total UDP packets: %d\n", metrics.udp_count);
            fprintf(files[i], "Total bytes of TCP packets: %lu\n", metrics.tcp_bytes);
            fprintf(files[i], "Total bytes of UDP packets: %lu\n", metrics.udp_bytes);
            fprintf(files[i], "Total flows: %d\n", metrics.net_flows);
            fprintf(files[i], "Total TCP flows: %d\n", metrics.tcp_flows);
            fprintf(files[i], "Total UDP flows: %d\n", metrics.udp_flows);
            fprintf(files[i], "Total TCP retransmissions: %d\n\n\n", metrics.retransmitted_tcp_count);
        }
        
        // close session 
        pcap_close(handle);

        //close files
        fclose(outfile);

        return 0;
    }

    return 0;
}
