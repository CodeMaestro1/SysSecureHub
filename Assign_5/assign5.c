#include "assign5.h"

void packet_handler(u_char *user, const struct pcap_pkthdr* header, const u_char* packet)
{
    metrics_t* metrics = (metrics_t*) user;

    metrics->total_packets++;

    // Check if packet is IPV4 or IPV6
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;
    uint16_t ether_type = ntohs(eth_header->ether_type); 

    if (ether_type != ETHERTYPE_IP && ether_type != ETHERTYPE_IPV6) {
        // printf("Not IPV4 or IPV6\n");
        return;
    }

    // Resolve IPV4/IPV6 packets
    /* Pointers to start point of various headers */
    const u_char *ip_header;
    const u_char *tcp_header;
    const u_char *payload;
    /* Header lengths in bytes */
    int ethernet_header_length = 14; /* Doesn't change */
    int ip_header_length;
    int tcp_header_length;
    int payload_length;

    uint8_t protocol;

    // IPV4
    if (ether_type == ETHERTYPE_IP) {
        struct ip* ip4_hdr = (struct ip*) (packet + sizeof(struct ether_header)); // pointer starts after ether header
        
        ip_header = (u_char*) ip4_hdr;
        ip_header_length = ip4_hdr->ip_hl * 4;  // Corrected calculation
        protocol = ip4_hdr->ip_p;

        printf("IPv4 Header:\n");
        printf("Version: %d\n", ip4_hdr->ip_v);                // IP version (4)
        printf("Header Length: %d bytes\n", ip4_hdr->ip_hl * 4);  // Header length in bytes
        printf("Type of Service: 0x%02x\n", ip4_hdr->ip_tos);    // Type of Service (TOS)
        printf("Total Length: %d\n", ntohs(ip4_hdr->ip_len));    // Total Length (in bytes)
        printf("Identification: 0x%04x\n", ntohs(ip4_hdr->ip_id)); // Identification field
        printf("Flags and Fragment Offset: 0x%04x\n", ntohs(ip4_hdr->ip_off)); // Flags & Fragment Offset
        printf("Time to Live (TTL): %d\n", ip4_hdr->ip_ttl);      // TTL
        printf("Protocol: %d\n", ip4_hdr->ip_p);                  // Protocol (e.g., TCP = 6, UDP = 17, etc.)
        printf("Checksum: 0x%04x\n", ntohs(ip4_hdr->ip_sum));     // Checksum
        printf("Source Address: %s\n", inet_ntoa(ip4_hdr->ip_src)); // Source IP address
        printf("Destination Address: %s\n", inet_ntoa(ip4_hdr->ip_dst)); // Destination IP address
    }
    // IPV6
    else if (ether_type == ETHERTYPE_IPV6) {
        struct ip6_hdr* ip6_header = (struct ip6_hdr*) (packet + sizeof(struct ether_header)); // pointer starts after ether header
        
        ip_header = (u_char*) ip6_header;
        ip_header_length = sizeof(struct ip6_hdr);
        protocol = ip6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt;

        char src_str[INET6_ADDRSTRLEN];
        char dst_str[INET6_ADDRSTRLEN];

        printf("IPv6 Header:\n");
        printf("Version: %d\n", (ip6_header->ip6_vfc >> 4) & 0x0F); // Extract Version (top 4 bits)
        printf("Traffic Class: 0x%02x\n", (ip6_header->ip6_vfc & 0x0F) << 4 | (ip6_header->ip6_flow >> 16)); // Traffic class
        printf("Flow Label: 0x%05x\n", ip6_header->ip6_flow & 0xFFFFF); // Flow Label (lower 20 bits)
        printf("Payload Length: %d\n", ntohs(ip6_header->ip6_plen)); // Payload Length (length of the data excluding the header)
        printf("Next Header: %d\n", ip6_header->ip6_nxt); // Next header field (protocol type for the payload)
        printf("Hop Limit: %d\n", ip6_header->ip6_hlim); // Hop Limit (TTL in IPv6)
        printf("Source Address: %s\n", inet_ntop(AF_INET6, &ip6_header->ip6_src, src_str, sizeof(src_str))); // Source IP address (IPv6)
        printf("Destination Address: %s\n", inet_ntop(AF_INET6, &ip6_header->ip6_dst, dst_str, sizeof(dst_str))); // Destination IP address
    }

    printf("\n------------\n");


    // Resolve TCP/UDP packets 

    // Flow counters 

    // Retransmitted packets 

}

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
        // printf("%s\n", dev->name);
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
    int opt;
    char *interface = NULL;
    char *pcap_file = NULL;
    char *filter = DEFAULT_FILTER;

    // Parse command-line options
    while ((opt = getopt(argc, argv, "i:r:f:h")) != -1) {
        switch (opt) {
            case 'i':
                interface = optarg;
                break;
            case 'r':
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

    // -i <interface> 
    if (interface) {
        /* Interface vars */
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t *handle;
        /* Filter vars */
        struct bpf_program fp;
        bpf_u_int32 mask;
        bpf_u_int32 net;
        /* Sniffing vars */
        struct pcap_pkthdr header;
        const u_char *packet;

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

        // online packet sniffing loop 
        metrics_t metrics = {0, 0, 0, 0, 0, 0}; // metrics struct to measure a bunch of stuff (instead of making a bunch of globals)

        pcap_loop(handle, 0, packet_handler, (u_char*) &metrics);
        
        // close session 
        pcap_close(handle);

        return 0;
    }

    // -r <file>   
    if (pcap_file) {
        printf("Analyzing PCAP file: %s\n", pcap_file);
    }

    // error (i and r)
    if (!interface && !pcap_file) {
        fprintf(stderr, "Error, use -h for help.\n");
        return 1;
    }

    return 0;
}
