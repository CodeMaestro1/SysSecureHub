# Overview

This project implements a custom network sniffer capable of analyzing TCP and UDP packets. It supports both IPv4 and IPv6 protocols and has been tested on Ubuntu 24.04. The sniffer allows users to inspect live traffic or analyze packets from pre-captured files.

---

## Features

- **Protocol Support**: Analyzes both IPv4 and IPv6 traffic.
- **Transport Layer Protocols**: Supports TCP and UDP packets.
- **Live Capture**: Captures real-time packets on a specified network interface.
- **File Analysis**: Reads and analyzes packets from PCAP files.
- **Custom Filtering**: Users can apply filter expressions to focus on specific traffic (e.g., port numbers or IP addresses).
- **TCP Retransmission Detection**: Detects retransmissions based on sequence numbers.

---

## Prerequisites

Ensure the following dependency is installed:

- **GCC** (GNU Compiler Collection)
- l**libpcap** (Packet capture library)

---

## Execution

The program supports the following arguments:

| Option | Description                                                                                   |
|--------|-----------------------------------------------------------------------------------------------|
| `-i`   | Specifies the network interface name for live packet capture (e.g., `eth0`).                 |
| `-r`   | Specifies the name of the packet capture (PCAP) file to analyze (e.g., `test.pcap`).          |
| `-f`   | Applies a filter expression in string format (e.g., `port 8080`).                             |
| `-h`   | Displays a help message explaining usage and available options.                               |

**Note**: For the `-r` option, the PCAP file extension must be provided.

### Example Usage

1. **Live Capture**:

   ```bash
   ./pcap_ex -i eth0 -f "port 8080"
   ```

2. **PCAP File Analysis**:

   ```bash
   ./pcap_ex -r test.pcap
   ```

To see detailed usage instructions, run:

```bash
./pcap_ex -h
```

---

## implementation


## Retransmission Detection

### TCP Retransmission Detection

TCP retransmissions occur under the following conditions:

- The sender does not receive an acknowledgment from the receiver within a certain time frame.
- The sender it receives three duplicate acknowledgments from the receiver.

Based on these characteristics, it is possible to detect retransmissions by checking the sequence number of the packets. If a packet is found to have the same sequence number as a previous packet, it can be concluded that it is a retransmission. From an implementation perspective, the sequence numbers of the packets can be stored in a list, and the sequence number of the current packet can be checked to determine if it is already present in the list. This allows for the identification of a retransmission.

### UDP Retransmission Detection

In the case of UDP, the lack of implementation of retransmissions is a consequence of the fundamental characteristics of the protocol. As a connectionless protocol, UDP does not guarantee the delivery of packets. Consequently, the concept of retransmission is not applicable within the context of UDP. Nevertheless, in certain instances, applications may implement retransmissions at the application layer with the objective of ensuring the delivery of packets.

---

## Limitations

The use of the program comes with the following limitations of usage:

- The program is designed to run on Linux systems only.
- The program does not support the detection of UDP retransmissions.
- The program online detects UDP and TCP packets and does not support other protocols.

## References

### General Guides

- [Interface/Filter Related Guide](https://www.tcpdump.org/pcap.html)

### `findalldevs()` Function

- [WinPcap Documentation](https://www.winpcap.org/docs/docs_412/html/group__wpcapfunc.html#ga7b128eaeef627b408f6a6e2a2f5eb45d)
- [TCPDump `pcap_findalldevs` Manual](https://www.tcpdump.org/manpages/pcap_findalldevs.3pcap.html)

### `pcap_loop`

- [Stanford Guide](http://yuba.stanford.edu/~casado/pcap/section3.html)
- [WinPcap Tutorial](https://www.winpcap.org/docs/docs_412/html/group__wpcap__tut3.html)

### Header and Statistics

- [DevDungeon - Using libpcap in C](https://www.devdungeon.com/content/using-libpcap-c)

### Ethernet Constants

- [UCLouvain Ethernet Constants Documentation](https://sites.uclouvain.be/SystInfo/usr/include/net/ethernet.h.html)

### Host/Network Endian Conversion Functions

- [GTA UFRJ Sockets Guide](https://www.gta.ufrj.br/ensino/eel878/sockets/htonsman.html)

### IP/IP6 Source Code

- [IPv4 Source Code](https://github.com/leostratus/netinet/blob/master/ip.h)
- [IPv6 Source Code](https://github.com/leostratus/netinet/blob/master/ip6.h)

### IP Header Information

- [Basic Packet Sniffer Construction](https://huangjianyu.wordpress.com/2012/04/29/basic-packet-sniffer-construction-from-the-ground-up/)

### IP Source/Destination Position

- [StackOverflow Discussion](https://stackoverflow.com/questions/21222369/getting-ip-address-of-a-packet-in-pcap-file)

### Constructing IPv4 Header Structures

- [StackOverflow - IP Struct Parameters](https://stackoverflow.com/questions/31121057/ip-struct-c-parameters)
- [GeeksForGeeks - IPv4 Datagram Header](https://www.geeksforgeeks.org/introduction-and-ipv4-datagram-header/)

### Constructing IPv6 Header Structures

- [GeeksForGeeks - IPv6 Header](https://www.geeksforgeeks.org/internet-protocol-version-6-ipv6-header/)
- [StackOverflow - Efficient Storage of IPv4/IPv6 Addresses](https://stackoverflow.com/questions/26531531/efficient-way-to-store-ipv4-ipv6-addresses)

### Print Metrics on Exit

- [StackOverflow - Catching Ctrl+C in C](https://stackoverflow.com/questions/4217037/catch-ctrl-c-in-c)

### Network Flow Definitions

- [FlowRecorder on GitHub](https://github.com/drnpkr/flowRecorder)

---
