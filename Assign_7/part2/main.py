from scapy.all import IP, TCP, UDP, ICMP, wrpcap, Raw, DNS, DNSQR
from base64 import b64encode 
from datetime import datetime

STUDENT_NAME = 'IochanasSalom-2021030047-PisimisisConstantinos-2021030008'
STUDENT_ID = '2021030047-2021030008'

def student_packet():
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    payload = f'{STUDENT_NAME} {timestamp}'
    packet = IP(dst="192.168.1.1") / TCP(dport=54321) / Raw(load = payload) #Use RAW since we have a custom payload

    return [packet]

def port_scan_packets():
    packets = list()
    protocol_and_ports = {
    "HTTP": 80,
    "HTTPS": 443,
    "SSH": 22,
    "TELNET": 23,
    "FTP": 21,
    "DNS": 53,
    "RTSP": 554,
    "SQL": 1433,
    "RDP": 3389,
    "MQTT": 1883
}

    for service, port in protocol_and_ports.items():
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        #Determine the protocol for each service
        #Ideally we should use the flag 's'(SYN) for TCP protocol but for the sake of the assignment we will ignore it
        protocol_packet = TCP(dport=port) if service != "DNS" else UDP(dport=port)

        payload = f'{STUDENT_NAME} {timestamp}'
        packet = IP(dst="192.168.1.2") / protocol_packet / Raw(load = payload)
        packets.append(packet)

    return packets

def base64_malicious_packets():
    packets = list()
    
    #Encode the student ID in base64
    encoded_payload = b64encode(STUDENT_ID.encode()).decode()

    for _ in range(5):
        
        packet = IP(dst="192.168.1.3") / TCP(dport=8080) / Raw(load = encoded_payload)
        packets.append(packet)

    return packets

def dns_suspricious_domain_packets():
    payload = "malicious.example.com"
    packet = IP(dst="192.168.1.1") / UDP(dport=53) / DNS(rd=1,qd=DNSQR(qname=payload,qtype="A"))

    return [packet]

def ping_test_packet():
    payload = 'PingTest-2025'
    packet = IP(dst="192.168.1.4") / ICMP() / Raw(load = payload)

    return [packet]

def save_to_pcap(filename, packets):
    wrpcap(filename, packets)

if __name__ == '__main__':
    funcs = (
            student_packet, 
            port_scan_packets,
            base64_malicious_packets,
            dns_suspricious_domain_packets,
            ping_test_packet
        )

    packets = list()
    for packet_func in funcs:
        packets.extend(packet_func())

    save_to_pcap('packets.pcap', packets)