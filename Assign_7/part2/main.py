from scapy.all import IP, TCP, UDP, ICMP, wrpcap
from base64 import b64encode 
from datetime import datetime

STUDENT_NAME = 'IochanasSalom-2021030047-PisimisisConstantinos-2021030008'
STUDENT_ID = '2021030047-2021030008'

def student_packet():
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    payload = f'{STUDENT_NAME} {timestamp}'
    packet = IP(dst="192.168.1.1") / TCP(dport=54321) / payload

    return [packet]

def port_scan_packets():
    packets = list()
    services = (80, 443, 22, 23, 21, 53, 554, 1433, 3389, 1883)

    for port in services:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        payload = f'{STUDENT_NAME} {timestamp}'
        packet = IP(dst="192.168.1.2") / TCP(dport=port) / payload
        packets.append(packet)

    return packets

def base64_malicious_packets():
    packets = list()

    for _ in range(5):
        payload = b64encode(STUDENT_ID.encode()).decode()
        packet = IP(dst="192.168.1.3") / TCP(dport=8080) / payload
        packets.append(packet)

    return packets

def dns_suspricious_domain_packets():
    payload = 'malicious.example.com'
    packet = IP(dst="192.168.1.1") / UDP(dport=53) / payload

    return [packet]

def ping_test_packet():
    payload = 'PingTest-2025'
    packet = IP(dst="192.168.1.4") / ICMP() / payload

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