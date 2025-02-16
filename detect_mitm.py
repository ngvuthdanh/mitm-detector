from scapy.all import rdpcap, ARP
from collections import defaultdict

def detect_arp_spoofing(pcap_file):
    packets = rdpcap(pcap_file)
    arp_table = defaultdict(set)

    for packet in packets:
        if packet.haslayer(ARP) and packet[ARP].op == 2:  
            ip = packet[ARP].psrc
            mac = packet[ARP].hwsrc
            arp_table[ip].add(mac)

    print("🔍 Kiểm tra ARP Spoofing...\n")
    for ip, macs in arp_table.items():
        if len(macs) > 1: 
            print(f"⚠️ Warning ARP Spoofing: IP {ip} MAC {macs}")

if __name__ == "__main__":
    pcap_file = "capture.pcap" 
    detect_arp_spoofing(pcap_file)
