from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

def packet_callback(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.proto

        print(f"[+] Packet: {src_ip} -> {dst_ip} | Protocol: {proto}")
        
        if packet.haslayer(TCP):
            print(f"    TCP Packet | Src Port: {packet[TCP].sport} -> Dst Port: {packet[TCP].dport}")
        elif packet.haslayer(UDP):
            print(f"    UDP Packet | Src Port: {packet[UDP].sport} -> Dst Port: {packet[UDP].dport}")

print("[*] Starting Network Sniffer...")
sniff(prn=packet_callback, store=False)
