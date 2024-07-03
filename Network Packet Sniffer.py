from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        protocol = ip_layer.proto
        src = ip_layer.src
        dst = ip_layer.dst
        
        # Determine the protocol
        if protocol == 6:  # TCP
            proto_name = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
        elif protocol == 17:  # UDP
            proto_name = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport
        else:
            proto_name = "Other"
            sport = dport = None
        
        print(f"Source: {src}:{sport}, Destination: {dst}:{dport}, Protocol: {proto_name}")
    
# Capture packets
sniff(prn=packet_callback, count=10)
