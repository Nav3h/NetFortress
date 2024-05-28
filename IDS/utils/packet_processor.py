"""
Module for processing network packets and extracting relevant information.
"""
from IDS.utils.common_utils import print_with_timestamp, cleanup_tracker, RED
from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.layers.inet6 import IPv6

def store_relevant_packet(packet):
    packet_data = {
        "timestamp": packet.time,
        "payload_len": len(packet.original)
    }

    if packet.haslayer(IP):
        packet_data.update({
            "src": packet[IP].src,
            "dst": packet[IP].dst,
            "ttl": packet[IP].ttl,
            "proto": packet[IP].proto,
            "len": packet[IP].len,
            "flags": packet[IP].flags,
            "id": packet[IP].id
        })
    elif packet.haslayer(IPv6):
        packet_data.update({
            "src": packet[IPv6].src,
            "dst": packet[IPv6].dst
        })

    if packet.haslayer(TCP):
        packet_data.update({
            "sport": packet[TCP].sport,
            "dport": packet[TCP].dport,
            "seq": packet[TCP].seq,
            "ack": packet[TCP].ack,
            "flags": packet[TCP].flags,
            "window": packet[TCP].window
        })

    if packet.haslayer(UDP):
        packet_data.update({
            "sport": packet[UDP].sport,
            "dport": packet[UDP].dport,
            "len": packet[UDP].len
        })

    if packet.haslayer(ICMP):
        packet_data.update({
            "type": packet[ICMP].type,
            "code": packet[ICMP].code,
            "id": packet[ICMP].id,
            "seq": packet[ICMP].seq
        })

    return packet_data

def process_packet(packet, detectors):
    """
    Process each packet, extract relevant information and pass it to the detectors.
    """
    packet_data = store_relevant_packet(packet)
    #print_with_timestamp(f"[DEBUG] Processing packet: {packet_data}", None)

    if packet_data.get('src') == '127.0.0.1' or packet_data.get('dst') == '127.0.0.1':
        return

    if "src" in packet_data and "dst" in packet_data:  # IP Packet
        #print_with_timestamp(f"[DEBUG] Packet is an IP packet with src {packet_data['src']} and dst {packet_data['dst']}", None)
        detectors['brute_force'].detect(packet_data)
        
        if "sport" in packet_data and "dport" in packet_data:  # TCP or UDP Packet
            #print_with_timestamp(f"[DEBUG] Packet is a TCP/UDP packet with sport {packet_data['sport']} and dport {packet_data['dport']}", None)
            detectors['port_scan'].detect(packet_data)
            detectors['syn_flood'].detect(packet_data)

        if "type" in packet_data and packet_data["type"] == 8:  # ICMP Echo Request Packet
            #print_with_timestamp(f"[DEBUG] Packet is an ICMP packet with type {packet_data['type']}", None)
            detectors['ping_sweep'].detect(packet_data)
