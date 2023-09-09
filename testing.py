from scapy.all import sniff
from collections import defaultdict

port_scan_tracker = defaultdict(set)
syn_tracker = defaultdict(int)
icmp_tracker = defaultdict(int)
brute_force_tracker = defaultdict(int)


def detect_brute_force(packet):
    dst = packet['dst']
    dport = packet.get('dport')  # Use .get() to retrieve the value safely

    if dport is None:
        return
    
    if dport in [22, 21]:  # SSH or FTP as example
        brute_force_tracker[dst] += 1

    if brute_force_tracker[dst] > 20:  # example threshold
        print(f"Suspicious brute force activity on {dst}:{dport}")
        brute_force_tracker[dst] = 0  # reset


def detect_ping_sweep(packet):
    src = packet['src']
    packet_type = packet.get('type')

    if packet_type is None:
        return
        
    if packet_type == 8:  # ICMP Echo Request
        icmp_tracker[src] += 1

    if icmp_tracker[src] > 20:  # example threshold
        print(f"Suspicious ping sweep detected from {src}")
        icmp_tracker[src] = 0  # reset

def detect_data_exfil(packet):
    dst = packet['dst']
    payload_len = packet['payload_len']

    if payload_len > 5000:  # arbitrary large size threshold
        print(f"Possible data exfiltration to {dst}")


def detect_syn_flood(packet):
    flags = packet['flags']
    src = packet['src']

    if "S" in flags and "A" not in flags:  # Pure SYN flag
        syn_tracker[src] += 1

    if syn_tracker[src] > 100:  # example threshold
        print(f"Suspicious SYN flood activity from {src}")
        syn_tracker[src] = 0  # reset

def detect_port_scan(packet):
    src = packet['src']
    dport = packet.get('dport')  # Use .get() to avoid KeyError
    if not dport:
        return
    
    port_scan_tracker[src].add(dport)

    if len(port_scan_tracker[src]) > 20:  # example threshold
        print(f"Suspicious port scanning activity detected from {src}")
        port_scan_tracker[src].clear()  # reset once detected

def store_relevant_packet(packet):
    packet_data = {
        "timestamp": packet.time,
        "payload_len": len(packet.original) if packet.haslayer("Raw") else 0
    }

    # Capture IP layer details (common for IPv4 and IPv6)
    if packet.haslayer("IP"):
        packet_data.update({
            "src": packet["IP"].src,
            "dst": packet["IP"].dst,
            "ttl": packet["IP"].ttl,
            "proto": packet["IP"].proto,
            "len": packet["IP"].len,
            "flags": packet["IP"].flags,
            "id": packet["IP"].id
        })
        return packet_data

    # Capture TCP layer details
    if packet.haslayer("TCP"):
        packet_data.update({
            "sport": packet["TCP"].sport,
            "dport": packet["TCP"].dport,
            "seq": packet["TCP"].seq,
            "ack": packet["TCP"].ack,
            "flags": packet["TCP"].flags,
            "window": packet["TCP"].window
        })
        return packet_data

    # Capture UDP layer details
    if packet.haslayer("UDP"):
        packet_data.update({
            "sport": packet["UDP"].sport,
            "dport": packet["UDP"].dport,
            "len": packet["UDP"].len
        })
        return packet_data

    # Capture ICMP layer details
    if packet.haslayer("ICMP"):
        packet_data.update({
            "type": packet["ICMP"].type,
            "code": packet["ICMP"].code,
            "id": packet["ICMP"].id,
            "seq": packet["ICMP"].seq
        })
        return packet_data

    # Optionally: save the summary to a file or database.

# Packet processing function
def process_packet(packet):
    # Store packet data
    packet_data = store_relevant_packet(packet)
    
    # Call each detection function
    detect_port_scan(packet_data)
    detect_syn_flood(packet_data)
    detect_ping_sweep(packet_data)
    detect_data_exfil(packet_data)
    detect_brute_force(packet_data)


# Main function
def main():
    print("Starting network monitor...")
    # Sniff packets and process them using the process_packet function
    sniff(prn=process_packet, filter="ip", store=0)

if __name__ == "__main__":
    main()