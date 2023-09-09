import threading
import time
from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.sendrecv import send, sniff
from collections import defaultdict
import random
from colorama import Fore, Style
from colorama import Fore
import winsound
# ------ Monitoring Code ---------
GREEN = Fore.GREEN
RED = Fore.LIGHTRED_EX
RESET = Style.RESET_ALL
port_scan_tracker = defaultdict(set)
SYN_COUNTER = defaultdict(lambda: {"count": 0, "last_seen": 0})
TIME_WINDOW = 10  # 10 seconds
THRESHOLD = 50  
icmp_tracker = defaultdict(lambda: {"count": 0, "last_seen": 0})
brute_force_tracker = defaultdict(lambda: {"count": 0, "last_seen": 0})

def cleanup_tracker(tracker):
    current_time = time.time()
    for key, value in list(tracker.items()):
        if current_time - value["last_seen"] > TIME_WINDOW:
            del tracker[key]

# ... [All the detect_XXX functions and store_relevant_packet here] ...
def detect_brute_force(packet):
    dst = packet.get('dst')
    dport = packet.get('dport')

    if dport is None:
        return
    if not dst:
        return
    
    if dport in [22, 21]:  # SSH or FTP as examples
        if dst not in brute_force_tracker:
            brute_force_tracker[dst] = {'count': 0, 'last_seen': time.time()}
        
        brute_force_tracker[dst]['count'] += 1
        brute_force_tracker[dst]['last_seen'] = time.time()

        if brute_force_tracker[dst]['count'] > 5:  # decrease threshold
           print(f"{RED}Suspicious brute force activity on {dst}:{dport}{RESET}")
           winsound.Beep(1000, 1000)
           del brute_force_tracker[dst]  # reset

    cleanup_tracker(brute_force_tracker)



def detect_ping_sweep(packet):
    src = packet.get('src')
    packet_type = packet.get('type')

    if not src or packet_type is None:
        return
        
    if packet_type == 8:  # ICMP Echo Request
        if src not in icmp_tracker:
            icmp_tracker[src] = {'count': 0, 'last_seen': time.time()}
            
        icmp_tracker[src]['count'] += 1
        icmp_tracker[src]['last_seen'] = time.time()

        if icmp_tracker[src]['count'] > 15:  # decrease threshold
            print(f"{RED}Suspicious ping sweep detected from {src}{RESET}")
            winsound.Beep(1000, 1000)
            del icmp_tracker[src]  # reset

    cleanup_tracker(icmp_tracker)


def detect_data_exfil(packet):
    dst = packet.get('dst')
    payload_len = packet.get('payload_len')

    if not dst:
        return
    
    if payload_len > 5000:  # decreased threshold for testing
        print(f"{RED}Possible data exfiltration to {dst}{RESET}")
        winsound.Beep(1000, 1000)


def detect_syn_flood(packet_data):

    if 'flags' in packet_data and 'S' in packet_data['flags']:
        src_ip = packet_data['src']
        if src_ip not in SYN_COUNTER:
            SYN_COUNTER[src_ip] = {'count': 0, 'last_seen': time.time()}
        
        SYN_COUNTER[src_ip]['count'] += 1
        SYN_COUNTER[src_ip]['last_seen'] = time.time()

        print(f"{GREEN}[DEBUG] SYN Count from {src_ip}: {SYN_COUNTER[src_ip]['count']}{RESET}")

        if SYN_COUNTER[src_ip]['count'] > THRESHOLD:
            print(f"{RED}Potential SYN flood attack detected from {src_ip}!{RESET}")
            winsound.Beep(1000, 1000)
            del SYN_COUNTER[src_ip]  # reset

    cleanup_tracker(SYN_COUNTER)

def detect_port_scan(packet):
    src = packet.get('src')
    dport = packet.get('dport')

    if not src or not dport:
        return
    
    if src not in port_scan_tracker:
        port_scan_tracker[src] = {'ports': set(), 'last_seen': time.time()}
    
    port_scan_tracker[src]['ports'].add(dport)
    port_scan_tracker[src]['last_seen'] = time.time()

    if len(port_scan_tracker[src]['ports']) > 15:  # example threshold
        print(f"{RED}Suspicious port scanning activity detected from {src}{RESET}")
        winsound.Beep(1000, 1000)
        del port_scan_tracker[src]  # reset

    cleanup_tracker(port_scan_tracker)


def store_relevant_packet(packet):
    packet_data = {
        "timestamp": packet.time,
        "payload_len": len(packet.original) if packet.haslayer("Raw") else 0
    }

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

    if packet.haslayer("TCP"):
        packet_data.update({
            "sport": packet["TCP"].sport,
            "dport": packet["TCP"].dport,
            "seq": packet["TCP"].seq,
            "ack": packet["TCP"].ack,
            "flags": packet["TCP"].flags,
            "window": packet["TCP"].window
        })

    if packet.haslayer("UDP"):
        packet_data.update({
            "sport": packet["UDP"].sport,
            "dport": packet["UDP"].dport,
            "len": packet["UDP"].len
        })

    if packet.haslayer("ICMP"):
        packet_data.update({
            "type": packet["ICMP"].type,
            "code": packet["ICMP"].code,
            "id": packet["ICMP"].id,
            "seq": packet["ICMP"].seq
        })

    return packet_data

def process_packet(packet):
    packet_data = store_relevant_packet(packet)
    
    if "src" in packet_data and "dst" in packet_data:  # IP Packet
        detect_port_scan(packet_data)
        detect_data_exfil(packet_data)
        detect_brute_force(packet_data)
        
        if "sport" in packet_data and "dport" in packet_data:  # TCP or UDP Packet
            detect_syn_flood(packet_data)

    elif "type" in packet_data:  # ICMP Packet
        detect_ping_sweep(packet_data)

    else:
        print(f"Unhandled packet type: {packet.summary()}")

# ------ Simulation Code ---------

def simulate_ping_sweep(target_ip_prefix):
    for i in range(1, 101):  # Range from 1 to 100
        ip = f"{target_ip_prefix}.{i}"
        packet = IP(dst=ip)/ICMP()
        send(packet, verbose=0)
    print("Ping sweep simulation completed.")

def simulate_port_scan(target_ip):
    ports = random.sample(range(1, 5000), 100)  # 100 ports from 1 to 5000
    for port in ports:
        packet = IP(dst=target_ip)/TCP(dport=port, flags="S")
        send(packet, verbose=0)
    print(f"Port scan simulation completed on {target_ip}.")

def simulate_syn_flood(target_ip, target_port):
    for i in range(500):  # Sending 500 SYN packets
        packet = IP(dst=target_ip)/TCP(dport=target_port, flags="S")
        send(packet, verbose=2)
        time.sleep(0.01)  # 10 ms delay
    print(f"SYN flood simulation completed on {target_ip}.")

def simulate_suspicious_activity():
    time.sleep(5)  # Sleep for 5 seconds to give the monitor time to start
    TARGET_IP_PREFIX = "192.168.1"  # Example IP prefix for ping sweep
    MY_IP = "192.168.1.22"  # Your machine's IP address

    simulate_ping_sweep(TARGET_IP_PREFIX)
    simulate_port_scan(MY_IP)  # Adjusted to your IP
    simulate_syn_flood(MY_IP, 22)  # Adjusted to your IP

# ------ Main Execution ---------
def network_monitor():
    print("Monitoring network traffic...")
    sniff(iface="Ethernet", prn=process_packet)
    
if __name__ == "__main__":
    monitor_thread = threading.Thread(target=network_monitor)
    simulator_thread = threading.Thread(target=simulate_suspicious_activity)

    monitor_thread.start()
    simulator_thread.start()

    monitor_thread.join()
    simulator_thread.join()





