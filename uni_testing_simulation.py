import threading
import time
from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.sendrecv import send, sniff
from collections import defaultdict
import random
from colorama import Fore, Style
from colorama import Fore
import winsound
from collections import defaultdict, deque
from datetime import datetime
import logging
# ------ Monitoring Code ---------
GREEN = Fore.GREEN
RED = Fore.LIGHTRED_EX
RESET = Style.RESET_ALL
port_scan_tracker = defaultdict(set)
SYN_COUNTER = defaultdict(lambda: {"count": 0, "last_seen": 0})
TIME_WINDOW = 10  # 10 seconds
THRESHOLD = 50  
SNIFFING_INTERFACE = "Ethernet"
BRUTE_FORCE_THRESHOLD = 10
SYN_THRESHOLD = 100
DATA_EXFIL_THRESHOLD = 7000
PING_SWEEP_THRESHOLD = 10
SYN_THRESHOLD = 75
PORT_SCAN_THRESHOLD = 15
monitor_thread_started = threading.Event()
icmp_tracker = defaultdict(lambda: {"count": 0, "last_seen": 0})
brute_force_tracker = defaultdict(lambda: {"count": 0, "last_seen": 0})
# Using deque to efficiently handle cleanup
tracker_times = defaultdict(deque)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
def print_with_timestamp(msg, color=None):
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    if color:
        print(f"{color}[{current_time}] {msg}{RESET}")
    else:
        print(f"[{current_time}] {msg}")

def cleanup_tracker(tracker):
    current_time = time.time()
    for key, times in tracker_times.items():
        while times and current_time - times[0] > TIME_WINDOW:
            times.popleft()
            tracker[key]['count'] -= 1
        if not times:
            del tracker[key]

# ... [All the detect_XXX functions and store_relevant_packet here] ...
def detect_brute_force(packet):
    dst = packet.get('dst')
    dport = packet.get('dport')

    if dport is None or not dst:
        return
    
    if brute_force_tracker[dst]['count'] > BRUTE_FORCE_THRESHOLD:
        print(f"{RED}Suspicious brute force activity on {dst}:{dport}{RESET}")
        winsound.Beep(1000, 1000)
        del brute_force_tracker[dst]

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
    elif packet.haslayer("IPv6"):
        # If it's an IPv6 packet, just grab source and destination for now
        packet_data.update({
            "src": packet["IPv6"].src,
            "dst": packet["IPv6"].dst
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
    # Reducing the number of IPs pinged to 10 for faster simulation
    for i in range(1, 11):  
        ip = f"{target_ip_prefix}.{i}"
        packet = IP(dst=ip)/ICMP()
        send(packet, verbose=0)
    print("[{}] Ping sweep simulation completed.".format(time.ctime()))

def simulate_port_scan(target_ip):
    # Reducing the number of ports scanned to 3 for faster simulation
    ports = [22, 80, 443] 
    for port in ports:
        packet = IP(dst=target_ip)/TCP(dport=port, flags="S")
        send(packet, verbose=0)
    print(f"[{time.ctime()}] Port scan simulation completed on {target_ip}.")

def simulate_syn_flood(target_ip, target_port):
    # Increasing the number of SYN packets sent at once to 500 for a more intense simulation
    for i in range(500):  
        packet = IP(dst=target_ip)/TCP(dport=target_port, flags="S")
        send(packet, verbose=0)
    print(f"[{time.ctime()}] SYN flood simulation completed on {target_ip}:{target_port}.")

def simulate_suspicious_activity():
    TARGET_IP_PREFIX = "192.168.1"  # Example IP prefix for ping sweep
    MY_IP = "192.168.1.22"  # Your machine's IP address

    simulate_ping_sweep(TARGET_IP_PREFIX)
    simulate_port_scan(MY_IP)
    simulate_syn_flood(MY_IP, 22)
# ------ Main Execution ---------
def network_monitor():
    print("Monitoring network traffic...")
    monitor_thread_started.set()  # Indicate that the monitor has started
    sniff(iface=SNIFFING_INTERFACE, filter="ip", prn=process_packet) # filter set to "ip" will focus on IPv4 packets.
    
def wait_for_monitor_to_start():
    while not monitor_thread_started:
        time.sleep(0.1)

if __name__ == "__main__":
    
    monitor_thread = threading.Thread(target=network_monitor)
    simulator_thread = threading.Thread(target=simulate_suspicious_activity)

    monitor_thread.start()
    monitor_thread_started.wait()  # This will block until the monitor_thread_started event is set
    simulator_thread.start()

    monitor_thread.join()
    simulator_thread.join()








