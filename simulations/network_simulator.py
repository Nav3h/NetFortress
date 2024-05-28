"""
This module contains functions to simulate various network activities 
for testing an Intrusion Detection System.
"""
import time
from IDS.utils.common_utils import print_with_timestamp, cleanup_tracker, RED
from scapy.layers.inet import IP, ICMP, TCP
from scapy.sendrecv import send
import random

def simulate_ping_sweep(target_ip_prefix):
    """Simulates a ping sweep attack."""
    for i in range(1, 255):
            ip = f"192.168.1.{i}"
            pkt = IP(dst=ip) / ICMP()
            send(pkt, verbose=False)
            time.sleep(0.1)
            #print_with_timestamp(f"[DEBUG] Simulating ping sweep: {ip}", None)

def simulate_port_scan(target_ip):
    """Simulates a port scan attack."""
    ports = range(1, 65535)
    for port in ports:
        packet = IP(dst=target_ip)/TCP(dport=port, flags="S")
        send(packet, verbose=False)
    print(f"[{time.ctime()}] Port scan simulation completed on {target_ip}.")

def simulate_syn_flood(target_ip, target_port):
    """Simulates a SYN flood attack."""
    for i in range(4000):  
        packet = IP(dst=target_ip)/TCP(dport=target_port, flags="S")
        send(packet, verbose=False)
    print(f"[{time.ctime()}] SYN flood simulation completed on {target_ip}:{target_port}.")

def simulate_brute_force(target_ip, target_port, num_attempts=10000):
    """Simulates a brute force attack."""
    for i in range(num_attempts):
        password = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=8))
        packet = IP(dst=target_ip)/TCP(dport=target_port)/password
        send(packet, verbose=False)
    print(f"[{time.ctime()}] Brute force simulation completed on {target_ip}:{target_port}.")

def simulate_suspicious_activity():
    """Simulates various types of network attacks."""
    target_ip_prefix = "192.168.1"
    my_ip = "192.168.56.1"
    target_port = 22

    simulate_ping_sweep(target_ip_prefix)
    simulate_port_scan(my_ip)
    simulate_syn_flood(my_ip, target_port)
    simulate_brute_force(my_ip, target_port)

if __name__ == "__main__":
    simulate_suspicious_activity()

