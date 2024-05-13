"""
Module for detecting brute force attacks in network traffic.
"""

import time
from collections import defaultdict
from IDS.utils.common_utils import print_with_timestamp, cleanup_tracker, RED
from IDS.detectors.attack_detector import AttackDetector
from collections import deque

TIME_WINDOW = 10

class BruteForceDetector(AttackDetector):
    def __init__(self, threshold):
        self.threshold = threshold  
        self.brute_force_tracker = {} 

    def detect(self, packet_data):
        dst_ip = packet_data.get('dst')
        dst_port = packet_data.get('dport')
        current_time = time.time()

        if dst_ip is None or dst_port is None:
            return

        ip_port_key = (dst_ip, dst_port)

        if ip_port_key not in self.brute_force_tracker:
            self.brute_force_tracker[ip_port_key] = {
                'count': 0, 
                'times': deque()
            }
        self.brute_force_tracker[ip_port_key]['count'] += 1
        self.brute_force_tracker[ip_port_key]['times'].append(current_time)


        while self.brute_force_tracker[ip_port_key]['times'] and  current_time - self.brute_force_tracker[ip_port_key]['times'][0] > TIME_WINDOW:
            self.brute_force_tracker[ip_port_key]['times'].popleft()
            self.brute_force_tracker[ip_port_key]['count'] -= 1

        if self.brute_force_tracker[ip_port_key]['count'] > 50:
            print(f"[DEBUG] High brute force count for {dst_ip}:{dst_port}: {self.brute_force_tracker[ip_port_key]['count']}")

        if self.brute_force_tracker[ip_port_key]['count'] > self.threshold:
            print(f"[ALERT] Brute force detected on {dst_ip}:{dst_port}")

            self.brute_force_tracker[ip_port_key] = {
                'count': 0, 
                'times': deque()
            }

