"""
Module for detecting SYN flood attacks in network traffic.
"""
import time
from IDS.utils.common_utils import print_with_timestamp, cleanup_tracker, RED
from IDS.detectors.attack_detector import AttackDetector
from collections import deque, defaultdict

class SynFloodDetector(AttackDetector):
    def __init__(self, threshold=100):  # Adding default threshold
        super().__init__(threshold)
        self.syn_counter = defaultdict(lambda: {'count': 0, 'times': deque()})

    def detect(self, packet_data):
        src_ip = packet_data.get('src')
        flags = packet_data.get('flags', '')
        #print_with_timestamp(f"[DEBUG] SYN Flood Detector received packet: {packet_data}", None)
        #print_with_timestamp(f"[DEBUG] SYN Flood Detector checking packet with flags: {flags}", None)
        
        if 'S' in flags:
            entry = self.syn_counter[src_ip]
            entry['times'].append(time.time())
            entry['count'] += 1

            cleanup_tracker(self.syn_counter, 60)
            #print_with_timestamp(f"[DEBUG] SYN Flood Detector updated entry for {src_ip}: {entry}", None)
            
            if entry['count'] > self.threshold:
                print_with_timestamp(f"[ALERT] SYN flood attack detected from {src_ip}!", RED)
                entry['times'].clear()
                entry['count'] = 0
