"""
Module for detecting SYN flood attacks in network traffic.
"""
from collections import defaultdict
import time
from IDS.utils.common_utils import print_with_timestamp, cleanup_tracker, RED

class SynFloodDetector:
    """
    A class for detecting SYN flood attacks.
    """
    def __init__(self, threshold):
        self.threshold = threshold
        self.syn_counter = defaultdict(lambda: {"count": 0, "last_seen": 0})

    def detect(self, packet_data):
        """Detect potential SYN flood attacks in the given packet data."""
        if 'flags' in packet_data and 'S' in packet_data['flags']:
            src_ip = packet_data['src']
            if src_ip not in self.syn_counter:
                self.syn_counter[src_ip] = {'count': 0, 'last_seen': time.time()}
            
            self.syn_counter[src_ip]['count'] += 1
            self.syn_counter[src_ip]['last_seen'] = time.time()

            print_with_timestamp(f"[DEBUG] SYN Count from {src_ip}: {self.syn_counter[src_ip]['count']}")

            if self.syn_counter[src_ip]['count'] > self.threshold:
                print_with_timestamp(f"Potential SYN flood attack detected from {src_ip}!", RED)
                del self.syn_counter[src_ip]  # reset

        cleanup_tracker(self.syn_counter,60)
