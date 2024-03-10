"""
Module for detecting ping sweep scans in network traffic.
"""
from collections import defaultdict
import time
from IDS.utils.common_utils import print_with_timestamp, cleanup_tracker, RED
from IDS.detectors.attack_detector import AttackDetector

class PingSweepDetector(AttackDetector):
    """
    A class for detecting ping sweep scans.
    """
    def __init__(self, threshold):
        self.threshold = threshold
        self.icmp_tracker = defaultdict(lambda: {"count": 0, "last_seen": 0})

    def detect(self, packet):
        """Detect potential port scanning activity in the given packet."""
        src = packet.get('src')
        packet_type = packet.get('type')

        if not src or packet_type is None:
            return       
             
        if packet_type == 8:  # ICMP Req
            if src not in self.icmp_tracker:
                self.icmp_tracker[src] = {'count': 0, 'last_seen': time.time()}                
            self.icmp_tracker[src]['count'] += 1

            self.icmp_tracker[src]['last_seen'] = time.time()
            if self.icmp_tracker[src]['count'] > self.threshold:
                print_with_timestamp(f"Suspicious ping sweep detected from {src}", RED)
                del self.icmp_tracker[src]  

        cleanup_tracker(self.icmp_tracker, 60)
