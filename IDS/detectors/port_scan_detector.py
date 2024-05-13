"""
Module for detecting port scanning activities in network traffic.
"""
from collections import deque
from collections import defaultdict
import time
from IDS.utils.common_utils import print_with_timestamp, cleanup_tracker, RED
from IDS.detectors.attack_detector import AttackDetector


class PortScanDetector(AttackDetector):
    """
    A class for detecting port scanning activities.
    """
    def __init__(self, threshold):
        self.threshold = threshold
        self.port_scan_tracker = {}

    def detect(self, packet_data):
        src = packet_data.get('src')
        dport = packet_data.get('dport')

        if not src or not dport:
            return
        
        if src not in self.port_scan_tracker:
            self.port_scan_tracker[src] = {
            'ports': set(),
            'last_seen': time.time(),
            'times': deque()
            }
        
        self.port_scan_tracker[src]['ports'].add(dport)
        self.port_scan_tracker[src]['last_seen'] = time.time()
        self.port_scan_tracker[src]['times'].append(time.time())

        if len(self.port_scan_tracker[src]['ports']) > 50:
            print(f"[DEBUG] High port scan activity detected from {src}: {len(self.port_scan_tracker[src]['ports'])}")


        if len(self.port_scan_tracker[src]['ports']) > self.threshold:
            print_with_timestamp(f"Suspicious port scanning activity detected from {src}", RED)
            del self.port_scan_tracker[src]  

        cleanup_tracker(self.port_scan_tracker, 60)
