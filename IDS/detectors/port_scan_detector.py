"""
Module for detecting port scanning activities in network traffic.
"""

import time
from IDS.detectors.attack_detector import AttackDetector
from collections import deque, defaultdict
from IDS.utils.common_utils import print_with_timestamp, cleanup_tracker, RED

class PortScanDetector(AttackDetector):
    def __init__(self, threshold=50):  # Adding default threshold
        super().__init__(threshold)
        self.port_scan_tracker = defaultdict(lambda: {'ports': set(), 'times': deque()})

    def detect(self, packet_data):
        src = packet_data.get('src')
        dport = packet_data.get('dport')
        #print_with_timestamp(f"[DEBUG] Port Scan Detector received packet: {packet_data}", None)
        
        if not src or not dport:
            #print_with_timestamp(f"[DEBUG] Port Scan Detector skipping packet due to missing src or dport", None)
            return

        entry = self.port_scan_tracker[src]
        entry['ports'].add(dport)
        entry['times'].append(time.time())

        cleanup_tracker(self.port_scan_tracker, 60)
        #print_with_timestamp(f"[DEBUG] Port Scan Detector updated entry for {src}: {entry}", None)

        if len(entry['ports']) > self.threshold:
            print_with_timestamp(f"[ALERT] Suspicious port scanning activity detected from {src}", RED)
            entry['ports'].clear()
            entry['times'].clear()

