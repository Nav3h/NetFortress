"""
Module for detecting port scanning activities in network traffic.
"""

import time
from IDS.detectors.attack_detector import AttackDetector
from collections import deque, defaultdict
from IDS.utils.common_utils import print_with_timestamp, cleanup_tracker, RED
from IDS.utils.db_manager import create_connection, insert_detection, hash_detection

class PortScanDetector(AttackDetector):
    def __init__(self, threshold=50):  # Adding default threshold
        super().__init__(threshold)
        self.port_scan_tracker = defaultdict(lambda: {'ports': set(), 'times': deque()})

    def detect(self, packet_data):
        conn = create_connection("ids_database.db")
        src = packet_data.get('src')
        dport = packet_data.get('dport')

        if not src or not dport:
            return

        entry = self.port_scan_tracker[src]
        entry['ports'].add(dport)
        entry['times'].append(time.time())

        cleanup_tracker(self.port_scan_tracker, 30)

        if len(entry['ports']) > self.threshold:
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
            detection = ("port_scan", src, "N/A", timestamp, hash_detection([src, "N/A", timestamp]))
            insert_detection(conn, detection)
            print_with_timestamp(f"[ALERT] Suspicious port scanning activity detected from {src}", RED)
            entry['ports'].clear()
            entry['times'].clear()
        conn.close()