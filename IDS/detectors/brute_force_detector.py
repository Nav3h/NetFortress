"""
Module for detecting brute force attacks in network traffic.
"""

from IDS.utils.common_utils import print_with_timestamp, cleanup_tracker, RED
from IDS.detectors.attack_detector import AttackDetector
from IDS.utils.db_manager import create_connection, insert_detection, hash_detection
import time
from collections import defaultdict

class BruteForceDetector(AttackDetector):
    def __init__(self, threshold):
        super().__init__(threshold)
        self.failed_attempts = defaultdict(int)
    
    def detect(self, packet_data):
        conn = create_connection("ids_database.db")
        src = packet_data.get('src')
        dst = packet_data.get('dst')
        port = packet_data.get('dport')

        if not src or not dst or not port:
            return

        key = (src, dst, port)
        if packet_data.get('status') == 'failed':
            self.failed_attempts[key] += 1
            print_with_timestamp(f"[DEBUG] BruteForceDetector: {key} has {self.failed_attempts[key]} failed attempts", None)
            
            if self.failed_attempts[key] >= self.threshold:
                timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
                detection = ("brute_force", src, dst, timestamp, hash_detection([src, dst, timestamp]))
                insert_detection(conn, detection)
                print_with_timestamp(f"[ALERT] Brute force attack detected from {src} to {dst} on port {port}!", RED)
                self.failed_attempts[key] = 0
        elif packet_data.get('status') == 'success':
            if key in self.failed_attempts:
                del self.failed_attempts[key]
        conn.close()