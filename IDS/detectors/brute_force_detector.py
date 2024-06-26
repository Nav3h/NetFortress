"""
Module for detecting brute force attacks in network traffic.
"""

import time
from collections import defaultdict, deque
from IDS.utils.common_utils import print_with_timestamp, RED
from IDS.utils.db_manager import create_connection, insert_detection, hash_detection
from IDS.detectors.attack_detector import AttackDetector

TIME_WINDOW = 60

class BruteForceDetector(AttackDetector):
    def __init__(self, threshold):
        super().__init__(threshold)  # Initialize the base class with the threshold
        self.brute_force_tracker = defaultdict(lambda: {'count': 0, 'times': deque()})

    def detect(self, packet_data):
        conn = create_connection("ids_database.db")  # Create database connection
        dst_ip = packet_data.get('dst')
        dst_port = packet_data.get('dport')
        current_time = time.time()

        if not dst_ip or not dst_port:
            conn.close()
            return  # Skip detection if key information is missing

        ip_port_key = (dst_ip, str(dst_port))  # Ensure port is a string

        tracker = self.brute_force_tracker[ip_port_key]
        tracker['count'] += 1
        tracker['times'].append(current_time)

        while tracker['times'] and current_time - tracker['times'][0] > TIME_WINDOW:
            tracker['times'].popleft()
            tracker['count'] -= 1

        if tracker['count'] > self.threshold:
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
            detection = ("brute_force", dst_ip, str(dst_port), timestamp, hash_detection([dst_ip, str(dst_port), timestamp]))
            insert_detection(conn, detection)
            print_with_timestamp(f"[ALERT] Brute force detected on {dst_ip}:{dst_port}", RED)
            tracker['times'].clear()
            tracker['count'] = 0
        conn.close()

