"""
Module for detecting SYN flood attacks in network traffic.
"""
import time
from IDS.utils.common_utils import print_with_timestamp, cleanup_tracker, RED
from IDS.detectors.attack_detector import AttackDetector
from collections import deque, defaultdict
from IDS.utils.db_manager import create_connection, insert_detection, hash_detection

class SynFloodDetector(AttackDetector):
    def __init__(self, threshold=100):  # Adding default threshold
        super().__init__(threshold)
        self.syn_counter = defaultdict(lambda: {'count': 0, 'times': deque()})

    def detect(self, packet_data):
        conn = create_connection("ids_database.db")
        src_ip = packet_data.get('src')
        flags = packet_data.get('flags', '')

        if 'S' in flags:
            entry = self.syn_counter[src_ip]
            entry['times'].append(time.time())
            entry['count'] += 1

            cleanup_tracker(self.syn_counter, 60)
            
            if entry['count'] > self.threshold:
                timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
                detection = ("syn_flood", src_ip, "N/A", timestamp, hash_detection([src_ip, "N/A", timestamp]))
                insert_detection(conn, detection)
                print_with_timestamp(f"[ALERT] SYN flood attack detected from {src_ip}!", RED)
                entry['times'].clear()
                entry['count'] = 0
        conn.close()