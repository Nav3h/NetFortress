"""
Module for detecting brute force attacks in network traffic.
"""
import time
from collections import defaultdict
from IDS.utils.common_utils import print_with_timestamp, cleanup_tracker, RED
from IDS.detectors.attack_detector import AttackDetector
from collections import deque
import time

class BruteForceDetector(AttackDetector):
    def __init__(self, threshold=50):  # Adding default threshold
        super().__init__(threshold)
        self.attempts = defaultdict(lambda: {'count': 0, 'times': deque(), 'last_seen': None})
        #print_with_timestamp("[DEBUG] Brute Force Detector initialized", None)

    def detect(self, packet_data):
        #print_with_timestamp(f"[DEBUG] Brute Force Detector received packet: {packet_data}", None)
        src_ip = packet_data.get('src')
        dst_ip = packet_data.get('dst')
        dst_port = packet_data.get('dport')
        timestamp = packet_data.get('timestamp')

        if src_ip and dst_ip and dst_port:
            key = (dst_ip, dst_port)
            entry = self.attempts[key]
            entry['count'] += 1
            entry['times'].append(timestamp)
            entry['last_seen'] = timestamp
            #print_with_timestamp(f"[DEBUG] Brute Force Detector updated entry for {key}: {entry}", None)

            # Perform cleanup
            self.cleanup(key, entry)

            # Detect brute force
            if entry['count'] > self.threshold:
                print_with_timestamp(f"[ALERT] Brute force attack detected on {dst_ip}:{dst_port} from {src_ip}!", RED)

    def cleanup(self, key, entry):
        current_time = time.time()
        while entry['times'] and current_time - entry['times'][0] > 60:  # Cleanup threshold
            entry['times'].popleft()
            entry['count'] -= 1
        #print_with_timestamp(f"[DEBUG] Brute Force Detector after cleanup for {key}: {entry}", None)

