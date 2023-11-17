"""
Module for detecting brute force attacks in network traffic.
"""

import time
from collections import defaultdict
from IDS.utils.common_utils import print_with_timestamp, cleanup_tracker, RED
from collections import deque

TIME_WINDOW = 10

class BruteForceDetector:
    def __init__(self, threshold):
        """
        Initialize the brute force detector with a threshold.
        """
        self.threshold = threshold
        self.brute_force_tracker = {}

    def detect(self, packet_data):
        """
        Detect potential brute force activities based on packet data.
        """
        dst = packet_data.get('dst')
        dport = packet_data.get('dport')

        if not dst or not dport:
            return

        if dst not in self.brute_force_tracker:
            self.brute_force_tracker[dst] = {
                'count': 0,
                'last_seen': time.time(),
                'times': deque()
            }

        self.brute_force_tracker[dst]['count'] += 1
        self.brute_force_tracker[dst]['last_seen'] = time.time()
        self.brute_force_tracker[dst]['times'].append(time.time())

              
        if self.brute_force_tracker[dst]['count'] > self.threshold:
            print_with_timestamp(f"Suspicious brute force activity on {dst}:{dport}", RED)
            del self.brute_force_tracker[dst]

        self.cleanup_tracker(dst)


    def cleanup_tracker(self, dst):
        """
        Cleanup old entries from the tracker.
        """
        current_time = time.time()

        if dst not in self.brute_force_tracker:
            self.brute_force_tracker[dst] = {'count': 0, 'times': deque(), 'last_seen': 0}

        times = self.brute_force_tracker[dst]['times']

        while times and current_time - times[0] > TIME_WINDOW:
            times.popleft()

        if not times:
            del self.brute_force_tracker[dst]
