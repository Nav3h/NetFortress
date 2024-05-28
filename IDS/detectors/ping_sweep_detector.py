"""
Module for detecting ping sweep scans in network traffic.
"""
import time
from IDS.detectors.attack_detector import AttackDetector
from collections import deque, defaultdict
from IDS.utils.common_utils import print_with_timestamp, cleanup_tracker, RED
import datetime


class PingSweepDetector:
    def __init__(self, threshold):
        self.threshold = threshold
        self.icmp_requests = {}
        #print(f"[DEBUG] PingSweepDetector initialized with threshold: {self.threshold}")

    def detect(self, packet):
        src_ip = packet.get('src')
        dst_ip = packet.get('dst')
        icmp_type = packet.get('type')
        #print(f"[DEBUG] PingSweepDetector.detect called with packet: src_ip={src_ip}, dst_ip={dst_ip}, icmp_type={icmp_type}")

        if icmp_type == 8:  # Echo request (ping)
            #print(f"[DEBUG] Detected ICMP type 8 (echo request) from {src_ip} to {dst_ip}")
            if src_ip not in self.icmp_requests:
                self.icmp_requests[src_ip] = []
            self.icmp_requests[src_ip].append(datetime.datetime.now())
            self._check_for_sweep(src_ip)

    def _check_for_sweep(self, src_ip):
        current_time = datetime.datetime.now()
        self.icmp_requests[src_ip] = [timestamp for timestamp in self.icmp_requests[src_ip] if (current_time - timestamp).seconds <= 1]
        #print(f"[DEBUG] Current ICMP requests for {src_ip}: {self.icmp_requests[src_ip]}")

        if len(self.icmp_requests[src_ip]) > self.threshold:
            self._alert(src_ip)

    def _alert(self, src_ip):
        print(f"[ALERT] Ping sweep detected from {src_ip}!")

