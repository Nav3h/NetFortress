"""
Module for detecting data exfiltration attempts in network traffic.
"""
from IDS.utils.common_utils import print_with_timestamp, RED
from IDS.detectors.attack_detector import AttackDetector

class DataExfilDetector(AttackDetector):
    """
    A class for detecting data exfiltration attempts.
    """
    def __init__(self, threshold):
        self.threshold = threshold

    def detect(self, packet):
        dst = packet.get('dst')
        payload_len = packet.get('payload_len')

        if not dst:
            return
        
        if payload_len > self.threshold:
            print_with_timestamp(f"Possible data exfiltration to {dst}", RED)
