"""
Main script for running the Intrusion Detection System.
"""
import threading
from scapy.all import sniff
import logging
from scapy.config import conf
from colorama import Fore, Style
from IDS.detectors.syn_flood_detector import SynFloodDetector
from IDS.detectors.ping_sweep_detector import PingSweepDetector
from IDS.detectors.brute_force_detector import BruteForceDetector
from IDS.detectors.port_scan_detector import PortScanDetector
from IDS.detectors.data_exfiltration import DataExfilDetector
from IDS.utils.packet_processor import process_packet
from simulations.network_simulator import simulate_suspicious_activity
GREEN = Fore.GREEN
conf.logLevel = logging.ERROR


def network_monitor(detectors, interface="\\Device\\NPF_Loopback"):  #currently on loopback for the testing. change interface accordingly as needed for scanning.
    print("Monitoring network traffic started",GREEN)
    sniff(iface=interface, filter="ip", prn=lambda x: process_packet(x, detectors))

if __name__ == "__main__":
    syn_flood_detector = SynFloodDetector(threshold=15)
    ping_sweep_detector = PingSweepDetector(threshold=10)
    brute_force_detector = BruteForceDetector(threshold=1000)
    port_scan_detector = PortScanDetector(threshold=11)
    data_exfil_detector = DataExfilDetector(threshold=5000)

    detectors = {
        "syn_flood": syn_flood_detector,
        "ping_sweep": ping_sweep_detector,
        "brute_force": brute_force_detector,
        "port_scan": port_scan_detector,
        "data_exfil": data_exfil_detector
    }

    monitor_thread = threading.Thread(target=network_monitor, args=(detectors,))
    simulator_thread = threading.Thread(target=simulate_suspicious_activity) 

    monitor_thread.start()
    simulator_thread.start()

    monitor_thread.join()
    simulator_thread.join()

