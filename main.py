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
from IDS.detectors.detector_factory import DetectorFactory
from IDS.utils.packet_processor import process_packet
from simulations.network_simulator import simulate_suspicious_activity
GREEN = Fore.GREEN

def network_monitor(detectors, interface="\\Device\\NPF_Loopback"):  #currently on loopback for the testing. change interface accordingly as needed for scanning.
    print("Monitoring network traffic started",GREEN)
    try:
        sniff(iface=interface, filter="ip", prn=lambda x: process_packet(x, detectors))
    except Exception as e:
        logging.error("[!] Error during packet sniffing: {e}")
    finally:
        logging.info("[-] Stopping the network sniffing proccess") 
            

if __name__ == "__main__":
    syn_flood_detector = DetectorFactory.create_detector("syn_flood", 200)
    ping_sweep_detector = DetectorFactory.create_detector("ping_sweep", 500)
    brute_force_detector = DetectorFactory.create_detector("brute_force", 5000)
    port_scan_detector = DetectorFactory.create_detector("port_scan", 300)
    detectors = {
        "syn_flood": syn_flood_detector,
        "ping_sweep": ping_sweep_detector,
        "brute_force": brute_force_detector,
        "port_scan": port_scan_detector
    }

    monitor_thread = threading.Thread(target=network_monitor, args=(detectors,))
    simulator_thread = threading.Thread(target=simulate_suspicious_activity) 

    monitor_thread.start()
    simulator_thread.start()

    monitor_thread.join()
    simulator_thread.join()

