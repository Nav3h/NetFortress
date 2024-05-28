"""
Main script for running the Intrusion Detection System.
"""
import threading
from scapy.all import sniff
import logging
from colorama import Fore, Style
from IDS.detectors.syn_flood_detector import SynFloodDetector
from IDS.detectors.ping_sweep_detector import PingSweepDetector
from IDS.detectors.brute_force_detector import BruteForceDetector
from IDS.detectors.port_scan_detector import PortScanDetector
from IDS.detectors.detector_factory import DetectorFactory
from IDS.utils.packet_processor import process_packet
from simulations.network_simulator import simulate_suspicious_activity
GREEN = Fore.GREEN
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def network_monitor(detectors, interface="\\Device\\NPF_Loopback"):  #currently on loopback for the testing. change interface accordingly as needed for scanning.
    print("Monitoring network traffic started", GREEN)
    try:
        sniff(iface=interface, filter="ip", prn=lambda x: process_packet(x, detectors))
    except Exception as e:
        logging.error(f"[!] Error during packet sniffing: {str(e)}")
    finally:
        logging.info("[-] Stopping the network sniffing process") 

if __name__ == "__main__":
    print("[DEBUG] Starting system initialization")
    syn_flood_detector = DetectorFactory.create_detector("syn_flood", 2500)
    ping_sweep_detector = DetectorFactory.create_detector("ping_sweep", 10)
    brute_force_detector = DetectorFactory.create_detector("brute_force", 8000)
    port_scan_detector = DetectorFactory.create_detector("port_scan", 1500)

    print("[DEBUG] Detectors initialized")
    detectors = {
        "syn_flood": syn_flood_detector,
        "ping_sweep": ping_sweep_detector,
        "brute_force": brute_force_detector,
        "port_scan": port_scan_detector
    }

    monitor_thread = threading.Thread(target=network_monitor, args=(detectors,))
    simulator_thread = threading.Thread(target=simulate_suspicious_activity) 

    print("[DEBUG] Threads started")

    monitor_thread.start()
    simulator_thread.start()

    monitor_thread.join()
    simulator_thread.join()
    print("[DEBUG] System shutdown")



