from IDS.detectors.detector_factory import DetectorFactory
from IDS.utils.packet_processor import process_packet
from IDS.utils.db_manager import create_connection, create_table
from IDS.utils.gui import start_gui
import threading
from scapy.all import sniff
import logging

def network_monitor(detectors, interface="\\Device\\NPF_Loopback"):
    """
    Monitors network traffic and processes packets.
    """
    print("[+] Monitoring network traffic started")
    try:
        sniff(iface=interface, filter="ip", prn=lambda x: process_packet(x, detectors))
    except Exception as e:
        logging.error(f"[!] Error during packet sniffing: {str(e)}")
    finally:
        logging.info("[-] Stopping the network sniffing process")

if __name__ == "__main__":
    conn = create_connection("ids_database.db")
    create_table(conn)

    syn_flood_detector = DetectorFactory.create_detector("syn_flood", 2055)
    brute_force_detector = DetectorFactory.create_detector("brute_force", 6225)
    port_scan_detector = DetectorFactory.create_detector("port_scan", 6050)

    detectors = {
        "syn_flood": syn_flood_detector,
        "brute_force": brute_force_detector,
        "port_scan": port_scan_detector
    }

    gui_thread = threading.Thread(target=start_gui, args=(detectors, network_monitor))

    gui_thread.start()

    gui_thread.join()