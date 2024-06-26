# detector_factory.py

from IDS.detectors.syn_flood_detector import SynFloodDetector
from IDS.detectors.brute_force_detector import BruteForceDetector
from IDS.detectors.port_scan_detector import PortScanDetector

class DetectorFactory:
    @staticmethod
    def create_detector(detector_type, threshold):
        if detector_type == "syn_flood":
            return SynFloodDetector(threshold)
        elif detector_type == "brute_force":
            return BruteForceDetector(threshold)
        elif detector_type == "port_scan":
            return PortScanDetector(threshold)
        else:
            raise ValueError(f"Unknown detector type: {detector_type}")
