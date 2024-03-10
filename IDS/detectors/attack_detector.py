from abc import ABC, abstractmethod

class AttackDetector(ABC):
    def __init__(self, threshold):
        self.threshold = threshold

    @abstractmethod
    def detect(self, packet):
        pass
