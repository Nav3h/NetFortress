"""
Module containing common utility functions and constants used across the project.
"""
import time
from datetime import datetime
from collections import deque
from colorama import Fore, Style


RED = Fore.LIGHTRED_EX
RESET = Style.RESET_ALL

def print_with_timestamp(msg, color=None):
    """
    Print a message with a timestamp.
    """
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    if color:
        print(f"{color}[{current_time}] {msg}{RESET}")
    else:
        print(f"[{current_time}] {msg}")


def cleanup_tracker(tracker, time_window):
    """
    Clean up old entries in the tracker based on the given time window.
    """
    current_time = time.time()
    for key in list(tracker.keys()):
        if 'count' not in tracker[key]:
            tracker[key]['count'] = 0
        if 'times' not in tracker[key]:
            tracker[key]['times'] = deque()

        times = tracker[key]['times']
        while times and current_time - times[0] > time_window:
            times.popleft()
            tracker[key]['count'] -= 1
        if not times:
            del tracker[key]

