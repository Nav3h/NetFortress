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
    keys_to_remove = []
    for key, data in tracker.items():
        if 'times' in data and data['times']:
            while data['times'] and current_time - data['times'][0] > time_window:
                data['times'].popleft()
                if 'count' in data:
                    data['count'] -= 1
            if not data['times'] or ('count' in data and data['count'] <= 0):
                keys_to_remove.append(key)
    for key in keys_to_remove:
        del tracker[key]





