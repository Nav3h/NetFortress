import tkinter as tk
from tkinter import messagebox
from threading import Thread
from simulations.network_simulator import simulate_suspicious_activity

def start_monitoring(detectors, network_monitor):
    """
    Starts network monitoring in a separate thread.
    """
    monitor_thread = Thread(target=network_monitor, args=(detectors,))
    monitor_thread.start()
    messagebox.showinfo("Info", "Network monitoring started.")

def start_simulation():
    """
    Starts attack simulation in a separate thread.
    """
    simulator_thread = Thread(target=simulate_suspicious_activity)
    simulator_thread.start()
    messagebox.showinfo("Info", "Attack simulation started.")

def start_gui(detectors, network_monitor):
    """
    Starts the graphical user interface.
    """
    root = tk.Tk()
    root.title("NetFortress IDS")

    frame = tk.Frame(root, padx=10, pady=10)
    frame.pack(padx=10, pady=10)

    monitor_button = tk.Button(frame, text="Start Monitoring", command=lambda: start_monitoring(detectors, network_monitor))
    monitor_button.grid(row=0, column=0, padx=5, pady=5)

    simulation_button = tk.Button(frame, text="Simulate Attacks", command=start_simulation)
    simulation_button.grid(row=0, column=1, padx=5, pady=5)

    root.mainloop()