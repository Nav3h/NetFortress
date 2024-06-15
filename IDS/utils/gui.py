import tkinter as tk
from tkinter import messagebox
from threading import Thread
from simulations.network_simulator import simulate_suspicious_activity
from IDS.utils.db_manager import create_connection
from tkinter.scrolledtext import ScrolledText
from PIL import Image, ImageTk

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

def show_logs():
    """
    Fetches and displays the logs from the database in a readable format.
    """
    conn = create_connection("ids_database.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM detections")
    records = cursor.fetchall()
    conn.close()

    log_window = tk.Toplevel()
    log_window.title("Detection Logs")

    text_area = ScrolledText(log_window, wrap=tk.WORD, width=100, height=20)
    text_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

    headers = f"{'ID':<5} {'Attack Type':<15} {'Source IP':<20} {'Destination IP':<20} {'Timestamp':<25} {'Hash':<64}\n"
    text_area.insert(tk.END, headers)
    text_area.insert(tk.END, "-"*150 + "\n")

    for record in records:
        log_entry = f"{record[0]:<5} {record[1]:<15} {record[2]:<20} {record[3]:<20} {record[4]:<25} {record[5]:<64}\n"
        text_area.insert(tk.END, log_entry)

    text_area.configure(state='disabled')

def start_gui(detectors, network_monitor):
    """
    Starts the graphical user interface.
    """
    root = tk.Tk()
    root.title("NetFortress IDS")

    # Set window size and remove default padding
    root.geometry("800x600")
    root.configure(bg='#263238')

    # Load and set background image
    bg_image = Image.open("IDS/utils/ids.png")
    bg_photo = ImageTk.PhotoImage(bg_image)
    
    background_label = tk.Label(root, image=bg_photo)
    background_label.place(relwidth=1, relheight=1)

    # Style the buttons to match the theme
    button_style = {
        "font": ("Helvetica", 12, "bold"),
        "bg": "#00796B",
        "fg": "white",
        "relief": "raised",
        "bd": 5,
        "width": 20,
        "height": 2
    }

    monitor_button = tk.Button(root, text="Start Monitoring", command=lambda: start_monitoring(detectors, network_monitor), **button_style)
    monitor_button.place(relx=0.3, rely=0.4, anchor='center')

    simulation_button = tk.Button(root, text="Simulate Attacks", command=start_simulation, **button_style)
    simulation_button.place(relx=0.7, rely=0.4, anchor='center')

    logs_button = tk.Button(root, text="Show Logs", command=show_logs, **button_style)
    logs_button.place(relx=0.5, rely=0.6, anchor='center')

    root.mainloop()
