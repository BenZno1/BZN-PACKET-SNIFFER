import socket
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext
import sys
import os

target_ip = ""
start_port = 0
end_port = 0
scan_active = False
threads = []

def hide_console():
    """ Hides the CMD window on Windows """
    if sys.platform.startswith("win"):
        os.system("cls")  # Clear CMD (optional)
        try:
            import ctypes
            ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
        except:
            pass

def scan_port(target, port):
    if not scan_active:
        return
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            result = s.connect_ex((target, port))
            if result == 0:
                message = f"Port {port} - OPEN\n"
                root.after(0, lambda: update_output(open_ports_text, message))
            else:
                message = f"Port {port} - CLOSED\n"
                root.after(0, lambda: update_output(closed_ports_text, message))
    except Exception as e:
        root.after(0, lambda: update_output(closed_ports_text, f"Error scanning port {port}: {e}\n"))

def update_output(text_widget, message):
    """ Updates the respective output box (Open or Closed ports) """
    text_widget.insert(tk.END, message)
    text_widget.see(tk.END)  # Auto-scroll to latest result

def scan_ports_range():
    global scan_active
    scan_active = True
    open_ports_text.insert(tk.END, "\n--- Starting Scan ---\n")
    closed_ports_text.insert(tk.END, "\n--- Starting Scan ---\n")
    root.update_idletasks()
    target = target_entry.get()
    start = int(start_port_entry.get())
    end = int(end_port_entry.get())
    
    for port in range(start, end + 1):
        if not scan_active:
            break
        thread = threading.Thread(target=scan_port, args=(target, port))
        threads.append(thread)
        thread.start()

def stop_scan():
    global scan_active
    scan_active = False
    open_ports_text.insert(tk.END, "--- Scan Paused ---\n")
    closed_ports_text.insert(tk.END, "--- Scan Paused ---\n")

def clear_output():
    open_ports_text.delete(1.0, tk.END)
    closed_ports_text.delete(1.0, tk.END)

def create_gui():
    global target_entry, start_port_entry, end_port_entry, open_ports_text, closed_ports_text, root
    root = tk.Tk()
    root.title("BZN PORT SCANNER")  # Set window title
    root.geometry("600x500")
    root.configure(bg="#181818")
    
    style = ttk.Style()
    style.theme_use("clam")
    style.configure("TLabel", foreground="white", background="#181818", font=("Segoe UI", 12))
    style.configure("TButton", font=("Segoe UI", 12), padding=10, relief="flat", background="#282C34", foreground="white")
    
    frame = ttk.Frame(root, padding=20, style="TFrame")
    frame.pack(fill="both", expand=True)
    
    ttk.Label(frame, text="Target IP:").grid(row=0, column=0, columnspan=2, sticky="w", pady=5)
    target_entry = tk.Entry(frame, font=("Segoe UI", 11), bg="#2E2E2E", fg="white", relief="flat")
    target_entry.grid(row=1, column=0, columnspan=2, sticky="ew", pady=5, ipady=5)
    
    ttk.Label(frame, text="Start Port:").grid(row=2, column=0, sticky="w", pady=5)
    start_port_entry = tk.Entry(frame, font=("Segoe UI", 11), bg="#2E2E2E", fg="white", relief="flat")
    start_port_entry.grid(row=2, column=1, sticky="ew", pady=5, ipady=5)
    
    ttk.Label(frame, text="End Port:").grid(row=3, column=0, sticky="w", pady=5)
    end_port_entry = tk.Entry(frame, font=("Segoe UI", 11), bg="#2E2E2E", fg="white", relief="flat")
    end_port_entry.grid(row=3, column=1, sticky="ew", pady=5, ipady=5)
    
    button_frame = ttk.Frame(frame)
    button_frame.grid(row=4, column=0, columnspan=2, pady=15)
    
    start_button = ttk.Button(button_frame, text="Start Scan", command=scan_ports_range)
    start_button.pack(side="left", expand=True, padx=5)
    
    stop_button = ttk.Button(button_frame, text="Pause Scan", command=stop_scan)
    stop_button.pack(side="left", expand=True, padx=5)
    
    clear_button = ttk.Button(button_frame, text="Clear Output", command=clear_output)
    clear_button.pack(side="left", expand=True, padx=5)
    
    result_frame = ttk.Frame(frame)
    result_frame.grid(row=5, column=0, columnspan=2, sticky="nsew", pady=10)

    ttk.Label(result_frame, text="OPEN PORTS", foreground="green").grid(row=0, column=0, sticky="nsew", pady=5)
    ttk.Label(result_frame, text="CLOSED PORTS", foreground="red").grid(row=0, column=1, sticky="nsew", pady=5)

    open_ports_text = scrolledtext.ScrolledText(result_frame, width=30, height=10, font=("Consolas", 11), bg="#202020", fg="green", insertbackground="white", borderwidth=2, relief="flat")
    open_ports_text.grid(row=1, column=0, sticky="nsew", padx=5)

    closed_ports_text = scrolledtext.ScrolledText(result_frame, width=30, height=10, font=("Consolas", 11), bg="#202020", fg="red", insertbackground="white", borderwidth=2, relief="flat")
    closed_ports_text.grid(row=1, column=1, sticky="nsew", padx=5)

    root.grid_columnconfigure(0, weight=1)
    root.grid_columnconfigure(1, weight=1)
    result_frame.grid_columnconfigure(0, weight=1)
    result_frame.grid_columnconfigure(1, weight=1)

    root.mainloop()

if __name__ == "__main__":
    hide_console()  # Hide CMD when running on Windows
    create_gui()
