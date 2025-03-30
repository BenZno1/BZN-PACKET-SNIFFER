import scapy.all as scapy
import tkinter as tk
from tkinter import ttk
from threading import Thread
import time

# Function to get network interfaces (to select which interface to sniff)
def get_interfaces():
    return scapy.get_if_list()

# Process the captured packet
def process_packet(packet):
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        packet_info = f"Packet captured: {src_ip} -> {dst_ip}"
        
        # Update the text box with the packet details
        output_box.insert(tk.END, f"{packet_info}\n")
        output_box.yview(tk.END)  # Auto-scroll to the latest packet

# Sniff packets in a separate thread to keep the GUI responsive
def sniff_packets(interface, packet_filter):
    global capturing
    capturing = True
    output_box.insert(tk.END, "Sniffing started...\n")
    output_box.yview(tk.END)  # Auto-scroll to the latest message
    captured = False  # Flag to track if any packets are captured

    # Sniff for 10 seconds
    scapy.sniff(iface=interface, prn=process_packet, filter=packet_filter, store=False, timeout=10)
    
    # If no packets were captured, show "No data found"
    if not captured:
        output_box.insert(tk.END, "Sniffing complete. No data found.\n")
    output_box.yview(tk.END)  # Auto-scroll to the latest message

# Stop sniffing
def stop_sniffing():
    global capturing
    capturing = False
    output_box.insert(tk.END, "Sniffing stopped.\n")
    output_box.yview(tk.END)

# Start the packet sniffing process
def start_sniffing():
    interface = interface_combobox.get()  # Get selected network interface
    packet_filter = packet_filter_combobox.get()  # Get selected packet filter (e.g., ICMP, HTTP, etc.)

    if not interface or not packet_filter:
        output_box.insert(tk.END, "Please select both interface and filter.\n")
        output_box.yview(tk.END)  # Auto-scroll to the latest message
        return

    # Check if we are capturing and stop previous sniffing if needed
    stop_sniffing()

    # Start the sniffing thread
    sniff_thread = Thread(target=sniff_packets, args=(interface, packet_filter))
    sniff_thread.start()

# Setup the Tkinter GUI
def create_gui():
    global interface_combobox, packet_filter_combobox, output_box

    # Create the main window
    window = tk.Tk()
    window.title("BZN Packet Sniffer")

    # Create a frame
    frame = ttk.Frame(window, padding=10)
    frame.grid(row=0, column=0)

    # Label and combo box for selecting network interface
    ttk.Label(frame, text="Select Network Interface:").grid(row=0, column=0, padx=5, pady=5)
    interfaces = get_interfaces()  # Get available interfaces
    interface_combobox = ttk.Combobox(frame, values=interfaces, width=40)
    interface_combobox.grid(row=0, column=1, padx=5, pady=5)

    # Label and combo box for selecting packet filter (e.g., ICMP)
    ttk.Label(frame, text="Select Packet Filter (e.g., icmp):").grid(row=1, column=0, padx=5, pady=5)
    packet_filter_combobox = ttk.Combobox(frame, values=["icmp", "http", "tcp", "udp"], width=40)
    packet_filter_combobox.grid(row=1, column=1, padx=5, pady=5)

    # Start sniffing button
    start_button = ttk.Button(frame, text="Start Sniffing", command=start_sniffing)
    start_button.grid(row=2, column=0, padx=5, pady=5)

    # Stop sniffing button
    stop_button = ttk.Button(frame, text="Stop Sniffing", command=stop_sniffing)
    stop_button.grid(row=2, column=1, padx=5, pady=5)

    # Text box for showing packet details
    output_box = tk.Text(window, height=20, width=80, wrap=tk.WORD, state=tk.DISABLED, bg="#2E2E2E", fg="white")
    output_box.grid(row=1, column=0, padx=10, pady=10)

    # Start the GUI
    window.mainloop()

if __name__ == "__main__":
    create_gui()
