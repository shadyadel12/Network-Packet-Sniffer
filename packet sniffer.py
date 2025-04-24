import threading
from scapy.all import sniff, Ether, IP, TCP, UDP, wrpcap
import tkinter as tk
from tkinter.scrolledtext import ScrolledText
from tkinter import filedialog

class PacketSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Basic Network Sniffer")
        self.text_area = ScrolledText(root, width=100, height=30, bg="black", fg="lime", font=("Consolas", 10))
        self.text_area.pack(padx=10, pady=10)

        self.sniffing = False
        self.sniffer_thread = None
        self.captured_packets = []

        # Button Frame
        btn_frame = tk.Frame(root)
        btn_frame.pack(pady=5)

        self.start_button = tk.Button(btn_frame, text="Start Sniffer", command=self.start_sniffer, bg="green", fg="white", width=20)
        self.start_button.pack(side=tk.LEFT, padx=10)

        self.stop_button = tk.Button(btn_frame, text="Stop Sniffer", command=self.stop_sniffer, bg="red", fg="white", width=20, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=10)

        self.save_button = tk.Button(btn_frame, text="Save to PCAP", command=self.save_to_pcap, bg="blue", fg="white", width=20)
        self.save_button.pack(side=tk.LEFT, padx=10)

    def start_sniffer(self):
        if not self.sniffing:
            self.sniffing = True
            self.captured_packets.clear()
            self.sniffer_thread = threading.Thread(target=self.sniff_packets, daemon=True)
            self.sniffer_thread.start()
            self.text_area.insert(tk.END, "[Sniffer started]\n")
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)

    def stop_sniffer(self):
        self.sniffing = False
        self.text_area.insert(tk.END, "[Sniffer stopped by user]\n")
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def sniff_packets(self):
        sniff(prn=self.analyze_packet, store=False, stop_filter=lambda x: not self.sniffing)

    def analyze_packet(self, packet):
        if not self.sniffing:
            return

        self.captured_packets.append(packet)

        lines = ["\n--- Packet Captured ---"]
        
        if Ether in packet:
            ether = packet[Ether]
            lines.append(f"Ethernet: {ether.src} -> {ether.dst} | Type: {hex(ether.type)}")
        
        if IP in packet:
            ip = packet[IP]
            lines.append(f"IP: {ip.src} -> {ip.dst} | Protocol: {ip.proto}")
        
        if TCP in packet:
            tcp = packet[TCP]
            lines.append(f"TCP: Port {tcp.sport} -> {tcp.dport}")
        elif UDP in packet:
            udp = packet[UDP]
            lines.append(f"UDP: Port {udp.sport} -> {udp.dport}")
        
        self.log_packet("\n".join(lines))

    def log_packet(self, text):
        self.text_area.insert(tk.END, text + "\n")
        self.text_area.yview(tk.END)

    def save_to_pcap(self):
        if not self.captured_packets:
            self.text_area.insert(tk.END, "[No packets to save]\n")
            return
        
        file_path = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP files", "*.pcap")])
        if file_path:
            wrpcap(file_path, self.captured_packets)
            self.text_area.insert(tk.END, f"[Saved {len(self.captured_packets)} packets to {file_path}]\n")

# Run GUI
if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferGUI(root)
    root.mainloop()
