import threading
import queue
import time
import random
import ipaddress
from scapy.all import sniff, IP, TCP, UDP
from config import WHITELISTED_IPS, SIMULATION_MODE_FALLBACK

class PacketSniffer:
    def __init__(self):
        self.packet_queue = queue.Queue()
        self.is_running = False
        self.thread = None
        self.error = None

    def _packet_callback(self, packet):
        """Callback function executed for each captured packet."""
        if not self.is_running:
            return

        # We only care about IP packets
        if IP in packet:
            try:
                # Validate IPs
                src_ip = str(ipaddress.ip_address(packet[IP].src))
                dst_ip = str(ipaddress.ip_address(packet[IP].dst))
            except ValueError:
                # Malformed IP address in packet
                return

            # Ignore whitelisted IPs
            if src_ip in WHITELISTED_IPS or dst_ip in WHITELISTED_IPS:
                return

            src_port = 0
            dst_port = 0

            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport

            # Sanitize and bound variables to prevent anomalies or integer overflows down the line
            src_port = max(0, min(65535, int(src_port)))
            dst_port = max(0, min(65535, int(dst_port)))
            payload_size = max(0, min(65535, len(packet)))

            packet_data = {
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'payload_size': payload_size
            }

            self.packet_queue.put(packet_data)

    def _start_sniffing(self):
        """Internal sniffing loop."""
        print("[*] Packet sniffer thread started.")
        # We sniff without blocking by using store=False
        try:
            sniff(prn=self._packet_callback, store=False, stop_filter=lambda x: not self.is_running)
        except Exception as e:
            if SIMULATION_MODE_FALLBACK:
                print(f"[-] Sniffing error: {e}")
                print("[!] FALLING BACK TO SIMULATION MODE: Generating synthetic network traffic for testing...")
                self._simulate_traffic()
            else:
                print(f"[-] Sniffing error (requires admin/root privileges): {e}")
                self.error = str(e)
                self.is_running = False

    def start(self):
        """Starts the sniffer in a background thread."""
        self.is_running = True
        self.thread = threading.Thread(target=self._start_sniffing, daemon=True)
        self.thread.start()

    def stop(self):
        """Stops the sniffer."""
        self.is_running = False
        if self.thread:
            self.thread.join(timeout=2)
            print("[*] Packet sniffer stopped.")

    def get_packet(self, timeout=1.0):
        """Retrieves a packet from the queue, if available."""
        try:
            return self.packet_queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def _simulate_traffic(self):
        """Generates mock synthetic network traffic for testing without Npcap/Admin."""
        while self.is_running:
            # Generate normal-looking traffic most of the time
            src_ip = f"192.168.1.{random.randint(2, 50)}"
            dst_ip = f"192.168.1.{random.randint(2, 50)}"
            src_port = random.randint(1024, 65535)
            dst_port = random.choice([80, 443, 22, 53, 8080])
            payload_size = random.randint(40, 1500)

            # Occasionally generate an anomaly (e.g. huge payload or weird port)
            if random.random() < 0.05:
                src_ip = f"10.0.0.{random.randint(1, 255)}"
                dst_port = random.randint(1, 1024)
                payload_size = random.randint(5000, 20000)

            packet_data = {
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'payload_size': payload_size
            }
            self.packet_queue.put(packet_data)
            time.sleep(random.uniform(0.1, 0.5))
