import pyshark
import threading
import netifaces
import queue

class PacketSniffer:
    def __init__(self, interface=None, display_filter=None, packet_handler=None):
        if interface is None:
            self.interface = netifaces.gateways().get('default', {}).get(netifaces.AF_INET, [None, None])[1]
            if self.interface is None:
                raise ValueError("No default network interface found.")
        else:
            self.interface = interface
        
        self.display_filter = display_filter
        self.capture = None
        self.sniffing = threading.Event()
        self.thread = None
        self.packet_handler = packet_handler or self.default_packet_handler
        self.packet_queue = queue.Queue()
        self.packet_counter = 0  # Initialize the packet counter

    def start_sniffing(self):
        if self.sniffing.is_set():
            print("Sniffing is already in progress.")
            return
        
        self.sniffing.set()
        self.thread = threading.Thread(target=self._capture_packets, daemon=True)
        self.thread.start()
        print(f"Started packet sniffing on {self.interface}...")

    def _capture_packets(self):
        try:
            self.capture = pyshark.LiveCapture(interface=self.interface, display_filter=self.display_filter)
            for packet in self.capture.sniff_continuously():
                if not self.sniffing.is_set():
                    break
                self.packet_handler(packet)
        except Exception as e:
            print(f"Error during packet capture: {e}")
        finally:
            self.sniffing.clear()

    def default_packet_handler(self, packet):
        # Check if the packet has IP layer
        if 'IP' in packet:
            self.packet_counter += 1  # Increment the packet serial number
            # Default packet info retrieval
            packet_info = {
                "serial_no": self.packet_counter,  # Add serial number to packet info
                "time": packet.sniff_time,
                "src": packet.ip.src,
                "dst": packet.ip.dst,
                "protocol": packet.transport_layer if 'IP' in packet else 'N/A',
                "length": packet.length,
                "info": self.extract_info(packet)
            }
            self.packet_queue.put(packet_info)

    def extract_info(self, packet):
        """Extract detailed packet info based on available fields."""
        info = []

        # Ethernet Layer info
        if 'eth' in packet:
            eth_src = packet.eth.src
            eth_dst = packet.eth.dst
            info.append(f"Ethernet: {eth_src} -> {eth_dst}")

        # IP Layer info
        if 'IP' in packet:
            ip_src = packet.ip.src
            ip_dst = packet.ip.dst
            protocol = packet.ip.proto
            info.append(f"IP: {ip_src} -> {ip_dst}, Protocol: {protocol}")

            # Additional IP info (TTL, Identification, flags, etc.)
            ttl = packet.ip.ttl if hasattr(packet.ip, 'ttl') else 'N/A'
            identification = packet.ip.id if hasattr(packet.ip, 'id') else 'N/A'
            flags = packet.ip.flags if hasattr(packet.ip, 'flags') else 'N/A'
            info.append(f"IP TTL: {ttl}, ID: {identification}, Flags: {flags}")

        # ARP Layer info
        if 'ARP' in packet:
            arp_op = packet.arp.op
            arp_src_ip = packet.arp.src_ip
            arp_dst_ip = packet.arp.dst_ip
            info.append(f"ARP: {arp_op}, {arp_src_ip} -> {arp_dst_ip}")

        # TCP Layer info
        if 'TCP' in packet:
            tcp_src_port = packet.tcp.srcport
            tcp_dst_port = packet.tcp.dstport
            tcp_flags = packet.tcp.flags
            tcp_seq = packet.tcp.seq if hasattr(packet.tcp, 'seq') else 'N/A'
            tcp_ack = packet.tcp.ack if hasattr(packet.tcp, 'ack') else 'N/A'
            tcp_window = packet.tcp.window_size if hasattr(packet.tcp, 'window_size') else 'N/A'
            info.append(f"TCP: {tcp_src_port} -> {tcp_dst_port}, Flags: {tcp_flags}, "
                        f"Seq: {tcp_seq}, Ack: {tcp_ack}, Window: {tcp_window}")

        # UDP Layer info
        if 'UDP' in packet:
            udp_src_port = packet.udp.srcport
            udp_dst_port = packet.udp.dstport
            udp_length = packet.udp.length if hasattr(packet.udp, 'length') else 'N/A'
            info.append(f"UDP: {udp_src_port} -> {udp_dst_port}, Length: {udp_length}")

        # DNS Layer info
        if 'DNS' in packet:
            if hasattr(packet.dns, 'qry_name'):
                dns_query = packet.dns.qry_name
                info.append(f"DNS Query: {dns_query}")
            if hasattr(packet.dns, 'qry_type'):
                dns_query_type = packet.dns.qry_type
                info.append(f"DNS Type: {dns_query_type}")
            if hasattr(packet.dns, 'a'):
                dns_answer = packet.dns.a
                info.append(f"DNS Answer: {dns_answer}")

        # HTTP Layer info
        if 'HTTP' in packet:
            if hasattr(packet.http, 'host'):
                http_host = packet.http.host
                info.append(f"HTTP Host: {http_host}")
            if hasattr(packet.http, 'user_agent'):
                http_user_agent = packet.http.user_agent
                info.append(f"HTTP User-Agent: {http_user_agent}")
            if hasattr(packet.http, 'referer'):
                http_referer = packet.http.referer
                info.append(f"HTTP Referer: {http_referer}")
            if hasattr(packet.http, 'method'):
                http_method = packet.http.method
                info.append(f"HTTP Method: {http_method}")
            if hasattr(packet.http, 'status_code'):
                http_status_code = packet.http.status_code
                info.append(f"HTTP Status Code: {http_status_code}")

        # ICMP Layer info
        if 'ICMP' in packet:
            icmp_type = packet.icmp.type
            icmp_code = packet.icmp.code
            info.append(f"ICMP: Type {icmp_type}, Code {icmp_code}")

        # TLS Layer info
        if 'TLS' in packet:
            if hasattr(packet.tls, 'handshake_type'):
                tls_handshake_type = packet.tls.handshake_type
                info.append(f"TLS Handshake: {tls_handshake_type}")
            if hasattr(packet.tls, 'record_type'):
                tls_record_type = packet.tls.record_type
                info.append(f"TLS Record Type: {tls_record_type}")

        # IP Fragmentation info (if applicable)
        if 'IP' in packet and hasattr(packet.ip, 'frag_offset') and packet.ip.frag_offset != '0':
            fragment_offset = packet.ip.frag_offset
            more_fragments = packet.ip.flags_more_fragments
            info.append(f"IP Fragmentation: Offset {fragment_offset}, More Fragments: {more_fragments}")

        # Raw Data (Hex)
        if hasattr(packet, 'raw'):
            raw_data = packet.raw
            info.append(f"Raw Data (Hex): {raw_data.hex()[:50]}...")  # Show the first 50 bytes

        if not info:
            return "N/A"
        
        return " | ".join(info)


    def stop_sniffing(self):
        if not self.sniffing.is_set():
            print("No sniffing session to stop.")
            return
        
        self.sniffing.clear()
        if self.capture:
            self.capture.close()
        if self.thread:
            self.thread.join()
        print("Stopped packet sniffing.")

    def get_latest_packets(self):
        packets = []
        while not self.packet_queue.empty():
            packets.append(self.packet_queue.get())
        return packets
