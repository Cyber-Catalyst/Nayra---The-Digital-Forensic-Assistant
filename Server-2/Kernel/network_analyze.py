import os
import shap, dpkt
import numpy as np
import pandas as pd
from functools import lru_cache
import math
from collections import Counter
from scapy.all import rdpcap, IP, TCP, UDP, ICMP, DNS, Raw, ARP, DHCP, Ether
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import KMeans
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans
from sklearn.metrics import silhouette_score
from scapy.contrib.bgp import BGP
from scapy.contrib.ospf import OSPF_Hdr as OSPF
from scapy.contrib.isis import *
from scapy.contrib.lldp import *
from custom_protocol import *
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache

class NetworkAnalyzer:
    def __init__(self):
        self.vectorizer = None
        self.model = None

    @lru_cache(maxsize=1000)
    def calculate_entropy(self, data_tuple):
        """Calculate Shannon entropy of given data (optimized for caching)."""
        if not data_tuple:
            return 0
        p_counts = Counter(data_tuple)
        total = len(data_tuple)
        return -sum((count/total) * math.log2(count/total) for count in p_counts.values())

    def cached_shap_explainer(self, model, data):
        """Computes SHAP explainer without LRU cache (avoiding memory bloat)."""
        data = np.array(data)
        explainer = shap.Explainer(lambda X: model.decision_function(X), data)
        return explainer

    def deep_packet_inspection(self, packet):
        """Detect suspicious payloads using probability-based classification."""
        if packet.haslayer(Raw):
            try:
                payload = bytes(packet[Raw]).decode(errors='replace').strip()
            except UnicodeDecodeError:
                print("⚠️ Warning: UnicodeDecodeError encountered in payload. Using fallback decoding.")
                payload = str(bytes(packet[Raw]))  # Fallback: Convert bytes to string representation
            if self.vectorizer is None or self.model is None:
                print("⚠️ Warning: Model not trained. Skipping deep packet inspection.")
                return 0 
            if not payload:
                return 0 
            payload_vector = self.vectorizer.transform([payload])
            cluster_label = self.model.predict(payload_vector)[0]
            cluster_centers = self.model.cluster_centers_
            distances = np.linalg.norm(cluster_centers - payload_vector.toarray(), axis=1)
            min_distance = distances[cluster_label]
            max_distance = np.max(distances) if np.max(distances) > 0 else 1
            anomaly_score = min_distance / max_distance  # Normalize between 0 and 1
            threshold = 0.7  
            return 1 if anomaly_score > threshold else 0
        return 0

    def get_protocol(self, packet):
        try:
            eth = dpkt.ethernet.Ethernet(packet)
            if isinstance(eth.data, dpkt.ip.IP):
                ip = eth.data
                if isinstance(ip.data, dpkt.tcp.TCP):
                    tcp = ip.data
                    return self.analyze_tcp_payload(tcp.data, tcp.dport, tcp.sport)
                elif isinstance(ip.data, dpkt.udp.UDP):
                    udp = ip.data
                    return self.analyze_udp_payload(udp.data, udp.dport, udp.sport)

            if packet.haslayer(OSPF):
                ospf_type = packet[OSPF].type
                ospf_types = {
                    1: "OSPF Hello",
                    2: "OSPF Database Description",
                    3: "OSPF Link-State Request",
                    4: "OSPF Link-State Update",
                    5: "OSPF Link-State Acknowledgment"
                }
                return f"OSPF ({ospf_types.get(ospf_type, 'Unknown OSPF Type')})"
        except Exception as e:
            return f"Error detecting protocol: {e}"
        return "Unknown Protocol"

    def analyze_tcp_payload(self, payload, dport, sport):
        """Analyzes TCP payload heuristically to determine the protocol."""
        if payload.startswith(b'GET') or payload.startswith(b'POST') or b'HTTP' in payload:
            return "HTTP"
        if payload.startswith(b'SSH-'):
            return "SSH"
        if payload.startswith(b'220') and b'SMTP' in payload:
            return "SMTP"
        if b'FTP' in payload:
            return "FTP"
        if b'MySQL' in payload:
            return "MySQL"
        if b'RDP' in payload:
            return "RDP"
        if b'Telnet' in payload or payload.startswith(b'\xff\xfb'):
            return "Telnet"
        if b'POP3' in payload:
            return "POP3"
        if b'IMAP' in payload:
            return "IMAP"
        if b'LDAP' in payload:
            return "LDAP"
        if b'SMB' in payload:
            return "SMB"
        if b'BGP' in payload or dport == 179 or sport == 179:
            return "BGP"
        return "Unknown TCP Protocol"

    def analyze_udp_payload(self, payload, dport, sport):
        """Analyzes UDP payload heuristically to determine the protocol."""
        if payload.startswith(b'DNS'):
            return "DNS"
        if b'SIP' in payload:
            return "SIP"
        if b'NTP' in payload:
            return "NTP"
        if b'SNMP' in payload or dport == 161 or sport == 161:
            return "SNMP"
        if b'TFTP' in payload:
            return "TFTP"
        if b'SYSLOG' in payload:
            return "SYSLOG"
        if b'RADIUS' in payload:
            return "RADIUS"
        if b'QUIC' in payload:
            return "QUIC"
        if b'DHCP' in payload:
            return "DHCP"
        if dport in [520, 521]:
            return "RIP"
        if payload.startswith(b'VXLAN'):
            return "VXLAN"
        if payload.startswith(b'MPLS'):
            return "MPLS"
        if payload.startswith(b'LDP'):
            return "LDP"
        if payload.startswith(b'RSVP'):
            return "RSVP"
        if payload.startswith(b'L2TP'):
            return "L2TP"
        if payload.startswith(b'PPTP'):
            return "PPTP"
        if payload.startswith(b'IGMP'):
            return "IGMP"
        return "Unknown UDP Protocol"

    def get_missing_ip_reason(self, packet):
        """Dynamically determines why the source or destination IP is missing."""
        if IP in packet:
            return None  
        additional_protocols = ["SNMP", "IGMP", "BGP", "OSPF", "L2TP", "PPTP", "RIP", "ISIS", "LLDP"]
        if ARP in packet:
            return "No IP Layer (ARP Packet - MAC-based communication)"
        elif DHCP in packet:
            return "No IP Layer (DHCP Uses MAC Until IP is Assigned)"
        elif packet.haslayer(Ether) and not packet.haslayer(IP):
            return "Non-IP Packet (Layer 2 Traffic)"
        if packet.haslayer(DNS):
            return "No IP Layer (DNS Query - Typically Uses UDP/IP, but No IP in This Frame)"
        elif "SNMP" in additional_protocols and packet.haslayer(SNMP):
            return "No IP Layer (SNMP Management Packet - Possible Direct Link Layer Transmission)"
        elif "OSPF" in additional_protocols and packet.haslayer(OSPF):
            return "No IP Layer (OSPF Routing Packet - Operates at Layer 3 but May Be Encapsulated)"
        elif "BGP" in additional_protocols and packet.haslayer(BGP):
            return "No IP Layer (BGP Routing - Usually Over TCP/IP, But Encapsulation May Vary)"
        elif "RIP" in additional_protocols and packet.haslayer(RIP):
            return "No IP Layer (RIP Routing - Can Be Encapsulated Without Explicit IP)"
        elif "ISIS" in additional_protocols and packet.haslayer(ISIS):
            return "No IP Layer (ISIS Routing - Operates Without Direct IP Assignment)"
        elif "LLDP" in additional_protocols and packet.haslayer(LLDP):
            return "No IP Layer (LLDP Packet - Used for Network Discovery at Layer 2)"
        elif "L2TP" in additional_protocols and packet.haslayer(L2TP):
            return "No IP Layer (L2TP - Encapsulated Tunneling Protocol)"
        elif "PPTP" in additional_protocols and packet.haslayer(PPTP):
            return "No IP Layer (PPTP - Tunnel Control Traffic Without Direct IP)"
        return "Unknown Reason (Check Packet Structure)"

    def get_missing_tcp_flags_reason(self, packet):
        """Dynamically determines why TCP flags are missing or provides flag details."""
        if packet.haslayer(TCP):
            flags = packet[TCP].flags
            flag_explanation = []
            flag_map = {
                0x02: "SYN (Connection Initiation)",
                0x10: "ACK (Acknowledgment)",
                0x11: "FIN-ACK (Graceful Connection Termination)",
                0x04: "RST (Reset - Connection Terminated Abruptly)",
                0x08: "PSH (Push - Immediate Data Transmission)",
                0x20: "URG (Urgent - Priority Data Transmission)",
                0x40: "ECE (Explicit Congestion Notification)",
                0x80: "CWR (Congestion Window Reduced)"
            }
            for flag, meaning in flag_map.items():
                if flags & flag:
                    flag_explanation.append(meaning)
            return ", ".join(flag_explanation) if flag_explanation else "Unknown TCP Flags"
        if UDP in packet:
            return "TCP Flags Not Applicable (UDP Packet - Stateless Transmission)"
        elif ICMP in packet:
            return "TCP Flags Not Applicable (ICMP Packet - Control Message Only)"
        elif ARP in packet:
            return "TCP Flags Not Applicable (ARP Packet - Address Resolution Only)"
        elif packet.haslayer(Ether) and not (packet.haslayer(TCP) or packet.haslayer(UDP)):
            return "No Transport Layer (Likely Layer 2 Protocol Without TCP/UDP)"
        return "Unknown Reason (No Transport Layer Detected)"

    def extract_features_parallel(self, packet, last_timestamp):
        """Extract features, handling missing timestamps and IP values safely."""
        ip_src = packet[IP].src if IP in packet else "No IP"
        ip_dst = packet[IP].dst if IP in packet else "No IP"
        ttl = packet[IP].ttl if IP in packet else "No TTL"
        tcp_flags = "No TCP"
        if packet.haslayer(TCP):
            flags = packet[TCP].flags
            flag_map = {
                0x01: "FIN", 0x02: "SYN", 0x04: "RST", 0x08: "PSH", 
                0x10: "ACK", 0x20: "URG", 0x40: "ECE", 0x80: "CWR", 0x100: "NS"
            }
            tcp_flags = ", ".join(flag_name for flag, flag_name in flag_map.items() if flags & flag) or "No TCP Flags"
        packet_time = getattr(packet, 'time', None)  # Handle missing timestamps
        inter_arrival_time = float(packet_time - last_timestamp) if last_timestamp and packet_time else 0.0
        row = {
            "src_mac": packet.src if hasattr(packet, 'src') else "No Ethernet Layer",
            "dst_mac": packet.dst if hasattr(packet, 'dst') else "No Ethernet Layer",
            "ip_src": ip_src,
            "ip_dst": ip_dst,
            "missing_ip_reason": self.get_missing_ip_reason(packet) if ip_src == "No IP" or ip_dst == "No IP" else None,
            "ttl": ttl,
            "src_port": packet[TCP].sport if packet.haslayer(TCP) else (packet[UDP].sport if packet.haslayer(UDP) else "No Transport Layer"),
            "dst_port": packet[TCP].dport if packet.haslayer(TCP) else (packet[UDP].dport if packet.haslayer(UDP) else "No Transport Layer"),
            "protocol": "TCP" if packet.haslayer(TCP) else ("UDP" if packet.haslayer(UDP) else "Other"),
            "packet_size": len(packet),
            "has_raw": 1 if packet.haslayer(Raw) else 0,
            "entropy": self.calculate_entropy(bytes(packet[Raw])) if packet.haslayer(Raw) else 0,
            "tcp_flags": tcp_flags,
            "inter_arrival_time": inter_arrival_time,
            "suspicious_payload": self.deep_packet_inspection(packet),
            "ttl_anomaly": self.detect_ttl_anomaly(ttl) if isinstance(ttl, int) else "Unknown"
        }
        return row

    def detect_ttl_anomaly(self, ttl):
        """Detects TTL-based anomalies."""
        if ttl <= 5:
            return "⚠️ Very Low TTL - Possible Routing Loop or Excessive Hops"
        elif ttl > 200:
            return "⚠️ High TTL - Possible Evasion Technique"
        return "✅ Normal TTL"

    def extract_features(self, packets):
        features = []
        last_timestamp = None
        with ThreadPoolExecutor() as executor:
            results = executor.map(lambda p: self.extract_features_parallel(p, last_timestamp), packets)
            features.extend(results)
            last_timestamp = packets[-1].time if packets else None
        return features

    def train_vectorizer_and_model(self, packets):
        """Train a TF-IDF vectorizer and determine the optimal number of clusters dynamically."""
        payloads = [bytes(packet[Raw]).decode(errors='ignore') for packet in packets if packet.haslayer(Raw)]
        if not payloads:
            print("❌ No Raw payloads found in packets. Skipping model training.")
            return None, None
        self.vectorizer = TfidfVectorizer(max_features=500)
        X = self.vectorizer.fit_transform(payloads)
        distortions = []
        silhouette_scores = []
        cluster_range = range(2, min(10, len(payloads))) 
        for k in cluster_range:
            kmeans = KMeans(n_clusters=k, random_state=42)
            labels = kmeans.fit_predict(X)
            distortions.append(kmeans.inertia_)
            silhouette_scores.append(silhouette_score(X, labels))
        optimal_clusters = cluster_range[silhouette_scores.index(max(silhouette_scores))]
        self.model = KMeans(n_clusters=optimal_clusters, random_state=42)
        self.model.fit(X)
        print(f"✅ Optimal clusters found: {optimal_clusters}")
        return self.vectorizer, self.model

    def detect_anomalies(self, features):
        df = pd.DataFrame(features)
        df_numeric = df[["has_raw", "packet_size", "entropy", "inter_arrival_time", "suspicious_payload"]].copy()
        scaler = StandardScaler()
        df_scaled = scaler.fit_transform(df_numeric)
        model = OneClassSVM(kernel='rbf', gamma='auto', nu=0.05)
        df["anomaly_score"] = model.fit_predict(df_scaled)
        explainer = self.cached_shap_explainer(model, tuple(map(tuple, df_scaled)))
        shap_values = explainer(df_scaled)
        def get_anomaly_reason(index):
            feature_importance = np.abs(shap_values.values[index])
            top_indices = feature_importance.argsort()[::-1]
            top_reasons = [f"{df_numeric.columns[i]} ({shap_values.values[index][i]:.4f})" for i in top_indices[:3]]
            return ", ".join(top_reasons)
        df["anomaly"] = df["anomaly_score"].apply(lambda x: "✅" if x == -1 else "❌")
        df["anomaly_reason"] = df.index.map(lambda i: get_anomaly_reason(i) if df["anomaly"][i] == "✅" else "❌")
        return df.drop(columns=["anomaly_score"]).to_dict(orient='records')
    
    def calculate_accuracy_rate(self, anomalies):
        """Calculate the overall accuracy rate of the anomaly detection report."""
        if not anomalies:
            return 0.0  
        total_anomalies = sum(1 for entry in anomalies if entry["anomaly"] == "✅")
        total_non_anomalies = sum(1 for entry in anomalies if entry["anomaly"] == "❌")
        total_entries = len(anomalies)
        if total_entries == 0:
            return 0.0 
        accuracy_rate = (total_non_anomalies / total_entries) * 100
        return round(accuracy_rate, 2) 

    def analyze_pcap(self, file_path):
        packets = rdpcap(file_path)
        features = self.extract_features(packets)
        anomalies = self.detect_anomalies(features)
        accuracy_rate = self.calculate_accuracy_rate(anomalies)
        return {"total_packets": len(packets), "accuracy_rate": accuracy_rate, "analysis_results": anomalies}

    def generate_report(self, file_name, analysis):
        """Generate CSV & Excel reports, now including TTL."""
        report_xlsx = f"{file_name}_report.xlsx"
        df = pd.DataFrame(analysis["analysis_results"])
        accuracy_rate = analysis["accuracy_rate"]
        with pd.ExcelWriter(report_xlsx, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name="Network Analysis")
            worksheet = writer.sheets["Network Analysis"]
            for col in df.columns:
                col_width = max(df[col].astype(str).apply(len).max(), len(col)) + 2
                col_idx = df.columns.get_loc(col) + 1
                worksheet.column_dimensions[chr(64 + col_idx)].width = col_width
        print(f"✅ Excel Report saved at: {report_xlsx}")
        print(f"📊 Accuracy Rate: {accuracy_rate}%")

    def analyze_file(self, file_path):
        file_name, file_ext = os.path.splitext(file_path)
        if file_ext in [".pcapng", ".pcap"]:
            packets = rdpcap(file_path)
            self.vectorizer, self.model = self.train_vectorizer_and_model(packets)
            if self.vectorizer is None or self.model is None:
                print("❌ Skipping analysis due to lack of payload data.")
                return
            analysis = self.analyze_pcap(file_path)
            self.generate_report(file_name, analysis)
        else:
            print("❌ Unsupported file type. Please use a PCAP file.")

if __name__ == "__main__":
    file_path = input("Enter the PCAP file path: ")
    analyzer = NetworkAnalyzer()
    analyzer.analyze_file(file_path)