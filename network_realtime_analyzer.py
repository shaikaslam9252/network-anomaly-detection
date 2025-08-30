from scapy.all import sniff
import datetime
import random
import numpy as np
from sklearn.cluster import KMeans

class RealTimeNetworkAnalyzer:
    def __init__(self):
        # Threshold for anomaly detection
        self.critical_anomaly_threshold = 0.2
        self.custom_anomaly_triggered = False
        self.baseline_data = []  # Store baseline data for comparison
        self.packet_data = []  # Store packet data for analysis

    def capture_network_traffic(self, packet_count=10):
        # Capture live packets using Scapy
        def process_packet(packet):
            if packet.haslayer('IP'):
                try:
                    # Extract packet details
                    traffic_data = {
                        "timestamp": datetime.datetime.now(),
                        "source_ip": packet['IP'].src,
                        "destination_ip": packet['IP'].dst,
                        "packet_size": len(packet),
                        "protocol": packet['IP'].proto,
                        "anomaly_score": random.uniform(-0.1, 0.1)  # Simulate anomaly score
                    }
                    self.packet_data.append(traffic_data)

                    # If a custom anomaly is triggered, add an artificial anomaly
                    if self.custom_anomaly_triggered:
                        traffic_data["anomaly_score"] = random.uniform(0.25, 0.35)  # High anomaly score
                        traffic_data["alert"] = "ALERT: High anomaly score detected!"
                    
                except Exception as e:
                    print(f"Error processing packet: {e}")

        # Sniff packets
        sniff(count=packet_count, prn=process_packet, filter="ip", store=0)
        
        # Return the captured traffic data
        return self.packet_data

    def detect_anomalies(self):
        # Capture live traffic
        traffic_data = self.capture_network_traffic(packet_count=10)

        # Extract the anomaly scores
        anomaly_scores = np.array([entry["anomaly_score"] for entry in traffic_data]).reshape(-1, 1)

        # Train the KMeans model only if enough data has been collected
        anomalies = []
        if len(self.baseline_data) > 10:  # Ensure we have enough baseline data
            kmeans = KMeans(n_clusters=2, random_state=42)
            kmeans.fit(np.array(self.baseline_data).reshape(-1, 1))
            predicted_clusters = kmeans.predict(anomaly_scores)

            # Anomalies are those that are not in the main cluster (cluster 0)
            anomalies = [entry for entry, cluster in zip(traffic_data, predicted_clusters) if cluster == 1]
        
        # Update baseline data
        self.baseline_data.extend(anomaly_scores.flatten())

        return anomalies

    def trigger_custom_anomaly(self):
        self.custom_anomaly_triggered = True

    def reset_custom_anomaly(self):
        self.custom_anomaly_triggered = False
