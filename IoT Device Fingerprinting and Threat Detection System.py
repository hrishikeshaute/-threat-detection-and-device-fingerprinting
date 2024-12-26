import pandas as pd
from scapy.all import sniff, conf
from sklearn.ensemble import IsolationForest
import threading
from flask import Flask, render_template

# Flask app setup
app = Flask(__name__)

# List to hold alerts
alerts = []

# List to hold packet features
packet_data = []

# The machine learning model for anomaly detection
model = IsolationForest(contamination=0.05)  # 5% of the data is assumed to be anomalies

# Function to process packets and extract features
def extract_features(packet):
    if packet.haslayer('IP'):
        # Extract source and destination IP, packet size, and timestamp
        source_ip = packet['IP'].src
        dest_ip = packet['IP'].dst
        packet_size = len(packet)
        timestamp = packet.time
        
        # Store the extracted data
        packet_data.append([source_ip, dest_ip, packet_size, timestamp])
        
        # Once we have enough data, fit the model and predict anomalies
        if len(packet_data) >= 100:  # Example threshold for fitting
            df = pd.DataFrame(packet_data, columns=['Source IP', 'Dest IP', 'Packet Size', 'Timestamp'])
            # Use only packet size and timestamp for anomaly detection
            features = df[['Packet Size', 'Timestamp']]
            model.fit(features)
            
            # Predict anomalies
            predictions = model.predict(features)
            for i, prediction in enumerate(predictions):
                if prediction == -1:  # Anomaly detected
                    alerts.append(f"Anomaly detected in packet from {source_ip} at {timestamp}")
            
            # Reset packet data to avoid overfitting
            packet_data.clear()

# Function to start packet sniffing in the background
def start_sniffing():
    conf.l3socket = conf.L3socket  # Set Scapy to use Layer 3 (IP layer)
    sniff(prn=extract_features, store=0)  # Start sniffing at Layer 3

# Start the sniffing thread
sniff_thread = threading.Thread(target=start_sniffing)
sniff_thread.daemon = True
sniff_thread.start()

# Flask route for displaying alerts
@app.route('/')
def index():
    return render_template('index.html', alerts=alerts)

# Run the Flask app
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

#python3 iot_fingerprint_detection.py
#pip install scapy pandas scikit-learn flask
