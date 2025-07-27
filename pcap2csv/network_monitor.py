#!/usr/bin/env python3
"""
Live Network Traffic Analysis Tool

This script captures network traffic in real-time, processes it to extract
features using the CICIoT2023 modules, and uses a pre-trained XGBoost
model to predict if the traffic is malicious.

To Run:
- Ensure you have root/administrator privileges.
- On Linux/macOS: sudo python network_monitor.py
- On Windows: Run from an Administrator Command Prompt.
"""

import os
import time
import pandas as pd
import numpy as np
import joblib
from scapy.all import sniff, wrpcap
from datetime import datetime
import ctypes # <-- Import ctypes for the admin check on Windows

# Import the feature extraction logic from your provided files
from Feature_extraction import Feature_extraction

# --- Global Configuration ---
MODEL_FILENAME = 'network_intrusion_model.joblib'
TEMP_PCAP_DIR = 'temp_pcap'
TEMP_CSV_DIR = 'temp_csv'

LABEL_MAPPING = [
    'BACKDOOR_MALWARE', 'BENIGN', 'BROWSERHIJACKING', 'COMMANDINJECTION',
    'DDOS-ACK_FRAGMENTATION', 'DDOS-HTTP_FLOOD', 'DDOS-ICMP_FLOOD',
    'DDOS-ICMP_FRAGMENTATION', 'DDOS-PSHACK_FLOOD', 'DDOS-RSTFINFLOOD',
    'DDOS-SLOWLORIS', 'DDOS-SYNONYMOUSIP_FLOOD', 'DDOS-SYN_FLOOD',
    'DDOS-TCP_FLOOD', 'DDOS-UDP_FLOOD', 'DDOS-UDP_FRAGMENTATION',
    'DICTIONARYBRUTEFORCE', 'DOS-UDP_FLOOD', 'DOS-HTTP_FLOOD', 'DOS-SYN_FLOOD',
    'DOS-TCP_FLOOD', 'DOS-UDP_FLOOD', 'MIRAI-GREETH_FLOOD', 'MIRAI-GREIP_FLOOD',
    'MIRAI-UDPPLAIN', 'DDOS-UDP_FLOOD', 'RECON-HOSTDISCOVERY',
    'RECON-OSSCAN', 'RECON-PINGSWEEP', 'RECON-PORTSCAN', 'SQLINJECTION',
    'UPLOADING_ATTACK', 'VULNERABILITYSCAN', 'XSS'
]

def is_admin():
    """Check if the script is running with administrative privileges."""
    try:
        # For Unix-like systems (Linux, macOS)
        is_admin_flag = (os.geteuid() == 0)
    except AttributeError:
        # For Windows
        is_admin_flag = (ctypes.windll.shell32.IsUserAnAdmin() != 0)
    return is_admin_flag

def setup_directories():
    """Create temporary directories for pcap and csv files if they don't exist."""
    os.makedirs(TEMP_PCAP_DIR, exist_ok=True)
    os.makedirs(TEMP_CSV_DIR, exist_ok=True)

def capture_and_process_batch(packet_count=200, timeout=60):
    """
    Captures a batch of live packets, saves them to a temporary pcap file,
    and runs the feature extraction process.
    """
    timestamp = int(time.time())
    temp_pcap_file = os.path.join(TEMP_PCAP_DIR, f"capture_{timestamp}.pcap")
    temp_csv_basename = os.path.join(TEMP_CSV_DIR, f"features_{timestamp}")

    print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Capturing {packet_count} packets (timeout: {timeout}s)...")

    try:
        packets = sniff(count=packet_count, timeout=timeout, iface=None)
        if not packets:
            print("No packets were captured in this batch.")
            return None

        wrpcap(temp_pcap_file, packets)
        print(f"Captured {len(packets)} packets. Saved to {temp_pcap_file}")
    except Exception as e:
        print(f"Error during packet capture: {e}")
        return None

    try:
        print("Extracting features from captured packets...")
        fe = Feature_extraction()
        fe.pcap_evaluation(pcap_file=temp_pcap_file, csv_file_name=temp_csv_basename)

        output_csv = temp_csv_basename + ".csv"
        if os.path.exists(output_csv):
            print(f"Feature extraction successful. CSV saved to {output_csv}")
            return output_csv
        else:
            print("Feature extraction did not produce a CSV file.")
            return None
    except Exception as e:
        print(f"An error occurred during feature extraction: {e}")
        return None

def predict_from_csv(csv_path, model):
    """
    Loads data from the feature CSV, makes predictions using the loaded model,
    and displays the results.
    """
    if not os.path.exists(csv_path):
        print(f"Error: CSV file not found at {csv_path}")
        return

    try:
        df = pd.read_csv(csv_path)
        df.replace([np.inf, -np.inf], np.nan, inplace=True)

        if df.isnull().values.any():
            print("Warning: Missing values found in feature data. The model's preprocessor will handle them.")

        X_live = df[model.feature_names_in_]

        predictions_numeric = model.predict(X_live)
        predictions_proba = model.predict_proba(X_live)
        predicted_labels = [LABEL_MAPPING[i] for i in predictions_numeric]

        print("\n--- PREDICTION RESULTS ---")
        for i, label in enumerate(predicted_labels):
            confidence = predictions_proba[i][predictions_numeric[i]] * 100
            if label != 'BENIGN':
                print(f"🚨 Row {i+1}: Detected potential threat: {label} (Confidence: {confidence:.2f}%)")
            else:
                print(f"✅ Row {i+1}: Traffic appears BENIGN (Confidence: {confidence:.2f}%)")
        print("--------------------------\n")

    except Exception as e:
        print(f"An error occurred during prediction: {e}")
        import traceback
        traceback.print_exc()

def run_live_monitor():
    """Main loop for continuous live traffic monitoring and prediction."""
    print("Starting Live Traffic Monitor...")

    if not os.path.exists(MODEL_FILENAME):
        print(f"FATAL: Model file '{MODEL_FILENAME}' not found. Please train the model and place it here.")
        return

    print(f"Loading model from {MODEL_FILENAME}...")
    try:
        loaded_model = joblib.load(MODEL_FILENAME)
        print("✅ Model loaded successfully!")
    except Exception as e:
        print(f"FATAL: Failed to load model. Error: {e}")
        return

    setup_directories()

    try:
        while True:
            feature_csv_file = capture_and_process_batch()
            if feature_csv_file:
                predict_from_csv(feature_csv_file, loaded_model)
            print("Waiting for the next batch... (Press Ctrl+C to stop)")
            time.sleep(10)

    except KeyboardInterrupt:
        print("\nStopping live monitor. Exiting.")

if __name__ == "__main__":
    if not is_admin(): # <-- Use the new cross-platform function
        print("🚨 This script requires root/administrator privileges to capture packets.")
        print("Please run with 'sudo' on Linux/macOS or as an Administrator on Windows.")
    else:
        run_live_monitor()