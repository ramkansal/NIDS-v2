#!/usr/bin/env python3
"""
Live Network Traffic Analysis and Attack Simulation Tool

This script integrates the CICIoT2023 feature extraction modules to perform:
1.  Live Packet Analysis: Captures network traffic in real-time, processes it to extract
    features, and uses a pre-trained XGBoost model to predict if the traffic is malicious.
2.  Attack Simulation: Simulates various network attacks by crafting and sending packets
    based on a sample attack data file.

To Run Live Analysis:
- sudo python network_monitor.py --mode monitor

To Run Attack Simulation:
- sudo python network_monitor.py --mode simulate
"""

import os
import time
import pandas as pd
import numpy as np
import joblib
import argparse
from scapy.all import sniff, wrpcap, IP, TCP, ICMP, UDP, send
from tqdm import tqdm

# Import the feature extraction logic from your provided files
from Feature_extraction import Feature_extraction

# --- Global Configuration ---
MODEL_FILENAME = 'network_intrusion_model.joblib'
TEMP_PCAP_DIR = 'temp_pcap'
TEMP_CSV_DIR = 'temp_csv'
ATTACK_DATA_FILE = 'attacks_sample.csv' # A sample file for the simulator

# The LabelEncoder uses this order. This is crucial for mapping predictions back to labels.
# This should be the output of `le.classes_` from your training script.
# I have derived this from your classification report.
LABEL_MAPPING = [
    'BACKDOOR_MALWARE', 'BENIGN', 'BROWSERHIJACKING', 'COMMANDINJECTION',
    'DDOS-ACK_FRAGMENTATION', 'DDOS-HTTP_FLOOD', 'DDOS-ICMP_FLOOD',
    'DDOS-ICMP_FRAGMENTATION', 'DDOS-PSHACK_FLOOD', 'DDOS-RSTFINFLOOD',
    'DDOS-SLOWLORIS', 'DDOS-SYNONYMOUSIP_FLOOD', 'DDOS-SYN_FLOOD',
    'DDOS-TCP_FLOOD', 'DDOS-UDP_FLOOD', 'DDOS-UDP_FRAGMENTATION',
    'DICTIONARYBRUTEFORCE', 'DNS_SPOOFING', 'DOS-HTTP_FLOOD', 'DOS-SYN_FLOOD',
    'DOS-TCP_FLOOD', 'DOS-UDP_FLOOD', 'MIRAI-GREETH_FLOOD', 'MIRAI-GREIP_FLOOD',
    'MIRAI-UDPPLAIN', 'MITM-ARPSPOOFING', 'RECON-HOSTDISCOVERY',
    'RECON-OSSCAN', 'RECON-PINGSWEEP', 'RECON-PORTSCAN', 'SQLINJECTION',
    'UPLOADING_ATTACK', 'VULNERABILITYSCAN', 'XSS'
]


# ==============================================================================
# PART 1: LIVE MONITORING AND PREDICTION
# ==============================================================================

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
    
    # Capture packets using Scapy
    # NOTE: "iface" might need to be changed based on your system's network interface name
    # (e.g., "eth0", "en0", "Wi-Fi"). Leave as None to auto-detect.
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

    # Process the pcap file using your Feature_extraction module
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

        # The model pipeline handles all preprocessing (imputing, scaling, encoding)
        # We just need to ensure the columns are in the correct order
        # and handle any infinite values that may have been generated.
        df.replace([np.inf, -np.inf], np.nan, inplace=True)

        if df.isnull().values.any():
            print("Warning: Missing values found in feature data. The model's preprocessor will handle them.")

        # Ensure all feature columns expected by the model are present
        # The 'preprocessor' in the pipeline knows which columns to expect.
        X_live = df[model.feature_names_in_]
        
        # Make predictions
        predictions_numeric = model.predict(X_live)
        predictions_proba = model.predict_proba(X_live)

        # Map numeric predictions back to string labels
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
    
    # Load the trained model pipeline
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
            # 1. Capture and Process
            feature_csv_file = capture_and_process_batch()

            # 2. Predict (if features were extracted)
            if feature_csv_file:
                predict_from_csv(feature_csv_file, loaded_model)

            print("Waiting for the next batch... (Press Ctrl+C to stop)")
            time.sleep(10) # Pause between batches

    except KeyboardInterrupt:
        print("\nStopping live monitor. Cleaning up temporary files...")
        # Optional: cleanup temporary files on exit
        # for f in os.listdir(TEMP_PCAP_DIR): os.remove(os.path.join(TEMP_PCAP_DIR, f))
        # for f in os.listdir(TEMP_CSV_DIR): os.remove(os.path.join(TEMP_CSV_DIR, f))
        print("Cleanup complete. Exiting.")


# ==============================================================================
# PART 2: ATTACK SIMULATOR
# ==============================================================================

def create_attack_sample_file():
    """Creates a sample CSV file for the attack simulator if it doesn't exist."""
    if not os.path.exists(ATTACK_DATA_FILE):
        print(f"Creating sample attack file: {ATTACK_DATA_FILE}")
        attack_data = """Label,Dst_IP,Dst_Port
DDOS-TCP_FLOOD,192.168.1.10,80
DDOS-UDP_FLOOD,192.168.1.10,53
DDOS-ICMP_FLOOD,192.168.1.10,0
RECON-PORTSCAN,192.168.1.10,22
"""
        with open(ATTACK_DATA_FILE, 'w') as f:
            f.write(attack_data)

def run_attack_simulation():
    """
    Simulates attacks by reading from a CSV and crafting corresponding packets.
    NOTE: This is a basic simulation. It does not perfectly replicate complex, stateful attacks.
    """
    print("Starting Attack Simulator...")
    create_attack_sample_file()

    if not os.path.exists(ATTACK_DATA_FILE):
        print(f"Attack data file not found: {ATTACK_DATA_FILE}")
        return
        
    attacks_df = pd.read_csv(ATTACK_DATA_FILE)
    print(f"Loaded {len(attacks_df)} attack scenarios from {ATTACK_DATA_FILE}")
    
    for index, row in attacks_df.iterrows():
        attack_type = row['Label']
        dst_ip = row['Dst_IP']
        dst_port = int(row['Dst_Port'])
        
        print(f"\n--- Simulating: {attack_type} against {dst_ip}:{dst_port} ---")
        
        packet = None
        # Use a high source port to avoid conflicts with system services
        src_port = 60000 
        
        try:
            if 'TCP_FLOOD' in attack_type:
                packet = IP(dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='S') # SYN Flood
            elif 'UDP_FLOOD' in attack_type:
                payload = "X" * 1024 # Large payload
                packet = IP(dst=dst_ip) / UDP(sport=src_port, dport=dst_port) / payload
            elif 'ICMP_FLOOD' in attack_type:
                packet = IP(dst=dst_ip) / ICMP() # Echo request
            elif 'PORTSCAN' in attack_type:
                print(f"Simulating Port Scan by sending a single SYN packet to port {dst_port}")
                packet = IP(dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='S')
            else:
                print(f"Warning: No simulation logic defined for '{attack_type}'. Skipping.")
                continue

            # Send a burst of packets to simulate a flood
            num_packets = 150 if 'FLOOD' in attack_type else 1
            print(f"Sending {num_packets} packets...")
            
            # Use tqdm for a progress bar
            for _ in tqdm(range(num_packets), desc=f"Sending {attack_type}"):
                send(packet, verbose=0) # verbose=0 suppresses scapy's default output
                time.sleep(0.01) # Small delay between packets

            print(f"✅ Simulation for {attack_type} complete.")
            time.sleep(2) # Pause before the next attack

        except Exception as e:
            print(f"Error during simulation of {attack_type}: {e}")

# ==============================================================================
# MAIN EXECUTION
# ==============================================================================

if __name__ == "__main__":
    from datetime import datetime

    parser = argparse.ArgumentParser(
        description="Live Network Analysis and Attack Simulation Tool.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        '--mode',
        type=str,
        required=True,
        choices=['monitor', 'simulate'],
        help="""Choose the operation mode:
- monitor:  Capture and analyze live network traffic.
- simulate: Run a pre-defined attack simulation."""
    )
    
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("🚨 This script requires root/administrator privileges to capture and send packets.")
        print("Please run with 'sudo' on Linux/macOS or as an Administrator on Windows.")
    elif args.mode == 'monitor':
        run_live_monitor()
    elif args.mode == 'simulate':
        run_attack_simulation()