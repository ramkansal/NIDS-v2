#!/usr/bin/env python3
"""
Network Attack Simulator

This script simulates various network attacks by crafting and sending packets
based on a sample attack data file. It is designed to test the effectiveness
of the network_monitor.py script.

To Run:
- Ensure you have root/administrator privileges.
- On Linux/macOS: sudo python attack_simulator.py
- On Windows: Run from an Administrator Command Prompt.
"""
import os
import time
import pandas as pd
from scapy.all import IP, TCP, ICMP, UDP, send
from tqdm import tqdm
import ctypes # <-- Import ctypes for the admin check on Windows

# --- Global Configuration ---
ATTACK_DATA_FILE = 'attacks_sample.csv'

def is_admin():
    """Check if the script is running with administrative privileges."""
    try:
        # For Unix-like systems (Linux, macOS)
        is_admin_flag = (os.geteuid() == 0)
    except AttributeError:
        # For Windows
        is_admin_flag = (ctypes.windll.shell32.IsUserAnAdmin() != 0)
    return is_admin_flag

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
    print("Please edit 'attacks_sample.csv' to change target IPs and ports.")

    for index, row in attacks_df.iterrows():
        attack_type = row['Label']
        dst_ip = row['Dst_IP']
        dst_port = int(row['Dst_Port'])

        print(f"\n--- Simulating: {attack_type} against {dst_ip}:{dst_port} ---")

        packet = None
        src_port = 60000

        try:
            if 'TCP_FLOOD' in attack_type:
                packet = IP(dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='S')
            elif 'UDP_FLOOD' in attack_type:
                payload = "X" * 1024
                packet = IP(dst=dst_ip) / UDP(sport=src_port, dport=dst_port) / payload
            elif 'ICMP_FLOOD' in attack_type:
                packet = IP(dst=dst_ip) / ICMP()
            elif 'PORTSCAN' in attack_type:
                print(f"Simulating Port Scan by sending a single SYN packet to port {dst_port}")
                packet = IP(dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='S')
            else:
                print(f"Warning: No simulation logic defined for '{attack_type}'. Skipping.")
                continue

            num_packets = 150 if 'FLOOD' in attack_type else 1
            print(f"Sending {num_packets} packets...")

            for _ in tqdm(range(num_packets), desc=f"Sending {attack_type}"):
                send(packet, verbose=0)
                time.sleep(0.01)

            print(f"✅ Simulation for {attack_type} complete.")
            time.sleep(2)

        except Exception as e:
            print(f"Error during simulation of {attack_type}: {e}")

if __name__ == "__main__":
    if not is_admin(): # <-- Use the new cross-platform function
        print("🚨 This script requires root/administrator privileges to send packets.")
        print("Please run with 'sudo' on Linux/macOS or as an Administrator on Windows.")
    else:
        run_attack_simulation()