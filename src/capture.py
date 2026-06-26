#!/usr/bin/env python3
"""
Network Packet Capture for AI Threat Hunter
"""

import os
import time
from datetime import datetime
from scapy.all import sniff, wrpcap

# Get the project root directory (where this script is located)
script_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(script_dir)

# Create output directory
raw_dir = os.path.join(project_root, 'data', 'raw')
os.makedirs(raw_dir, exist_ok=True)

# Capture settings
interface = 'eth0'
duration = 30

print(f" Starting packet capture on {interface}")
print(f"⏱  Duration: {duration} seconds")
print(f" Saving to: {raw_dir}")
print("Press Ctrl+C to stop early")

packets = []

def packet_callback(pkt):
    packets.append(pkt)
    if len(packets) % 10 == 0:
        print(f" Captured {len(packets)} packets...")

try:
    sniff(iface=interface, prn=packet_callback, timeout=duration)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = os.path.join(raw_dir, f'capture_{timestamp}.pcap')
    wrpcap(filename, packets)
    
    print(f"\n Captured {len(packets)} packets")
    print(f" Saved to: {filename}")

except Exception as e:
    print(f" Error: {e}")
