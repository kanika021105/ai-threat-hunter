#!/usr/bin/env python3
"""
Enhanced Feature Extraction from PCAP
Extracts 10+ features for better threat detection
"""

import os
import pandas as pd
import glob
from scapy.all import rdpcap, IP, TCP, UDP, ICMP, Ether
from datetime import datetime
import numpy as np

def extract_features(packet):
    """Extract comprehensive features from a single packet"""
    feat = {}
    
    # 1. Basic packet info
    feat['packet_len'] = len(packet)
    feat['time'] = float(packet.time)
    
    # 2. Ethernet layer
    if Ether in packet:
        feat['eth_type'] = packet[Ether].type
    else:
        feat['eth_type'] = 0
    
    # 3. IP layer features
    if IP in packet:
        ip = packet[IP]
        feat['ip_len'] = ip.len
        feat['ip_ttl'] = ip.ttl
        feat['ip_proto'] = ip.proto
        feat['ip_flags'] = ip.flags
        feat['ip_frag'] = ip.frag
        feat['ip_tos'] = ip.tos
        feat['ip_id'] = ip.id
        feat['has_ip'] = 1
        
        # 4. Protocol-specific features
        if TCP in packet:
            tcp = packet[TCP]
            feat['tcp_sport'] = tcp.sport
            feat['tcp_dport'] = tcp.dport
            feat['tcp_flags'] = tcp.flags
            feat['tcp_window'] = tcp.window
            feat['tcp_urgptr'] = tcp.urgptr
            feat['proto_type'] = 'TCP'
            
        elif UDP in packet:
            udp = packet[UDP]
            feat['udp_sport'] = udp.sport
            feat['udp_dport'] = udp.dport
            feat['udp_len'] = udp.len
            feat['proto_type'] = 'UDP'
            
        elif ICMP in packet:
            icmp = packet[ICMP]
            feat['icmp_type'] = icmp.type
            feat['icmp_code'] = icmp.code
            feat['proto_type'] = 'ICMP'
        else:
            feat['proto_type'] = 'OTHER'
    else:
        # Non-IP packets
        feat['ip_len'] = 0
        feat['ip_ttl'] = 0
        feat['ip_proto'] = 0
        feat['ip_flags'] = 0
        feat['ip_frag'] = 0
        feat['ip_tos'] = 0
        feat['ip_id'] = 0
        feat['has_ip'] = 0
        feat['proto_type'] = 'NON_IP'
        feat['tcp_sport'] = 0
        feat['tcp_dport'] = 0
        feat['tcp_flags'] = 0
        feat['tcp_window'] = 0
        feat['tcp_urgptr'] = 0
        feat['udp_sport'] = 0
        feat['udp_dport'] = 0
        feat['udp_len'] = 0
        feat['icmp_type'] = 0
        feat['icmp_code'] = 0
    
    # 5. Calculated features (derived)
    feat['has_tcp'] = 1 if 'tcp_sport' in feat and feat['tcp_sport'] > 0 else 0
    feat['has_udp'] = 1 if 'udp_sport' in feat and feat['udp_sport'] > 0 else 0
    feat['has_icmp'] = 1 if 'icmp_type' in feat and feat['icmp_type'] > 0 else 0
    feat['is_syn'] = 1 if 'tcp_flags' in feat and (feat['tcp_flags'] & 0x02) else 0
    feat['is_ack'] = 1 if 'tcp_flags' in feat and (feat['tcp_flags'] & 0x10) else 0
    feat['is_fin'] = 1 if 'tcp_flags' in feat and (feat['tcp_flags'] & 0x01) else 0
    feat['is_rst'] = 1 if 'tcp_flags' in feat and (feat['tcp_flags'] & 0x04) else 0
    
    # 6. Port-based classification (common services)
    if 'tcp_dport' in feat and feat['tcp_dport'] > 0:
        if feat['tcp_dport'] == 80 or feat['tcp_dport'] == 443:
            feat['is_web'] = 1
        elif feat['tcp_dport'] == 22:
            feat['is_ssh'] = 1
        elif feat['tcp_dport'] == 53:
            feat['is_dns'] = 1
        else:
            feat['is_web'] = 0
            feat['is_ssh'] = 0
            feat['is_dns'] = 0
    else:
        feat['is_web'] = 0
        feat['is_ssh'] = 0
        feat['is_dns'] = 0
    
    return feat

def process_pcap(pcap_file):
    """Process a PCAP file and extract features"""
    print("Processing: " + pcap_file)
    packets = rdpcap(pcap_file)
    
    features_list = []
    for pkt in packets:
        features = extract_features(pkt)
        features_list.append(features)
    
    df = pd.DataFrame(features_list)
    return df

def main():
    # Find PCAPs
    pcap_files = glob.glob('data/raw/*.pcap')
    if not pcap_files:
        print("No PCAP files found in data/raw/")
        return
    
    print("Found " + str(len(pcap_files)) + " PCAP files")
    
    # Process each PCAP
    all_dfs = []
    for pcap_file in pcap_files:
        df = process_pcap(pcap_file)
        if not df.empty:
            all_dfs.append(df)
            print("   Extracted " + str(len(df)) + " packets with " + str(len(df.columns)) + " features")
    
    if not all_dfs:
        print("No data extracted")
        return
    
    # Combine all data
    combined_df = pd.concat(all_dfs, ignore_index=True)
    
    # Fill NaN values with 0
    combined_df = combined_df.fillna(0)
    
    # Save to CSV
    os.makedirs('data/processed', exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_file = "data/processed/features_" + timestamp + ".csv"
    combined_df.to_csv(output_file, index=False)
    
    print("\nTotal packets processed: " + str(len(combined_df)))
    print("Features extracted: " + str(len(combined_df.columns)))
    print("Saved to: " + output_file)
    
    # Show feature summary
    print("\nFeatures: " + str(combined_df.columns.tolist()))
    print("\nSample data:")
    print(combined_df.head(3))

if __name__ == "__main__":
    main()
