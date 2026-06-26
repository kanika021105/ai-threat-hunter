#!/usr/bin/env python3
"""
Enhanced Real-time Threat Detection with 10+ Features
Fixed version with proper type conversion
"""

import joblib
import pandas as pd
import numpy as np
from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether, IPv6
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

# Load enhanced model and scaler
model = joblib.load('models/threat_detector_enhanced.pkl')
scaler = joblib.load('models/scaler_enhanced.pkl')
feature_columns = joblib.load('models/feature_columns.pkl')

print("Enhanced AI Threat Hunter Active!")
print("Monitoring network traffic with 32 features...")
print("Press Ctrl+C to stop\n")

def extract_packet_features(packet):
    """Extract comprehensive features from a single packet"""
    feat = {}
    
    # Basic packet info
    feat['packet_len'] = len(packet)
    feat['time'] = float(packet.time)
    
    # Ethernet layer
    if Ether in packet:
        feat['eth_type'] = packet[Ether].type
    else:
        feat['eth_type'] = 0
    
    # IP layer features
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
        
        # Protocol-specific features
        if TCP in packet:
            tcp = packet[TCP]
            feat['tcp_sport'] = int(tcp.sport)
            feat['tcp_dport'] = int(tcp.dport)
            feat['tcp_flags'] = int(tcp.flags)
            feat['tcp_window'] = int(tcp.window)
            feat['tcp_urgptr'] = int(tcp.urgptr)
            feat['proto_type'] = 'TCP'
            # UDP fields to 0
            feat['udp_sport'] = 0
            feat['udp_dport'] = 0
            feat['udp_len'] = 0
            # ICMP fields to 0
            feat['icmp_type'] = 0
            feat['icmp_code'] = 0
            
        elif UDP in packet:
            udp = packet[UDP]
            feat['udp_sport'] = int(udp.sport)
            feat['udp_dport'] = int(udp.dport)
            feat['udp_len'] = int(udp.len)
            feat['proto_type'] = 'UDP'
            # TCP fields to 0
            feat['tcp_sport'] = 0
            feat['tcp_dport'] = 0
            feat['tcp_flags'] = 0
            feat['tcp_window'] = 0
            feat['tcp_urgptr'] = 0
            # ICMP fields to 0
            feat['icmp_type'] = 0
            feat['icmp_code'] = 0
            
        elif ICMP in packet:
            icmp = packet[ICMP]
            feat['icmp_type'] = int(icmp.type)
            feat['icmp_code'] = int(icmp.code)
            feat['proto_type'] = 'ICMP'
            # TCP fields to 0
            feat['tcp_sport'] = 0
            feat['tcp_dport'] = 0
            feat['tcp_flags'] = 0
            feat['tcp_window'] = 0
            feat['tcp_urgptr'] = 0
            # UDP fields to 0
            feat['udp_sport'] = 0
            feat['udp_dport'] = 0
            feat['udp_len'] = 0
            
        else:
            feat['proto_type'] = 'OTHER'
            # All protocol fields to 0
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
            
    elif IPv6 in packet:
        # IPv6 support
        ip6 = packet[IPv6]
        feat['ip_len'] = 0  # IPv6 doesn't have len field like IPv4
        feat['ip_ttl'] = int(ip6.hlim)
        feat['ip_proto'] = int(ip6.nh)
        feat['ip_flags'] = 0
        feat['ip_frag'] = 0
        feat['ip_tos'] = 0
        feat['ip_id'] = 0
        feat['has_ip'] = 1
        
        # Check for protocol in IPv6
        if TCP in packet:
            tcp = packet[TCP]
            feat['tcp_sport'] = int(tcp.sport)
            feat['tcp_dport'] = int(tcp.dport)
            feat['tcp_flags'] = int(tcp.flags)
            feat['tcp_window'] = int(tcp.window)
            feat['tcp_urgptr'] = int(tcp.urgptr)
            feat['proto_type'] = 'TCP6'
            feat['udp_sport'] = 0
            feat['udp_dport'] = 0
            feat['udp_len'] = 0
            feat['icmp_type'] = 0
            feat['icmp_code'] = 0
        elif UDP in packet:
            udp = packet[UDP]
            feat['udp_sport'] = int(udp.sport)
            feat['udp_dport'] = int(udp.dport)
            feat['udp_len'] = int(udp.len)
            feat['proto_type'] = 'UDP6'
            feat['tcp_sport'] = 0
            feat['tcp_dport'] = 0
            feat['tcp_flags'] = 0
            feat['tcp_window'] = 0
            feat['tcp_urgptr'] = 0
            feat['icmp_type'] = 0
            feat['icmp_code'] = 0
        else:
            feat['proto_type'] = 'IP6_OTHER'
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
    
    # Calculated features
    feat['has_tcp'] = 1 if feat.get('tcp_sport', 0) > 0 else 0
    feat['has_udp'] = 1 if feat.get('udp_sport', 0) > 0 else 0
    feat['has_icmp'] = 1 if feat.get('icmp_type', 0) > 0 else 0
    feat['is_syn'] = 1 if feat.get('tcp_flags', 0) & 0x02 else 0
    feat['is_ack'] = 1 if feat.get('tcp_flags', 0) & 0x10 else 0
    feat['is_fin'] = 1 if feat.get('tcp_flags', 0) & 0x01 else 0
    feat['is_rst'] = 1 if feat.get('tcp_flags', 0) & 0x04 else 0
    
    # Port-based classification
    if feat.get('tcp_dport', 0) > 0:
        if feat['tcp_dport'] in [80, 443]:
            feat['is_web'] = 1
            feat['is_ssh'] = 0
            feat['is_dns'] = 0
        elif feat['tcp_dport'] == 22:
            feat['is_web'] = 0
            feat['is_ssh'] = 1
            feat['is_dns'] = 0
        elif feat['tcp_dport'] == 53:
            feat['is_web'] = 0
            feat['is_ssh'] = 0
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

def packet_callback(packet):
    """Called for each captured packet"""
    try:
        # Extract features
        features = extract_packet_features(packet)
        df = pd.DataFrame([features])
        
        # Fill NaN values
        df = df.fillna(0)
        
        # Ensure all required columns exist
        for col in feature_columns:
            if col not in df.columns:
                df[col] = 0
        
        # Select features in correct order
        X = df[feature_columns]
        
        # Scale and predict
        X_scaled = scaler.transform(X)
        prediction = model.predict(X_scaled)
        
        if prediction[0] == -1:
            timestamp = datetime.now().strftime('%H:%M:%S')
            print(timestamp + " THREAT! " + str(packet.summary())[:80])
            
    except Exception as e:
        # Silent handling of errors
        pass

print("Ready to detect threats!\n")

try:
    # Start sniffing
    sniff(iface='eth0', prn=packet_callback, store=False)
except KeyboardInterrupt:
    print("\nThreat Hunter stopped")
except Exception as e:
    print("Error: " + str(e))
