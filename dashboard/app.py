#!/usr/bin/env python3
"""
AI Threat Hunter Dashboard
Real-time visualization of network threats
"""

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import threading
import time
from datetime import datetime
import json
import os
import sys

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.detect_threats import extract_packet_features, model, scaler, feature_columns
from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether

app = Flask(__name__)
app.config['SECRET_KEY'] = 'threat-hunter-secret'
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Global variables
threats = []
packet_count = 0
threat_count = 0
is_monitoring = False
MAX_THREATS = 100

def packet_callback(packet):
    """Process packet and detect threats"""
    global packet_count, threat_count, threats
    
    packet_count += 1
    
    try:
        # Extract features
        import pandas as pd
        features = extract_packet_features(packet)
        df = pd.DataFrame([features])
        df = df.fillna(0)
        
        # Ensure all columns exist
        for col in feature_columns:
            if col not in df.columns:
                df[col] = 0
        
        # Select features
        X = df[feature_columns]
        
        # Scale and predict
        X_scaled = scaler.transform(X)
        prediction = model.predict(X_scaled)
        
        if prediction[0] == -1:
            threat_count += 1
            threat_data = {
                'id': threat_count,
                'timestamp': datetime.now().strftime('%H:%M:%S'),
                'summary': str(packet.summary())[:100],
                'protocol': 'TCP' if TCP in packet else 'UDP' if UDP in packet else 'ICMP' if ICMP in packet else 'Other',
                'src': packet[IP].src if IP in packet else 'Unknown',
                'dst': packet[IP].dst if IP in packet else 'Unknown',
                'packet_len': len(packet)
            }
            
            # Add to threats list
            threats.insert(0, threat_data)
            if len(threats) > MAX_THREATS:
                threats.pop()
            
            # Emit threat alert
            socketio.emit('threat_alert', threat_data)
            
    except Exception as e:
        pass

def monitor_network():
    """Start network monitoring in background thread"""
    global is_monitoring
    is_monitoring = True
    print("Starting network monitoring...")
    sniff(iface='eth0', prn=packet_callback, store=False)

@app.route('/')
def index():
    """Serve dashboard"""
    return render_template('dashboard.html')

@app.route('/api/stats')
def get_stats():
    """Get current statistics"""
    return jsonify({
        'total_packets': packet_count,
        'total_threats': threat_count,
        'recent_threats': threats[:10]
    })

@app.route('/api/threats')
def get_threats():
    """Get all threats"""
    return jsonify({
        'threats': threats,
        'count': len(threats)
    })

@app.route('/api/start')
def start_monitoring():
    """Start monitoring"""
    global is_monitoring
    if not is_monitoring:
        thread = threading.Thread(target=monitor_network)
        thread.daemon = True
        thread.start()
        return jsonify({'status': 'started'})
    return jsonify({'status': 'already running'})

@app.route('/api/stop')
def stop_monitoring():
    """Stop monitoring"""
    global is_monitoring
    is_monitoring = False
    return jsonify({'status': 'stopped'})

@app.route('/api/clear')
def clear_threats():
    """Clear threats"""
    global threats, threat_count
    threats = []
    threat_count = 0
    return jsonify({'status': 'cleared'})

@socketio.on('connect')
def handle_connect():
    print('Client connected')
    emit('connected', {'status': 'connected'})

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

if __name__ == '__main__':
    print("\n" + "="*50)
    print("AI Threat Hunter Dashboard")
    print("="*50)
    print("Starting server...")
    print("Open http://localhost:5000 in your browser")
    print("Press Ctrl+C to stop")
    print("="*50 + "\n")
    
    # Start monitoring automatically
    thread = threading.Thread(target=monitor_network)
    thread.daemon = True
    thread.start()
    
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)
