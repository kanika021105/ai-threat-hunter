#!/usr/bin/env python3
"""
Train ML Model with Enhanced Features
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import glob
import os

def main():
    # Load the latest features
    files = glob.glob('data/processed/*.csv')
    if not files:
        print("No feature files found")
        return
    
    latest = sorted(files)[-1]
    print("Loading: " + latest)
    df = pd.read_csv(latest)
    
    # Fill missing values
    df = df.fillna(0)
    
    # Exclude non-numeric columns for training
    exclude_cols = ['proto_type', 'time']
    feature_columns = [col for col in df.columns if col not in exclude_cols and df[col].dtype in ['int64', 'float64']]
    X = df[feature_columns]
    
    print("\nTraining data shape: " + str(X.shape))
    print("Features used (" + str(len(feature_columns)) + "): " + str(feature_columns[:10]) + "...")
    
    # Scale the features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    # Train Isolation Forest
    model = IsolationForest(
        contamination=0.15,
        random_state=42,
        n_estimators=100
    )
    model.fit(X_scaled)
    
    # Save model and scaler
    os.makedirs('models', exist_ok=True)
    joblib.dump(model, 'models/threat_detector_enhanced.pkl')
    joblib.dump(scaler, 'models/scaler_enhanced.pkl')
    joblib.dump(feature_columns, 'models/feature_columns.pkl')
    
    # Predict on training data
    predictions = model.predict(X_scaled)
    anomalies = sum(predictions == -1)
    
    print("\nEnhanced Model trained successfully!")
    print("Anomalies detected: " + str(anomalies) + "/" + str(len(X)) + " (" + str(round(anomalies/len(X)*100, 1)) + "%)")
    print("Saved to: models/threat_detector_enhanced.pkl")
    print("Total features: " + str(len(feature_columns)))
    
    # Show which features are most important (simplified)
    print("\nFeature importance (based on variance):")
    variances = X.var()
    for feat in variances.nlargest(5).index:
        print("   - " + feat + ": " + str(round(variances[feat], 2)))

if __name__ == "__main__":
    main()
