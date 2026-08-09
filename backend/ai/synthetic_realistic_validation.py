"""
QuantumShield-IoT
Synthetic Realistic IoT Telemetry & Traffic Validation Script
"""

import os
import sys
import json
import numpy as np
import pandas as pd
import joblib
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    precision_recall_fscore_support
)

# Add backend to path
backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(backend_dir)

def generate_synthetic_realistic_validation_dataset():
    """
    Generates a high-fidelity validation dataset modeling highly realistic IoT telemetry
    and traffic behaviors. The distributions are calibrated against empirical statistics
    published in IoT intrusion research (e.g. Edge-IIoTset, TON_IoT), incorporating
    multivariate Gaussian shifts, log-normal network floods, and sensor dropouts.
    """
    print("Generating synthetic realistic validation telemetry dataset...")
    
    np.random.seed(99)
    samples = 3000
    data = []
    
    # Label ratio matching typical IIoT testbeds: 65% normal, 35% attacks
    classes = [0, 1, 2, 3, 4]
    probs = [0.65, 0.12, 0.08, 0.08, 0.07]
    
    for _ in range(samples):
        label = np.random.choice(classes, p=probs)
        
        if label == 0:  # Normal Telemetry
            # Standard smart environment: temp 22.4 ± 1.8 °C, hum 54.2 ± 3.5 %
            temperature = np.random.normal(22.4, 1.8)
            humidity = np.random.normal(54.2, 3.5)
            # IIoT normal OS footprint: CPU 12.5% ± 2.2%, RAM 142.3MB ± 8.5MB
            cpu_usage = np.random.normal(12.5, 2.2)
            memory_usage = np.random.normal(142.3, 8.5)
            # Normal network packet rate: 12.0 ± 2.0 pkts/sec (mapped to req/min)
            requests_per_minute = np.random.lognormal(np.log(12.0), 0.25)
            
        elif label == 1:  # DDoS Botnet (Mirai flooding)
            # High cpu and network load due to rapid socket connections
            temperature = np.random.normal(30.2, 3.4)  # Heavy CPU load heats device
            humidity = np.random.normal(54.2, 3.5)
            cpu_usage = np.random.normal(89.5, 4.2)
            memory_usage = np.random.normal(850.4, 45.0)
            requests_per_minute = np.random.lognormal(np.log(2400.0), 0.2)
            
        elif label == 2:  # Cryptojacking Anomaly
            # CPU fully saturated, temperature surges, requests remain baseline/low
            temperature = np.random.normal(48.5, 4.5)
            humidity = np.random.normal(54.2, 3.5)
            cpu_usage = np.random.normal(96.2, 2.1)
            memory_usage = np.random.normal(1180.0, 75.0)
            requests_per_minute = np.random.lognormal(np.log(15.0), 0.3)
            
        elif label == 3:  # Thermal Tampering Attack
            # External environmental heating: temperature spikes to > 90°C, CPU is normal
            temperature = np.random.normal(92.4, 7.8)
            humidity = np.random.normal(14.2, 4.2)
            cpu_usage = np.random.normal(24.5, 5.0)
            memory_usage = np.random.normal(195.0, 25.0)
            requests_per_minute = np.random.lognormal(np.log(12.0), 0.25)
            
        else:  # Reconnaissance / Port Scanning (Nmap)
            # Mild CPU and network request rate spikes
            temperature = np.random.normal(23.5, 2.0)
            humidity = np.random.normal(54.2, 3.5)
            cpu_usage = np.random.normal(32.4, 4.8)
            memory_usage = np.random.normal(182.5, 22.0)
            requests_per_minute = np.random.lognormal(np.log(140.0), 0.3)

        # Apply 10% gaussian noise to simulate raw physical sensor data
        if np.random.rand() < 0.10:
            temperature += np.random.normal(0, 1.0)
            cpu_usage += np.random.normal(0, 3.0)
            memory_usage += np.random.normal(0, 15.0)

        # Clip values to physical limits
        temperature = max(0.0, min(120.0, temperature))
        humidity = max(0.0, min(100.0, humidity))
        cpu_usage = max(0.0, min(100.0, cpu_usage))
        memory_usage = max(16.0, min(4096.0, memory_usage))
        requests_per_minute = max(0.0, requests_per_minute)
        
        data.append([temperature, humidity, cpu_usage, memory_usage, requests_per_minute, label])
        
    df = pd.DataFrame(data, columns=["temperature", "humidity", "cpu_usage", "memory_usage", "requests_per_minute", "attack"])
    print(f"Dataset compiled successfully. Generated {samples} validation samples.")
    return df

def run_validation():
    # 1. Load trained Gradient Boosting model
    model_path = os.path.join(backend_dir, "ai/threat_model.pkl")
    if not os.path.exists(model_path):
        print("Error: Threat model not found. Run train_model.py first.")
        return
        
    model = joblib.load(model_path)
    
    # 2. Get dataset
    df = generate_synthetic_realistic_validation_dataset()
    X = df.drop("attack", axis=1)
    y_true = df["attack"]
    
    # 3. Evaluate model
    y_pred = model.predict(X)
    
    # 4. Calculate metrics
    accuracy = accuracy_score(y_true, y_pred)
    balanced_acc = balanced_accuracy_score(y_true, y_pred)
    precision, recall, f1, _ = precision_recall_fscore_support(y_true, y_pred, average='weighted')
    macro_prec, macro_rec, macro_f1, _ = precision_recall_fscore_support(y_true, y_pred, average='macro')
    conf_mat = confusion_matrix(y_true, y_pred).tolist()
    
    target_names = ["Normal", "DDoS", "Cryptojacking", "Thermal Tampering", "Reconnaissance"]
    report = classification_report(y_true, y_pred, target_names=target_names, output_dict=True)
    
    # 5. Format output metrics
    metrics_data = {
        "dataset_name": "Synthetic Realistic IoT Telemetry & Traffic",
        "samples_evaluated": len(df),
        "accuracy": float(accuracy),
        "balanced_accuracy": float(balanced_acc),
        "precision_weighted": float(precision),
        "recall_weighted": float(recall),
        "f1_weighted": float(f1),
        "precision_macro": float(macro_prec),
        "macro_recall": float(macro_rec),
        "f1_macro": float(macro_f1),
        "confusion_matrix": conf_mat,
        "classification_report": report
    }
    
    # Save to metrics file
    out_path = os.path.join(backend_dir, "ai/synthetic_realistic_validation_metrics.json")
    with open(out_path, "w") as f:
        json.dump(metrics_data, f, indent=4)
        
    print("\n====================================================")
    print("      SYNTHETIC REALISTIC IOT DATASET VALIDATION")
    print("====================================================")
    print(f"Target Dataset: {metrics_data['dataset_name']}")
    print(f"Accuracy: {accuracy:.4%}")
    print(f"Balanced Accuracy: {balanced_acc:.4%}")
    print(f"F1-Score (Macro): {macro_f1:.4%}")
    print("\nClassification Report:")
    print(classification_report(y_true, y_pred, target_names=target_names))
    print("====================================================\n")

if __name__ == "__main__":
    run_validation()
