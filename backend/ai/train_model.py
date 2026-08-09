"""
QuantumShield-IoT
AI Multi-Class Threat Detection Model Trainer
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)
import joblib

# ==========================================
# DATASET GENERATION
# ==========================================
def generate_dataset(samples=15000):
    data = []
    
    # Probabilities for classes:
    # 0: Normal (70%)
    # 1: DDoS (10%)
    # 2: Cryptojacking (8%)
    # 3: Thermal Tampering (6%)
    # 4: Reconnaissance (6%)
    classes = [0, 1, 2, 3, 4]
    probs = [0.70, 0.10, 0.08, 0.06, 0.06]
    
    for _ in range(samples):
        scenario = np.random.choice(classes, p=probs)
        
        if scenario == 0:  # Normal
            temperature = np.random.uniform(20, 35)
            humidity = np.random.uniform(30, 80)
            cpu_usage = np.random.uniform(5, 30)
            memory_usage = np.random.uniform(100, 300)
            requests_per_minute = np.random.uniform(5, 30)
        elif scenario == 1:  # DDoS
            temperature = np.random.uniform(25, 45)
            humidity = np.random.uniform(30, 80)
            cpu_usage = np.random.uniform(75, 100)
            memory_usage = np.random.uniform(500, 1500)
            requests_per_minute = np.random.uniform(1000, 5000)
        elif scenario == 2:  # Cryptojacking
            temperature = np.random.uniform(35, 55)
            humidity = np.random.uniform(30, 80)
            cpu_usage = np.random.uniform(90, 100)
            memory_usage = np.random.uniform(800, 2000)
            requests_per_minute = np.random.uniform(10, 50)
        elif scenario == 3:  # Thermal Tampering
            temperature = np.random.uniform(75, 110)
            humidity = np.random.uniform(5, 30)
            cpu_usage = np.random.uniform(10, 40)
            memory_usage = np.random.uniform(100, 300)
            requests_per_minute = np.random.uniform(5, 30)
        else:  # Reconnaissance
            temperature = np.random.uniform(20, 35)
            humidity = np.random.uniform(30, 80)
            cpu_usage = np.random.uniform(15, 45)
            memory_usage = np.random.uniform(150, 450)
            requests_per_minute = np.random.uniform(150, 400)
            
        data.append([
            temperature,
            humidity,
            cpu_usage,
            memory_usage,
            requests_per_minute,
            scenario
        ])

    columns = [
        "temperature",
        "humidity",
        "cpu_usage",
        "memory_usage",
        "requests_per_minute",
        "attack"
    ]
    return pd.DataFrame(data, columns=columns)

# ==========================================
# MAIN
# ==========================================
def main():
    print("\nGenerating Multi-Class Security Telemetry Dataset...")
    df = generate_dataset(samples=15000)
    df.to_csv("attack_dataset.csv", index=False)
    print("Dataset Saved to attack_dataset.csv")

    X = df.drop("attack", axis=1)
    y = df["attack"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("\nTraining Multi-Class Gradient Boosting Threat Classifier...")
    model = GradientBoostingClassifier(
        n_estimators=100,
        learning_rate=0.1,
        max_depth=3,
        random_state=42
    )

    model.fit(X_train, y_train)
    predictions = model.predict(X_test)
    accuracy = accuracy_score(y_test, predictions)

    print(f"\nModel Accuracy: {accuracy:.4f}")
    
    target_names = ["Normal", "DDoS", "Cryptojacking", "Thermal Tampering", "Reconnaissance"]
    print("\nClassification Report:")
    print(classification_report(y_test, predictions, target_names=target_names))

    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, predictions))

    # Feature Importance analysis
    importances = model.feature_importances_
    features = X.columns
    print("\nFeature Importance Rankings:")
    for f, imp in sorted(zip(features, importances), key=lambda x: x[1], reverse=True):
        print(f" - {f}: {imp:.4%}")

    joblib.dump(model, "threat_model.pkl")
    print("\nOptimized Multi-Class Threat Detection Model Saved: threat_model.pkl")

if __name__ == "__main__":
    main()