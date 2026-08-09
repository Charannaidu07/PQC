"""
QuantumShield-IoT
AI Advanced Threat Detection Model Trainer
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)
import joblib

# ==========================================
# DATASET GENERATION
# ==========================================
def generate_dataset(samples=12000):
    data = []
    for _ in range(samples):
        # We generate three classes of data to make it realistic:
        # 0: Normal operation
        # 1: DDoS / High Traffic Attack
        # 2: Hardware/Thermal Anomaly (Tampering)
        
        scenario = np.random.choice([0, 1, 2], p=[0.75, 0.15, 0.10])
        
        if scenario == 0:  # Normal
            temperature = np.random.uniform(20, 38)
            humidity = np.random.uniform(30, 80)
            cpu_usage = np.random.uniform(5, 45)
            memory_usage = np.random.uniform(100, 750)
            requests_per_minute = np.random.uniform(5, 60)
            attack = 0
        elif scenario == 1:  # DDoS / Network Attack
            temperature = np.random.uniform(25, 45)
            humidity = np.random.uniform(30, 80)
            cpu_usage = np.random.uniform(75, 100)
            memory_usage = np.random.uniform(900, 2500)
            requests_per_minute = np.random.uniform(800, 6000)
            attack = 1
        else:  # Thermal / Hardware Tampering Anomaly
            temperature = np.random.uniform(70, 105)
            humidity = np.random.uniform(10, 40)
            cpu_usage = np.random.uniform(40, 90)
            memory_usage = np.random.uniform(600, 1500)
            requests_per_minute = np.random.uniform(10, 150)
            attack = 1  # Labeled as attack/anomaly
            
        data.append([
            temperature,
            humidity,
            cpu_usage,
            memory_usage,
            requests_per_minute,
            attack
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
    print("\nGenerating Advanced Security Telemetry Dataset...")
    df = generate_dataset(samples=12000)
    df.to_csv("attack_dataset.csv", index=False)
    print("Dataset Saved to attack_dataset.csv")

    X = df.drop("attack", axis=1)
    y = df["attack"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("\nTraining Advanced Gradient Boosting Threat Classifier...")
    # Using Gradient Boosting Classifier (better gradient updates, handles non-linear boundaries cleanly)
    model = GradientBoostingClassifier(
        n_estimators=150,
        learning_rate=0.08,
        max_depth=4,
        subsample=0.85,
        random_state=42
    )

    model.fit(X_train, y_train)
    predictions = model.predict(X_test)
    accuracy = accuracy_score(y_test, predictions)

    print(f"\nModel Accuracy: {accuracy:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, predictions, target_names=["Normal", "Anomaly/Attack"]))

    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, predictions))

    # Feature Importance analysis
    importances = model.feature_importances_
    features = X.columns
    print("\nFeature Importance Rankings:")
    for f, imp in sorted(zip(features, importances), key=lambda x: x[1], reverse=True):
        print(f" - {f}: {imp:.4%}")

    joblib.dump(model, "threat_model.pkl")
    print("\nOptimized Threat Detection Model Saved: threat_model.pkl")

if __name__ == "__main__":
    main()