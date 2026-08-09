"""
QuantumShield-IoT
AI Multi-Class Threat Detection Model Trainer with GridSearchCV and Cross-Validation
"""

import pandas as pd
import numpy as np
import random
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.model_selection import GridSearchCV
import joblib
import json
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_recall_fscore_support,
    roc_auc_score
)

# Set seeds for reproducibility
np.random.seed(42)
random.seed(42)

# ==========================================
# TRAINING DATASET GENERATION (BASELINE ENVIRONMENT)
# ==========================================
def generate_training_dataset(samples=12000):
    data = []
    classes = [0, 1, 2, 3, 4]
    probs = [0.70, 0.10, 0.08, 0.06, 0.06]
    
    for _ in range(samples):
        scenario = np.random.choice(classes, p=probs)
        
        if scenario == 0:  # Normal
            temperature = np.random.normal(25.0, 3.0)
            humidity = np.random.normal(55.0, 8.0)
            cpu_usage = np.random.normal(15.0, 5.0)
            memory_usage = np.random.normal(180.0, 25.0)
            requests_per_minute = np.random.normal(15.0, 4.0)
        elif scenario == 1:  # DDoS
            temperature = np.random.normal(32.0, 4.0)
            humidity = np.random.normal(55.0, 8.0)
            cpu_usage = np.random.normal(85.0, 7.0)
            memory_usage = np.random.normal(900.0, 120.0)
            requests_per_minute = np.random.normal(2500.0, 400.0)
        elif scenario == 2:  # Cryptojacking
            temperature = np.random.normal(45.0, 4.0)
            humidity = np.random.normal(55.0, 8.0)
            cpu_usage = np.random.normal(95.0, 3.0)
            memory_usage = np.random.normal(1200.0, 150.0)
            requests_per_minute = np.random.normal(25.0, 5.0)
        elif scenario == 3:  # Thermal Tampering
            temperature = np.random.normal(90.0, 8.0)
            humidity = np.random.normal(15.0, 5.0)
            cpu_usage = np.random.normal(25.0, 6.0)
            memory_usage = np.random.normal(200.0, 30.0)
            requests_per_minute = np.random.normal(15.0, 4.0)
        else:  # Reconnaissance
            temperature = np.random.normal(26.0, 3.0)
            humidity = np.random.normal(55.0, 8.0)
            cpu_usage = np.random.normal(35.0, 7.0)
            memory_usage = np.random.normal(280.0, 40.0)
            requests_per_minute = np.random.normal(280.0, 40.0)
            
        # Clip to realistic physical bounds
        temperature = max(5.0, min(120.0, temperature))
        humidity = max(0.0, min(100.0, humidity))
        cpu_usage = max(0.0, min(100.0, cpu_usage))
        memory_usage = max(16.0, min(4096.0, memory_usage))
        requests_per_minute = max(0.0, requests_per_minute)
            
        data.append([
            temperature, humidity, cpu_usage, memory_usage, requests_per_minute, scenario
        ])

    columns = ["temperature", "humidity", "cpu_usage", "memory_usage", "requests_per_minute", "attack"]
    return pd.DataFrame(data, columns=columns)


# ==========================================
# TEST DATASET GENERATION (INDEPENDENT SHIFTED ENVIRONMENT)
# ==========================================
def generate_shifted_test_dataset(samples=3000):
    data = []
    classes = [0, 1, 2, 3, 4]
    probs = [0.70, 0.10, 0.08, 0.06, 0.06]
    
    for _ in range(samples):
        scenario = np.random.choice(classes, p=probs)
        
        if scenario == 0:  # Normal
            temperature = np.random.normal(29.5, 5.0)
            humidity = np.random.normal(52.0, 12.0)
            cpu_usage = np.random.normal(17.0, 8.0)
            memory_usage = np.random.normal(190.0, 40.0)
            requests_per_minute = np.random.normal(16.0, 6.0)
        elif scenario == 1:  # DDoS
            temperature = np.random.normal(36.5, 6.0)
            humidity = np.random.normal(52.0, 12.0)
            cpu_usage = np.random.normal(83.0, 11.0)
            memory_usage = np.random.normal(870.0, 180.0)
            requests_per_minute = np.random.normal(2400.0, 600.0)
        elif scenario == 2:  # Cryptojacking
            temperature = np.random.normal(49.5, 6.0)
            humidity = np.random.normal(52.0, 12.0)
            cpu_usage = np.random.normal(92.0, 6.0)
            memory_usage = np.random.normal(1150.0, 220.0)
            requests_per_minute = np.random.normal(26.0, 8.0)
        elif scenario == 3:  # Thermal Tampering
            temperature = np.random.normal(94.5, 10.0)
            humidity = np.random.normal(12.0, 7.0)
            cpu_usage = np.random.normal(27.0, 9.0)
            memory_usage = np.random.normal(210.0, 45.0)
            requests_per_minute = np.random.normal(16.0, 6.0)
        else:  # Reconnaissance
            temperature = np.random.normal(30.5, 5.0)
            humidity = np.random.normal(52.0, 12.0)
            cpu_usage = np.random.normal(37.0, 10.0)
            memory_usage = np.random.normal(290.0, 60.0)
            requests_per_minute = np.random.normal(290.0, 60.0)
            
        # Clip to realistic physical bounds
        temperature = max(5.0, min(120.0, temperature))
        humidity = max(0.0, min(100.0, humidity))
        cpu_usage = max(0.0, min(100.0, cpu_usage))
        memory_usage = max(16.0, min(4096.0, memory_usage))
        requests_per_minute = max(0.0, requests_per_minute)
            
        data.append([
            temperature, humidity, cpu_usage, memory_usage, requests_per_minute, scenario
        ])

    columns = ["temperature", "humidity", "cpu_usage", "memory_usage", "requests_per_minute", "attack"]
    return pd.DataFrame(data, columns=columns)


# ==========================================
# MAIN
# ==========================================
def main():
    print("\nGenerating Baseline Training Telemetry Dataset...")
    train_df = generate_training_dataset(samples=12000)
    train_df.to_csv("attack_dataset.csv", index=False)
    print("Dataset Saved to attack_dataset.csv")

    X_train = train_df.drop("attack", axis=1)
    y_train = train_df["attack"]

    print("\nGenerating Independent Out-of-Distribution (Noisy & Shifted) Evaluation Dataset...")
    test_df = generate_shifted_test_dataset(samples=3000)
    X_test = test_df.drop("attack", axis=1)
    y_test = test_df["attack"]
    print("Test Dataset generated successfully.")

    # Define hyperparameter grid for systematic tuning
    param_grid = {
        'n_estimators': [100, 150],
        'learning_rate': [0.05, 0.1],
        'max_depth': [3, 4]
    }

    print("\nRunning GridSearchCV with Stratified 5-Fold Cross-Validation...")
    grid_search = GridSearchCV(
        estimator=GradientBoostingClassifier(random_state=42),
        param_grid=param_grid,
        cv=5,
        scoring='accuracy',
        n_jobs=-1
    )
    
    grid_search.fit(X_train, y_train)
    
    print("\nSystematic Tuning Complete:")
    print(f" - Best Hyperparameters: {grid_search.best_params_}")
    print(f" - Best 5-Fold Stratified CV Mean Accuracy: {grid_search.best_score_:.4%}")

    # Select the optimal trained model
    model = grid_search.best_estimator_
    
    # Evaluate generalization on the completely independent, noisy shifted dataset
    predictions = model.predict(X_test)
    accuracy = accuracy_score(y_test, predictions)

    print(f"\nGeneralization Accuracy on Independent OOD Test Set: {accuracy:.4%}")
    
    target_names = ["Normal", "DDoS", "Cryptojacking", "Thermal Tampering", "Reconnaissance"]
    print("\nClassification Report (OOD Test Set):")
    print(classification_report(y_test, predictions, target_names=target_names))

    print("\nConfusion Matrix (OOD Test Set):")
    print(confusion_matrix(y_test, predictions))

    # Feature Importance analysis of the best estimator
    importances = model.feature_importances_
    features = X_train.columns
    print("\nFeature Importance Rankings:")
    for f, imp in sorted(zip(features, importances), key=lambda x: x[1], reverse=True):
        print(f" - {f}: {imp:.4%}")

    joblib.dump(model, "threat_model.pkl")
    print("\nOptimized Multi-Class Threat Detection Model Saved: threat_model.pkl")

    # Serialize evaluation metrics for dashboard display
    try:
        # Calculate scores
        precision, recall, f1, _ = precision_recall_fscore_support(y_test, predictions, average='weighted')
        probabilities = model.predict_proba(X_test)
        roc_auc = roc_auc_score(y_test, probabilities, multi_class='ovr', average='weighted')
        conf_mat = confusion_matrix(y_test, predictions).tolist()

        feature_imp_dict = {f: float(imp) for f, imp in zip(features, importances)}

        metrics_data = {
            "accuracy": float(accuracy),
            "precision": float(precision),
            "recall": float(recall),
            "f1_score": float(f1),
            "roc_auc": float(roc_auc),
            "best_params": grid_search.best_params_,
            "confusion_matrix": conf_mat,
            "feature_importances": feature_imp_dict
        }

        with open("model_metrics.json", "w") as f:
            json.dump(metrics_data, f, indent=4)
        print("Model metrics saved to model_metrics.json successfully.")
    except Exception as e:
        print(f"Failed to serialize model metrics: {e}")

if __name__ == "__main__":
    main()