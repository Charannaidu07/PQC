"""
QuantumShield-IoT
Adaptive PQC Selection Engine (Split KEM & Digital Signature Classifiers)
"""

import os
import random
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import joblib

# ==========================================
# MODEL PATHS
# ==========================================

MODEL_DIR = os.path.dirname(os.path.abspath(__file__))
KEM_MODEL_FILE = os.path.join(MODEL_DIR, "kem_selector.pkl")
SIG_MODEL_FILE = os.path.join(MODEL_DIR, "sig_selector.pkl")

# ==========================================
# PRIMITIVE OPTIONS
# ==========================================

KEMS = {
    0: "ML-KEM-512",
    1: "ML-KEM-768"
}

SIGNATURES = {
    0: "ML-DSA-44",
    1: "FN-DSA-512"
}

# ==========================================
# BENCHMARK DATA DYNAMIC RETRIEVAL
# ==========================================

def get_latest_benchmark_stats():
    """
    Retrieves the actual measured cryptographic latencies, sizes, and memory overheads
    from the database to drive the optimal selection utility formulas.
    """
    import sys
    sys.path.append(os.path.join(MODEL_DIR, ".."))
    from database import SessionLocal, BenchmarkResult
    
    session = SessionLocal()
    stats = {}
    try:
        for algo in ["ML-KEM-512", "ML-KEM-768", "ML-DSA-44", "FN-DSA-512"]:
            res = session.query(BenchmarkResult).filter(BenchmarkResult.algorithm == algo).order_by(BenchmarkResult.timestamp.desc()).first()
            if res:
                stats[algo] = {
                    "decap_ms": res.decap_mean_ms or res.decapsulation_time_ms,
                    "keygen_ms": res.keygen_mean_ms or res.keygen_time_ms,
                    "sign_ms": res.sign_mean_ms or res.signature_time_ms,
                    "verify_ms": res.verify_mean_ms or res.verify_time_ms,
                    "memory_mb": res.memory_usage_mb,
                    "cpu_percent": res.cpu_usage_percent,
                    "pub_key_size": res.pub_key_size_bytes,
                    "ciphertext_size": res.ciphertext_size_bytes,
                    "signature_size": res.signature_size_bytes
                }
    except Exception as e:
        print(f"Error querying benchmark stats from DB: {e}")
    finally:
        session.close()
    return stats

# ==========================================
# DATASET GENERATION
# ==========================================

def compute_optimal_kem(cpu, ram, battery, threat_score, stats):
    """
    Computes the utility-maximizing KEM algorithm using actual database benchmark measurements:
    0: ML-KEM-512, 1: ML-KEM-768
    """
    if ram < 512:
        return 0  # Severe memory limit override
        
    kem_512 = stats.get("ML-KEM-512", {
        "decap_ms": 0.22, "memory_mb": 0.18, "ciphertext_size": 768
    })
    kem_768 = stats.get("ML-KEM-768", {
        "decap_ms": 0.37, "memory_mb": 0.02, "ciphertext_size": 1088
    })

    w_security = 10.0 * threat_score
    w_battery = 0.05 * (100.0 - battery)
    w_bandwidth = 0.005
    w_latency = 2.0

    # Utility = Security_Level - (Latency_Cost + Battery_Cost + Bandwidth_Cost)
    u_512 = (w_security * 1.0) - (w_latency * kem_512["decap_ms"] + w_battery * 1.0 + w_bandwidth * kem_512["ciphertext_size"])
    u_768 = (w_security * 3.0) - (w_latency * kem_768["decap_ms"] + w_battery * 1.5 + w_bandwidth * kem_768["ciphertext_size"])
    
    return 1 if u_768 > u_512 else 0

def compute_optimal_sig(cpu, ram, battery, threat_score, stats):
    """
    Computes the utility-maximizing Digital Signature algorithm using actual database benchmark measurements:
    0: ML-DSA-44, 1: FN-DSA-512
    """
    sig_dsa = stats.get("ML-DSA-44", {
        "keygen_ms": 0.44, "memory_mb": 0.04, "signature_size": 2420
    })
    sig_fn = stats.get("FN-DSA-512", {
        "keygen_ms": 29.45, "memory_mb": 0.17, "signature_size": 662
    })

    w_security = 8.0 * threat_score
    w_battery = 0.05 * (100.0 - battery)
    w_cpu = 0.02 * cpu
    w_bandwidth = 0.005
    w_latency = 0.5

    # Utility = Security_Level - (Latency_Cost + Battery_Cost + CPU_Cost + Bandwidth_Cost)
    u_dsa = (w_security * 1.0) - (w_latency * sig_dsa["keygen_ms"] + w_battery * 1.5 + w_cpu * 1.0 + w_bandwidth * sig_dsa["signature_size"])
    u_fn = (w_security * 1.0) - (w_latency * sig_fn["keygen_ms"] + w_battery * 3.0 + w_cpu * 5.0 + w_bandwidth * sig_fn["signature_size"])
    
    return 1 if u_fn > u_dsa else 0

def generate_dataset(samples=5000):
    stats = get_latest_benchmark_stats()
    rows = []
    for _ in range(samples):
        cpu = random.uniform(1, 100)
        ram = random.uniform(128, 4096)
        battery = random.uniform(1, 100)
        threat_score = random.uniform(0, 1)

        kem_label = compute_optimal_kem(cpu, ram, battery, threat_score, stats)
        sig_label = compute_optimal_sig(cpu, ram, battery, threat_score, stats)

        rows.append([cpu, ram, battery, threat_score, kem_label, sig_label])

    return pd.DataFrame(
        rows,
        columns=["cpu_usage", "ram_usage", "battery_level", "threat_score", "kem_label", "sig_label"]
    )

# ==========================================
# TRAIN
# ==========================================

def train_selector():
    print("\nGenerating Selector Dataset...")
    random.seed(42)
    df = generate_dataset()

    X = df[["cpu_usage", "ram_usage", "battery_level", "threat_score"]]
    y_kem = df["kem_label"]
    y_sig = df["sig_label"]

    from sklearn.model_selection import train_test_split, cross_val_score
    from sklearn.metrics import accuracy_score, f1_score, confusion_matrix
    import json

    metrics = {}

    # Evaluate & Train KEM model
    print("Training KEM Selection model...")
    X_train, X_test, y_train, y_test = train_test_split(X, y_kem, test_size=0.2, random_state=42)
    kem_model = RandomForestClassifier(n_estimators=100, random_state=42)
    kem_model.fit(X_train, y_train)
    
    # Eval
    kem_pred = kem_model.predict(X_test)
    kem_acc = accuracy_score(y_test, kem_pred)
    kem_f1 = f1_score(y_test, kem_pred, average="macro")
    kem_cv = cross_val_score(RandomForestClassifier(n_estimators=100, random_state=42), X, y_kem, cv=5).mean()
    kem_cm = confusion_matrix(y_test, kem_pred).tolist()
    
    metrics["kem"] = {
        "accuracy": float(kem_acc),
        "f1_macro": float(kem_f1),
        "cross_validation_mean": float(kem_cv),
        "confusion_matrix": kem_cm
    }

    # Re-fit KEM model on complete dataset
    kem_model_final = RandomForestClassifier(n_estimators=100, random_state=42)
    kem_model_final.fit(X, y_kem)
    joblib.dump(kem_model_final, KEM_MODEL_FILE)
    print(f"KEM Selector Model Saved: {KEM_MODEL_FILE}")

    # Evaluate & Train Signature model
    print("Training Signature Selection model...")
    X_train, X_test, y_train, y_test = train_test_split(X, y_sig, test_size=0.2, random_state=42)
    sig_model = RandomForestClassifier(n_estimators=100, random_state=42)
    sig_model.fit(X_train, y_train)
    
    # Eval
    sig_pred = sig_model.predict(X_test)
    sig_acc = accuracy_score(y_test, sig_pred)
    sig_f1 = f1_score(y_test, sig_pred, average="macro")
    sig_cv = cross_val_score(RandomForestClassifier(n_estimators=100, random_state=42), X, y_sig, cv=5).mean()
    sig_cm = confusion_matrix(y_test, sig_pred).tolist()
    
    metrics["sig"] = {
        "accuracy": float(sig_acc),
        "f1_macro": float(sig_f1),
        "cross_validation_mean": float(sig_cv),
        "confusion_matrix": sig_cm
    }

    # Re-fit Signature model on complete dataset
    sig_model_final = RandomForestClassifier(n_estimators=100, random_state=42)
    sig_model_final.fit(X, y_sig)
    joblib.dump(sig_model_final, SIG_MODEL_FILE)
    print(f"Signature Selector Model Saved: {SIG_MODEL_FILE}")

    # Save evaluation metrics to json
    metrics_path = os.path.join(MODEL_DIR, "../ai/selector_metrics.json")
    with open(metrics_path, "w") as f:
        json.dump(metrics, f, indent=4)
    print(f"Selector model evaluation metrics written to: {metrics_path}")

# ==========================================
# LOAD
# ==========================================

_kem_model = None
_sig_model = None

def load_models():
    global _kem_model, _sig_model
    if _kem_model is None or _sig_model is None:
        if not os.path.exists(KEM_MODEL_FILE) or not os.path.exists(SIG_MODEL_FILE):
            print("PQC selector models not found. Training now...")
            train_selector()
        try:
            _kem_model = joblib.load(KEM_MODEL_FILE)
            _sig_model = joblib.load(SIG_MODEL_FILE)
            print("Successfully loaded KEM and Signature selector models.")
        except Exception as e:
            print(f"Failed to load PQC selector models: {e}")
            _kem_model, _sig_model = None, None
    return _kem_model, _sig_model

# ==========================================
# SELECT SUITE
# ==========================================

def select_algorithm(
    cpu=None,
    memory=None,
    battery=None,
    cpu_usage=None,
    ram_usage=None,
    battery_level=None,
    threat_score=None
):
    """
    Returns (selected_kem, selected_signature) as a cryptographically correct 
    dual-primitive suite rather than conflating KEMs and Digital Signatures.
    """
    cpu_val = cpu if cpu is not None else cpu_usage
    memory_val = memory if memory is not None else ram_usage
    battery_val = battery if battery is not None else battery_level
    threat_val = threat_score if threat_score is not None else 0.10

    if battery_val is None:
        battery_val = 100
    if cpu_val is None:
        cpu_val = 0
    if memory_val is None:
        memory_val = 0

    kem_model, sig_model = load_models()
    if kem_model is not None and sig_model is not None:
        try:
            df_features = pd.DataFrame(
                [[cpu_val, memory_val, battery_val, threat_val]],
                columns=["cpu_usage", "ram_usage", "battery_level", "threat_score"]
            )
            pred_kem = kem_model.predict(df_features)[0]
            pred_sig = sig_model.predict(df_features)[0]
            
            selected_kem = KEMS.get(pred_kem, "ML-KEM-512")
            selected_sig = SIGNATURES.get(pred_sig, "ML-DSA-44")
            return selected_kem, selected_sig
        except Exception as e:
            print(f"PQC selection prediction error: {e}")

    # Fallback to utility optimization logic
    stats = get_latest_benchmark_stats()
    pred_kem = compute_optimal_kem(cpu_val, memory_val, battery_val, threat_val, stats)
    pred_sig = compute_optimal_sig(cpu_val, memory_val, battery_val, threat_val, stats)
    
    selected_kem = KEMS.get(pred_kem, "ML-KEM-512")
    selected_sig = SIGNATURES.get(pred_sig, "ML-DSA-44")

    return selected_kem, selected_sig

# ==========================================
# TEST
# ==========================================

if __name__ == "__main__":
    train_selector()

    print("\nTesting Selector Options:")
    test_cases = [
        {"cpu": 35, "ram": 1024, "battery": 80, "threat": 0.20},
        {"cpu": 20, "ram": 256, "battery": 10, "threat": 0.10},
        {"cpu": 90, "ram": 4096, "battery": 90, "threat": 0.95}
    ]

    for tc in test_cases:
        kem, sig = select_algorithm(
            cpu_usage=tc["cpu"],
            ram_usage=tc["ram"],
            battery_level=tc["battery"],
            threat_score=tc["threat"]
        )
        print(f"Input {tc} -> Selected Suite: KEM={kem}, Signature={sig}")