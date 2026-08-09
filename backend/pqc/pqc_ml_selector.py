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
    0: "Kyber512",
    1: "Kyber768"
}

SIGNATURES = {
    0: "Dilithium2",
    1: "Falcon512"
}

# ==========================================
# DATASET GENERATION
# ==========================================

def generate_dataset(samples=5000):
    rows = []
    for _ in range(samples):
        cpu = random.uniform(1, 100)
        ram = random.uniform(128, 4096)
        battery = random.uniform(1, 100)
        threat_score = random.uniform(0, 1)

        # ----------------------------------
        # KEM SELECTION RULES
        # ----------------------------------
        # For lower resource states, select Kyber512 (ML-KEM-512) for lower footprint.
        # Otherwise select Kyber768 (ML-KEM-768) for standard protection.
        if battery < 20 or ram < 512:
            kem_label = 0  # Kyber512
        else:
            kem_label = 1  # Kyber768

        # ----------------------------------
        # SIGNATURE SELECTION RULES
        # ----------------------------------
        # If threat level is high, use Dilithium2 (ML-DSA-44) as standardized baseline.
        # If CPU constraint is severe, use Falcon512 (FN-DSA) for lower bandwidth/computation signature verify overhead.
        # Otherwise default to Dilithium2.
        if threat_score > 0.70:
            sig_label = 0  # Dilithium2
        elif cpu > 75:
            sig_label = 1  # Falcon512
        else:
            sig_label = 0  # Dilithium2

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

    # Train KEM model
    print("Training KEM Selection model...")
    y_kem = df["kem_label"]
    kem_model = RandomForestClassifier(n_estimators=100, random_state=42)
    kem_model.fit(X, y_kem)
    joblib.dump(kem_model, KEM_MODEL_FILE)
    print(f"KEM Selector Model Saved: {KEM_MODEL_FILE}")

    # Train Signature model
    print("Training Signature Selection model...")
    y_sig = df["sig_label"]
    sig_model = RandomForestClassifier(n_estimators=100, random_state=42)
    sig_model.fit(X, y_sig)
    joblib.dump(sig_model, SIG_MODEL_FILE)
    print(f"Signature Selector Model Saved: {SIG_MODEL_FILE}")

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
            
            selected_kem = KEMS.get(pred_kem, "Kyber512")
            selected_sig = SIGNATURES.get(pred_sig, "Dilithium2")
            return selected_kem, selected_sig
        except Exception as e:
            print(f"PQC selection prediction error: {e}")

    # Fallback to rule-based logic
    if battery_val < 20 or memory_val < 512:
        selected_kem = "Kyber512"
    else:
        selected_kem = "Kyber768"

    if threat_val > 0.70:
        selected_sig = "Dilithium2"
    elif cpu_val > 75:
        selected_sig = "Falcon512"
    else:
        selected_sig = "Dilithium2"

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