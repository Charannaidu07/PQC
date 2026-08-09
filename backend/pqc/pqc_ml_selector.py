"""
QuantumShield-IoT
Adaptive PQC Selection Engine
"""

import os
import random
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
import joblib

# ==========================================
# MODEL FILE
# ==========================================

MODEL_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_FILE = os.path.join(MODEL_DIR, "pqc_selector.pkl")

# ==========================================
# ALGORITHMS
# ==========================================

ALGORITHMS = {
    0: "Kyber512",
    1: "Kyber768",
    2: "Dilithium2",
    3: "Falcon512"
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
        # RULES FOR TRAINING LABELS
        # ----------------------------------

        if battery < 20:

            label = 0  # Kyber512

        elif ram < 512:

            label = 0

        elif threat_score > 0.80:

            label = 2  # Dilithium2

        elif cpu > 80:

            label = 3  # Falcon512

        else:

            label = 1  # Kyber768

        rows.append([

            cpu,

            ram,

            battery,

            threat_score,

            label
        ])

    return pd.DataFrame(

        rows,

        columns=[

            "cpu_usage",

            "ram_usage",

            "battery_level",

            "threat_score",

            "algorithm"
        ]
    )

# ==========================================
# TRAIN
# ==========================================

def train_selector():

    print(
        "\nGenerating Dataset..."
    )

    random.seed(42)
    df = generate_dataset()

    X = df[

        [
            "cpu_usage",
            "ram_usage",
            "battery_level",
            "threat_score"
        ]
    ]

    y = df["algorithm"]

    model = RandomForestClassifier(

        n_estimators=100,

        random_state=42
    )

    model.fit(X, y)

    joblib.dump(

        model,

        MODEL_FILE
    )

    print(
        f"Model Saved: {MODEL_FILE}"
    )

# ==========================================
# LOAD
# ==========================================

_loaded_model = None

def load_model():
    global _loaded_model
    if _loaded_model is None:
        if not os.path.exists(MODEL_FILE):
            print(f"PQC selector model not found at {MODEL_FILE}. Training now...")
            train_selector()
        try:
            _loaded_model = joblib.load(MODEL_FILE)
            print("Successfully loaded PQC selector model.")
        except Exception as e:
            print(f"Failed to load PQC selector model: {e}")
            _loaded_model = None
    return _loaded_model

# ==========================================
# SELECT ALGORITHM
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

    # Try predicting using the machine learning model
    model = load_model()
    if model is not None:
        try:
            # Features: cpu_usage, ram_usage, battery_level, threat_score
            df_features = pd.DataFrame(
                [[cpu_val, memory_val, battery_val, threat_val]],
                columns=["cpu_usage", "ram_usage", "battery_level", "threat_score"]
            )
            prediction = model.predict(df_features)[0]
            algorithm = ALGORITHMS.get(prediction)
            if algorithm:
                return algorithm
        except Exception as e:
            print(f"PQC selection prediction error: {e}")

    # Fallback to rule-based logic
    if battery_val < 20:
        return "Kyber512"
    elif cpu_val < 40:
        return "Falcon512"
    elif memory_val > 1500:
        return "Dilithium2"
    else:
        return "Kyber768"

# ==========================================
# TEST
# ==========================================

if __name__ == "__main__":

    train_selector()

    print(
        "\nTesting Selector\n"
    )

    algorithm = select_algorithm(

        cpu_usage=35,

        ram_usage=1024,

        battery_level=80,

        threat_score=0.20
    )

    print(
        f"Selected: {algorithm}"
    )

    algorithm = select_algorithm(

        cpu_usage=20,

        ram_usage=256,

        battery_level=10,

        threat_score=0.10
    )

    print(
        f"Selected: {algorithm}"
    )

    algorithm = select_algorithm(

        cpu_usage=60,

        ram_usage=4096,

        battery_level=90,

        threat_score=0.95
    )

    print(
        f"Selected: {algorithm}"
    )