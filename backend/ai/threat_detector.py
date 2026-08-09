"""
QuantumShield-IoT
Real-Time AI Multi-Class Threat Detector
"""

import os
import sys
import joblib
import pandas as pd

# -----------------------------------------
# DATABASE IMPORT
# -----------------------------------------

sys.path.append(
    os.path.abspath(
        os.path.join(
            os.path.dirname(__file__),
            ".."
        )
    )
)

from database import (
    SessionLocal,
    ThreatLog
)

# -----------------------------------------
# LOAD MODEL & MAPS
# -----------------------------------------

MODEL_PATH = os.path.join(
    os.path.dirname(__file__),
    "threat_model.pkl"
)

model = joblib.load(MODEL_PATH)
print("Multi-Class Threat Detection Model Loaded")

THREAT_MAP = {
    0: "Normal",
    1: "DDoS",
    2: "Cryptojacking",
    3: "Thermal Tampering",
    4: "Reconnaissance"
}

# -----------------------------------------
# DATABASE
# -----------------------------------------

db = SessionLocal()

# -----------------------------------------
# DETECT THREAT
# -----------------------------------------

def detect_threat(payload):
    try:
        temperature = payload.get("temperature", 0)
        humidity = payload.get("humidity", 0)
        cpu_usage = payload.get("cpu_usage", 0)
        memory_usage = payload.get("memory_usage", 0)
        requests_per_minute = payload.get("requests_per_minute", 20)
        device_id = payload.get("device_id", "unknown")

        features = pd.DataFrame(
            [[
                temperature,
                humidity,
                cpu_usage,
                memory_usage,
                requests_per_minute
            ]],
            columns=[
                "temperature",
                "humidity",
                "cpu_usage",
                "memory_usage",
                "requests_per_minute"
            ]
        )

        prediction = model.predict(features)[0]
        probability = model.predict_proba(features)[0]
        confidence = float(max(probability))

        # Prediction 0 is Normal operation
        if prediction == 0:
            return {
                "device_id": device_id,
                "threat": False,
                "confidence": confidence,
                "threat_type": "Normal"
            }

        # Handle severity logic
        severity = "LOW"
        if confidence > 0.95:
            severity = "HIGH"
        elif confidence > 0.80:
            severity = "MEDIUM"

        # Dynamically predict threat type using AI classification result
        threat_type = THREAT_MAP.get(prediction, "AI_DETECTED_ATTACK")

        threat = ThreatLog(
            device_id=device_id,
            threat_type=threat_type,
            confidence=confidence,
            severity=severity,
            temperature=temperature,
            humidity=humidity,
            cpu_usage=cpu_usage,
            memory_usage=memory_usage,
            requests_per_minute=requests_per_minute,
            blocked=(severity == "HIGH")
        )

        db.add(threat)
        db.commit()

        print(f"Threat Detected [{device_id}] Class={threat_type} (Conf={confidence*100:.1f}%)")

        return {
            "device_id": device_id,
            "threat": True,
            "confidence": confidence,
            "severity": severity,
            "threat_type": threat_type
        }

    except Exception as e:
        print(f"Detection Error: {e}")
        return {
            "error": str(e)
        }