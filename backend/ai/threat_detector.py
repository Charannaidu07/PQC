"""
QuantumShield-IoT
Real-Time AI Threat Detector
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
# LOAD MODEL
# -----------------------------------------

MODEL_PATH = os.path.join(
    os.path.dirname(__file__),
    "threat_model.pkl"
)

model = joblib.load(
    MODEL_PATH
)

print(
    "Threat Detection Model Loaded"
)

# -----------------------------------------
# DATABASE
# -----------------------------------------

db = SessionLocal()

# -----------------------------------------
# DETECT THREAT
# -----------------------------------------

def detect_threat(payload):

    try:

        temperature = payload.get(
            "temperature",
            0
        )

        humidity = payload.get(
            "humidity",
            0
        )

        cpu_usage = payload.get(
            "cpu_usage",
            0
        )

        memory_usage = payload.get(
            "memory_usage",
            0
        )

        requests_per_minute = payload.get(
            "requests_per_minute",
            20
        )

        device_id = payload.get(
            "device_id",
            "unknown"
        )

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

        prediction = model.predict(
            features
        )[0]

        probability = (
            model.predict_proba(
                features
            )[0]
        )

        confidence = float(
            max(probability)
        )

        if prediction == 0:

            return {
                "device_id":
                    device_id,

                "threat":
                    False,

                "confidence":
                    confidence
            }

        severity = "LOW"

        if confidence > 0.95:

            severity = "HIGH"

        elif confidence > 0.80:

            severity = "MEDIUM"

        threat_type = payload.get("attack_type", "AI_DETECTED_ATTACK")

        threat = ThreatLog(

            device_id=device_id,

            threat_type=threat_type,

            confidence=confidence,

            severity=severity,

            temperature=temperature,

            humidity=humidity,

            cpu_usage=cpu_usage,

            memory_usage=memory_usage,

            requests_per_minute=
                requests_per_minute,

            blocked=(severity == "HIGH")
        )

        db.add(threat)

        db.commit()

        print(
            f"Threat Detected "
            f"[{device_id}] "
            f"Confidence="
            f"{confidence:.2f}"
        )

        return {

            "device_id":
                device_id,

            "threat":
                True,

            "confidence":
                confidence,

            "severity":
                severity
        }

    except Exception as e:

        print(
            f"Detection Error: {e}"
        )

        return {
            "error":
                str(e)
        }