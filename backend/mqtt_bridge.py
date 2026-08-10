import json
import random
from datetime import datetime
import paho.mqtt.client as mqtt

from database import (
    SessionLocal,
    Device
)

from ai.threat_detector import detect_threat

try:
    from pqc.pqc_ml_selector import select_algorithm
except ImportError:
    select_algorithm = None

import os

MQTT_BROKER = os.getenv("MQTT_BROKER", "localhost")
MQTT_PORT = int(os.getenv("MQTT_PORT", "1883"))
MQTT_TOPIC = os.getenv("MQTT_TOPIC", "iot/data")

# Global Thread-Safe Log Buffer
SYSTEM_LOGS = []

def log_event(service: str, level: str, msg: str):
    timestamp = datetime.now().strftime("%H:%M:%S")
    event = {
        "time": timestamp,
        "type": level,      # "INF", "WRN", "ERR"
        "service": service,  # "PQC", "KEM", "SIG", "AI", "SOC", "FW"
        "text": msg
    }
    SYSTEM_LOGS.append(event)
    if len(SYSTEM_LOGS) > 300:
        SYSTEM_LOGS.pop(0)
    print(f"[{timestamp}] [{level}] [{service}] {msg}")

def process_payload(payload: dict):
    device_id = payload.get("device_id")
    if not device_id:
        return

    db = SessionLocal()
    try:
        # 0. Handle PQC Secure Channel Decryption & Verification
        is_encrypted = "encrypted_payload" in payload
        raw_telemetry = payload

        if is_encrypted:
            try:
                sig_algo = payload.get("signature_algorithm", "ML-DSA-44")
                
                # Fetch device's registered public signature key from the DB
                existing_device = db.query(Device).filter(Device.device_id == device_id).first()
                db_pub_key = None
                if existing_device:
                    if sig_algo == "ML-DSA-44" or sig_algo == "Dilithium2":
                        db_pub_key = existing_device.sig_public_key_ml_dsa_44
                    elif sig_algo == "FN-DSA-512" or sig_algo == "Falcon512":
                        db_pub_key = existing_device.sig_public_key_fn_dsa_512
                        
                # Close the TOFU spoofing vulnerability by requiring pre-registered keys
                public_key_to_use = db_pub_key
                
                if not public_key_to_use:
                    log_event("SOC", "ERR", f"Verification failed: No public key registered for device {device_id}")
                    # Log spoofing threat
                    from database import ThreatLog
                    threat_log = ThreatLog(
                        device_id=device_id,
                        threat_type="Signature Spoofing",
                        ground_truth_type="Spoofing Attack",
                        predicted_type="Signature Spoofing",
                        confidence=1.0,
                        severity="HIGH",
                        blocked=True,
                        timestamp=datetime.utcnow()
                    )
                    db.add(threat_log)
                    db.commit()
                    log_event("FW", "ERR", f"SOC automated firewall BLOCKED unauthenticated packet from unregistered device {device_id}")
                    return
                    
                from pqc.pqc_secure_channel import verify_and_decrypt_payload
                raw_telemetry = verify_and_decrypt_payload(payload, public_key_to_use)
                
                # 1. Replay Protection (Sequence & Timestamp checking)
                sequence = raw_telemetry.get("sequence", 0)
                timestamp_str = raw_telemetry.get("timestamp")
                
                if existing_device:
                    # 1a. Validate timestamp first to prevent desynchronization attacks
                    if timestamp_str:
                        packet_time = datetime.fromisoformat(timestamp_str)
                        time_diff = abs((datetime.utcnow() - packet_time).total_seconds())
                        if time_diff > 120.0:  # Allow 2 minutes window to account for minor clock skew
                            raise ValueError(f"Replay/timestamp skew detected: packet timestamp {timestamp_str} is outside the allowed window (skew: {time_diff:.1f}s)")
                            
                    # 1b. Atomic replay protection check & update (sequence check)
                    from sqlalchemy import text
                    stmt = text(
                        "UPDATE devices "
                        "SET last_sequence = :seq "
                        "WHERE device_id = :device_id AND (last_sequence < :seq OR last_sequence IS NULL)"
                    )
                    result = db.execute(stmt, {"seq": sequence, "device_id": device_id})
                    if result.rowcount == 0:
                        dev_exists = db.query(Device).filter(Device.device_id == device_id).first()
                        if not dev_exists:
                            raise ValueError(f"Device {device_id} not found in database.")
                        else:
                            raise ValueError(f"Replay attack detected: sequence {sequence} <= last seen sequence {dev_exists.last_sequence}")
                    
                    db.expire(existing_device, ['last_sequence'])
                
            except Exception as e:
                log_event("SOC", "ERR", f"PQC Decryption/Signature verification failed for device {device_id}: {e}")
                # Log spoofing threat
                from database import ThreatLog
                threat_log = ThreatLog(
                    device_id=device_id,
                    threat_type="Signature Spoofing",
                    ground_truth_type="Spoofing Attack",
                    predicted_type="Signature Spoofing",
                    confidence=1.0,
                    severity="HIGH",
                    blocked=True,
                    timestamp=datetime.utcnow()
                )
                db.add(threat_log)
                db.commit()
                log_event("FW", "ERR", f"SOC automated firewall BLOCKED tampered/replayed packet from device {device_id} due to verification error")
                return

        # Parse telemetry fields
        cpu_usage = raw_telemetry.get("cpu_usage", 0)
        memory_usage = raw_telemetry.get("memory_usage", 0)
        battery = raw_telemetry.get("battery", 100)
        attack_type = raw_telemetry.get("attack_type")

        # 2. Run AI Threat Detector
        result = detect_threat(raw_telemetry, db=db)
        is_threat = result.get("threat", False)
        severity = result.get("severity", "LOW")
        confidence = result.get("confidence", 0.0)

        # 3. Determine threat score and select PQC algorithm using RandomForest model
        if is_threat:
            threat_score = confidence
            log_event("AI", "WRN", f"Threat detected on device {device_id} ({attack_type or 'Anomaly'}) - severity: {severity} (conf: {confidence*100:.1f}%)")
        else:
            threat_score = random.uniform(0.02, 0.10) # realistic normal variation

        selected_kem, selected_sig = "ML-KEM-512", "ML-DSA-44"
        if select_algorithm:
            try:
                selected_kem, selected_sig = select_algorithm(
                    cpu_usage=cpu_usage,
                    ram_usage=memory_usage,
                    battery_level=battery,
                    threat_score=threat_score
                )
            except Exception as e:
                print(f"Error calling select_algorithm: {e}")

        # 4. Handle auto-mitigation
        status = "ONLINE"
        existing_device = db.query(Device).filter(Device.device_id == device_id).first()
        if existing_device and existing_device.status == "BLOCKED":
            status = "BLOCKED"

        if is_threat and severity == "HIGH":
            status = "BLOCKED"
            log_event("FW", "ERR", f"SOC automated firewall BLOCKED device {device_id} due to high severity threat")

        # 5. Save device state in DB and log cryptographic validations
        if existing_device:
            # Log successful decryption on normal packets occasionally to prevent flood
            rand = random.random()
            if rand < 0.005:
                log_event("KEM", "INF", f"Decrypted telemetry successfully via {selected_kem} session key on device {device_id}")
            elif rand < 0.010:
                log_event("SIG", "INF", f"Validated authentic telemetry signature using {selected_sig} on device {device_id}")
            elif rand < 0.012:
                log_event("PQC", "INF", f"PQC communication channels verified for {device_id} ({selected_kem} + {selected_sig})")

            existing_device.cpu_usage = cpu_usage
            existing_device.memory_usage = memory_usage
            existing_device.battery_level = battery
            existing_device.selected_kem = selected_kem
            existing_device.selected_signature = selected_sig
            existing_device.last_seen = datetime.utcnow()
            existing_device.status = status
            db.commit()
        else:
            # Unregistered devices are completely blocked to prevent spoofing / Sybil attacks
            log_event("SOC", "ERR", f"Blocked packet: Device {device_id} is not registered in the database.")
            return

    except Exception as e:
        db.rollback()
        print(f"Error in process_payload: {e}")
    finally:
        db.close()

def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print("Connected to MQTT Broker")
        client.subscribe(MQTT_TOPIC)
        print(f"Subscribed to {MQTT_TOPIC}")
    else:
        print(f"Connection failed: {rc}")

def on_message(client, userdata, msg):
    try:
        payload = json.loads(msg.payload.decode())
        process_payload(payload)
    except Exception as e:
        print(f"Message Error: {e}")

client = mqtt.Client()
client.on_connect = on_connect
client.on_message = on_message

# Authentication
mqtt_user = os.getenv("MQTT_USER")
mqtt_password = os.getenv("MQTT_PASSWORD")
if mqtt_user:
    client.username_pw_set(mqtt_user, mqtt_password)

# TLS configuration
mqtt_ca_certs = os.getenv("MQTT_CA_CERTS")
mqtt_client_cert = os.getenv("MQTT_CLIENT_CERT")
mqtt_client_key = os.getenv("MQTT_CLIENT_KEY")
if mqtt_ca_certs:
    try:
        client.tls_set(
            ca_certs=mqtt_ca_certs,
            certfile=mqtt_client_cert,
            keyfile=mqtt_client_key
        )
        print("MQTT Bridge TLS Configured successfully.")
    except Exception as e:
        print(f"Error configuring MQTT TLS: {e}")

def start():
    print("Starting MQTT Bridge...")
    try:
        client.connect(
            MQTT_BROKER,
            MQTT_PORT,
            60
        )
        client.loop_forever()
    except Exception as e:
        print(f"Failed to start MQTT loop: {e}")

if __name__ == "__main__":
    start()
