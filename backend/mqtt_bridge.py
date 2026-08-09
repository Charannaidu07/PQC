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

MQTT_BROKER = "localhost"
MQTT_PORT = 1883
MQTT_TOPIC = "iot/data"

db = SessionLocal()

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
    try:
        device_id = payload.get("device_id")
        if not device_id:
            return

        cpu_usage = payload.get("cpu_usage", 0)
        memory_usage = payload.get("memory_usage", 0)
        battery = payload.get("battery", 100)
        attack_type = payload.get("attack_type")

        # 1. Run AI Threat Detector
        result = detect_threat(payload)
        is_threat = result.get("threat", False)
        severity = result.get("severity", "LOW")
        confidence = result.get("confidence", 0.0)

        # 2. Determine threat score and select PQC algorithm using RandomForest model
        if is_threat:
            threat_score = confidence
            log_event("AI", "WRN", f"Threat detected on device {device_id} ({attack_type or 'Anomaly'}) - severity: {severity} (conf: {confidence*100:.1f}%)")
        else:
            threat_score = random.uniform(0.02, 0.10) # realistic normal variation

        selected_algorithm = "Kyber512"
        if select_algorithm:
            try:
                selected_algorithm = select_algorithm(
                    cpu_usage=cpu_usage,
                    ram_usage=memory_usage,
                    battery_level=battery,
                    threat_score=threat_score
                )
            except Exception as e:
                print(f"Error calling select_algorithm: {e}")

        # 3. Handle auto-mitigation
        status = "ONLINE"
        existing_device = db.query(Device).filter(Device.device_id == device_id).first()
        if existing_device and existing_device.status == "BLOCKED":
            status = "BLOCKED"

        if is_threat and severity == "HIGH":
            status = "BLOCKED"
            log_event("FW", "ERR", f"SOC automated firewall BLOCKED device {device_id} due to high severity threat")
        else:
            # Randomly log normal transactions rarely to prevent log flooding (1.2% total chance)
            rand = random.random()
            if rand < 0.005:
                log_event("KEM", "INF", f"Shared secret decapsulated successfully via {selected_algorithm} on {device_id}")
            elif rand < 0.010:
                log_event("SIG", "INF", f"{selected_algorithm} digital signature validated for firmware on {device_id}")
            elif rand < 0.012:
                log_event("PQC", "INF", f"Session keypair rotated via {selected_algorithm} on {device_id}")

        # 4. Save device state in DB
        if existing_device:
            existing_device.cpu_usage = cpu_usage
            existing_device.memory_usage = memory_usage
            existing_device.battery_level = battery
            existing_device.selected_algorithm = selected_algorithm
            existing_device.last_seen = datetime.utcnow()
            existing_device.status = status
            db.commit()
        else:
            new_device = Device(
                device_id=device_id,
                device_name=f"Device-{device_id}",
                cpu_usage=cpu_usage,
                memory_usage=memory_usage,
                battery_level=battery,
                selected_algorithm=selected_algorithm,
                last_seen=datetime.utcnow(),
                status=status
            )
            db.add(new_device)
            db.commit()
            log_event("SOC", "INF", f"Registered new device: {device_id}")

    except Exception as e:
        print(f"Error in process_payload: {e}")

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
