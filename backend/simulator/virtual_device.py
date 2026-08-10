import os
import sys
import json
import time
import random
import uuid
import urllib.request
import paho.mqtt.client as mqtt

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pqc.pqc_oqs import PQCManager
from pqc.pqc_secure_channel import encrypt_and_sign_payload, get_bridge_public_key

DEVICE_ID = f"sec_standalone_{uuid.uuid4().hex[:6]}"
MQTT_BROKER = "localhost"
MQTT_PORT = 1883
TOPIC = "iot/data"
API_URL = "http://127.0.0.1:8000"

print(f"Initializing Secure Standalone Device: {DEVICE_ID}")

# 1. Generate local signature keys for this device
pqc = PQCManager()
sig_keys = {}
for sig in ["ML-DSA-44", "FN-DSA-512"]:
    sig_keys[sig] = pqc.generate_keypair(sig)

# 2. Register the device via the secure admin API using X-API-Key
try:
    register_url = f"{API_URL}/devices/register?device_id={DEVICE_ID}&device_name=Secure+Standalone+Device"
    req = urllib.request.Request(
        register_url,
        method="POST",
        headers={
            "X-API-Key": "quantumshield-secret-api-key",
            "User-Agent": "Mozilla/5.0"
        }
    )
    with urllib.request.urlopen(req, timeout=5) as response:
        res = json.loads(response.read().decode())
        print(f"Device registration response: {res.get('message')}")
except Exception as e:
    print(f"FastAPI Server is not running or registration failed: {e}")
    print("Will attempt to publish directly (ensure device public key is registered in DB).")

# 3. Connect to MQTT Broker
client = mqtt.Client()
try:
    client.connect(MQTT_BROKER, MQTT_PORT, 60)
    print(f"Connected to MQTT Broker at {MQTT_BROKER}:{MQTT_PORT}")
except Exception as e:
    print(f"MQTT Connection Error: {e}")
    exit(1)

def generate_telemetry():
    return {
        "device_id": DEVICE_ID,
        "temperature": round(random.uniform(22.0, 26.0), 2),
        "humidity": round(random.uniform(50.0, 60.0), 2),
        "battery": round(random.uniform(90.0, 100.0), 2),
        "cpu_usage": round(random.uniform(5.0, 15.0), 2),
        "memory_usage": round(random.uniform(128.0, 256.0), 2),
        "requests_per_minute": round(random.uniform(5.0, 15.0), 2),
        "sequence": 1,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }

# Session key state
session_key = None
session_ciphertext = None
packets_sent = 0
sequence = 1

print("Starting Secure Telemetry Publication loop...")
try:
    while True:
        payload = generate_telemetry()
        payload["sequence"] = sequence
        
        # Select current active algorithms
        kem_algo = "ML-KEM-512"
        sig_algo = "ML-DSA-44"
        sig_priv_key = sig_keys[sig_algo]["private_key"]
        
        # Negotiate/Rekey symmetric session keys every 20 packets
        if session_key is None or packets_sent >= 20:
            print("Negotiating new symmetric session key...")
            secured, key = encrypt_and_sign_payload(
                device_id=DEVICE_ID,
                payload_dict=payload,
                kem_algo=kem_algo,
                sig_algo=sig_algo,
                device_sig_private_key_hex=sig_priv_key
            )
            session_key = key
            session_ciphertext = secured["kem_ciphertext"]
            packets_sent = 1
        else:
            secured, _ = encrypt_and_sign_payload(
                device_id=DEVICE_ID,
                payload_dict=payload,
                kem_algo=kem_algo,
                sig_algo=sig_algo,
                device_sig_private_key_hex=sig_priv_key,
                session_key=session_key,
                session_kem_ciphertext_hex=session_ciphertext
            )
            packets_sent += 1
            
        client.publish(TOPIC, json.dumps(secured))
        print(f"Published secure packet #{sequence} over PQC Secure Channel.")
        
        sequence += 1
        time.sleep(10)
except KeyboardInterrupt:
    print("Secure Standalone Device terminated.")