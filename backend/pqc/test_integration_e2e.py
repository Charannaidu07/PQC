import sys
import os
import unittest
from datetime import datetime, timedelta

# Add backend dir to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database import SessionLocal, Device, ThreatLog, init_db
from pqc.pqc_secure_channel import (
    encrypt_and_sign_payload,
    verify_and_decrypt_payload,
    init_bridge_keys,
    DECRYPTED_SESSIONS_CACHE
)
from ai.threat_detector import detect_threat
from simulator.device_manager import get_simulator_device_keys

class TestE2EIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # 1. Initialize DB and Ephemeral KEM Keys
        init_db()
        init_bridge_keys(force_generate=True)
        
    def setUp(self):
        self.db = SessionLocal()
        self.device_id = "test_e2e_device_99"
        
        # Ensure clean state in DB
        self.db.query(ThreatLog).filter(ThreatLog.device_id == self.device_id).delete()
        self.db.query(Device).filter(Device.device_id == self.device_id).delete()
        self.db.commit()
        
        # Load simulator signature keys persistently
        self.sig_keys = get_simulator_device_keys(self.device_id)
        self.pub_key_ml_dsa = self.sig_keys["ML-DSA-44"]["public_key"]
        self.pub_key_fn_dsa = self.sig_keys["FN-DSA-512"]["public_key"]
        
        # Insert device record into DB (without overwriting if already registered)
        self.device = Device(
            device_id=self.device_id,
            device_name="E2E Test Device",
            status="ONLINE",
            selected_kem="ML-KEM-512",
            selected_signature="ML-DSA-44",
            sig_public_key_ml_dsa_44=self.pub_key_ml_dsa,
            sig_public_key_fn_dsa_512=self.pub_key_fn_dsa,
            last_sequence=10,
            last_seen=datetime.utcnow()
        )
        self.db.add(self.device)
        self.db.commit()
        self.db.refresh(self.device)
        
        DECRYPTED_SESSIONS_CACHE.clear()

    def tearDown(self):
        self.db.query(ThreatLog).filter(ThreatLog.device_id == self.device_id).delete()
        self.db.query(Device).filter(Device.device_id == self.device_id).delete()
        self.db.commit()
        self.db.close()

    def test_e2e_secure_telemetry_flow(self):
        # 1. Generate a valid normal telemetry payload
        telemetry = {
            "device_id": self.device_id,
            "temperature": 22.4,
            "humidity": 54.2,
            "cpu_usage": 12.5,
            "memory_usage": 142.3,
            "requests_per_minute": 10.0,
            "sequence": 11,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # 2. Encrypt & Sign payload (Device Side)
        kem_algo = "ML-KEM-512"
        sig_algo = "ML-DSA-44"
        sig_priv_key = self.sig_keys[sig_algo]["private_key"]
        
        secured_packet, session_key = encrypt_and_sign_payload(
            device_id=self.device_id,
            payload_dict=telemetry,
            kem_algo=kem_algo,
            sig_algo=sig_algo,
            device_sig_private_key_hex=sig_priv_key
        )
        
        # Ensure session key is NOT in the public packet
        self.assertNotIn("session_key", secured_packet)
        self.assertIn("encrypted_payload", secured_packet)
        self.assertIn("signature", secured_packet)
        self.assertEqual(secured_packet["protocol_version"], "1.0")

        # 3. Decrypt & Verify (Bridge Side)
        decrypted_payload = verify_and_decrypt_payload(secured_packet, self.pub_key_ml_dsa)
        self.assertEqual(decrypted_payload["device_id"], self.device_id)
        self.assertEqual(decrypted_payload["temperature"], 22.4)
        
        # 4. Threat Detection Validation
        threat_result = detect_threat(decrypted_payload, db=self.db)
        self.assertFalse(threat_result["threat"]) # Normal payload should have no threat

    def test_e2e_replay_attack_rejected(self):
        # 1. Generate packet with stale/replayed sequence number (10 <= 10)
        telemetry = {
            "device_id": self.device_id,
            "temperature": 22.4,
            "humidity": 54.2,
            "cpu_usage": 12.5,
            "memory_usage": 142.3,
            "requests_per_minute": 10.0,
            "sequence": 10,  # Stale sequence
            "timestamp": datetime.utcnow().isoformat()
        }
        
        kem_algo = "ML-KEM-512"
        sig_algo = "ML-DSA-44"
        sig_priv_key = self.sig_keys[sig_algo]["private_key"]
        
        secured_packet, _ = encrypt_and_sign_payload(
            device_id=self.device_id,
            payload_dict=telemetry,
            kem_algo=kem_algo,
            sig_algo=sig_algo,
            device_sig_private_key_hex=sig_priv_key
        )
        
        # 2. Feeding into the bridge's MQTT bridge simulation path
        # Simulate processing the payload
        from mqtt_bridge import process_payload
        process_payload(secured_packet)
        
        # Assert a ThreatLog was created for replay attack
        threats = self.db.query(ThreatLog).filter(ThreatLog.device_id == self.device_id).all()
        self.assertEqual(len(threats), 1)
        self.assertEqual(threats[0].threat_type, "Signature Spoofing") # Replay triggers signature failure/exception

    def test_e2e_expired_timestamp_rejected(self):
        # 1. Generate packet with expired timestamp (5 minutes old)
        expired_time = (datetime.utcnow() - timedelta(seconds=300)).isoformat()
        telemetry = {
            "device_id": self.device_id,
            "temperature": 22.4,
            "humidity": 54.2,
            "cpu_usage": 12.5,
            "memory_usage": 142.3,
            "requests_per_minute": 10.0,
            "sequence": 15,
            "timestamp": expired_time
        }
        
        kem_algo = "ML-KEM-512"
        sig_algo = "ML-DSA-44"
        sig_priv_key = self.sig_keys[sig_algo]["private_key"]
        
        secured_packet, _ = encrypt_and_sign_payload(
            device_id=self.device_id,
            payload_dict=telemetry,
            kem_algo=kem_algo,
            sig_algo=sig_algo,
            device_sig_private_key_hex=sig_priv_key
        )
        
        from mqtt_bridge import process_payload
        process_payload(secured_packet)
        
        # Assert packet was blocked
        threats = self.db.query(ThreatLog).filter(ThreatLog.device_id == self.device_id).all()
        self.assertEqual(len(threats), 1)
        self.assertEqual(threats[0].threat_type, "Signature Spoofing")

if __name__ == "__main__":
    unittest.main()
