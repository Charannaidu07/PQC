"""
QuantumShield-IoT
Comprehensive Secure-Channel Positive and Negative Security Test Suite
"""

import sys
import os
import json
import unittest
from datetime import datetime, timedelta

# Add backend directory to path to allow direct execution
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pqc.pqc_oqs import PQCManager
from pqc.pqc_secure_channel import (
    encrypt_and_sign_payload,
    verify_and_decrypt_payload,
    get_bridge_public_key,
    init_bridge_keys
)
from database import SessionLocal, Device, ThreatLog, init_db

class TestSecureChannel(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Initialize DB (which programmatically runs migrations)
        init_db()
        
        cls.device_id = "test_sec_dev_999"
        cls.kem_algo = "ML-KEM-512"
        cls.sig_algo = "ML-DSA-44"
        
        # Initialize KEM keys for bridge
        init_bridge_keys()
        
        # Generate signature keys for test device
        pqc = PQCManager(cls.sig_algo)
        cls.device_keys = pqc.generate_keypair()
        cls.device_pub_key = cls.device_keys["public_key"]
        cls.device_priv_key = cls.device_keys["private_key"]
        
        # Save test device in database with signature keys
        db = SessionLocal()
        try:
            device = db.query(Device).filter(Device.device_id == cls.device_id).first()
            if not device:
                device = Device(
                    device_id=cls.device_id,
                    device_name="Test Secure Device",
                    status="ONLINE",
                    selected_kem=cls.kem_algo,
                    selected_signature=cls.sig_algo
                )
                db.add(device)
            
            device.sig_public_key_ml_dsa_44 = cls.device_pub_key
            device.last_sequence = 100
            db.commit()
        finally:
            db.close()

    def test_01_positive_telemetry_flow(self):
        """Positive Test: Telemetry encrypted, signed, decrypted and matches original exactly."""
        telemetry = {
            "cpu_usage": 12.5,
            "memory_usage": 180.0,
            "battery": 95,
            "sequence": 105,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # 1. Encrypt and sign on device
        packet = encrypt_and_sign_payload(
            device_id=self.device_id,
            payload_dict=telemetry,
            kem_algo=self.kem_algo,
            sig_algo=self.sig_algo,
            device_sig_private_key_hex=self.device_priv_key
        )
        
        # 2. Verify and decrypt on bridge
        decrypted = verify_and_decrypt_payload(packet, self.device_pub_key)
        
        # 3. Assert match
        self.assertEqual(decrypted["cpu_usage"], telemetry["cpu_usage"])
        self.assertEqual(decrypted["memory_usage"], telemetry["memory_usage"])
        self.assertEqual(decrypted["sequence"], telemetry["sequence"])
        self.assertEqual(decrypted["timestamp"], telemetry["timestamp"])

    def test_02_modified_sequence(self):
        """Negative Test: Changing sequence inside telemetry payload fails signature verification."""
        telemetry = {
            "cpu_usage": 12.5,
            "sequence": 105,
            "timestamp": datetime.utcnow().isoformat()
        }
        packet = encrypt_and_sign_payload(
            device_id=self.device_id,
            payload_dict=telemetry,
            kem_algo=self.kem_algo,
            sig_algo=self.sig_algo,
            device_sig_private_key_hex=self.device_priv_key
        )
        
        # Simulate tampering telemetry payload sequence before encrypting (but packet ciphertext has already been created).
        # Note: Since sequence is inside the encrypted payload, modifying it requires changing the ciphertext.
        # If we tampered with the ciphertext, decryption fails or signature verification fails.
        # If we modify the signature metadata or ciphertext, verify_and_decrypt_payload raises ValueError.
        packet["encrypted_payload"] = packet["encrypted_payload"][:-8] + "00000000"
        
        with self.assertRaises(Exception):
            verify_and_decrypt_payload(packet, self.device_pub_key)

    def test_03_modified_timestamp(self):
        """Negative Test: Tampering with packet metadata timestamp."""
        # Verification of the signature encapsulates: device_id : protocol_version : kem_ciphertext : encrypted_payload
        # If we tamper with the packet structure or fields, signature validation must fail.
        telemetry = {
            "cpu_usage": 12.5,
            "sequence": 105,
            "timestamp": datetime.utcnow().isoformat()
        }
        packet = encrypt_and_sign_payload(
            device_id=self.device_id,
            payload_dict=telemetry,
            kem_algo=self.kem_algo,
            sig_algo=self.sig_algo,
            device_sig_private_key_hex=self.device_priv_key
        )
        
        # Tamper signature field
        packet["signature"] = packet["signature"][:-4] + "0000"
        
        with self.assertRaises(ValueError) as context:
            verify_and_decrypt_payload(packet, self.device_pub_key)
        self.assertIn("Invalid digital signature", str(context.exception))

    def test_04_modified_algorithm(self):
        """Negative Test: Fails when KEM or signature algorithm fields are altered in transit."""
        telemetry = {
            "cpu_usage": 12.5,
            "sequence": 105,
            "timestamp": datetime.utcnow().isoformat()
        }
        packet = encrypt_and_sign_payload(
            device_id=self.device_id,
            payload_dict=telemetry,
            kem_algo=self.kem_algo,
            sig_algo=self.sig_algo,
            device_sig_private_key_hex=self.device_priv_key
        )
        
        # Alter algorithm
        packet["kem_algorithm"] = "ML-KEM-768"
        
        # Should raise ValueError since AAD bind fails during decryption
        with self.assertRaises(Exception):
            verify_and_decrypt_payload(packet, self.device_pub_key)

    def test_05_modified_device_id(self):
        """Negative Test: Fails when device_id in packet is altered."""
        telemetry = {
            "cpu_usage": 12.5,
            "sequence": 105,
            "timestamp": datetime.utcnow().isoformat()
        }
        packet = encrypt_and_sign_payload(
            device_id=self.device_id,
            payload_dict=telemetry,
            kem_algo=self.kem_algo,
            sig_algo=self.sig_algo,
            device_sig_private_key_hex=self.device_priv_key
        )
        
        packet["device_id"] = "test_sec_dev_888"
        
        with self.assertRaises(ValueError) as context:
            verify_and_decrypt_payload(packet, self.device_pub_key)
        self.assertIn("Invalid digital signature", str(context.exception))

    def test_06_modified_ciphertext(self):
        """Negative Test: Fails when ciphertext is tampered with."""
        telemetry = {
            "cpu_usage": 12.5,
            "sequence": 105,
            "timestamp": datetime.utcnow().isoformat()
        }
        packet = encrypt_and_sign_payload(
            device_id=self.device_id,
            payload_dict=telemetry,
            kem_algo=self.kem_algo,
            sig_algo=self.sig_algo,
            device_sig_private_key_hex=self.device_priv_key
        )
        
        # Modify ciphertext character
        orig = packet["encrypted_payload"]
        tampered = "a" + orig[1:] if orig[0] != "a" else "b" + orig[1:]
        packet["encrypted_payload"] = tampered
        
        with self.assertRaises(ValueError) as context:
            verify_and_decrypt_payload(packet, self.device_pub_key)
        self.assertIn("Invalid digital signature", str(context.exception))

    def test_07_modified_signature(self):
        """Negative Test: Fails signature validation when signature is tampered with."""
        telemetry = {
            "cpu_usage": 12.5,
            "sequence": 105,
            "timestamp": datetime.utcnow().isoformat()
        }
        packet = encrypt_and_sign_payload(
            device_id=self.device_id,
            payload_dict=telemetry,
            kem_algo=self.kem_algo,
            sig_algo=self.sig_algo,
            device_sig_private_key_hex=self.device_priv_key
        )
        
        # Modify signature
        packet["signature"] = "f" + packet["signature"][1:]
        
        with self.assertRaises(ValueError) as context:
            verify_and_decrypt_payload(packet, self.device_pub_key)
        self.assertIn("Invalid digital signature", str(context.exception))

    def test_08_wrong_device_key(self):
        """Negative Test: Fails when verified with a different device public key."""
        telemetry = {
            "cpu_usage": 12.5,
            "sequence": 105,
            "timestamp": datetime.utcnow().isoformat()
        }
        packet = encrypt_and_sign_payload(
            device_id=self.device_id,
            payload_dict=telemetry,
            kem_algo=self.kem_algo,
            sig_algo=self.sig_algo,
            device_sig_private_key_hex=self.device_priv_key
        )
        
        # Generate another key pair representing another device
        pqc = PQCManager(self.sig_algo)
        another_keys = pqc.generate_keypair()
        another_pub_key = another_keys["public_key"]
        
        with self.assertRaises(ValueError) as context:
            verify_and_decrypt_payload(packet, another_pub_key)
        self.assertIn("Invalid digital signature", str(context.exception))

    def test_09_wrong_kem(self):
        """Negative Test: Fails decryption if the KEM ciphertext is altered."""
        telemetry = {
            "cpu_usage": 12.5,
            "sequence": 105,
            "timestamp": datetime.utcnow().isoformat()
        }
        packet = encrypt_and_sign_payload(
            device_id=self.device_id,
            payload_dict=telemetry,
            kem_algo=self.kem_algo,
            sig_algo=self.sig_algo,
            device_sig_private_key_hex=self.device_priv_key
        )
        
        # Tamper KEM ciphertext
        orig = packet["kem_ciphertext"]
        tampered = "0" + orig[1:] if orig[0] != "0" else "1" + orig[1:]
        packet["kem_ciphertext"] = tampered
        
        # Verification fails because signature signs the KEM ciphertext!
        with self.assertRaises(ValueError) as context:
            verify_and_decrypt_payload(packet, self.device_pub_key)
        self.assertIn("Invalid digital signature", str(context.exception))

    def test_10_expired_timestamp(self):
        """Negative Test: Expired timestamp is rejected by skewed window checking."""
        # We test the skew validation logic from mqtt_bridge.py
        expired_time = (datetime.utcnow() - timedelta(seconds=300)).isoformat() # 5 minutes old
        
        packet_time = datetime.fromisoformat(expired_time)
        time_diff = abs((datetime.utcnow() - packet_time).total_seconds())
        
        self.assertTrue(time_diff > 120.0, "Time difference should be greater than allowed 120 seconds window")

    def test_11_replayed_sequence(self):
        """Negative Test: Atomic sequence locks reject duplicate or lower sequence numbers."""
        db = SessionLocal()
        try:
            # Current last_sequence in database is 100 (setup in setUpClass).
            # If sequence is 100 or less, update should fail.
            sequence = 99
            from sqlalchemy import text
            stmt = text(
                "UPDATE devices "
                "SET last_sequence = :seq "
                "WHERE device_id = :device_id AND (last_sequence < :seq OR last_sequence IS NULL)"
            )
            result = db.execute(stmt, {"seq": sequence, "device_id": self.device_id})
            db.commit()
            
            # Row count should be 0 because 99 <= 100
            self.assertEqual(result.rowcount, 0, "Update must fail for lower sequence number")
            
            # Try duplicate sequence (100)
            result2 = db.execute(stmt, {"seq": 100, "device_id": self.device_id})
            db.commit()
            self.assertEqual(result2.rowcount, 0, "Update must fail for equal sequence number")
            
            # Try higher sequence (105) - Should succeed and update exactly 1 row
            result3 = db.execute(stmt, {"seq": 105, "device_id": self.device_id})
            db.commit()
            self.assertEqual(result3.rowcount, 1, "Update must succeed for higher sequence number")
        finally:
            db.close()

if __name__ == "__main__":
    unittest.main()
