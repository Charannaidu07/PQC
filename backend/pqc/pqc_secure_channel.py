"""
QuantumShield-IoT
PQC Secure Channel Layer (KEM + Authenticated Symmetric Encryption + Digital Signatures)
"""

import os
import json
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pqc.pqc_oqs import PQCManager

# Path to Bridge long-term KEM keys
BRIDGE_KEYS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bridge_keys.json")

def init_bridge_keys():
    """
    Generates Bridge KEM keypairs for ML-KEM-512 and ML-KEM-768 and stores them in a local JSON
    file if they do not exist. Reads existing keypairs if they are present.
    """
    if os.path.exists(BRIDGE_KEYS_FILE):
        try:
            with open(BRIDGE_KEYS_FILE, "r") as f:
                keys = json.load(f)
                if "ML-KEM-512" in keys and "ML-KEM-768" in keys:
                    return keys
        except Exception as e:
            print(f"Error reading bridge keys file, generating new keys: {e}")
            
    print("Generating new Bridge KEM keypairs...")
    pqc = PQCManager()
    keys = {}
    for kem in ["ML-KEM-512", "ML-KEM-768"]:
        try:
            keypair = pqc.generate_keypair(kem)
            keys[kem] = {
                "public_key": keypair["public_key"],
                "private_key": keypair["private_key"]
            }
        except Exception as e:
            print(f"Failed to generate keypair for {kem}: {e}")
            
    # Write to file
    try:
        with open(BRIDGE_KEYS_FILE, "w") as f:
            json.dump(keys, f, indent=4)
        print(f"Bridge KEM keypairs successfully saved to {BRIDGE_KEYS_FILE}")
    except Exception as e:
        print(f"Failed to save bridge keys: {e}")
        
    return keys

# Initialize Bridge Keys in memory
BRIDGE_KEYS = init_bridge_keys()

def get_bridge_public_key(kem_algorithm: str) -> str:
    """Returns the Bridge's public KEM key for a given algorithm."""
    return BRIDGE_KEYS.get(kem_algorithm, {}).get("public_key")

def encrypt_and_sign_payload(
    device_id: str,
    payload_dict: dict,
    kem_algo: str,
    sig_algo: str,
    device_sig_private_key_hex: str
) -> dict:
    """
    Secures a telemetry payload:
    1. Encapsulates a shared secret using the Bridge KEM public key.
    2. Derives a 256-bit symmetric key from the shared secret.
    3. Encrypts the payload JSON using AES-GCM.
    4. Signs the payload and metadata using the Device signature private key.
    
    Runs on the simulated device.
    """
    bridge_pub_key = get_bridge_public_key(kem_algo)
    if not bridge_pub_key:
        # If Bridge keys weren't initialized properly, force reload
        global BRIDGE_KEYS
        BRIDGE_KEYS = init_bridge_keys()
        bridge_pub_key = get_bridge_public_key(kem_algo)
        if not bridge_pub_key:
            raise ValueError(f"Bridge public key not found for KEM algorithm: {kem_algo}")

    # 1. Encapsulate shared secret
    pqc_kem = PQCManager(kem_algo)
    kem_ciphertext_hex, shared_secret_hex = pqc_kem.encapsulate(bridge_pub_key)

    # 2. Derive key from shared secret (SHA-256)
    symmetric_key = hashlib.sha256(bytes.fromhex(shared_secret_hex)).digest()

    # 3. Encrypt with AES-GCM
    payload_str = json.dumps(payload_dict)
    aesgcm = AESGCM(symmetric_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, payload_str.encode(), None)
    encrypted_payload_hex = (nonce + ciphertext).hex()

    # 4. Sign the payload package (device_id : kem_ciphertext : encrypted_payload)
    message_to_sign = f"{device_id}:{kem_ciphertext_hex}:{encrypted_payload_hex}"
    pqc_sig = PQCManager(sig_algo)
    signature_hex = pqc_sig.sign(message_to_sign, device_sig_private_key_hex)

    return {
        "device_id": device_id,
        "encrypted_payload": encrypted_payload_hex,
        "kem_ciphertext": kem_ciphertext_hex,
        "kem_algorithm": kem_algo,
        "signature": signature_hex,
        "signature_algorithm": sig_algo
    }

def verify_and_decrypt_payload(
    msg_dict: dict,
    device_sig_public_key_hex: str
) -> dict:
    """
    Verifies signature and decrypts a telemetry payload:
    1. Verifies the signature over the encrypted payload block.
    2. Decapsulates the KEM ciphertext using the Bridge KEM private key.
    3. Decrypts the telemetry payload using AES-GCM and the derived symmetric key.
    
    Runs on the MQTT Bridge / Gateway.
    """
    device_id = msg_dict["device_id"]
    encrypted_payload_hex = msg_dict["encrypted_payload"]
    kem_ciphertext_hex = msg_dict["kem_ciphertext"]
    kem_algo = msg_dict["kem_algorithm"]
    signature_hex = msg_dict["signature"]
    sig_algo = msg_dict["signature_algorithm"]

    # 1. Verify digital signature
    message_to_sign = f"{device_id}:{kem_ciphertext_hex}:{encrypted_payload_hex}"
    pqc_sig = PQCManager(sig_algo)
    is_valid = pqc_sig.verify(message_to_sign, signature_hex, device_sig_public_key_hex)
    if not is_valid:
        raise ValueError("Invalid digital signature! Packet authentication failed.")

    # 2. Decapsulate shared secret
    bridge_private_key = BRIDGE_KEYS.get(kem_algo, {}).get("private_key")
    if not bridge_private_key:
        raise ValueError(f"Bridge private key not found in server keychain for KEM algorithm: {kem_algo}")
        
    pqc_kem = PQCManager(kem_algo)
    shared_secret_hex = pqc_kem.decapsulate(kem_ciphertext_hex, bridge_private_key)

    # 3. Derive key and decrypt payload
    symmetric_key = hashlib.sha256(bytes.fromhex(shared_secret_hex)).digest()
    aesgcm = AESGCM(symmetric_key)
    
    encrypted_bytes = bytes.fromhex(encrypted_payload_hex)
    nonce = encrypted_bytes[:12]
    ciphertext = encrypted_bytes[12:]
    
    decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)
    return json.loads(decrypted_bytes.decode())
