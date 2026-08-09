"""
QuantumShield-IoT
PQC Secure Channel Layer (KEM + Authenticated Symmetric Encryption + Digital Signatures)
"""

import os
import json
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from pqc.pqc_oqs import PQCManager

# Path to Bridge long-term KEM keys
BRIDGE_KEYS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bridge_keys.json")

# Global Decrypted Sessions Cache for performance optimization (ML-KEM session key caching)
DECRYPTED_SESSIONS_CACHE = {}

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
            
    # Write to file with OS-protected owner-only file permissions (0o600)
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        # Open file descriptor with restricted read/write permissions
        fd = os.open(BRIDGE_KEYS_FILE, flags, 0o600)
        with open(fd, "w") as f:
            json.dump(keys, f, indent=4)
        try:
            os.chmod(BRIDGE_KEYS_FILE, 0o600)
        except Exception:
            pass
        print(f"Bridge KEM keypairs successfully saved to {BRIDGE_KEYS_FILE} with owner-only access permissions.")
    except Exception as e:
        print(f"Failed to save bridge keys: {e}")
        
    return keys

# Initialize Bridge Keys in memory
BRIDGE_KEYS = init_bridge_keys()

def get_bridge_public_key(kem_algorithm: str) -> str:
    """Returns the Bridge's public KEM key for a given algorithm."""
    return BRIDGE_KEYS.get(kem_algorithm, {}).get("public_key")

def derive_session_key(shared_secret_hex: str, device_id: str, kem_algo: str) -> bytes:
    """
    Derives a 256-bit symmetric AES key from the KEM shared secret using HKDF-SHA-256
    with explicit domain separation context.
    """
    shared_secret_bytes = bytes.fromhex(shared_secret_hex)
    
    # Context info for domain separation
    info = f"QuantumShield-IoT:{device_id}:{kem_algo}:v1".encode("utf-8")
    
    # Use a static salt representing the QuantumShield domain
    salt = b"QuantumShield-IoT-Salt-v1"
    
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info
    )
    return hkdf.derive(shared_secret_bytes)

def encrypt_and_sign_payload(
    device_id: str,
    payload_dict: dict,
    kem_algo: str,
    sig_algo: str,
    device_sig_private_key_hex: str,
    session_key: bytes = None,
    session_kem_ciphertext_hex: str = None
) -> dict:
    """
    Secures a telemetry payload:
    1. Reuses or encapsulates a shared secret using the Bridge KEM public key.
    2. Derives a 256-bit symmetric key from the shared secret using HKDF.
    3. Encrypts the payload JSON using AES-GCM.
    4. Signs the payload and metadata using the Device signature private key.
    
    Runs on the simulated device.
    """
    if session_key is not None and session_kem_ciphertext_hex is not None:
        symmetric_key = session_key
        kem_ciphertext_hex = session_kem_ciphertext_hex
    else:
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

        # 2. Derive key from shared secret using HKDF
        symmetric_key = derive_session_key(shared_secret_hex, device_id, kem_algo)

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
        "signature_algorithm": sig_algo,
        "session_key": symmetric_key.hex()
    }

def verify_and_decrypt_payload(
    msg_dict: dict,
    device_sig_public_key_hex: str
) -> dict:
    """
    Verifies signature and decrypts a telemetry payload:
    1. Verifies the signature over the encrypted payload block.
    2. Decapsulates the KEM ciphertext using the Bridge KEM private key (utilizing session cache).
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

    # 2. Re-use or decapsulate session key
    if kem_ciphertext_hex in DECRYPTED_SESSIONS_CACHE:
        symmetric_key = DECRYPTED_SESSIONS_CACHE[kem_ciphertext_hex]
    else:
        bridge_private_key = BRIDGE_KEYS.get(kem_algo, {}).get("private_key")
        if not bridge_private_key:
            raise ValueError(f"Bridge private key not found in server keychain for KEM algorithm: {kem_algo}")
            
        pqc_kem = PQCManager(kem_algo)
        shared_secret_hex = pqc_kem.decapsulate(kem_ciphertext_hex, bridge_private_key)

        # Derive session key using HKDF
        symmetric_key = derive_session_key(shared_secret_hex, device_id, kem_algo)
        
        # Cache the session key to bypass future decapsulations
        DECRYPTED_SESSIONS_CACHE[kem_ciphertext_hex] = symmetric_key

    # 3. Decrypt payload
    aesgcm = AESGCM(symmetric_key)
    encrypted_bytes = bytes.fromhex(encrypted_payload_hex)
    nonce = encrypted_bytes[:12]
    ciphertext = encrypted_bytes[12:]
    
    decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)
    return json.loads(decrypted_bytes.decode())
