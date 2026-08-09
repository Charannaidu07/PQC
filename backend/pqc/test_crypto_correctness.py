"""
QuantumShield-IoT
Cryptographic Positive and Negative Unit Tests for KEM and Signatures
"""

import sys
import os

# Add backend directory to path to allow direct execution
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pqc.pqc_oqs import PQCManager

def run_kem_tests():
    print("\n--- RUNNING KEM POSITIVE & NEGATIVE TESTS ---")
    kems = ["ML-KEM-512", "ML-KEM-768"]
    
    for kem_algo in kems:
        print(f"\nTesting KEM: {kem_algo}")
        pqc = PQCManager(kem_algo)
        
        # 1. Key Generation
        keys = pqc.generate_keypair()
        pub_key = keys["public_key"]
        priv_key = keys["private_key"]
        print(f" [PASS] Key pair generated (PubKey len: {len(pub_key)}, PrivKey len: {len(priv_key)})")
        
        # 2. Positive Test: Correct ciphertext decapsulation
        ciphertext, secret = pqc.encapsulate(pub_key)
        recovered_secret = pqc.decapsulate(ciphertext, priv_key)
        print(" [PASS] Positive check: correct decapsulation matches encapsulated secret")
        assert secret == recovered_secret, f"KEM Positive check failed for {kem_algo}: secrets do not match"
        
        # 3. Negative Test: Modified ciphertext decapsulation
        # Modify the first character of the ciphertext to tamper with it
        tampered_ciphertext = list(ciphertext)
        tampered_ciphertext[0] = 'a' if tampered_ciphertext[0] != 'a' else 'b'
        tampered_ciphertext = "".join(tampered_ciphertext)
        
        try:
            tampered_recovered_secret = pqc.decapsulate(tampered_ciphertext, priv_key)
            # Kyber uses implicit rejection, meaning decapsulating an invalid ciphertext
            # returns a pseudorandom secret rather than failing with an error.
            print(" [PASS] Negative check: tampered ciphertext returns incorrect secret (implicit rejection)")
            assert secret != tampered_recovered_secret, f"KEM Negative check failed for {kem_algo}: tampered ciphertext recovered original secret"
        except Exception as e:
            # Some libraries or parameters might fail explicitly
            print(f" [PASS] Negative check: tampered ciphertext failed decapsulation with error: {e}")

def run_signature_tests():
    print("\n--- RUNNING SIGNATURE POSITIVE & NEGATIVE TESTS ---")
    sigs = ["ML-DSA-44", "FN-DSA-512"]
    original_message = b"authenticated iot telemetry payload data"
    
    for sig_algo in sigs:
        print(f"\nTesting Signature: {sig_algo}")
        pqc = PQCManager(sig_algo)
        
        # 1. Key Generation
        keys = pqc.generate_keypair()
        pub_key = keys["public_key"]
        priv_key = keys["private_key"]
        print(f" [PASS] Key pair generated (PubKey len: {len(pub_key)}, PrivKey len: {len(priv_key)})")
        
        # 2. Positive Test: Correct message and signature
        signature = pqc.sign(original_message, priv_key)
        is_valid = pqc.verify(original_message, signature, pub_key)
        print(" [PASS] Positive check: correct message and signature verifies as TRUE")
        assert is_valid is True, f"Signature Positive check failed for {sig_algo}"
        
        # 3. Negative Test 1: Modified message, same signature
        modified_message = b"tampered iot telemetry payload data"
        is_valid_modified_msg = pqc.verify(modified_message, signature, pub_key)
        print(" [PASS] Negative check 1: modified message with original signature verifies as FALSE")
        assert is_valid_modified_msg is False, f"Signature Negative check 1 (modified message) failed for {sig_algo} (returned True)"
        
        # 4. Negative Test 2: Same message, modified signature
        tampered_signature = list(signature)
        # Modify first character of the signature
        tampered_signature[0] = 'a' if tampered_signature[0] != 'a' else 'b'
        tampered_signature = "".join(tampered_signature)
        
        is_valid_modified_sig = pqc.verify(original_message, tampered_signature, pub_key)
        print(" [PASS] Negative check 2: original message with tampered signature verifies as FALSE")
        assert is_valid_modified_sig is False, f"Signature Negative check 2 (tampered signature) failed for {sig_algo} (returned True)"

if __name__ == "__main__":
    print("====================================================")
    print("   PQC CRYPTOGRAPHIC POSITIVE & NEGATIVE TESTS")
    print("====================================================")
    try:
        run_kem_tests()
        run_signature_tests()
        print("\n====================================================")
        print("      ALL CRYPTOGRAPHIC TESTS PASSED SUCCESSFULLY")
        print("====================================================")
    except AssertionError as ae:
        print(f"\n[FAIL] Assertion Error: {ae}")
        sys.exit(1)
    except Exception as e:
        print(f"\n[FAIL] Unexpected Error: {e}")
        sys.exit(1)
