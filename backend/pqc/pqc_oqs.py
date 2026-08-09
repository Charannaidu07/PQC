"""
QuantumShield-IoT
PQC Abstraction Layer using real oqs library with fallback resolution
"""

import time
import oqs

OQS_ALGO_MAP = {
    "Kyber512": "ML-KEM-512",
    "Kyber768": "ML-KEM-768",
    "Dilithium2": "ML-DSA-44",
    "Falcon512": "Falcon-512"
}

class PQCManager:

    def __init__(self, algorithm="Kyber512"):
        self.supported_kems = [
            "Kyber512",
            "Kyber768"
        ]
        self.supported_signatures = [
            "Dilithium2",
            "Falcon512"
        ]
        
        all_supported = self.supported_kems + self.supported_signatures
        if algorithm not in all_supported:
            raise ValueError(f"Unsupported PQC algorithm: '{algorithm}'. Supported options: {all_supported}")
            
        self.algorithm = algorithm

    def _resolve_algo(self, algo_name, is_kem=True):
        """
        Dynamically verifies if the requested algorithm (or its standard FIPS name)
        is supported and enabled in the host's OQS library. Falls back to legacy
        aliases if the standard name is not compiled, preventing runtime segfaults.
        """
        target_oqs = OQS_ALGO_MAP.get(algo_name, algo_name)
        
        # Query host compiled capabilities
        if is_kem:
            enabled_mechanisms = oqs.get_enabled_kem_mechanisms()
        else:
            enabled_mechanisms = oqs.get_enabled_sig_mechanisms()
            
        # 1. Match primary standardized/preferred OQS name
        if target_oqs in enabled_mechanisms:
            return target_oqs
            
        # 2. Fall back to alternative names or original project labels
        fallback_options = {
            "ML-KEM-512": ["Kyber512", "Kyber512-AES"],
            "ML-KEM-768": ["Kyber768", "Kyber768-AES"],
            "ML-DSA-44": ["Dilithium2", "Dilithium2-AES"],
            "Falcon-512": ["Falcon512", "Falcon-padded-512"]
        }
        
        candidates = fallback_options.get(target_oqs, [])
        for candidate in candidates:
            if candidate in enabled_mechanisms:
                return candidate
                
        # 3. Check if the input key is directly supported
        if algo_name in enabled_mechanisms:
            return algo_name

        # 4. Fail fast with descriptive error
        enabled_list_str = ", ".join(enabled_mechanisms[:8]) + ("..." if len(enabled_mechanisms) > 8 else "")
        raise ValueError(
            f"Cryptographic algorithm '{algo_name}' (OQS target: '{target_oqs}') is not enabled "
            f"in the host liboqs environment. Enabled options: [{enabled_list_str}]"
        )

    # ----------------------------------
    # KEY GENERATION
    # ----------------------------------

    def generate_keypair(self, algorithm=None):
        if algorithm is not None:
            self.algorithm = algorithm
            
        is_kem = self.algorithm in self.supported_kems
        oqs_algo = self._resolve_algo(self.algorithm, is_kem=is_kem)
        
        if is_kem:
            with oqs.KeyEncapsulation(oqs_algo) as kem:
                public_key = kem.generate_keypair()
                private_key = kem.export_secret_key()
        else:
            with oqs.Signature(oqs_algo) as sig:
                public_key = sig.generate_keypair()
                private_key = sig.export_secret_key()
                
        return {
            "algorithm": self.algorithm,
            "public_key": public_key.hex(),
            "private_key": private_key.hex()
        }

    # ----------------------------------
    # ENCAPSULATION
    # ----------------------------------

    def encapsulate(self, public_key_hex):
        oqs_algo = self._resolve_algo(self.algorithm, is_kem=True)
        public_key_bytes = bytes.fromhex(public_key_hex)
        
        with oqs.KeyEncapsulation(oqs_algo) as kem:
            ciphertext, shared_secret = kem.encap_secret(public_key_bytes)
            
        return ciphertext.hex(), shared_secret.hex()

    # ----------------------------------
    # DECAPSULATION
    # ----------------------------------

    def decapsulate(self, ciphertext_hex, private_key_hex):
        oqs_algo = self._resolve_algo(self.algorithm, is_kem=True)
        ciphertext_bytes = bytes.fromhex(ciphertext_hex)
        private_key_bytes = bytes.fromhex(private_key_hex)
        
        with oqs.KeyEncapsulation(oqs_algo, secret_key=private_key_bytes) as kem:
            shared_secret = kem.decap_secret(ciphertext_bytes)
            
        return shared_secret.hex()

    # ----------------------------------
    # SIGN
    # ----------------------------------

    def sign(self, message, private_key_hex):
        oqs_algo = self._resolve_algo(self.algorithm, is_kem=False)
        private_key_bytes = bytes.fromhex(private_key_hex)
        
        if isinstance(message, str):
            message_bytes = message.encode()
        else:
            message_bytes = message
            
        with oqs.Signature(oqs_algo, secret_key=private_key_bytes) as sig:
            signature = sig.sign(message_bytes)
            
        return signature.hex()

    # ----------------------------------
    # VERIFY
    # ----------------------------------

    def verify(self, message, signature_hex, public_key_hex, algorithm=None):
        if algorithm is not None:
            self.algorithm = algorithm
            
        oqs_algo = self._resolve_algo(self.algorithm, is_kem=False)
        signature_bytes = bytes.fromhex(signature_hex)
        public_key_bytes = bytes.fromhex(public_key_hex)
        
        if isinstance(message, str):
            message_bytes = message.encode()
        else:
            message_bytes = message
            
        with oqs.Signature(oqs_algo) as sig:
            is_valid = sig.verify(message_bytes, signature_bytes, public_key_bytes)
            
        return is_valid


# ======================================
# BENCHMARK
# ======================================

def benchmark_algorithm(algorithm="Kyber512"):
    pqc = PQCManager(algorithm)

    start = time.perf_counter()
    keys = pqc.generate_keypair(algorithm)
    keygen_time = (time.perf_counter() - start) * 1000

    is_kem = algorithm.startswith("Kyber")

    if is_kem:
        start = time.perf_counter()
        ciphertext, secret = pqc.encapsulate(keys["public_key"])
        enc_time = (time.perf_counter() - start) * 1000

        start = time.perf_counter()
        pqc.decapsulate(ciphertext, keys["private_key"])
        dec_time = (time.perf_counter() - start) * 1000

        return {
            "algorithm": algorithm,
            "keygen_ms": round(keygen_time, 4),
            "encapsulation_ms": round(enc_time, 4),
            "decapsulation_ms": round(dec_time, 4),
            "signature_ms": 0.0,
            "verify_ms": 0.0
        }
    else:
        # Signature algorithms
        message = b"test message"
        start = time.perf_counter()
        signature = pqc.sign(message, keys["private_key"])
        sig_time = (time.perf_counter() - start) * 1000

        start = time.perf_counter()
        pqc.verify(message, signature, keys["public_key"])
        ver_time = (time.perf_counter() - start) * 1000

        return {
            "algorithm": algorithm,
            "keygen_ms": round(keygen_time, 4),
            "encapsulation_ms": 0.0,
            "decapsulation_ms": 0.0,
            "signature_ms": round(sig_time, 4),
            "verify_ms": round(ver_time, 4)
        }


# ======================================
# TEST
# ======================================

if __name__ == "__main__":
    pqc = PQCManager()
    
    print("\nRunning benchmarks...")
    for alg in ["Kyber512", "Kyber768", "Dilithium2", "Falcon512"]:
        try:
            res = benchmark_algorithm(alg)
            print(f"Benchmark {alg}: {res}")
        except Exception as e:
            print(f"Benchmark {alg} failed: {e}")