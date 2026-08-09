"""
QuantumShield-IoT
PQC Abstraction Layer
Version 1
"""

import secrets
import hashlib
import time


class PQCManager:

    def __init__(self):

        self.supported_kems = [
            "Kyber512",
            "Kyber768"
        ]

        self.supported_signatures = [
            "Dilithium2",
            "Falcon512"
        ]

    # ----------------------------------
    # KEY GENERATION
    # ----------------------------------

    def generate_keypair(
        self,
        algorithm="Kyber512"
    ):

        public_key = (
            secrets.token_hex(64)
        )

        private_key = (
            secrets.token_hex(64)
        )

        return {

            "algorithm":
                algorithm,

            "public_key":
                public_key,

            "private_key":
                private_key
        }

    # ----------------------------------
    # ENCAPSULATION
    # ----------------------------------

    def encapsulate(
        self,
        public_key
    ):

        shared_secret = (
            secrets.token_hex(32)
        )

        ciphertext = hashlib.sha256(
            (
                public_key +
                shared_secret
            ).encode()
        ).hexdigest()

        return (
            ciphertext,
            shared_secret
        )

    # ----------------------------------
    # DECAPSULATION
    # ----------------------------------

    def decapsulate(
        self,
        ciphertext,
        private_key
    ):

        return hashlib.sha256(
            (
                ciphertext +
                private_key
            ).encode()
        ).hexdigest()

    # ----------------------------------
    # SIGN
    # ----------------------------------

    def sign(
        self,
        message,
        private_key
    ):

        return hashlib.sha256(
            (
                message +
                private_key
            ).encode()
        ).hexdigest()

    # ----------------------------------
    # VERIFY
    # ----------------------------------

    def verify(
        self,
        message,
        signature,
        private_key
    ):

        expected = hashlib.sha256(
            (
                message +
                private_key
            ).encode()
        ).hexdigest()

        return signature == expected


# ======================================
# BENCHMARK
# ======================================

def benchmark_algorithm(
    algorithm="Kyber512"
):

    pqc = PQCManager()

    start = time.perf_counter()

    keys = pqc.generate_keypair(
        algorithm
    )

    keygen_time = (
        time.perf_counter()
        - start
    ) * 1000

    is_kem = algorithm.startswith("Kyber")

    if is_kem:
        start = time.perf_counter()
        ciphertext, secret = (
            pqc.encapsulate(
                keys["public_key"]
            )
        )
        enc_time = (
            time.perf_counter()
            - start
        ) * 1000

        start = time.perf_counter()
        pqc.decapsulate(
            ciphertext,
            keys["private_key"]
        )
        dec_time = (
            time.perf_counter()
            - start
        ) * 1000

        return {
            "algorithm": algorithm,
            "keygen_ms": round(keygen_time, 4),
            "encrypt_ms": round(enc_time, 4),
            "decrypt_ms": round(dec_time, 4),
            "signature_ms": 0.0,
            "verify_ms": 0.0
        }
    else:
        # Signature algorithms
        message = b"test message"
        start = time.perf_counter()
        signature = pqc.sign(
            message,
            keys["private_key"]
        )
        sig_time = (
            time.perf_counter()
            - start
        ) * 1000

        start = time.perf_counter()
        pqc.verify(
            message,
            signature,
            keys["private_key"]
        )
        ver_time = (
            time.perf_counter()
            - start
        ) * 1000

        return {
            "algorithm": algorithm,
            "keygen_ms": round(keygen_time, 4),
            "encrypt_ms": 0.0,
            "decrypt_ms": 0.0,
            "signature_ms": round(sig_time, 4),
            "verify_ms": round(ver_time, 4)
        }


# ======================================
# TEST
# ======================================

if __name__ == "__main__":

    pqc = PQCManager()

    keys = pqc.generate_keypair()

    print("\nGenerated Keys")

    print(
        keys["algorithm"]
    )

    result = benchmark_algorithm()

    print("\nBenchmark")

    print(result)