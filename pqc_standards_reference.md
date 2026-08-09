# Post-Quantum Cryptography (PQC) Standardization Reference Guide

This document maps the project-specific cryptographic identifiers in the **QuantumShield-IoT** workspace to their formal NIST (National Institute of Standards and Technology) standardized names and corresponding Federal Information Processing Standards (FIPS) publications. This guide is structured for direct inclusion in the experimental methodology section of academic publications (such as IEEE papers).

---

## 1. Cryptographic Naming & Standards Mapping

| Project Variable / UI Label | NIST Standard Name | NIST Publication | Primary Mathematical Family / Problem | NIST Security Level |
| :--- | :--- | :--- | :--- | :--- |
| **`Kyber512`** | **`ML-KEM-512`** | **FIPS 203** (Finalized Aug 2024) | Module Learning with Errors (M-LWE) | Level 1 (AES-128 equivalent) |
| **`Kyber768`** | **`ML-KEM-768`** | **FIPS 203** (Finalized Aug 2024) | Module Learning with Errors (M-LWE) | Level 3 (AES-192 equivalent) |
| **`Dilithium2`** | **`ML-DSA-44`** | **FIPS 204** (Finalized Aug 2024) | Module-LWE / Module Short Integer Solution (M-SIS) | Level 2 (AES-128 equivalent) |
| **`Falcon512`** | **`FN-DSA-512`** / `Falcon-512` | **FIPS 206** (Draft) | NTRU Lattice over cyclotomic fields / GPV framework | Level 1 (AES-128 equivalent) |

---

## 2. Algorithm Families & Mathematical Bases

### A. ML-KEM (Module-Lattice Key Encapsulation Mechanism)
* **Standardization:** Finalized in **FIPS 203** (August 2024), derived from the **CRYSTALS-Kyber** submission.
* **Mathematical Basis:** Security relies on the hardness of the Module Learning with Errors (M-LWE) problem.
* **Parameter Sets:**
  - **`ML-KEM-512`** ($k=2$): Designed for Level 1 security. Key sizes: Public Key = 800 bytes, Secret Key = 1,632 bytes, Ciphertext = 768 bytes.
  - **`ML-KEM-768`** ($k=3$): Designed for Level 3 security. Key sizes: Public Key = 1,184 bytes, Secret Key = 2,400 bytes, Ciphertext = 1,088 bytes.
* **Application:** Used for post-quantum key exchange (encapsulation and decapsulation) to secure data-in-transit.

### B. ML-DSA (Module-Lattice Digital Signature Algorithm)
* **Standardization:** Finalized in **FIPS 204** (August 2024), derived from the **CRYSTALS-Dilithium** submission.
* **Mathematical Basis:** Relies on the hardness of M-LWE and Module Short Integer Solution (M-SIS) problems using a Fiat-Shamir with Aborts framework.
* **Parameter Sets:**
  - **`ML-DSA-44`** (historically aligned with *Dilithium2*): Configured with module dimensions $(k,l) = (4,4)$ for Level 2 security. Key sizes: Public Key = 1,312 bytes, Secret Key = 2,560 bytes, Signature = 2,420 bytes.
* **Application:** Used for asymmetric device authentication, handshake validation, and firmware integrity signatures.

### C. FN-DSA (Fourier-Based NTRU Digital Signature Algorithm)
* **Standardization:** Standardized under draft **FIPS 206**, derived from the **Falcon** submission.
* **Mathematical Basis:** Relies on the NTRU problem. Utilizes the Gentry-Peikert-Vaikuntanathan (GPV) framework combined with fast Fourier sampling over ring structures.
* **Parameter Sets:**
  - **`FN-DSA-512`** (historically aligned with *Falcon-512*): Offers Level 1 security. Key sizes: Public Key = 897 bytes, Secret Key = 1,281 bytes, Signature = 666 bytes.
* **Application:** Ideal for bandwidth-constrained IoT networks due to its exceptionally small signature size (666 bytes, which is ~3.6x smaller than ML-DSA-44).
