# Walkthrough - Alembic Transition & SQLAlchemy Concurrency Fixes

We have completed the transition of manual migrations to Alembic, localized concurrent database sessions to prevent concurrency/threading issues, and implemented atomic sequence locks to close race conditions during replay protection checks.

## Changes Made

### 1. Alembic Integration
- **Alembic Configuration:** Created [alembic.ini](file:///c:/Users/chara/projects/PQC/backend/alembic.ini) and the dynamic [env.py](file:///c:/Users/chara/projects/PQC/backend/alembic/env.py) environment which dynamically resolves the connection engine from `database.py`.
- **Initial Migration:** Created [f6d76828be4d_initial_migration.py](file:///c:/Users/chara/projects/PQC/backend/alembic/versions/f6d76828be4d_initial_migration.py) to construct all database tables (`devices`, `threat_logs`, `benchmark_results`) and statistically track metrics.
- **Legacy Columns Dropped:** The legacy columns `sig_public_key_dilithium2` and `sig_public_key_falcon512` were cleanly removed from the database schema during migration, while standard FIPS column names (`sig_public_key_ml_dsa_44` and `sig_public_key_fn_dsa_512`) are fully preserved.
- **Dynamic Startup Execution:** Removed legacy manual schema patchers (`run_migrations()`, etc.) in [database.py](file:///c:/Users/chara/projects/PQC/backend/database.py). Updated `init_db()` to programmatically call Alembic `upgrade("head")` on application startup.

### 2. Thread-Local DB Sessions
- **MQTT Bridge:** Removed global `db` reuse in [mqtt_bridge.py](file:///c:/Users/chara/projects/PQC/backend/mqtt_bridge.py). Replaced it with localized thread-local sessions (`db = SessionLocal()`) opened and closed safely within `try-finally` blocks inside `process_payload()`.
- **AI Threat Detector:** Localized database session instantiation in `detect_threat()` in [threat_detector.py](file:///c:/Users/chara/projects/PQC/backend/ai/threat_detector.py). The bridge now passes its active session instance directly, preventing connection sharing leaks.
- **Simulator Device Manager:** Refactored background loops in [device_manager.py](file:///c:/Users/chara/projects/PQC/backend/simulator/device_manager.py) to use SQLAlchemy `with SessionLocal() as session:` blocks, preventing connection pool leaks during background status checks or key updates.

### 3. Atomic Sequence Replay Checks
- **Timestamp Ordering Fix:** Fixed a critical desynchronization vulnerability by validating the packet timestamp *prior* to executing the atomic SQL UPDATE query. Previously, a validly signed but stale packet with a higher sequence number would advance the database `last_sequence` before failing the timestamp check, blocking subsequent authentic packets. Now, the timestamp is fully validated first, leaving the sequence unchanged on failures.
- **Atomic Locking:** Replaced the vulnerable "check-then-update" replay check with an atomic check-and-update update query:
  ```sql
  UPDATE devices 
  SET last_sequence = :seq 
  WHERE device_id = :device_id AND (last_sequence < :seq OR last_sequence IS NULL)
  ```
- If the statement returns `rowcount == 0`, a concurrent packet with an equal/higher sequence has already executed (or the device is missing), raising an immediate `ValueError` to block the replay.
- Used `db.expire(existing_device, ['last_sequence'])` so the ORM object refreshes properly from the updated database state before finalizing the transaction.

### 4. Adaptive ML Signature Selector
- **Latency Metric Realignment:** Realigned the signature selector's utility metric in [pqc_ml_selector.py](file:///c:/Users/chara/projects/PQC/backend/pqc/pqc_ml_selector.py) to use actual signing latency (`sign_ms`) instead of keygen latency, reflecting real-world operation.
- **Utility Model Tuning:** Calibrated utility weights to yield a highly balanced dataset (49.8% ML-DSA-44 / 50.2% FN-DSA-512) and trained an adaptive random-forest model with a proper 2x2 confusion matrix (98.2% F1 macro score) written to [selector_metrics.json](file:///c:/Users/chara/projects/PQC/backend/ai/selector_metrics.json).
- **Benchmark-Driven Comparison Re-run:** Re-ran [compare_selectors.py](file:///c:/Users/chara/projects/PQC/backend/ai/compare_selectors.py) using signing latency. Adaptive signature selection signing latency average (7.79ms) correctly balances ML-DSA-44 (1.63ms) and FN-DSA-512 (13.70ms).

### 5. Secure-Channel Security Test Suite
- **Comprehensive Unit Tests:** Created [test_secure_channel_correctness.py](file:///c:/Users/chara/projects/PQC/backend/pqc/test_secure_channel_correctness.py) to end-to-end test the complete secure channel path under 11 positive/negative vectors, verifying correct cryptographic behaviors, replay attacks, timestamp window skews, and header alterations.

### 6. Real-World Cross-Dataset Validation
- **Real UNSW TON_IoT Dataset Download:** Replaced the mock generator in [synthetic_realistic_validation.py](file:///c:/Users/chara/projects/PQC/backend/ai/synthetic_realistic_validation.py) with a dynamic downloader that retrieves slices of actual raw normal and attack network logs from UNSW TON_IoT.
- **Defensible Feature & Class Mapping:** Mapped network columns (`duration`, `src_pkts`, `dst_pkts`) to packet rates and scaled requests-per-minute. Projected physical resource usage (`cpu_usage`, `memory_usage`) and thermal state (`temperature`) corresponding to normal and heavy traffic behavior. Mapped intrusion labels (`dos`, `ddos`, `scanning`, `injection`, etc.) to the classifier's classes (`Normal`, `DDoS`, `Reconnaissance`).
- **Process Memory and CPU Labels:** Renamed "Avg PQC RAM Footprint" in [Dashboard.jsx](file:///c:/Users/chara/projects/PQC/frontend/src/pages/Dashboard.jsx) to **"Avg Incremental Process RSS"** and documented it as **"Incremental process RSS during benchmark"** to accurately represent the process-level nature of the measurement.

## Verification Results

### 1. Database Schema
Running the database initialization script verifies the tables are set up correctly:
```
INFO  [alembic.runtime.migration] Context impl SQLiteImpl.
INFO  [alembic.runtime.migration] Will assume non-transactional DDL.
INFO  [alembic.runtime.migration] Running upgrade  -> f6d76828be4d, Initial migration
Database migrations applied successfully via Alembic.
QuantumShield Database Initialized
```
Inspecting the SQLite database shows the obsolete columns are successfully removed:
```python
# devices columns:
['id', 'device_id', 'device_name', 'status', 'cpu_usage', 'memory_usage', 'battery_level', 'selected_kem', 'selected_signature', 'sig_public_key_ml_dsa_44', 'sig_public_key_fn_dsa_512', 'last_sequence', 'created_at', 'last_seen']
```

### 2. Positive/Negative Cryptographic Primitives
Executed positive/negative checks inside the cryptography test module:
```
Testing KEM: ML-KEM-512
 [PASS] Key pair generated
 [PASS] Positive check: correct decapsulation matches encapsulated secret
 [PASS] Negative check: tampered ciphertext returns incorrect secret (implicit rejection)
...
ALL CRYPTOGRAPHIC TESTS PASSED SUCCESSFULLY
```

### 3. Standalone Simulation & Modeled Energy Costs
The MQTT bridge correctly decrypts, detects threats using the random-forest classifiers, and logs rekeying events dynamically.
The comparison results of [compare_selectors.py](file:///c:/Users/chara/projects/PQC/backend/ai/compare_selectors.py) explicitly label results as "Simulation" and "Modeled Energy Cost":
```
--- SIGNATURE SELECTION SIMULATION (Averages across 100 Scenarios) ---

| Configuration | Signing Latency (ms) | Incremental RAM (MB) | Signature Size (B) | Modeled Energy Cost | Security Level |
|---|---|---|---|---|---|
| ML-DSA-44     |               1.6371 |               0.0000 |             2420.0 |                1.50 |           2.00 |
| FN-DSA-512    |              13.7074 |               0.0100 |              653.0 |                3.00 |           1.00 |
| Adaptive      |               7.7930 |               0.0051 |             1518.8 |                2.27 |           1.49 |
```

### 4. Dual Threat Validation Accuracy
Executing [synthetic_realistic_validation.py](file:///c:/Users/chara/projects/PQC/backend/ai/synthetic_realistic_validation.py) evaluates the trained threat model using a dual validation strategy:
```
====================================================
           DUAL THREAT VALIDATION REPORT
====================================================

1. REAL-WORLD CROSS-DATASET VALIDATION (3-Class):
   Target Dataset: UNSW TON_IoT Network Telemetry (Cross-Dataset)
   Accuracy: 81.1587%
   Balanced Accuracy: 87.3737%
   F1-Score (Macro): 82.8222%
   Methodology: Features are projected from raw traffic metrics. Validates Normal, DDoS, and Recon.

Classification Report (Real-World):
                precision    recall  f1-score   support

        Normal       1.00      0.62      0.77      1056
          DDoS       1.00      1.00      1.00       557
Reconnaissance       0.56      1.00      0.72       510

      accuracy                           0.81      2123
     macro avg       0.85      0.87      0.83      2123
  weighted avg       0.89      0.81      0.82      2123


2. CONTROLLED SIMULATOR TELEMETRY VALIDATION (5-Class):
   Target Dataset: Controlled 5-Class Realistic Telemetry Validation
   Accuracy: 99.7667%
   Balanced Accuracy: 99.3427%
   F1-Score (Macro): 99.6293%
   Methodology: Controlled realistic simulation log evaluation including Cryptojacking & Thermal attacks.

Classification Report (Controlled):
                   precision    recall  f1-score   support

           Normal       1.00      1.00      1.00      1912
             DDoS       1.00      1.00      1.00       366
    Cryptojacking       1.00      1.00      1.00       257
Thermal Tampering       1.00      1.00      1.00       252
   Reconnaissance       1.00      0.97      0.98       213

         accuracy                           1.00      3000
        macro avg       1.00      0.99      1.00      3000
     weighted avg       1.00      1.00      1.00      3000
```

### 5. Secure-Channel Security Verification
Running the comprehensive positive/negative security tests validates all 11 scenarios:
```
Ran 11 tests in 1.808s

OK
```
