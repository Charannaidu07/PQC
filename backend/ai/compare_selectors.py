"""
QuantumShield-IoT
Adaptive PQC Selection vs. Fixed Suite Evaluation Experiment
"""

import os
import sys
import random
import json
import numpy as np
import pandas as pd

# Add backend directory to path
backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(backend_dir)

from pqc.pqc_ml_selector import select_algorithm, get_latest_benchmark_stats

def run_comparison_experiment():
    print("====================================================")
    # 1. Load benchmark results
    stats = get_latest_benchmark_stats()
    if not stats:
        print("Warning: Benchmark stats not found in database. Using fallback values.")
        stats = {
            "ML-KEM-512": {"decap_ms": 0.2229, "memory_mb": 0.18, "ciphertext_size": 768, "security": 1.0, "energy": 1.0},
            "ML-KEM-768": {"decap_ms": 0.3744, "memory_mb": 0.02, "ciphertext_size": 1088, "security": 3.0, "energy": 1.5},
            "ML-DSA-44": {"keygen_ms": 0.4428, "sign_ms": 1.6371, "verify_ms": 0.5140, "memory_mb": 0.04, "signature_size": 2420, "security": 2.0, "energy": 1.5},
            "FN-DSA-512": {"keygen_ms": 29.4533, "sign_ms": 13.7074, "verify_ms": 0.6526, "memory_mb": 0.17, "signature_size": 662, "security": 1.0, "energy": 3.0}
        }
    else:
        # Inject metadata attributes if missing
        stats["ML-KEM-512"]["security"] = 1.0
        stats["ML-KEM-512"]["energy"] = 1.0
        stats["ML-KEM-768"]["security"] = 3.0
        stats["ML-KEM-768"]["energy"] = 1.5
        stats["ML-DSA-44"]["security"] = 2.0
        stats["ML-DSA-44"]["energy"] = 1.5
        stats["FN-DSA-512"]["security"] = 1.0
        stats["FN-DSA-512"]["energy"] = 3.0
        
        # Ensure sign_ms is populated
        if "sign_ms" not in stats["ML-DSA-44"]:
            stats["ML-DSA-44"]["sign_ms"] = stats["ML-DSA-44"].get("sign_mean_ms") or 1.6371
        if "sign_ms" not in stats["FN-DSA-512"]:
            stats["FN-DSA-512"]["sign_ms"] = stats["FN-DSA-512"].get("sign_mean_ms") or 13.7074

    print("Successfully loaded benchmark-driven metrics for simulation.")

    # 2. Generate scenario cases
    random.seed(1337)
    np.random.seed(1337)
    
    num_scenarios = 100
    scenarios = []
    for _ in range(num_scenarios):
        scenarios.append({
            "cpu_usage": random.uniform(1.0, 100.0),
            "ram_usage": random.uniform(128.0, 4096.0),
            "battery_level": random.uniform(1.0, 100.0),
            "threat_score": random.uniform(0.0, 1.0)
        })

    # 3. Track configurations metrics
    results = {
        "kem": {
            "ML-KEM-512": {"latency": [], "memory": [], "bandwidth": [], "energy": [], "security": []},
            "ML-KEM-768": {"latency": [], "memory": [], "bandwidth": [], "energy": [], "security": []},
            "Adaptive": {"latency": [], "memory": [], "bandwidth": [], "energy": [], "security": []}
        },
        "sig": {
            "ML-DSA-44": {"latency": [], "memory": [], "bandwidth": [], "energy": [], "security": []},
            "FN-DSA-512": {"latency": [], "memory": [], "bandwidth": [], "energy": [], "security": []},
            "Adaptive": {"latency": [], "memory": [], "bandwidth": [], "energy": [], "security": []}
        }
    }

    # 4. Run simulation
    for sc in scenarios:
        # Select algorithm using trained RandomForest model
        sel_kem, sel_sig = select_algorithm(
            cpu_usage=sc["cpu_usage"],
            ram_usage=sc["ram_usage"],
            battery_level=sc["battery_level"],
            threat_score=sc["threat_score"]
        )

        # A. KEM calculations
        for cfg in ["ML-KEM-512", "ML-KEM-768", "Adaptive"]:
            target_cfg = cfg if cfg != "Adaptive" else sel_kem
            data = stats[target_cfg]
            results["kem"][cfg]["latency"].append(data.get("decap_ms", 0.0))
            results["kem"][cfg]["memory"].append(data.get("memory_mb", 0.0))
            results["kem"][cfg]["bandwidth"].append(data.get("ciphertext_size", 0))
            results["kem"][cfg]["energy"].append(data["energy"])
            results["kem"][cfg]["security"].append(data["security"])

        # B. Signature calculations (using sign_ms for telemetry transmission signature latency)
        for cfg in ["ML-DSA-44", "FN-DSA-512", "Adaptive"]:
            target_cfg = cfg if cfg != "Adaptive" else sel_sig
            data = stats[target_cfg]
            results["sig"][cfg]["latency"].append(data.get("sign_ms", 0.0) or data.get("sign_mean_ms", 1.6))
            results["sig"][cfg]["memory"].append(data.get("memory_mb", 0.0))
            results["sig"][cfg]["bandwidth"].append(data.get("signature_size", 0))
            results["sig"][cfg]["energy"].append(data["energy"])
            results["sig"][cfg]["security"].append(data["security"])

    # 5. Aggregate averages (Simulated evaluation based on empirical benchmark stats lookup)
    summary = {}
    for layer in ["kem", "sig"]:
        summary[layer] = {}
        for cfg in results[layer]:
            summary[layer][cfg] = {
                "latency_ms": round(float(np.mean(results[layer][cfg]["latency"])), 4),
                "memory_mb": round(float(np.mean(results[layer][cfg]["memory"])), 4),
                "bandwidth_bytes": round(float(np.mean(results[layer][cfg]["bandwidth"])), 1),
                "modeled_relative_energy": round(float(np.mean(results[layer][cfg]["energy"])), 2),
                "policy_security_weight": round(float(np.mean(results[layer][cfg]["security"])), 2)
            }

    # 6. Save results to JSON
    out_path = os.path.join(backend_dir, "ai/selector_comparison_results.json")
    with open(out_path, "w") as f:
        json.dump(summary, f, indent=4)

    # 7. Print markdown table
    print("\n====================================================")
    print("      PQC SUITE COMPARISON SIMULATION RESULTS (BENCHMARK-DRIVEN)")
    print("====================================================")
    print("\n--- KEM SELECTION SIMULATION (Averages across 100 Scenarios) ---\n")
    print("| Configuration | Decap Latency (ms) | Incremental RAM (MB) | Ciphertext Size (B) | Modeled Relative Energy | Policy Security Weight |")
    print("|---|---|---|---|---|---|")
    for cfg, m in summary["kem"].items():
        print(f"| {cfg:13s} | {m['latency_ms']:18.4f} | {m['memory_mb']:20.4f} | {m['bandwidth_bytes']:19.1f} | {m['modeled_relative_energy']:23.2f} | {m['policy_security_weight']:22.2f} |")

    print("\n--- SIGNATURE SELECTION SIMULATION (Averages across 100 Scenarios) ---\n")
    print("| Configuration | Signing Latency (ms) | Incremental RAM (MB) | Signature Size (B) | Modeled Relative Energy | Policy Security Weight |")
    print("|---|---|---|---|---|---|")
    for cfg, m in summary["sig"].items():
        print(f"| {cfg:13s} | {m['latency_ms']:20.4f} | {m['memory_mb']:20.4f} | {m['bandwidth_bytes']:18.1f} | {m['modeled_relative_energy']:23.2f} | {m['policy_security_weight']:22.2f} |")
    print("====================================================\n")

if __name__ == "__main__":
    run_comparison_experiment()
