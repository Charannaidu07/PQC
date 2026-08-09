"""
QuantumShield-IoT
Benchmark Engine using real resource measurements
"""

import time
import psutil

from database import (
    SessionLocal,
    BenchmarkResult
)

from pqc.pqc_oqs import (
    benchmark_algorithm
)

# ==========================================
# DATABASE
# ==========================================

db = SessionLocal()

# ==========================================
# PQC ALGORITHMS
# ==========================================

ALGORITHMS = [
    "ML-KEM-512",
    "ML-KEM-768",
    "ML-DSA-44",
    "FN-DSA-512"
]

# ==========================================
# BENCHMARK
# ==========================================

def run_benchmark(algorithm):
    print(f"\nRunning {algorithm}")

    import gc
    proc = psutil.Process()
    
    # Force garbage collection to clean up the heap before recording the baseline RSS
    gc.collect()
    baseline_rss = proc.memory_info().rss
    peak_rss = baseline_rss
    
    # 1. Initialize CPU tracking
    proc.cpu_percent(None)
    start_time = time.perf_counter()
    start_cpu_time = proc.cpu_times().user + proc.cpu_times().system

    # 2. Run the PQC algorithm operations 100 times, accumulating timings and tracking peak memory RSS
    iterations = 100
    keygen_list = []
    encap_list = []
    decap_list = []
    sign_list = []
    verify_list = []

    for _ in range(iterations):
        res = benchmark_algorithm(algorithm)
        current_rss = proc.memory_info().rss
        if current_rss > peak_rss:
            peak_rss = current_rss
            
        if "keygen_ms" in res:
            keygen_list.append(res["keygen_ms"])
        if "encapsulation_ms" in res:
            encap_list.append(res["encapsulation_ms"])
        if "decapsulation_ms" in res:
            decap_list.append(res["decapsulation_ms"])
        if "signature_ms" in res:
            sign_list.append(res["signature_ms"])
        if "verify_ms" in res:
            verify_list.append(res["verify_ms"])

    end_time = time.perf_counter()
    end_cpu_time = proc.cpu_times().user + proc.cpu_times().system

    # 3. Calculate process CPU utilization percentage during benchmark
    elapsed = end_time - start_time
    cpu_elapsed = end_cpu_time - start_cpu_time
    if elapsed > 0:
        cpu_usage = (cpu_elapsed / elapsed) * 100.0
    else:
        cpu_usage = 0.0

    # Clamp to realistic bounds (1% to 100% single-thread core utilisation)
    cpu_usage = min(100.0, max(1.0, cpu_usage))

    # 4. Measure incremental memory overhead RSS usage (Peak - Baseline)
    incremental_memory_bytes = max(0, peak_rss - baseline_rss)
    memory_mb = incremental_memory_bytes / (1024.0 * 1024.0)

    # 5. Compute statistical distributions
    import numpy as np

    def calc_stats(lst):
        if not lst or all(v == 0.0 for v in lst):
            return {
                "mean": 0.0, "median": 0.0, "std": 0.0,
                "p95": 0.0, "p99": 0.0, "min": 0.0, "max": 0.0
            }
        arr = np.array(lst)
        return {
            "mean": round(float(np.mean(arr)), 4),
            "median": round(float(np.median(arr)), 4),
            "std": round(float(np.std(arr)), 4),
            "p95": round(float(np.percentile(arr, 95)), 4),
            "p99": round(float(np.percentile(arr, 99)), 4),
            "min": round(float(np.min(arr)), 4),
            "max": round(float(np.max(arr)), 4)
        }

    keygen_stats = calc_stats(keygen_list)
    encap_stats = calc_stats(encap_list)
    decap_stats = calc_stats(decap_list)
    sign_stats = calc_stats(sign_list)
    verify_stats = calc_stats(verify_list)

    # Extract size metrics from the last run (res)
    pub_key_size = res.get("pub_key_size", 0)
    secret_key_size = res.get("secret_key_size", 0)
    ciphertext_size = res.get("ciphertext_size", 0)
    shared_secret_size = res.get("shared_secret_size", 0)
    signature_size = res.get("signature_size", 0)

    benchmark = BenchmarkResult(
        algorithm=algorithm,
        # Backward-compatible fields
        keygen_time_ms=keygen_stats["mean"],
        encapsulation_time_ms=encap_stats["mean"],
        decapsulation_time_ms=decap_stats["mean"],
        signature_time_ms=sign_stats["mean"],
        verify_time_ms=verify_stats["mean"],
        
        # Rigorous statistical fields
        keygen_mean_ms=keygen_stats["mean"],
        keygen_median_ms=keygen_stats["median"],
        keygen_std_ms=keygen_stats["std"],
        keygen_p95_ms=keygen_stats["p95"],
        keygen_p99_ms=keygen_stats["p99"],
        keygen_min_ms=keygen_stats["min"],
        keygen_max_ms=keygen_stats["max"],
        
        encap_mean_ms=encap_stats["mean"],
        encap_median_ms=encap_stats["median"],
        encap_std_ms=encap_stats["std"],
        encap_p95_ms=encap_stats["p95"],
        encap_p99_ms=encap_stats["p99"],
        encap_min_ms=encap_stats["min"],
        encap_max_ms=encap_stats["max"],
        
        decap_mean_ms=decap_stats["mean"],
        decap_median_ms=decap_stats["median"],
        decap_std_ms=decap_stats["std"],
        decap_p95_ms=decap_stats["p95"],
        decap_p99_ms=decap_stats["p99"],
        decap_min_ms=decap_stats["min"],
        decap_max_ms=decap_stats["max"],
        
        sign_mean_ms=sign_stats["mean"],
        sign_median_ms=sign_stats["median"],
        sign_std_ms=sign_stats["std"],
        sign_p95_ms=sign_stats["p95"],
        sign_p99_ms=sign_stats["p99"],
        sign_min_ms=sign_stats["min"],
        sign_max_ms=sign_stats["max"],
        
        verify_mean_ms=verify_stats["mean"],
        verify_median_ms=verify_stats["median"],
        verify_std_ms=verify_stats["std"],
        verify_p95_ms=verify_stats["p95"],
        verify_p99_ms=verify_stats["p99"],
        verify_min_ms=verify_stats["min"],
        verify_max_ms=verify_stats["max"],
        
        memory_usage_mb=round(memory_mb, 2),
        cpu_usage_percent=round(cpu_usage, 2),
        
        # Cryptographic sizes in bytes
        pub_key_size_bytes=pub_key_size,
        secret_key_size_bytes=secret_key_size,
        ciphertext_size_bytes=ciphertext_size,
        shared_secret_size_bytes=shared_secret_size,
        signature_size_bytes=signature_size
    )

    db.add(benchmark)
    db.commit()

    print(f"Stored in database - Mean Latencies (keygen: {benchmark.keygen_time_ms:.4f} ms, encap: {benchmark.encapsulation_time_ms:.4f} ms, decap: {benchmark.decapsulation_time_ms:.4f} ms)")
    print(f"                     StDev Latencies (keygen: {keygen_stats['std']:.4f} ms, encap: {encap_stats['std']:.4f} ms, decap: {decap_stats['std']:.4f} ms)")
    print(f"                     Memory: {benchmark.memory_usage_mb:.2f} MB, Process CPU Load: {benchmark.cpu_usage_percent:.2f}%")

# ==========================================
# RUN ALL
# ==========================================

def run_all():
    start = time.time()

    for algorithm in ALGORITHMS:
        try:
            run_benchmark(algorithm)
        except Exception as e:
            print(f"{algorithm} failed: {e}")

    end = time.time()

    print("\nCompleted")
    print(f"Total Time: {end-start:.2f}s")


if __name__ == "__main__":
    run_all()