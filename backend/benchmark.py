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
    "Kyber512",
    "Kyber768",
    "Dilithium2",
    "Falcon512"
]

# ==========================================
# BENCHMARK
# ==========================================

def run_benchmark(algorithm):
    print(f"\nRunning {algorithm}")

    proc = psutil.Process()
    
    # 1. Initialize CPU tracking
    proc.cpu_percent(None)
    start_time = time.perf_counter()
    start_cpu_time = proc.cpu_times().user + proc.cpu_times().system

    # 2. Run the PQC algorithm operations 100 times to get stable readings
    iterations = 100
    for _ in range(iterations):
        _ = benchmark_algorithm(algorithm)

    end_time = time.perf_counter()
    end_cpu_time = proc.cpu_times().user + proc.cpu_times().system

    # 3. Calculate actual CPU utilization percentage
    elapsed = end_time - start_time
    cpu_elapsed = end_cpu_time - start_cpu_time
    if elapsed > 0:
        cpu_usage = (cpu_elapsed / elapsed) * 100.0
    else:
        cpu_usage = 0.0

    # Clamp to realistic bounds (1% to 100% single-thread core utilisation)
    cpu_usage = min(100.0, max(1.0, cpu_usage))

    # 4. Measure physical RAM RSS usage of the process
    mem_bytes = proc.memory_info().rss
    memory_mb = mem_bytes / (1024.0 * 1024.0)

    # 5. Measure single-run latency for the record
    result = benchmark_algorithm(algorithm)

    benchmark = BenchmarkResult(
        algorithm=algorithm,
        keygen_time_ms=result["keygen_ms"],
        encrypt_time_ms=result["encrypt_ms"],
        decrypt_time_ms=result["decrypt_ms"],
        signature_time_ms=result.get("signature_ms", 0.0),
        verify_time_ms=result.get("verify_ms", 0.0),
        memory_usage_mb=round(memory_mb, 2),
        cpu_usage_percent=round(cpu_usage, 2)
    )

    db.add(benchmark)
    db.commit()

    print(f"Stored in database - Memory: {benchmark.memory_usage_mb:.2f} MB, CPU: {benchmark.cpu_usage_percent:.2f}%")

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