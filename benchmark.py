#!/usr/bin/env python3
"""
Zero-Dependency Benchmark Tool for Micro-Redis-Vault
===================================================
Fires concurrent TCP requests and measures throughput and P50/P95/P99 latency.
"""

import socket
import time
import threading
import statistics
import sys

HOST = "127.0.0.1"
PORT = 6379
TOTAL_REQUESTS = 2000
CONCURRENCY = 20

latencies = []
lock = threading.Lock()

def worker(num_requests):
    local_lats = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((HOST, PORT))
        for i in range(num_requests):
            start = time.perf_counter()
            s.sendall(f"SET key:{i} value_{i}\r\n".encode('utf-8'))
            resp = s.recv(1024)
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            local_lats.append(elapsed_ms)
        s.close()
    except Exception as e:
        print(f"Worker error: {e}")
    with lock:
        latencies.extend(local_lats)

def run_benchmark():
    print("=" * 60)
    print(" ⚡ MICRO-REDIS-VAULT ZERO-DEP BENCHMARK TOOL ⚡")
    print(f" Target: {HOST}:{PORT}")
    print(f" Total Operations: {TOTAL_REQUESTS} | Concurrency: {CONCURRENCY} threads")
    print("=" * 60)

    reqs_per_thread = TOTAL_REQUESTS // CONCURRENCY
    threads = []
    start_total = time.perf_counter()

    for _ in range(CONCURRENCY):
        t = threading.Thread(target=worker, args=(reqs_per_thread,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    total_time = time.perf_counter() - start_total
    if not latencies:
        print("❌ Benchmark failed: No requests completed.")
        return

    latencies.sort()
    ops_per_sec = len(latencies) / total_time
    p50 = statistics.median(latencies)
    p95 = latencies[int(len(latencies) * 0.95)]
    p99 = latencies[int(len(latencies) * 0.99)]

    print(f"\n📊 RESULTS:")
    print(f"  • Completed Requests : {len(latencies)}")
    print(f"  • Total Time Elapsed : {total_time:.3f} s")
    print(f"  • Throughput Rate    : \033[1;32m{ops_per_sec:,.0f} ops/sec\033[0m")
    print(f"  • P50 Latency (Avg)  : {p50:.3f} ms")
    print(f"  • P95 Latency        : {p95:.3f} ms")
    print(f"  • P99 Latency        : {p99:.3f} ms")
    print("=" * 60 + "\n")

if __name__ == "__main__":
    run_benchmark()
