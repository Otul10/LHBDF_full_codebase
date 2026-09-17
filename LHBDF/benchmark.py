#!/usr/bin/env python3
"""
LHBDF — Resource Consumption Benchmark
==========================================
Measures CPU, RAM, latency, and throughput of the LHBDF pipeline.
Directly supports the "lightweight deployment" claim in the proposal
(Section 8.6 — Computational Overhead).

Usage:
  python benchmark.py logs/large_auth.csv
  python benchmark.py logs/large_auth.csv --repetitions 10
"""

import sys
import argparse

from modules.resource_monitor import benchmark_pipeline


def print_report(metrics: dict, logfile: str) -> None:
    W = 64
    print()
    print("═" * W)
    print("  LHBDF — RESOURCE CONSUMPTION BENCHMARK".center(W))
    print("═" * W)
    print(f"  Log file        : {logfile}")
    print(f"  Repetitions     : {metrics['repetitions']} batches × "
          f"{metrics['inner_loops_per_repetition']} inner runs")
    print(f"  Events processed: {metrics.get('event_count', 'N/A')} per run")
    print(f"  IP windows found: {metrics['ip_windows_detected']}")
    print("─" * W)
    print(f"  Detection Latency (avg) : {metrics['latency_ms_avg']:>10.4f} ms")
    print(f"  Detection Latency (min) : {metrics['latency_ms_min']:>10.4f} ms")
    print(f"  Detection Latency (max) : {metrics['latency_ms_max']:>10.4f} ms")
    print(f"  Throughput              : {metrics.get('throughput_events_per_sec', 0):>10.1f} events/sec")
    print(f"  CPU Utilization (avg)   : {metrics['cpu_pct_avg']:>10.2f} %")
    print(f"  Peak RAM Usage          : {metrics['ram_peak_mb']:>10.2f} MB")
    print("═" * W)
    print()
    print("  Interpretation:")
    print(f"  → Processing {metrics.get('event_count', 0)} log entries took only")
    print(f"    {metrics['latency_ms_avg']:.3f} ms (avg of {metrics['repetitions']} batches) using")
    print(f"    {metrics['ram_peak_mb']:.1f} MB RAM and {metrics['cpu_pct_avg']:.1f}% CPU —")
    print(f"    confirming suitability for resource-constrained SMB environments")
    print(f"    without specialized hardware.\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Benchmark LHBDF resource consumption")
    parser.add_argument("logfile", help="Path to authentication log file")
    parser.add_argument("--repetitions", type=int, default=5, help="Number of measurement batches to average (default: 5)")
    args = parser.parse_args()

    print(f"\n  Running {args.repetitions} benchmark repetitions on {args.logfile} ...")
    metrics = benchmark_pipeline(args.logfile, repetitions=args.repetitions)
    print_report(metrics, args.logfile)
