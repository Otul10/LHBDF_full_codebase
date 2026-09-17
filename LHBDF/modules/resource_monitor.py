"""
LHBDF - Resource Consumption Monitor
----------------------------------------
Measures the computational overhead of the LHBDF pipeline,
directly supporting the "lightweight" claim in the proposal
(Section 8.6 — Computational Overhead).

Metrics captured:
  - Wall-clock detection latency (ms)
  - CPU utilization (%) — computed from precise process CPU-time
    deltas (user + system), NOT polled cpu_percent() samples.
    Polling is unreliable for sub-100ms workloads; a CPU-time delta
    divided by wall-time delta is exact regardless of duration.
  - Peak RAM usage (MB) — process RSS (resident set size)
  - Throughput (log events processed per second)
"""

import time
import psutil
import os


class ResourceMonitor:
    """
    Context-manager resource monitor using precise CPU-time deltas
    (robust even for very fast, sub-millisecond code blocks).

    Usage:
        with ResourceMonitor() as mon:
            ... do work ...
        metrics = mon.report(event_count=596)
    """

    def __init__(self):
        self._process = psutil.Process(os.getpid())

    def __enter__(self):
        self._mem_before = self._process.memory_info().rss
        self._cpu_before = self._process.cpu_times()
        self.start_time = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.end_time = time.perf_counter()
        self._cpu_after = self._process.cpu_times()
        self._mem_after = self._process.memory_info().rss
        return False

    @property
    def elapsed_ms(self) -> float:
        return (self.end_time - self.start_time) * 1000

    def report(self, event_count: int = None) -> dict:
        wall_time_s = max(self.end_time - self.start_time, 1e-9)
        cpu_time_s = (
            (self._cpu_after.user - self._cpu_before.user) +
            (self._cpu_after.system - self._cpu_before.system)
        )
        cpu_pct = round((cpu_time_s / wall_time_s) * 100, 2)
        ram_mb  = round(max(self._mem_before, self._mem_after) / (1024 * 1024), 2)

        result = {
            "latency_ms": round(self.elapsed_ms, 3),
            "cpu_pct":    cpu_pct,
            "ram_peak_mb": ram_mb,
        }
        if event_count is not None and self.elapsed_ms > 0:
            result["throughput_events_per_sec"] = round(event_count / (self.elapsed_ms / 1000), 1)
            result["event_count"] = event_count
        return result


def benchmark_pipeline(logfile: str, repetitions: int = 5, target_batch_ms: float = 200.0) -> dict:
    """
    Runs the full LHBDF pipeline (parse -> extract -> score) repeatedly
    on the same log file and returns averaged resource metrics.

    Each "repetition" is itself a BATCH of many inner iterations run
    inside a single ResourceMonitor context. This matters because OS
    process CPU-time accounting has limited resolution (often several
    milliseconds); timing a single sub-millisecond pipeline run directly
    produces unstable, inflated CPU% readings due to that quantization.
    Batching enough inner iterations to reach `target_batch_ms` of total
    wall time makes the measurement stable regardless of dataset size,
    then divides back down to a reliable per-run latency figure.
    """
    from modules.log_parser import parse_log
    from modules.feature_extractor import extract_features
    from modules.risk_scorer import score_all

    # Calibration run: estimate single-pass latency to size the batch
    t0 = time.perf_counter()
    entries  = parse_log(logfile)
    features = extract_features(entries)
    scored   = score_all(features)
    single_pass_ms = max((time.perf_counter() - t0) * 1000, 0.001)

    inner_loops = max(1, int(target_batch_ms / single_pass_ms))

    batch_results = []
    ip_windows = len(scored)
    event_count = len(entries)

    for _ in range(repetitions):
        with ResourceMonitor() as mon:
            for _ in range(inner_loops):
                entries  = parse_log(logfile)
                features = extract_features(entries)
                scored   = score_all(features)
        batch = mon.report(event_count=len(entries) * inner_loops)
        # Convert batch totals into reliable per-single-run figures
        batch_results.append({
            "latency_ms": batch["latency_ms"] / inner_loops,
            "cpu_pct":    batch["cpu_pct"],          # CPU% is already a ratio, no scaling needed
            "ram_peak_mb": batch["ram_peak_mb"],
        })

    latencies = [r["latency_ms"] for r in batch_results]
    cpu_vals  = [r["cpu_pct"] for r in batch_results]
    ram_vals  = [r["ram_peak_mb"] for r in batch_results]

    avg_latency_ms = sum(latencies) / len(latencies)

    return {
        "latency_ms_avg": round(avg_latency_ms, 4),
        "latency_ms_min": round(min(latencies), 4),
        "latency_ms_max": round(max(latencies), 4),
        "cpu_pct_avg":    round(sum(cpu_vals) / len(cpu_vals), 2),
        "ram_peak_mb":    round(max(ram_vals), 2),
        "throughput_events_per_sec": round(event_count / (avg_latency_ms / 1000), 1),
        "repetitions": repetitions,
        "inner_loops_per_repetition": inner_loops,
        "event_count": event_count,
        "ip_windows_detected": ip_windows,
    }
