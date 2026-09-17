#!/usr/bin/env python3
"""
LHBDF — Adaptive Threshold Runner
======================================
Calibrates thresholds from a baseline of known-normal authentication
behavior (μ + 2σ per indicator), then compares detection performance
against the fixed, hand-picked thresholds.

In a real deployment, the baseline would come from an initial
known-clean monitoring period. Here, it is built from the dataset's
own ground-truth-normal IPs to simulate that calibration period.

Usage:
  python adaptive_threshold_demo.py logs/large_auth.csv logs/large_ground_truth.json
"""

import sys

from modules.log_parser            import parse_log
from modules.evaluator              import load_ground_truth, _compute_metrics
from modules.risk_scorer            import score_all, is_alert_level
from modules.adaptive_threshold     import calibrate_thresholds, extract_features_adaptive
from modules.feature_extractor      import extract_features
from modules.adaptive_threshold_report import print_calibration, print_comparison


def run(logfile: str, gt_file: str) -> None:
    print()
    print("  ╔══════════════════════════════════════════════╗")
    print("  ║      LHBDF — Adaptive Threshold Mode         ║")
    print("  ╚══════════════════════════════════════════════╝")

    print(f"\n  [1/5] Parsing log file        → {logfile}")
    entries = parse_log(logfile)
    print(f"        {len(entries)} valid entries loaded.")

    print(f"  [2/5] Loading ground truth     → {gt_file}")
    ground_truth = load_ground_truth(gt_file)
    attack_ips = sum(ground_truth.values())
    print(f"        {len(ground_truth)} labeled IP(s) "
          f"({attack_ips} attack / {len(ground_truth) - attack_ips} normal)")

    print(f"  [3/5] Building calibration baseline from known-normal IPs...")
    normal_ips = {ip for ip, gt in ground_truth.items() if gt == 0}
    baseline_entries = [e for e in entries if e["ip_address"] in normal_ips]
    print(f"        {len(baseline_entries)} baseline entries from {len(normal_ips)} normal IPs")

    print(f"  [4/5] Calibrating thresholds (μ + 2σ)...")
    thresholds = calibrate_thresholds(baseline_entries)
    print_calibration(thresholds)

    print(f"  [5/5] Comparing Fixed vs. Adaptive detection performance...")

    # Fixed thresholds (existing defaults)
    fixed_features = extract_features(entries)
    fixed_scored   = score_all(fixed_features)
    fixed_preds = {s["ip_address"]: (1 if is_alert_level(s["risk_level"]) else 0) for s in fixed_scored}
    fixed_metrics = _compute_metrics(fixed_preds, ground_truth)

    # Adaptive thresholds
    adaptive_features = extract_features_adaptive(entries, thresholds)
    adaptive_scored    = score_all(adaptive_features)
    adaptive_preds = {s["ip_address"]: (1 if is_alert_level(s["risk_level"]) else 0) for s in adaptive_scored}
    adaptive_metrics = _compute_metrics(adaptive_preds, ground_truth)

    print_comparison(fixed_metrics, adaptive_metrics, total_ips=len(ground_truth), attack_ips=attack_ips)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("\n  Usage  : python adaptive_threshold_demo.py <logfile> <ground_truth.json>")
        print("  Example: python adaptive_threshold_demo.py logs/large_auth.csv logs/large_ground_truth.json\n")
        sys.exit(1)

    run(sys.argv[1], sys.argv[2])
