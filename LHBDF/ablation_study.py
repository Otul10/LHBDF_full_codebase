#!/usr/bin/env python3
"""
LHBDF — Ablation Study Runner
=================================
Tests 14 indicator-weight combinations against a labeled dataset
to determine which behavioral indicators contribute most to
detection performance. Directly answers RQ4.

Usage:
  python ablation_study.py logs/large_auth.csv logs/large_ground_truth.json
"""

import sys

from modules.log_parser        import parse_log
from modules.feature_extractor import extract_features
from modules.evaluator         import load_ground_truth
from modules.ablation          import run_ablation
from modules.ablation_report   import print_ablation_table


def run(logfile: str, gt_file: str) -> None:
    print()
    print("  ╔══════════════════════════════════════════════╗")
    print("  ║         LHBDF — Ablation Study Mode          ║")
    print("  ╚══════════════════════════════════════════════╝")

    print(f"\n  [1/3] Parsing labeled log    → {logfile}")
    entries = parse_log(logfile)
    print(f"        {len(entries)} valid entries loaded.")

    print(f"  [2/3] Extracting features    → 5-min sliding windows per IP")
    features = extract_features(entries)
    print(f"        {len(features)} IP window(s) identified.")

    print(f"  [3/3] Loading ground truth    → {gt_file}")
    ground_truth = load_ground_truth(gt_file)
    attack_ips = sum(ground_truth.values())
    print(f"        {len(ground_truth)} labeled IP(s) "
          f"({attack_ips} attack / {len(ground_truth) - attack_ips} normal)")
    print(f"\n  Testing 14 indicator combinations...")

    results = run_ablation(features, ground_truth)
    print_ablation_table(results, total_ips=len(ground_truth), attack_ips=attack_ips)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("\n  Usage  : python ablation_study.py <logfile> <ground_truth.json>")
        print("  Example: python ablation_study.py logs/large_auth.csv logs/large_ground_truth.json\n")
        sys.exit(1)

    run(sys.argv[1], sys.argv[2])
