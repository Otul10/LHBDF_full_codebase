#!/usr/bin/env python3
"""
LHBDF — Multi-Window Detection Runner
==========================================
Compares detection performance using a single 5-minute window vs.
the full multi-window approach (5-min + 1-hour + 24-hour, best-of-3).

Demonstrates why multi-window analysis matters: fast brute-force
attacks are caught at 5 minutes, credential stuffing at 1 hour, and
"low-and-slow" attacks (isolated attempts spread across a full day)
are structurally invisible to short windows and only caught at 24 hours.

Usage:
  python multi_window_analysis.py logs/large_auth.csv logs/large_ground_truth.json
"""

import sys

from modules.log_parser      import parse_log
from modules.evaluator       import load_ground_truth
from modules.multi_window    import evaluate_multi_window
from modules.multi_window_report import print_multi_window_metrics


def run(logfile: str, gt_file: str) -> None:
    print()
    print("  ╔══════════════════════════════════════════════╗")
    print("  ║     LHBDF — Multi-Window Detection Mode      ║")
    print("  ╚══════════════════════════════════════════════╝")

    print(f"\n  [1/3] Parsing labeled log    → {logfile}")
    entries = parse_log(logfile)
    print(f"        {len(entries)} valid entries loaded.")

    print(f"  [2/3] Loading ground truth    → {gt_file}")
    ground_truth = load_ground_truth(gt_file)
    attack_ips = sum(ground_truth.values())
    print(f"        {len(ground_truth)} labeled IP(s) "
          f"({attack_ips} attack / {len(ground_truth) - attack_ips} normal)")

    print(f"\n  [3/3] Running detection at 5-min, 1-hour, and 24-hour scales...")
    metrics = evaluate_multi_window(entries, ground_truth)
    print_multi_window_metrics(metrics, total_ips=len(ground_truth), attack_ips=attack_ips)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("\n  Usage  : python multi_window_analysis.py <logfile> <ground_truth.json>")
        print("  Example: python multi_window_analysis.py logs/large_auth.csv logs/large_ground_truth.json\n")
        sys.exit(1)

    run(sys.argv[1], sys.argv[2])
