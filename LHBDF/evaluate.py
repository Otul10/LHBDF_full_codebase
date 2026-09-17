#!/usr/bin/env python3
"""
LHBDF — Step 7: Evaluation Runner
=====================================
Runs the full detection pipeline against a LABELED dataset and
computes Precision, Recall, F1-Score, False Positive Rate (FPR),
and Accuracy for LHBDF and all 4 baseline models.

Usage:
  python evaluate.py logs/labeled_auth.csv logs/ground_truth.json
"""

import sys

from modules.log_parser        import parse_log
from modules.feature_extractor import extract_features
from modules.risk_scorer       import score_all
from modules.baseline_models   import evaluate_baselines
from modules.evaluator          import load_ground_truth, evaluate
from modules.metrics_report     import print_metrics_table


def run(logfile: str, gt_file: str) -> None:
    print()
    print("  ╔══════════════════════════════════════════════╗")
    print("  ║      LHBDF — Evaluation Mode (Labeled)       ║")
    print("  ╚══════════════════════════════════════════════╝")

    print(f"\n  [1/4] Parsing labeled log    → {logfile}")
    entries = parse_log(logfile)
    print(f"        {len(entries)} valid entries loaded.")

    print(f"  [2/4] Extracting features    → 5-min sliding windows per IP")
    features = extract_features(entries)
    print(f"        {len(features)} IP window(s) identified.")

    print(f"  [3/4] Scoring (LHBDF + baselines)")
    scored    = score_all(features)
    baselines = evaluate_baselines(features)

    print(f"  [4/4] Loading ground truth    → {gt_file}")
    ground_truth = load_ground_truth(gt_file)
    attack_ips = sum(ground_truth.values())
    print(f"        {len(ground_truth)} labeled IP(s) "
          f"({attack_ips} attack / {len(ground_truth) - attack_ips} normal)")

    results = evaluate(scored, baselines, ground_truth)
    print_metrics_table(results, total_ips=len(ground_truth), attack_ips=attack_ips)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("\n  Usage  : python evaluate.py <logfile> <ground_truth.json>")
        print("  Example: python evaluate.py logs/labeled_auth.csv logs/ground_truth.json\n")
        sys.exit(1)

    run(sys.argv[1], sys.argv[2])
