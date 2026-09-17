#!/usr/bin/env python3
"""
LHBDF — ROC Curve & AUC Runner
===================================
Sweeps the risk-score threshold from 0.0 to 1.0 and plots the ROC
curve for LHBDF (Proposed) and Conventional Hybrid, with the 3
binary baseline models shown as single operating points for
visual comparison. Saves a PNG figure for thesis use.

Usage:
  python roc_curve.py logs/large_auth.csv logs/large_ground_truth.json
"""

import sys

from modules.log_parser        import parse_log
from modules.feature_extractor import extract_features
from modules.risk_scorer       import score_all
from modules.baseline_models   import evaluate_baselines
from modules.evaluator         import load_ground_truth
from modules.roc_analysis      import sweep_thresholds, binary_operating_point
from modules.roc_report        import plot_roc_curves, print_roc_summary


def run(logfile: str, gt_file: str) -> None:
    print()
    print("  ╔══════════════════════════════════════════════╗")
    print("  ║      LHBDF — ROC Curve & AUC Analysis        ║")
    print("  ╚══════════════════════════════════════════════╝")

    print(f"\n  [1/4] Parsing log file        → {logfile}")
    entries = parse_log(logfile)
    print(f"        {len(entries)} valid entries loaded.")

    print(f"  [2/4] Loading ground truth     → {gt_file}")
    ground_truth = load_ground_truth(gt_file)
    attack_ips = sum(ground_truth.values())
    print(f"        {len(ground_truth)} labeled IP(s) "
          f"({attack_ips} attack / {len(ground_truth) - attack_ips} normal)")

    print(f"  [3/4] Scoring (LHBDF + baselines)...")
    features  = extract_features(entries)
    scored    = score_all(features)
    baselines = evaluate_baselines(features)

    lhbdf_scores  = {s["ip_address"]: s["risk_score"] for s in scored}
    hybrid_scores = {b["ip_address"]: b["conventional_hybrid_score"] for b in baselines}

    static_preds   = {b["ip_address"]: (1 if b["static_threshold"]   == "ALERT" else 0) for b in baselines}
    timewin_preds  = {b["ip_address"]: (1 if b["time_window"]        == "ALERT" else 0) for b in baselines}
    diversity_preds = {b["ip_address"]: (1 if b["username_diversity"] == "ALERT" else 0) for b in baselines}

    print(f"  [4/4] Sweeping thresholds (101 steps) and computing AUC...")
    curves = {
        "LHBDF (Proposed)":    sweep_thresholds(lhbdf_scores, ground_truth),
        "Conventional Hybrid": sweep_thresholds(hybrid_scores, ground_truth),
    }
    operating_points = {
        "Static Threshold":   binary_operating_point(static_preds, ground_truth),
        "Time-Window Freq.":  binary_operating_point(timewin_preds, ground_truth),
        "Username Diversity": binary_operating_point(diversity_preds, ground_truth),
    }

    png_path = plot_roc_curves(curves, operating_points)
    print_roc_summary(curves, operating_points, total_ips=len(ground_truth),
                       attack_ips=attack_ips, png_path=png_path)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("\n  Usage  : python roc_curve.py <logfile> <ground_truth.json>")
        print("  Example: python roc_curve.py logs/large_auth.csv logs/large_ground_truth.json\n")
        sys.exit(1)

    run(sys.argv[1], sys.argv[2])
