#!/usr/bin/env python3
"""
LHBDF — Statistical Significance Testing Runner
=====================================================
Tests whether LHBDF's F1-score improvement over each baseline model
is statistically significant, using bootstrap resampling (since only
one fixed evaluation run/test set is available) followed by a paired
t-test and Wilcoxon signed-rank test on the resulting F1 distributions.

Usage:
  python significance_testing.py logs/large_auth.csv logs/large_ground_truth.json
  python significance_testing.py logs/large_auth.csv logs/large_ground_truth.json --bootstrap 2000
"""

import sys
import argparse

from modules.log_parser        import parse_log
from modules.feature_extractor import extract_features
from modules.risk_scorer       import score_all, is_alert_level
from modules.baseline_models   import evaluate_baselines
from modules.evaluator         import load_ground_truth
from modules.significance_test import bootstrap_f1_distributions, run_significance_tests
from modules.significance_report import print_significance_results


def run(logfile: str, gt_file: str, n_bootstrap: int) -> None:
    print()
    print("  ╔══════════════════════════════════════════════╗")
    print("  ║  LHBDF — Statistical Significance Testing    ║")
    print("  ╚══════════════════════════════════════════════╝")

    print(f"\n  [1/4] Parsing log file        → {logfile}")
    entries = parse_log(logfile)
    print(f"        {len(entries)} valid entries loaded.")

    print(f"  [2/4] Loading ground truth     → {gt_file}")
    ground_truth = load_ground_truth(gt_file)
    print(f"        {len(ground_truth)} labeled IP(s).")

    print(f"  [3/4] Scoring (LHBDF + 4 baselines)...")
    features  = extract_features(entries)
    scored    = score_all(features)
    baselines = evaluate_baselines(features)

    predictions = {
        "LHBDF (Proposed)":    {s["ip_address"]: (1 if is_alert_level(s["risk_level"]) else 0) for s in scored},
        "Static Threshold":    {b["ip_address"]: (1 if b["static_threshold"]   == "ALERT" else 0) for b in baselines},
        "Time-Window Freq.":   {b["ip_address"]: (1 if b["time_window"]        == "ALERT" else 0) for b in baselines},
        "Username Diversity":  {b["ip_address"]: (1 if b["username_diversity"] == "ALERT" else 0) for b in baselines},
        "Conventional Hybrid": {b["ip_address"]: (1 if is_alert_level(b["conventional_hybrid_level"]) else 0) for b in baselines},
    }

    print(f"  [4/4] Running {n_bootstrap} bootstrap resamples + paired t-test / Wilcoxon...")
    distributions = bootstrap_f1_distributions(predictions, ground_truth, n_bootstrap=n_bootstrap)
    results = run_significance_tests(distributions, reference_model="LHBDF (Proposed)")

    print_significance_results(results, reference_model="LHBDF (Proposed)", n_bootstrap=n_bootstrap)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LHBDF statistical significance testing")
    parser.add_argument("logfile")
    parser.add_argument("ground_truth")
    parser.add_argument("--bootstrap", type=int, default=1000, help="Number of bootstrap resamples (default: 1000)")
    args = parser.parse_args()

    run(args.logfile, args.ground_truth, args.bootstrap)
