#!/usr/bin/env python3
"""
LHBDF — Real-World Hybrid Evaluation (Step 20)
====================================================
Addresses the "dataset realism" concern raised in peer review by
evaluating LHBDF on a HYBRID dataset: genuine real-world SSH server
traffic (LogHub OpenSSH_2k.log; Zhu et al., ICSE 2019) with LHBDF's
controlled, labeled attack/normal scenarios injected on top.

Runs TWO evaluations:
  1. PRIMARY  — strict Precision/Recall/F1 against the 104 injected,
                labeled IPs (same methodology as the fully-synthetic
                dataset, for direct comparison).
  2. QUALITATIVE — supplementary check of how LHBDF scores the 24
                REAL (unlabeled) attacking IPs already present in the
                real log, using the raw log content as informal
                evidence of ground truth.

Usage:
  python real_world_evaluation.py
  (uses logs/hybrid_auth.csv, logs/hybrid_ground_truth.json,
   logs/hybrid_background_ips.json by default)
"""

import sys
import json

from modules.log_parser          import parse_log
from modules.feature_extractor   import extract_features
from modules.risk_scorer         import score_all
from modules.baseline_models     import evaluate_baselines
from modules.evaluator           import load_ground_truth, evaluate
from modules.metrics_report      import print_metrics_table
from modules.multi_window        import analyze_multi_window
from modules.background_check    import check_background_ips
from modules.background_check_report import print_background_check


def run(logfile: str, gt_file: str, bg_file: str) -> None:
    print()
    print("  ╔══════════════════════════════════════════════╗")
    print("  ║   LHBDF — Real-World Hybrid Evaluation       ║")
    print("  ║           (Step 20)                          ║")
    print("  ╚══════════════════════════════════════════════╝")
    print()
    print("  Dataset: real LogHub OpenSSH_2k.log background + injected")
    print("           labeled attack/normal scenarios (104 IPs)")

    print(f"\n  [1/5] Parsing hybrid log      → {logfile}")
    entries = parse_log(logfile)
    print(f"        {len(entries)} total entries (real + injected).")

    print(f"  [2/5] Loading ground truth     → {gt_file}")
    ground_truth = load_ground_truth(gt_file)
    attack_ips = sum(ground_truth.values())
    print(f"        {len(ground_truth)} labeled (injected) IP(s) "
          f"({attack_ips} attack / {len(ground_truth) - attack_ips} normal)")

    with open(bg_file) as f:
        bg_ips = json.load(f)["background_ips"]
    print(f"        {len(bg_ips)} real background IP(s) — unlabeled")

    print(f"\n  [3/5] PRIMARY EVALUATION (strict, on labeled IPs only)")
    features  = extract_features(entries)
    scored    = score_all(features)
    baselines = evaluate_baselines(features)
    metrics   = evaluate(scored, baselines, ground_truth)
    print_metrics_table(metrics, total_ips=len(ground_truth), attack_ips=attack_ips)

    print(f"  [4/5] Building multi-window scores for background IP fallback...")
    mw_result = analyze_multi_window(entries)
    scored_by_scale = {
        "5-min":        {s["ip_address"]: s for s in scored},
        "multi_window": {s["ip_address"]: s for s in mw_result["best"]},
    }

    print(f"  [5/5] QUALITATIVE CHECK (real background IPs, unlabeled)")
    bg_results = check_background_ips(scored_by_scale, bg_ips)
    print_background_check(bg_results)


if __name__ == "__main__":
    logfile = sys.argv[1] if len(sys.argv) > 1 else "logs/hybrid_auth.csv"
    gt_file = sys.argv[2] if len(sys.argv) > 2 else "logs/hybrid_ground_truth.json"
    bg_file = sys.argv[3] if len(sys.argv) > 3 else "logs/hybrid_background_ips.json"
    run(logfile, gt_file, bg_file)
