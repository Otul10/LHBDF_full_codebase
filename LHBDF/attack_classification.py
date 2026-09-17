#!/usr/bin/env python3
"""
LHBDF — Attack Classification Module
=========================================
Classifies each detected alert into a specific attack type using
all 5 behavioral indicators (F, U, V, T, S) via rule-based logic:

  BRUTE_FORCE          — High failures, single/few accounts
  CREDENTIAL_STUFFING  — High diversity, moderate failures
  STOLEN_CRED_STUFFING — Near-zero failures, high success ratio
  BOT_PATTERN          — Very regular timing, automated tool
  LOW_AND_SLOW         — Sparse events, evasion of rate limits
  NORMAL               — Below alert threshold

Each classification includes a confidence level (HIGH/MEDIUM/LOW) and
a human-readable evidence string explaining which indicators drove the
decision — full explainability with no black-box inference.

Usage:
  python attack_classification.py logs/large_auth.csv logs/large_ground_truth.json
"""

import sys

from modules.log_parser          import parse_log
from modules.feature_extractor   import extract_features
from modules.risk_scorer         import score_all
from modules.evaluator           import load_ground_truth
from modules.attack_classifier   import classify_all
from modules.classification_report import evaluate_classification


def run(logfile: str, gt_file: str) -> None:
    print()
    print("  ╔══════════════════════════════════════════════╗")
    print("  ║    LHBDF — Attack Classification Mode        ║")
    print("  ╚══════════════════════════════════════════════╝")

    print(f"\n  [1/4] Parsing log file        → {logfile}")
    entries = parse_log(logfile)
    print(f"        {len(entries)} valid entries loaded.")

    print(f"  [2/4] Loading ground truth     → {gt_file}")
    ground_truth = load_ground_truth(gt_file)
    attack_ips   = sum(ground_truth.values())
    print(f"        {len(ground_truth)} labeled IP(s) "
          f"({attack_ips} attack / {len(ground_truth) - attack_ips} normal)")

    print(f"  [3/4] Scoring (5-indicator LHBDF formula)...")
    features   = extract_features(entries)
    scored     = score_all(features)
    alerts     = [s for s in scored if s.get("is_alert")]
    suspicious = [s for s in scored if s["risk_level"] == "SUSPICIOUS"]
    print(f"        {len(alerts)} alert(s) detected  "
          f"({sum(1 for s in scored if s['risk_level']=='CRITICAL')} CRITICAL / "
          f"{sum(1 for s in scored if s['risk_level']=='HIGH')} HIGH)")
    print(f"        {len(suspicious)} SUSPICIOUS IP(s) flagged for monitoring")

    print(f"  [4/4] Classifying attack types...")
    classified = classify_all(scored)
    evaluate_classification(classified, ground_truth)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("\n  Usage  : python attack_classification.py <logfile> <ground_truth.json>")
        print("  Example: python attack_classification.py logs/large_auth.csv logs/large_ground_truth.json\n")
        sys.exit(1)

    run(sys.argv[1], sys.argv[2])
