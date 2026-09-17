#!/usr/bin/env python3
"""
LHBDF — Lightweight Hybrid Behavioral Detection Framework
==========================================================
Detects brute-force and credential stuffing attacks
from authentication log files using behavioral risk scoring.

Usage:
  python main.py logs/sample_auth.csv
  python main.py logs/your_log.json
"""

import sys
import os

from modules.log_parser        import parse_log
from modules.feature_extractor import extract_features
from modules.risk_scorer       import score_all
from modules.alert_generator   import generate_alerts
from modules.baseline_models   import evaluate_baselines
from modules.comparator        import compare_models


def run(logfile: str) -> None:
    print()
    print("  ╔══════════════════════════════════════════════╗")
    print("  ║         LHBDF — Starting Analysis...         ║")
    print("  ╚══════════════════════════════════════════════╝")

    print(f"\n  [1/5] Parsing log file      → {logfile}")
    entries = parse_log(logfile)
    print(f"        {len(entries)} valid entries loaded.")

    print(f"  [2/5] Extracting features   → 5-min sliding windows per IP")
    features = extract_features(entries)
    print(f"        {len(features)} IP window(s) identified.")

    print(f"  [3/5] Calculating risk scores")
    scored = score_all(features)
    print(f"        {len(scored)} IP(s) scored.")

    print(f"  [4/5] Generating alerts...\n")
    generate_alerts(scored)

    print(f"  [5/5] Comparing with baseline models...")
    baselines = evaluate_baselines(features)
    compare_models(scored, baselines)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("\n  Usage  : python main.py <logfile>")
        print("  Example: python main.py logs/sample_auth.csv\n")
        sys.exit(1)

    logfile = sys.argv[1]
    run(logfile)
