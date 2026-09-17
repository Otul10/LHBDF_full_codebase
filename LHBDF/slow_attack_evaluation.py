"""
LHBDF - Slow-Attack Detector Evaluation
------------------------------------------
Compares three detection configurations against the labeled dataset:

  1. 5-Min Fast Path Only         (existing Table 5.1 baseline)
  2. Multi-Window Best-of-3       (existing Table 5.2 approach)
  3. 5-Min Fast Path + Dedicated Low-and-Slow Detector   (NEW)

Usage:
    python slow_attack_evaluation.py <logfile> <ground_truth.json>
"""

import sys
import json

from modules.log_parser import parse_log
from modules.feature_extractor import extract_features
from modules.risk_scorer import score_all
from modules.multi_window import analyze_multi_window
from modules.slow_attack_detector import detect_slow_attacks, merge_with_fast_path


def evaluate(scored_list, gt_raw):
    best = {}
    for s in scored_list:
        ip = s["ip_address"]
        if ip not in best or s["risk_score"] > best[ip]["risk_score"]:
            best[ip] = s
    tp = fp = tn = fn = 0
    for ip, truth in gt_raw.items():
        alerted = best.get(ip, {}).get("is_alert", False)
        if truth == 1 and alerted:
            tp += 1
        elif truth == 1 and not alerted:
            fn += 1
        elif truth == 0 and alerted:
            fp += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return {
        "TP": tp, "FP": fp, "TN": tn, "FN": fn,
        "Precision": round(precision, 4), "Recall": round(recall, 4),
        "F1": round(f1, 4), "FPR": round(fpr, 4),
    }


def main():
    if len(sys.argv) != 3:
        print("\n  Usage  : python slow_attack_evaluation.py <logfile> <ground_truth.json>")
        print("  Example: python slow_attack_evaluation.py logs/large_auth.csv logs/large_ground_truth.json\n")
        return

    logfile, gt_file = sys.argv[1], sys.argv[2]
    entries = parse_log(logfile)
    gt_raw = json.load(open(gt_file))

    results = {}

    features_5min = extract_features(entries, window_minutes=5)
    scored_5min = score_all(features_5min)
    results["5-Min Fast Path Only"] = evaluate(scored_5min, gt_raw)

    mw = analyze_multi_window(entries)
    results["Multi-Window Best-of-3"] = evaluate(mw["best"], gt_raw)

    slow_findings = detect_slow_attacks(entries)
    combined = merge_with_fast_path(scored_5min, slow_findings)
    results["5-Min + Slow-Attack Detector (NEW)"] = evaluate(combined, gt_raw)

    header = f"{'Configuration':38s} {'TP':>4s} {'FP':>4s} {'FN':>4s} {'Precision':>10s} {'Recall':>8s} {'F1':>8s} {'FPR':>8s}"
    print("\n" + header)
    print("-" * len(header))
    for name, m in results.items():
        print(f"{name:38s} {m['TP']:>4d} {m['FP']:>4d} {m['FN']:>4d} "
              f"{m['Precision']:>10.4f} {m['Recall']:>8.4f} {m['F1']:>8.4f} {m['FPR']:>8.4f}")
    print()

    if slow_findings:
        print(f"Slow-attack detector flagged {len(slow_findings)} account(s) directly:")
        for f in slow_findings:
            print(f"  {f['ip_address']:16s} -> '{f['username']}'  "
                  f"risk={f['risk_score']:.3f} ({f['severity']})  {f['evidence']}")
        print()


if __name__ == "__main__":
    main()
