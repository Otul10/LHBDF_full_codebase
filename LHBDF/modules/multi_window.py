"""
LHBDF - Multi-Window Detection
-----------------------------------
Runs feature extraction + risk scoring at three time scales to
catch attacks operating at different speeds:

  5 minutes  → Fast brute-force        (rapid repeated failures)
  1 hour     → Credential stuffing     (moderate-paced, many accounts)
  24 hours   → Low-and-slow attacks    (isolated attempts spread out)

A 5-minute window structurally CANNOT see two events that are hours
apart — they never co-occur inside any 5-minute slice. This module
re-runs the existing sliding-window extractor at each scale and keeps,
per IP, the single highest-risk finding plus which window size caught it.
"""

from modules.feature_extractor import extract_features
from modules.risk_scorer import score_all, is_alert_level

WINDOW_DEFINITIONS = [
    (5,    "5-Min (Fast Brute-Force)"),
    (60,   "1-Hour (Credential Stuffing)"),
    (1440, "24-Hour (Low-and-Slow)"),
]


def analyze_multi_window(entries: list[dict]) -> dict:
    """
    Runs detection at all 3 window scales.

    Returns:
      {
        "per_window": {label: {ip: scored_dict}},   # full results at each scale
        "best":       [scored_dict, ...]             # best (max risk) finding per IP
      }
    """
    per_window = {}
    best_by_ip = {}

    for window_minutes, label in WINDOW_DEFINITIONS:
        features = extract_features(entries, window_minutes=window_minutes)
        scored = score_all(features)
        per_window[label] = {s["ip_address"]: s for s in scored}

        for s in scored:
            ip = s["ip_address"]
            enriched = {**s, "detected_at_window": label, "window_minutes": window_minutes}
            if ip not in best_by_ip or s["risk_score"] > best_by_ip[ip]["risk_score"]:
                best_by_ip[ip] = enriched

    best = sorted(best_by_ip.values(), key=lambda x: x["risk_score"], reverse=True)
    return {"per_window": per_window, "best": best}


def evaluate_multi_window(entries: list[dict], ground_truth: dict) -> dict:
    """
    Compares detection performance using ONLY the 5-min window vs.
    the full multi-window approach (best-of-3), against ground truth.
    Returns metrics for: '5-min only', '1-hour only', '24-hour only',
    and 'Multi-Window (best-of-3)'.
    """
    result = analyze_multi_window(entries)
    per_window = result["per_window"]
    best = {s["ip_address"]: s for s in result["best"]}

    metrics = {}
    for label in per_window:
        preds = {ip: (1 if is_alert_level(s["risk_level"]) else 0)
                  for ip, s in per_window[label].items()}
        metrics[label] = _compute_metrics(preds, ground_truth)

    multi_preds = {ip: (1 if is_alert_level(s["risk_level"]) else 0)
                    for ip, s in best.items()}
    metrics["Multi-Window (best-of-3)"] = _compute_metrics(multi_preds, ground_truth)

    return metrics


def _compute_metrics(preds: dict, ground_truth: dict) -> dict:
    tp = fp = tn = fn = 0
    for ip, gt in ground_truth.items():
        pred = preds.get(ip, 0)  # IP absent from this window's results = "not flagged"
        if pred == 1 and gt == 1: tp += 1
        elif pred == 1 and gt == 0: fp += 1
        elif pred == 0 and gt == 0: tn += 1
        else: fn += 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall    = tp / (tp + fn) if (tp + fn) else 0.0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr       = fp / (fp + tn) if (fp + tn) else 0.0

    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": round(precision, 3),
        "recall":    round(recall, 3),
        "f1":        round(f1, 3),
        "fpr":       round(fpr, 3),
    }
