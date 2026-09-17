"""
LHBDF - Step 7: Evaluator
-----------------------------
Compares model predictions against a labeled ground-truth dataset
and computes Precision, Recall, F1-Score, False Positive Rate (FPR),
and Accuracy for:

  - LHBDF (Proposed)        — predicted ALERT when severity is HIGH or CRITICAL
  - Static Threshold         — predicted ALERT when failed_attempts >= threshold
  - Time-Window Frequency    — predicted ALERT when total_attempts >= threshold
  - Username Diversity       — predicted ALERT when unique_users >= threshold
  - Conventional Hybrid       — predicted ALERT when hybrid severity is HIGH or CRITICAL

Ground truth format (JSON):
  { "ip_address": 1 }   ← 1 = actual attack, 0 = normal activity
"""

import json
from modules.risk_scorer import is_alert_level


def load_ground_truth(path: str) -> dict:
    """Load ground-truth labels: {ip_address: 0|1}."""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return {k.strip().lower(): int(v) for k, v in data.items()}


def evaluate(scored: list[dict], baselines: list[dict], ground_truth: dict) -> dict:
    """
    Returns a dict of {model_name: {TP, FP, TN, FN, precision, recall, f1, fpr, accuracy}}
    """
    baseline_map = {b["ip_address"]: b for b in baselines}

    predictions = {
        "LHBDF (Proposed)":    {},
        "Static Threshold":    {},
        "Time-Window Freq.":   {},
        "Username Diversity":  {},
        "Conventional Hybrid": {},
    }

    for s in scored:
        ip = s["ip_address"]
        b = baseline_map.get(ip, {})
        predictions["LHBDF (Proposed)"][ip]    = 1 if is_alert_level(s["risk_level"]) else 0
        predictions["Static Threshold"][ip]    = 1 if b.get("static_threshold")        == "ALERT" else 0
        predictions["Time-Window Freq."][ip]   = 1 if b.get("time_window")             == "ALERT" else 0
        predictions["Username Diversity"][ip]  = 1 if b.get("username_diversity")      == "ALERT" else 0
        predictions["Conventional Hybrid"][ip] = 1 if is_alert_level(b.get("conventional_hybrid_level", "NORMAL")) else 0

    results = {}
    for model_name, preds in predictions.items():
        results[model_name] = _compute_metrics(preds, ground_truth)

    return results


def _compute_metrics(preds: dict, ground_truth: dict) -> dict:
    tp = fp = tn = fn = 0

    for ip, gt in ground_truth.items():
        # If an IP never produced a feature window, the model implicitly predicts "normal" (0)
        pred = preds.get(ip, 0)

        if pred == 1 and gt == 1:
            tp += 1
        elif pred == 1 and gt == 0:
            fp += 1
        elif pred == 0 and gt == 0:
            tn += 1
        else:  # pred == 0 and gt == 1
            fn += 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall    = tp / (tp + fn) if (tp + fn) else 0.0
    f1        = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    fpr       = fp / (fp + tn) if (fp + tn) else 0.0
    total     = tp + tn + fp + fn
    accuracy  = (tp + tn) / total if total else 0.0

    return {
        "TP": tp, "FP": fp, "TN": tn, "FN": fn,
        "precision": round(precision, 3),
        "recall":    round(recall, 3),
        "f1":        round(f1, 3),
        "fpr":       round(fpr, 3),
        "accuracy":  round(accuracy, 3),
    }
