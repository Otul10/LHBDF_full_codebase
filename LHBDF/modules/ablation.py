"""
LHBDF - Ablation Study Module
================================
Tests indicator combinations to show which behavioral indicators
contribute most to detection performance. Step 17 update: adds
S (Success Ratio) as a 5th indicator, plus new S-inclusive combinations
(S alone, F+S, U+V+S, and the updated 5-indicator full-hybrid variants).

Combinations tested:
  Single   : F, U, V, T, S only
  Pairwise : F+U, F+T, U+T, F+V, F+S, U+S
  Triple   : F+U+V, F+U+T, F+V+T, U+V+T, U+V+S
  Full     : LHBDF (5-weighted), Equal Hybrid (5 equal), legacy 4-only variants

IMPORTANT: weights below are used EXACTLY as given (NOT re-normalized
to sum to 1.0). The "LHBDF — Proposed Weights" row uses the literal
production weights from modules/risk_scorer.py (0.35/0.25/0.25/0.15/0.10,
summing to 1.10) with the same min(score, 1.0) cap applied -- this is
deliberate so this row reproduces the production formula's behavior
EXACTLY rather than an approximation. An earlier version of this module
normalized the LHBDF weights to sum to 1.0, which silently changed
several classification outcomes versus production (verified: one
stealthy brute-force case flipped from HIGH/0.613 under production to
SUSPICIOUS/0.557 under the normalized version) -- fixed by using the
raw production weights plus the same cap for every combination.
Prediction threshold: risk_score >= 0.60 → ATTACK
"""

COMBINATIONS = {
    # ── Single indicators ─────────────────────────────────
    "F only  (Failed Login)":    {"f": 1.00, "u": 0.00, "v": 0.00, "t": 0.00, "s": 0.00},
    "U only  (Username Div.)":   {"f": 0.00, "u": 1.00, "v": 0.00, "t": 0.00, "s": 0.00},
    "V only  (Login Velocity)":  {"f": 0.00, "u": 0.00, "v": 1.00, "t": 0.00, "s": 0.00},
    "T only  (Temporal Score)":  {"f": 0.00, "u": 0.00, "v": 0.00, "t": 1.00, "s": 0.00},
    "S only  (Success Ratio)":   {"f": 0.00, "u": 0.00, "v": 0.00, "t": 0.00, "s": 1.00},
    # ── Pairwise ──────────────────────────────────────────
    "F + U":                     {"f": 0.50, "u": 0.50, "v": 0.00, "t": 0.00, "s": 0.00},
    "F + V":                     {"f": 0.50, "u": 0.00, "v": 0.50, "t": 0.00, "s": 0.00},
    "F + T":                     {"f": 0.50, "u": 0.00, "v": 0.00, "t": 0.50, "s": 0.00},
    "U + T":                     {"f": 0.00, "u": 0.50, "v": 0.00, "t": 0.50, "s": 0.00},
    "F + S":                     {"f": 0.50, "u": 0.00, "v": 0.00, "t": 0.00, "s": 0.50},
    "U + S":                     {"f": 0.00, "u": 0.50, "v": 0.00, "t": 0.00, "s": 0.50},
    # ── Triple ────────────────────────────────────────────
    "F + U + V  (no Temporal/S)":  {"f": 0.33, "u": 0.33, "v": 0.33, "t": 0.00, "s": 0.00},
    "F + U + T  (no Velocity/S)":  {"f": 0.33, "u": 0.33, "v": 0.00, "t": 0.33, "s": 0.00},
    "F + V + T  (no Diversity/S)": {"f": 0.33, "u": 0.00, "v": 0.33, "t": 0.33, "s": 0.00},
    "U + V + T  (no Failed/S)":    {"f": 0.00, "u": 0.33, "v": 0.33, "t": 0.33, "s": 0.00},
    "U + V + S  (no Failed/T)":    {"f": 0.00, "u": 0.33, "v": 0.33, "t": 0.00, "s": 0.33},
    # ── 4-indicator full models (legacy, no S) ─────────────
    "Equal 4-Indicator (no S)":    {"f": 0.25, "u": 0.25, "v": 0.25, "t": 0.25, "s": 0.00},
    "LHBDF Weights (no S, legacy)":{"f": 0.35, "u": 0.25, "v": 0.25, "t": 0.15, "s": 0.00},
    # ── 5-indicator full models (current) ──────────────────
    "Equal Hybrid (0.20 each)":    {"f": 0.20, "u": 0.20, "v": 0.20, "t": 0.20, "s": 0.20},
    "LHBDF — Proposed Weights":    {"f": 0.35, "u": 0.25, "v": 0.25, "t": 0.15, "s": 0.10},  # matches risk_scorer.py exactly (un-normalized, sum=1.10, capped per-IP at 1.0 below)
}

THRESHOLD = 0.60


def run_ablation(features: list[dict], ground_truth: dict) -> list[dict]:
    """
    Test every indicator combination against ground truth.
    Returns a list of result dicts sorted by F1-Score.
    """
    results = []
    for name, weights in COMBINATIONS.items():
        metrics = _evaluate_combination(features, ground_truth, weights)
        results.append({"combination": name, **metrics})

    return sorted(results, key=lambda r: (r["f1"], r["recall"]), reverse=True)


def _evaluate_combination(features, ground_truth, weights):
    """
    Computes predictions for every IP that appears in `features`, but
    ONLY scores metrics against IPs present in `ground_truth` -- exactly
    matching the pattern in evaluator.py and multi_window.py. This
    matters when `features` includes unlabeled IPs (e.g. real background
    traffic in a hybrid dataset, Step 20): those IPs must NOT be
    silently treated as "normal" just because they lack a label, or a
    correctly-flagged real attacker gets miscounted as a false positive.
    """
    tp = fp = tn = fn = 0

    risk_by_ip = {}
    for feat in features:
        raw_risk = (
            weights["f"] * feat["f_score"] +
            weights["u"] * feat["u_score"] +
            weights["v"] * feat["v_score"] +
            weights["t"] * feat["t_score"] +
            weights.get("s", 0.0) * feat.get("s_score", 0.0)
        )
        risk_by_ip[feat["ip_address"]] = min(1.0, raw_risk)   # matches production cap

    for ip, gt in ground_truth.items():
        risk = risk_by_ip.get(ip)                # None if IP had no feature window
        pred = 1 if (risk is not None and risk >= THRESHOLD) else 0

        if pred == 1 and gt == 1: tp += 1
        elif pred == 1 and gt == 0: fp += 1
        elif pred == 0 and gt == 0: tn += 1
        else: fn += 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall    = tp / (tp + fn) if (tp + fn) else 0.0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr       = fp / (fp + tn) if (fp + tn) else 0.0
    accuracy  = (tp + tn) / (tp + fp + tn + fn) if (tp + fp + tn + fn) else 0.0

    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": round(precision, 3),
        "recall":    round(recall, 3),
        "f1":        round(f1, 3),
        "fpr":       round(fpr, 3),
        "accuracy":  round(accuracy, 3),
    }
