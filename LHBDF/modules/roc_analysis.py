"""
LHBDF - ROC Curve & AUC Analysis
-------------------------------------
Sweeps the risk-score decision threshold from 0.0 to 1.0 and computes
True Positive Rate (Recall) vs. False Positive Rate at each point,
producing the data needed for an ROC curve and its AUC (Area Under
the Curve) score.

Only applies to models that output a CONTINUOUS risk score:
  - LHBDF (Proposed, weighted formula)
  - Conventional Hybrid (equal-weight formula)

The 3 single-indicator baselines (Static Threshold, Time-Window,
Username Diversity) are binary ALERT/NORMAL classifiers with no
adjustable threshold -- they appear as a single (FPR, TPR) operating
point on the ROC plot for visual comparison, not a full curve.
"""

import numpy as np


def sweep_thresholds(ip_scores: dict, ground_truth: dict, n_steps: int = 101) -> dict:
    """
    ip_scores: {ip_address: continuous_risk_score (0-1)}
    ground_truth: {ip_address: 0|1}

    Returns: {
        "thresholds": [...], "tpr": [...], "fpr": [...], "auc": float
    }
    IPs with no score (never produced a feature window) are treated
    as risk_score = 0.0 (never alerts), consistent with how the rest
    of the pipeline treats "absent" IPs as implicitly normal.
    """
    thresholds = np.linspace(0.0, 1.0, n_steps)
    tprs, fprs = [], []

    all_ips = list(ground_truth.keys())
    scores = np.array([ip_scores.get(ip, 0.0) for ip in all_ips])
    labels = np.array([ground_truth[ip] for ip in all_ips])

    n_pos = labels.sum()
    n_neg = len(labels) - n_pos

    for t in thresholds:
        preds = (scores >= t).astype(int)
        tp = int(((preds == 1) & (labels == 1)).sum())
        fp = int(((preds == 1) & (labels == 0)).sum())
        tpr = tp / n_pos if n_pos else 0.0
        fpr = fp / n_neg if n_neg else 0.0
        tprs.append(tpr)
        fprs.append(fpr)

    auc = _compute_auc(fprs, tprs)

    return {
        "thresholds": thresholds.tolist(),
        "tpr": tprs,
        "fpr": fprs,
        "auc": round(auc, 4),
    }


def _compute_auc(fprs: list, tprs: list) -> float:
    """Trapezoidal-rule integration of TPR over FPR, sorted by FPR ascending."""
    points = sorted(zip(fprs, tprs))
    fpr_sorted = [p[0] for p in points]
    tpr_sorted = [p[1] for p in points]
    return float(np.trapezoid(tpr_sorted, fpr_sorted))


def binary_operating_point(preds: dict, ground_truth: dict) -> tuple:
    """
    For a binary (non-continuous) classifier, compute its single
    (FPR, TPR) operating point.
    """
    all_ips = list(ground_truth.keys())
    tp = fp = 0
    n_pos = sum(1 for ip in all_ips if ground_truth[ip] == 1)
    n_neg = len(all_ips) - n_pos

    for ip in all_ips:
        pred = preds.get(ip, 0)
        gt = ground_truth[ip]
        if pred == 1 and gt == 1:
            tp += 1
        elif pred == 1 and gt == 0:
            fp += 1

    tpr = tp / n_pos if n_pos else 0.0
    fpr = fp / n_neg if n_neg else 0.0
    return (fpr, tpr)
