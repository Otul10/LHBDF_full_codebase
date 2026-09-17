"""
LHBDF - ROC Curve Plot & Report
-------------------------------------
Generates the ROC curve figure (PNG) and prints a terminal summary
with AUC scores for thesis-quality reporting.
"""

import os
from datetime import datetime
import matplotlib
matplotlib.use("Agg")  # headless, no display needed
import matplotlib.pyplot as plt


def plot_roc_curves(curves: dict, operating_points: dict, output_dir: str = "output") -> str:
    """
    curves: {model_name: {"fpr": [...], "tpr": [...], "auc": float}}
    operating_points: {model_name: (fpr, tpr)}  -- for binary baselines

    Returns the saved PNG path.
    """
    os.makedirs(output_dir, exist_ok=True)

    fig, ax = plt.subplots(figsize=(7, 6.5), dpi=150)

    colors = {"LHBDF (Proposed)": "#00838f", "Conventional Hybrid": "#7b1fa2"}
    linestyles = {"LHBDF (Proposed)": "-", "Conventional Hybrid": "--"}
    linewidths = {"LHBDF (Proposed)": 3.2, "Conventional Hybrid": 2.0}
    for name, data in curves.items():
        c = colors.get(name, "#555555")
        ls = linestyles.get(name, "-")
        lw = linewidths.get(name, 2.4)
        ax.plot(data["fpr"], data["tpr"], label=f"{name} (AUC = {data['auc']:.3f})",
                 color=c, linewidth=lw, linestyle=ls, alpha=0.9)

    marker_colors = {"Static Threshold": "#d32f2f", "Time-Window Freq.": "#f57c00",
                      "Username Diversity": "#388e3c"}
    for name, (fpr, tpr) in operating_points.items():
        c = marker_colors.get(name, "#888888")
        ax.scatter([fpr], [tpr], color=c, s=90, zorder=5, marker="D",
                    label=f"{name} (FPR={fpr:.2f}, TPR={tpr:.2f})")

    ax.plot([0, 1], [0, 1], linestyle="--", color="gray", linewidth=1.2, label="Random Guess (AUC = 0.500)")

    ax.set_xlabel("False Positive Rate", fontsize=12)
    ax.set_ylabel("True Positive Rate (Recall)", fontsize=12)
    ax.set_title("ROC Curve — LHBDF vs. Baseline Models", fontsize=13, fontweight="bold")
    ax.set_xlim(-0.02, 1.02)
    ax.set_ylim(-0.02, 1.02)
    ax.legend(loc="lower right", fontsize=9, framealpha=0.95)
    ax.grid(alpha=0.25)
    fig.tight_layout()

    path = os.path.join(output_dir, f"roc_curve_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png")
    fig.savefig(path)
    plt.close(fig)
    return path


def print_roc_summary(curves: dict, operating_points: dict, total_ips: int, attack_ips: int,
                       png_path: str) -> None:
    W = 70
    print()
    print("═" * W)
    print("  ROC CURVE & AUC ANALYSIS".center(W))
    print("═" * W)
    print(f"  Labeled dataset: {total_ips} IPs total ({attack_ips} attack / {total_ips - attack_ips} normal)")
    print("─" * W)
    print("  Continuous-score models (full ROC curve):")
    for name, data in curves.items():
        bar = _auc_bar(data["auc"])
        print(f"    {name:<24} AUC = {data['auc']:.3f}  {bar}")

    print()
    print("  Binary baselines (single operating point):")
    for name, (fpr, tpr) in operating_points.items():
        print(f"    {name:<24} FPR={fpr:.3f}  TPR={tpr:.3f}")

    print("─" * W)
    auc_vals = [d["auc"] for d in curves.values()]
    if len(set(auc_vals)) == 1 and len(curves) > 1:
        print(f"\n  Note: LHBDF and Conventional Hybrid achieve identical AUC ({auc_vals[0]:.3f})")
        print(f"  despite ranking individual IPs differently in many positions -- the chosen")
        print(f"  weights (0.35/0.25/0.25/0.15) and equal weights (0.25 each) both separate")
        print(f"  attacks from normal activity equally well in AGGREGATE on this dataset.")
    print(f"\n  📊 ROC curve figure saved → {png_path}\n")


def _auc_bar(auc: float, width: int = 30) -> str:
    filled = int(round(auc * width))
    return "[" + "█" * filled + "░" * (width - filled) + "]"
