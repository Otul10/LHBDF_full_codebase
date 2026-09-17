"""
LHBDF - Adaptive Threshold Report
--------------------------------------
Formats and prints the Fixed vs. Adaptive threshold comparison.
"""

import os
from datetime import datetime


class C:
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    GREEN  = "\033[92m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"


def print_calibration(thresholds: dict) -> None:
    W = 88
    method = thresholds.get("method", "Median + 3×MAD")
    print()
    print(C.BOLD + C.CYAN + "═" * W + C.RESET)
    print(C.BOLD + C.WHITE + f"  ADAPTIVE THRESHOLD CALIBRATION  ({method})".center(W) + C.RESET)
    print(C.BOLD + C.CYAN + "═" * W + C.RESET)
    print(f"  Baseline windows used for calibration: {thresholds['baseline_windows']}")
    print(f"  Method: {method}  (robust to outliers, no normality assumption)")
    print(C.CYAN + "─" * W + C.RESET)

    cols = [("Indicator", 14), ("Median", 8), ("MAD", 7), ("Median+3×MAD", 14),
            ("Mean (μ)", 10), ("Std (σ)", 8), ("Fixed", 7), ("Chosen", 8)]
    header = "  " + " | ".join(f"{name:^{w}}" for name, w in cols)
    print(C.BOLD + header + C.RESET)
    print("  " + "-" * (W - 2))

    fixed = {"failed": 5, "unique": 3, "velocity": 10}
    adaptive = {
        "failed":   thresholds["threshold_failed"],
        "unique":   thresholds["threshold_unique"],
        "velocity": thresholds["threshold_velocity"],
    }
    labels = {"failed": "Failed Login", "unique": "Username Div.", "velocity": "Login Velocity"}

    for key in ["failed", "unique", "velocity"]:
        s = thresholds["stats"][key]
        chosen = adaptive[key]
        changed = C.YELLOW if chosen != fixed[key] else C.GREEN
        cells = [
            f"{labels[key]:<14}",
            f"{s['median']:^8.2f}",
            f"{s['mad']:^7.2f}",
            f"{s['median'] + 3*s['mad']:^14.2f}",
            f"{s['mean']:^10.3f}",
            f"{s['std']:^8.3f}",
            f"{fixed[key]:^7}",
            f"{changed}{chosen:^8.2f}{C.RESET}",
        ]
        print("  " + " | ".join(cells))

    print("  " + "-" * (W - 2))
    print(f"\n  Note: 'Chosen' = max(Median+3×MAD, floor) to prevent threshold collapse"
          f" when baseline variance is near zero.\n")


def print_comparison(fixed_metrics: dict, adaptive_metrics: dict, total_ips: int, attack_ips: int,
                      output_dir: str = "output") -> None:
    os.makedirs(output_dir, exist_ok=True)

    W = 78
    print(C.BOLD + C.CYAN + "═" * W + C.RESET)
    print(C.BOLD + C.WHITE + "  FIXED vs. ADAPTIVE (Median+3×MAD) — Detection Performance".center(W) + C.RESET)
    print(C.BOLD + C.CYAN + "═" * W + C.RESET)
    print(f"  Labeled dataset: {total_ips} IPs total ({attack_ips} attack / {total_ips - attack_ips} normal)")
    print(C.CYAN + "─" * W + C.RESET)

    cols = [("Mode", 12), ("Precision", 10), ("Recall", 8), ("F1-Score", 9), ("FPR", 7), ("TP/FP/FN", 12)]
    header = "  " + " | ".join(f"{name:^{w}}" for name, w in cols)
    print(C.BOLD + header + C.RESET)
    print("  " + "-" * (W - 2))

    for mode, m in [("Fixed", fixed_metrics), ("Adaptive", adaptive_metrics)]:
        is_better = mode == "Adaptive" and m["f1"] >= fixed_metrics["f1"]
        color = C.GREEN + C.BOLD if is_better else ""
        reset = C.RESET if color else ""
        marker = " ★" if is_better else "  "
        tp_fp_fn = f"{m['TP']}/{m['FP']}/{m['FN']}"
        cells = [
            f"{mode:<12}",
            f"{m['precision']:^10.3f}",
            f"{m['recall']:^8.3f}",
            f"{m['f1']:^9.3f}",
            f"{m['fpr']:^7.3f}",
            f"{tp_fp_fn:^12}",
        ]
        print(f"  {color}" + " | ".join(cells) + f"{reset}{marker}")

    print("  " + "-" * (W - 2))
    diff = adaptive_metrics["f1"] - fixed_metrics["f1"]
    verdict = "improves" if diff > 0 else ("matches" if diff == 0 else "slightly reduces")
    print(f"\n  Adaptive thresholding {verdict} F1-Score by {diff:+.3f} vs. fixed thresholds on this dataset.\n")

    path = os.path.join(output_dir, f"adaptive_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
    _save(fixed_metrics, adaptive_metrics, total_ips, attack_ips, path)
    print(f"  📄 Report saved → {path}\n")


def _save(fixed_metrics, adaptive_metrics, total_ips, attack_ips, path):
    lines = [
        "LHBDF Adaptive Threshold Comparison Report (Median + 3×MAD)",
        "=" * 60,
        f"Labeled dataset : {total_ips} IPs total ({attack_ips} attack / {total_ips - attack_ips} normal)",
        "",
    ]
    for mode, m in [("Fixed", fixed_metrics), ("Adaptive (Median+3×MAD)", adaptive_metrics)]:
        lines += [
            f"Mode: {mode}",
            f"  Precision={m['precision']}  Recall={m['recall']}  F1={m['f1']}  FPR={m['fpr']}",
            f"  TP={m['TP']} FP={m['FP']} TN={m['TN']} FN={m['FN']}",
            "-" * 60,
        ]
    with open(path, "w") as f:
        f.write("\n".join(lines))
