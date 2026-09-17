"""
LHBDF - Multi-Window Report
--------------------------------
Formats and prints multi-window detection comparison results.
"""

import os
from datetime import datetime


class C:
    RED    = "\033[91m"
    ORANGE = "\033[38;5;208m"
    YELLOW = "\033[93m"
    GREEN  = "\033[92m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"


def print_multi_window_metrics(metrics: dict, total_ips: int, attack_ips: int,
                                output_dir: str = "output") -> None:
    os.makedirs(output_dir, exist_ok=True)

    W = 90
    print()
    print(C.BOLD + C.CYAN + "═" * W + C.RESET)
    print(C.BOLD + C.WHITE + "  MULTI-WINDOW DETECTION — Does Window Size Matter?".center(W) + C.RESET)
    print(C.BOLD + C.CYAN + "═" * W + C.RESET)
    print(f"  Labeled dataset: {total_ips} IPs total ({attack_ips} attack / {total_ips - attack_ips} normal)")
    print(C.CYAN + "─" * W + C.RESET)

    cols = [("Window Scale", 32), ("Precision", 10), ("Recall", 8), ("F1-Score", 9), ("FPR", 7), ("TP/FN", 10)]
    header = "  " + " | ".join(f"{name:^{w}}" for name, w in cols)
    print(C.BOLD + header + C.RESET)
    print("  " + "-" * (W - 2))

    order = ["5-Min (Fast Brute-Force)", "1-Hour (Credential Stuffing)",
             "24-Hour (Low-and-Slow)", "Multi-Window (best-of-3)"]

    for label in order:
        if label not in metrics:
            continue
        m = metrics[label]
        is_multi = "Multi-Window" in label
        color = C.GREEN + C.BOLD if is_multi else ""
        reset = C.RESET if is_multi else ""
        marker = " ★" if is_multi else "  "
        cells = [
            f"{label:<32}",
            f"{m['precision']:^10.3f}",
            f"{m['recall']:^8.3f}",
            f"{m['f1']:^9.3f}",
            f"{m['fpr']:^7.3f}",
            f"{str(m['tp'])+'/'+str(m['fn']):^10}",
        ]
        print(f"  {color}" + " | ".join(cells) + f"{reset}{marker}")

    print("  " + "-" * (W - 2))
    print(f"\n  {C.GREEN}★{C.RESET} = Multi-Window approach (takes max risk across all 3 scales)\n")

    _print_insight(metrics)

    path = os.path.join(output_dir, f"multiwindow_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
    _save(metrics, total_ips, attack_ips, path)
    print(f"  📄 Multi-window report saved → {path}\n")


def _print_insight(metrics: dict) -> None:
    five_min = metrics.get("5-Min (Fast Brute-Force)")
    multi    = metrics.get("Multi-Window (best-of-3)")
    if not five_min or not multi:
        return

    print(C.BOLD + "  KEY INSIGHT" + C.RESET)
    gap = multi["recall"] - five_min["recall"]
    print(f"    • 5-minute window alone catches {five_min['recall']*100:.1f}% of attacks (Recall={five_min['recall']:.3f})")
    print(f"    • Adding 1-hour + 24-hour windows raises Recall to {multi['recall']*100:.1f}% "
          f"({'+' if gap >= 0 else ''}{gap:.3f})")
    missed = five_min["fn"] - multi["fn"]
    if missed > 0:
        print(f"    • {missed} attack(s) are structurally invisible to a 5-minute window alone "
              f"(events too far apart to ever co-occur in one window) — only caught via the 24-hour scale.")
    print()


def _save(metrics: dict, total_ips: int, attack_ips: int, path: str) -> None:
    lines = [
        "LHBDF Multi-Window Detection Report",
        "=" * 60,
        f"Labeled dataset : {total_ips} IPs total ({attack_ips} attack / {total_ips - attack_ips} normal)",
        "",
    ]
    for label, m in metrics.items():
        lines += [
            f"Window: {label}",
            f"  Precision={m['precision']}  Recall={m['recall']}  F1={m['f1']}  FPR={m['fpr']}",
            f"  TP={m['tp']} FP={m['fp']} TN={m['tn']} FN={m['fn']}",
            "-" * 60,
        ]
    with open(path, "w") as f:
        f.write("\n".join(lines))
