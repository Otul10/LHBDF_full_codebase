"""
LHBDF - Step 7: Metrics Report
-----------------------------------
Prints a formatted Precision / Recall / F1-Score / FPR / Accuracy
comparison table and saves results to output/.
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


def print_metrics_table(results: dict, total_ips: int, attack_ips: int, output_dir: str = "output") -> None:
    os.makedirs(output_dir, exist_ok=True)

    cols = [
        ("Model",     20),
        ("TP", 4), ("FP", 4), ("TN", 4), ("FN", 4),
        ("Precision", 10),
        ("Recall",     8),
        ("F1-Score",   9),
        ("FPR",        7),
        ("Accuracy",   9),
    ]
    row_width = sum(w for _, w in cols) + 3 * (len(cols) - 1) + 2  # separators " | " + leading spaces

    print()
    print(C.BOLD + C.CYAN + "═" * row_width + C.RESET)
    print(C.BOLD + C.WHITE + "  EVALUATION METRICS — Precision / Recall / F1-Score / FPR / Accuracy".center(row_width) + C.RESET)
    print(C.BOLD + C.CYAN + "═" * row_width + C.RESET)
    print(f"  Labeled dataset: {total_ips} IPs total  "
          f"({attack_ips} attack / {total_ips - attack_ips} normal)")
    print(C.CYAN + "─" * row_width + C.RESET)

    header = "  " + " | ".join(f"{name:^{w}}" for name, w in cols)
    print(C.BOLD + header + C.RESET)
    print("  " + "-" * (row_width - 2))

    best_f1 = max(r["f1"] for r in results.values())

    for model, r in results.items():
        is_best = (r["f1"] == best_f1)
        color = C.GREEN + C.BOLD if is_best else ""
        reset = C.RESET if is_best else ""

        cells = [
            f"{model:<{cols[0][1]}}",
            f"{r['TP']:^{cols[1][1]}}",
            f"{r['FP']:^{cols[2][1]}}",
            f"{r['TN']:^{cols[3][1]}}",
            f"{r['FN']:^{cols[4][1]}}",
            f"{r['precision']:^{cols[5][1]}.3f}",
            f"{r['recall']:^{cols[6][1]}.3f}",
            f"{r['f1']:^{cols[7][1]}.3f}",
            f"{r['fpr']:^{cols[8][1]}.3f}",
            f"{r['accuracy']:^{cols[9][1]}.3f}",
        ]
        marker = " \u2605" if is_best else "  "
        print(f"  {color}" + " | ".join(cells) + f"{reset}{marker}")

    print("  " + "-" * (row_width - 2))
    print(f"\n  {C.GREEN}\u2605{C.RESET} = Best F1-Score (best balance of precision & recall)\n")

    path = os.path.join(output_dir, f"metrics_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
    _save(results, total_ips, attack_ips, path)
    print(f"  \U0001F4C4 Metrics report saved \u2192 {path}\n")


def _save(results: dict, total_ips: int, attack_ips: int, path: str) -> None:
    lines = [
        "LHBDF Evaluation Metrics Report",
        "=" * 60,
        f"Labeled dataset : {total_ips} IPs total ({attack_ips} attack / {total_ips - attack_ips} normal)",
        "",
    ]
    for model, r in results.items():
        lines += [
            f"Model       : {model}",
            f"TP/FP/TN/FN : {r['TP']} / {r['FP']} / {r['TN']} / {r['FN']}",
            f"Precision   : {r['precision']}",
            f"Recall      : {r['recall']}",
            f"F1-Score    : {r['f1']}",
            f"FPR         : {r['fpr']}",
            f"Accuracy    : {r['accuracy']}",
            "-" * 60, "",
        ]
    with open(path, "w") as f:
        f.write("\n".join(lines))
