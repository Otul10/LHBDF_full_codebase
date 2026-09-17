"""
LHBDF - Ablation Study Report
--------------------------------
Prints a ranked table of all indicator combinations tested,
showing which behavioral indicators contribute most to
detection performance. Directly answers RQ4.
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


def print_ablation_table(results: list[dict], total_ips: int, attack_ips: int,
                          output_dir: str = "output") -> None:
    os.makedirs(output_dir, exist_ok=True)

    W = 100
    print()
    print(C.BOLD + C.CYAN + "═" * W + C.RESET)
    print(C.BOLD + C.WHITE + "  ABLATION STUDY — Which Behavioral Indicators Matter Most? (RQ4)".center(W) + C.RESET)
    print(C.BOLD + C.CYAN + "═" * W + C.RESET)
    print(f"  Labeled dataset: {total_ips} IPs total ({attack_ips} attack / {total_ips - attack_ips} normal)")
    print(C.CYAN + "─" * W + C.RESET)

    cols = [("Rank", 5), ("Indicator Combination", 28), ("Precision", 10),
            ("Recall", 8), ("F1-Score", 9), ("FPR", 7), ("Accuracy", 9)]
    header = "  " + " | ".join(f"{name:^{w}}" for name, w in cols)
    print(C.BOLD + header + C.RESET)
    print("  " + "-" * (W - 2))

    best_f1 = results[0]["f1"]

    for i, r in enumerate(results, start=1):
        is_proposed = "Proposed" in r["combination"]
        is_best = r["f1"] == best_f1

        if is_proposed:
            color = C.GREEN + C.BOLD
        elif is_best:
            color = C.YELLOW + C.BOLD
        else:
            color = ""
        reset = C.RESET if color else ""

        marker = " \u2605" if is_proposed else ("  " if not is_best else " \u2191")

        cells = [
            f"{i:^5}",
            f"{r['combination']:<28}",
            f"{r['precision']:^10.3f}",
            f"{r['recall']:^8.3f}",
            f"{r['f1']:^9.3f}",
            f"{r['fpr']:^7.3f}",
            f"{r['accuracy']:^9.3f}",
        ]
        print(f"  {color}" + " | ".join(cells) + f"{reset}{marker}")

    print("  " + "-" * (W - 2))
    print(f"\n  {C.GREEN}\u2605{C.RESET} = LHBDF Proposed Weights     "
          f"{C.YELLOW}\u2191{C.RESET} = Highest F1-Score in this study\n")

    _print_insights(results)

    path = os.path.join(output_dir, f"ablation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
    _save(results, total_ips, attack_ips, path)
    print(f"  \U0001F4C4 Ablation report saved \u2192 {path}\n")


def _print_insights(results: list[dict]) -> None:
    """Auto-generate a short interpretation of the ablation results."""
    singles = [r for r in results if r["combination"].endswith("only)") or " only " in r["combination"] or r["combination"].startswith(("F only", "U only", "V only", "T only"))]
    singles = [r for r in results if r["combination"].split()[1] == "only" or "only" in r["combination"].split("(")[0]]

    print(C.BOLD + "  KEY INSIGHTS" + C.RESET)

    # Find best and worst single indicators
    single_results = [r for r in results if r["combination"].startswith(("F only", "U only", "V only", "T only"))]
    if single_results:
        best_single  = max(single_results, key=lambda r: r["f1"])
        worst_single = min(single_results, key=lambda r: r["f1"])
        print(f"    \u2022 Strongest single indicator : {best_single['combination']}  (F1={best_single['f1']:.3f})")
        print(f"    \u2022 Weakest single indicator   : {worst_single['combination']}  (F1={worst_single['f1']:.3f})")

    proposed = next((r for r in results if "Proposed" in r["combination"]), None)
    equal    = next((r for r in results if "Equal" in r["combination"]), None)
    if proposed and single_results:
        best_single_f1 = max(r["f1"] for r in single_results)
        gain = proposed["f1"] - best_single_f1
        print(f"    \u2022 LHBDF vs. best single indicator : {'+' if gain >= 0 else ''}{gain:.3f} F1 improvement")
    if proposed and equal:
        diff = proposed["f1"] - equal["f1"]
        comp = "outperforms" if diff > 0 else ("matches" if diff == 0 else "underperforms vs.")
        print(f"    \u2022 Weighted (LHBDF) vs. Equal-weight hybrid : LHBDF {comp} equal weighting "
              f"({proposed['f1']:.3f} vs {equal['f1']:.3f})")
    print()


def _save(results, total_ips, attack_ips, path):
    lines = [
        "LHBDF Ablation Study Report",
        "=" * 60,
        f"Labeled dataset : {total_ips} IPs total ({attack_ips} attack / {total_ips - attack_ips} normal)",
        "",
    ]
    for i, r in enumerate(results, start=1):
        lines += [
            f"Rank {i}: {r['combination']}",
            f"  Precision={r['precision']}  Recall={r['recall']}  F1={r['f1']}  "
            f"FPR={r['fpr']}  Accuracy={r['accuracy']}",
            f"  TP={r['tp']} FP={r['fp']} TN={r['tn']} FN={r['fn']}",
            "-" * 60,
        ]
    with open(path, "w") as f:
        f.write("\n".join(lines))
