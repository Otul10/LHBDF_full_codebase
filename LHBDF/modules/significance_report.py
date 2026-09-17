"""
LHBDF - Significance Test Report
--------------------------------------
Formats and prints the paired t-test / Wilcoxon significance results.
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


def print_significance_results(results: dict, reference_model: str, n_bootstrap: int,
                                alpha: float = 0.05, output_dir: str = "output") -> None:
    os.makedirs(output_dir, exist_ok=True)

    W = 92
    print()
    print(C.BOLD + C.CYAN + "═" * W + C.RESET)
    print(C.BOLD + C.WHITE + "  STATISTICAL SIGNIFICANCE TESTING (Bootstrap Paired t-test & Wilcoxon)".center(W) + C.RESET)
    print(C.BOLD + C.CYAN + "═" * W + C.RESET)
    print(f"  Reference model: {reference_model}   |   Bootstrap resamples: {n_bootstrap}   |   α = {alpha}")
    print(C.CYAN + "─" * W + C.RESET)

    for model, r in results.items():
        print()
        print(C.BOLD + f"  {reference_model}  vs.  {model}" + C.RESET)
        print(f"    Mean F1 ({reference_model:<20}): {r['mean_f1_reference']:.4f}")
        print(f"    Mean F1 ({model:<20}): {r['mean_f1_other']:.4f}")
        print(f"    Mean difference            : {r['mean_diff']:+.4f}   "
              f"(95% CI: [{r['ci_95'][0]:+.4f}, {r['ci_95'][1]:+.4f}])")

        if r["t_note"]:
            print(f"    Paired t-test              : {C.YELLOW}{r['t_note']}{C.RESET}")
        else:
            sig = C.GREEN + "SIGNIFICANT" + C.RESET if r["significant_t"] else C.YELLOW + "not significant" + C.RESET
            print(f"    Paired t-test              : t={r['t_stat']:.4f}, p={r['t_pvalue']:.6f}  → {sig}")

        if r["w_note"]:
            print(f"    Wilcoxon signed-rank       : {C.YELLOW}{r['w_note']}{C.RESET}")
        else:
            sig = C.GREEN + "SIGNIFICANT" + C.RESET if r["significant_w"] else C.YELLOW + "not significant" + C.RESET
            print(f"    Wilcoxon signed-rank       : W={r['w_stat']:.4f}, p={r['w_pvalue']:.6f}  → {sig}")

    print()
    print(C.CYAN + "─" * W + C.RESET)
    print(f"\n  {C.BOLD}Interpretation:{C.RESET} p < {alpha} means the F1 difference is unlikely to be due to")
    print(f"  resampling chance alone. 'Identical predictions' means both models produced the")
    print(f"  exact same classification on every IP -- no test can show significance because")
    print(f"  there is genuinely zero difference to detect.\n")

    path = os.path.join(output_dir, f"significance_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
    _save(results, reference_model, n_bootstrap, alpha, path)
    print(f"  📄 Report saved → {path}\n")


def _save(results, reference_model, n_bootstrap, alpha, path):
    lines = [
        "LHBDF Statistical Significance Test Report",
        "=" * 60,
        f"Reference model    : {reference_model}",
        f"Bootstrap resamples: {n_bootstrap}",
        f"Significance level : alpha = {alpha}",
        "",
    ]
    for model, r in results.items():
        lines += [
            f"{reference_model} vs. {model}",
            f"  Mean F1 ({reference_model}) = {r['mean_f1_reference']}",
            f"  Mean F1 ({model}) = {r['mean_f1_other']}",
            f"  Mean difference = {r['mean_diff']}  95% CI = {r['ci_95']}",
            f"  Paired t-test: t={r['t_stat']}, p={r['t_pvalue']}"
            + (f"  [{r['t_note']}]" if r["t_note"] else f"  significant={r['significant_t']}"),
            f"  Wilcoxon: W={r['w_stat']}, p={r['w_pvalue']}"
            + (f"  [{r['w_note']}]" if r["w_note"] else f"  significant={r['significant_w']}"),
            "-" * 60,
        ]
    with open(path, "w") as f:
        f.write("\n".join(lines))
