"""
LHBDF - Step 6: Model Comparator
-----------------------------------
Builds a side-by-side comparison table:
  LHBDF (proposed, weighted) vs. 3 baseline models vs. Conventional Hybrid (equal-weight)
"""

import os
from datetime import datetime
from modules.risk_scorer import is_alert_level


class C:
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    GREEN  = "\033[92m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"


LEVEL_COLOR = {
    "CRITICAL": C.RED, "HIGH": "\033[38;5;208m", "SUSPICIOUS": C.YELLOW, "NORMAL": C.GREEN,
    "ALERT": C.RED,
}


def compare_models(scored: list[dict], baselines: list[dict], output_dir: str = "output") -> None:
    os.makedirs(output_dir, exist_ok=True)
    baseline_map = {b["ip_address"]: b for b in baselines}

    W = 112
    print()
    print(C.BOLD + C.CYAN + "═" * W + C.RESET)
    print(C.BOLD + C.WHITE + "  MODEL COMPARISON — LHBDF (Proposed) vs. Baseline Detection Models".center(W) + C.RESET)
    print(C.BOLD + C.CYAN + "═" * W + C.RESET)

    cols = [
        ("IP Address",       16),
        ("LHBDF (Proposed)", 18),
        ("Static Thresh.",   15),
        ("Time-Window",      13),
        ("Username Div.",    15),
        ("Conv. Hybrid",     18),
    ]
    header = "  " + " | ".join(f"{name:^{w}}" for name, w in cols)
    print(C.BOLD + header + C.RESET)
    print("  " + "-" * (W - 2))

    rows = []
    for s in scored:
        b = baseline_map.get(s["ip_address"], {})
        rows.append((s, b))

        ip_cell      = _cell(s["ip_address"], 16, "")
        lhbdf_cell   = _cell(f"{s['risk_level']} ({s['risk_score']:.2f})", 18, LEVEL_COLOR[s["risk_level"]])
        static_cell  = _cell(b["static_threshold"], 15, LEVEL_COLOR[b["static_threshold"]])
        tw_cell      = _cell(b["time_window"], 13, LEVEL_COLOR[b["time_window"]])
        ud_cell      = _cell(b["username_diversity"], 15, LEVEL_COLOR[b["username_diversity"]])
        ch_cell      = _cell(f"{b['conventional_hybrid_level']} ({b['conventional_hybrid_score']:.2f})", 18, LEVEL_COLOR[b["conventional_hybrid_level"]])

        print(f"  {ip_cell} | {lhbdf_cell} | {static_cell} | {tw_cell} | {ud_cell} | {ch_cell}")

    print("  " + "-" * (W - 2))
    _print_notes(rows)

    path = os.path.join(output_dir, f"comparison_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
    _save(rows, path)
    print(f"\n  📄 Comparison report saved → {path}\n")


def _cell(text: str, width: int, color: str) -> str:
    """Pad text to a fixed visible width, THEN wrap in color codes."""
    padded = f"{text:^{width}}"
    if color:
        return f"{color}{padded}{C.RESET}"
    return padded


def _print_notes(rows):
    print()
    print(C.BOLD + "  ANALYSIS NOTES" + C.RESET)
    any_diff = False
    for s, b in rows:
        lhbdf_alert = is_alert_level(s["risk_level"])
        disagreements = []

        if lhbdf_alert != (b["static_threshold"] == "ALERT"):
            disagreements.append("Static Threshold")
        if lhbdf_alert != (b["time_window"] == "ALERT"):
            disagreements.append("Time-Window Frequency")
        if lhbdf_alert != (b["username_diversity"] == "ALERT"):
            disagreements.append("Username Diversity")

        if disagreements:
            any_diff = True
            verdict = f"flags {s['risk_level']}" if lhbdf_alert else "does NOT flag an alert"
            print(f"    • {s['ip_address']}: LHBDF {verdict}, "
                  f"but {', '.join(disagreements)} disagree.")

    if not any_diff:
        print("    • All models agree on every IP in this dataset.")
    print()


def _save(rows, path):
    lines = ["LHBDF Model Comparison Report",
             "=" * 60, ""]
    for s, b in rows:
        lines += [
            f"IP Address          : {s['ip_address']}",
            f"LHBDF (Proposed)    : {s['risk_level']} ({s['risk_score']:.3f})",
            f"Static Threshold    : {b['static_threshold']}",
            f"Time-Window Freq.   : {b['time_window']}",
            f"Username Diversity  : {b['username_diversity']}",
            f"Conventional Hybrid : {b['conventional_hybrid_level']} ({b['conventional_hybrid_score']:.3f})",
            "-" * 60, ""
        ]
    with open(path, "w") as f:
        f.write("\n".join(lines))
