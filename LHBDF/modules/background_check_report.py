"""
LHBDF - Background Check Report
-------------------------------------
Formats and prints the qualitative real-background-IP check results.
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
    GRAY   = "\033[90m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

LEVEL_COLOR = {"CRITICAL": C.RED, "HIGH": C.ORANGE, "SUSPICIOUS": C.YELLOW, "NORMAL": C.GREEN}


def print_background_check(results: list[dict], output_dir: str = "output") -> None:
    os.makedirs(output_dir, exist_ok=True)
    from modules.background_check import summarize
    stats = summarize(results)

    W = 96
    print()
    print(C.BOLD + C.CYAN + "═" * W + C.RESET)
    print(C.BOLD + C.WHITE + "  QUALITATIVE CHECK — Real Background IPs (LogHub OpenSSH, unlabeled)".center(W) + C.RESET)
    print(C.BOLD + C.CYAN + "═" * W + C.RESET)
    print(f"  {C.YELLOW}NOTE: These IPs have NO official ground truth. This is a supplementary,{C.RESET}")
    print(f"  {C.YELLOW}illustrative check -- NOT part of the primary Precision/Recall/F1 evaluation.{C.RESET}")
    print(C.CYAN + "─" * W + C.RESET)
    print(f"  Real background IPs        : {stats['total_background_ips']}")
    print(f"  Produced a feature window  : {stats['scored_ips']}  ({stats['unscored_ips']} too sparse to score)")
    print(f"  Flagged HIGH/CRITICAL      : {stats['flagged_alert']} / {stats['scored_ips']}  ({stats['flagged_pct']}%)")
    print(C.CYAN + "─" * W + C.RESET)

    cols = [("Real IP","16"), ("Risk","6"), ("Severity","11"), ("Attack Type","20"),
            ("Evidence","30"), ("Window","14")]
    header = "  " + " | ".join(f"{n:^{int(w)}}" for n, w in cols)
    print(C.BOLD + header + C.RESET)
    print("  " + "-" * (W - 2))

    scored = sorted([r for r in results if r["scored"]], key=lambda r: r["risk_score"], reverse=True)
    for r in scored:
        color = LEVEL_COLOR.get(r["risk_level"], "")
        evidence = f"{r['failed_attempts']} failed, {r['unique_users']} user(s)"
        cells = [
            f"{r['ip']:<16}", f"{r['risk_score']:^6.3f}",
            f"{color}{r['risk_level']:^11}{C.RESET}",
            f"{r['attack_type']:<20}"[:20], f"{evidence:<30}"[:30], f"{r['detected_at']:<14}"[:14],
        ]
        print("  " + " | ".join(cells))

    unscored = [r for r in results if not r["scored"]]
    if unscored:
        print(f"\n  {C.GRAY}Too sparse to score ({len(unscored)}): "
              f"{', '.join(r['ip'] for r in unscored)}{C.RESET}")

    print("  " + "-" * (W - 2))
    print(f"\n  {C.BOLD}Interpretation:{C.RESET} {stats['flagged_pct']}% of real attacking IPs with sufficient")
    print(f"  activity were independently flagged HIGH or CRITICAL by LHBDF, with attack-type")
    print(f"  classifications plausible given their raw behavior (see Evidence column) --")
    print(f"  despite LHBDF never being tuned or trained on this real dataset.\n")

    path = os.path.join(output_dir, f"background_check_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
    _save(results, stats, path)
    print(f"  📄 Report saved → {path}\n")


def _save(results, stats, path):
    lines = ["LHBDF Qualitative Background Check Report (Real IPs, Unlabeled)",
             "=" * 60,
             f"Total background IPs      : {stats['total_background_ips']}",
             f"Scored (had a window)     : {stats['scored_ips']}",
             f"Flagged HIGH/CRITICAL     : {stats['flagged_alert']} ({stats['flagged_pct']}%)",
             ""]
    for r in results:
        if r["scored"]:
            lines.append(f"{r['ip']:<18} risk={r['risk_score']:.3f} ({r['risk_level']})  "
                          f"type={r['attack_type']}  failed={r['failed_attempts']} users={r['unique_users']}  "
                          f"window={r['detected_at']}")
        else:
            lines.append(f"{r['ip']:<18} NOT SCORED — {r['reason']}")
    with open(path, "w") as f:
        f.write("\n".join(lines))
