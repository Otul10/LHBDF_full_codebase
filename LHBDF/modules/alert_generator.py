"""
LHBDF - Step 4: Alert Generator
---------------------------------
Prints colour-coded terminal alerts (4-tier severity) and saves
a report to /output/.
"""

import os
from datetime import datetime
from modules.attack_classifier import classify


class C:
    RED      = "\033[91m"
    ORANGE   = "\033[38;5;208m"
    YELLOW   = "\033[93m"
    GREEN    = "\033[92m"
    CYAN     = "\033[96m"
    WHITE    = "\033[97m"
    BOLD     = "\033[1m"
    RESET    = "\033[0m"


LEVEL_COLOR = {"CRITICAL": C.RED, "HIGH": C.ORANGE, "SUSPICIOUS": C.YELLOW, "NORMAL": C.GREEN}
LEVEL_ICON  = {"CRITICAL": "🟣", "HIGH": "🔴", "SUSPICIOUS": "🟡", "NORMAL": "🟢"}
LEVEL_ORDER = ["CRITICAL", "HIGH", "SUSPICIOUS", "NORMAL"]


def generate_alerts(scored: list[dict], output_dir: str = "output") -> None:
    os.makedirs(output_dir, exist_ok=True)
    now = datetime.now()
    counts = {lvl: sum(1 for s in scored if s["risk_level"] == lvl) for lvl in LEVEL_ORDER}

    _header(now, len(scored), counts)
    for s in scored:
        _alert_block(s)
    _summary(counts)

    path = os.path.join(output_dir, f"report_{now.strftime('%Y%m%d_%H%M%S')}.txt")
    _save(scored, now, path)
    print(f"\n  📄 Report saved → {path}\n")


def _header(now, total, counts):
    W = 78
    print()
    print(C.BOLD + C.CYAN  + "═" * W + C.RESET)
    print(C.BOLD + C.WHITE + "  LHBDF — Lightweight Hybrid Behavioral Detection Framework".center(W) + C.RESET)
    print(C.BOLD + C.CYAN  + "═" * W + C.RESET)
    print(f"  Run Time   : {now.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  IPs Scanned: {total}")
    alert_str = "  ".join(f"{LEVEL_COLOR[l]}{counts[l]} {l}{C.RESET}" for l in LEVEL_ORDER)
    print(f"  Severity   : {alert_str}")
    print(C.CYAN + "─" * W + C.RESET)


def _alert_block(s: dict):
    level  = s["risk_level"]
    color  = LEVEL_COLOR[level]
    icon   = LEVEL_ICON[level]
    clf    = classify(s)
    attack = clf["attack_type"].replace("_", " ").title()
    conf   = clf["confidence"]
    s_val  = s.get("s_score", 0.0)
    succ   = s.get("successful_attempts", s["total_attempts"] - s["failed_attempts"])

    print()
    print(color + C.BOLD +
          f"  {icon}  [{level}]  {s['ip_address']}   "
          f"Risk Score: {s['risk_score']:.3f}   ← {attack} ({conf})" + C.RESET)
    print(f"     Window   : {s['window_start'].strftime('%H:%M:%S')} – {s['window_end'].strftime('%H:%M:%S')}")
    print(f"     Attempts : {s['total_attempts']} total  "
          f"({s['failed_attempts']} failures / {succ} successes / {s['unique_users']} unique user(s))")
    print(f"     Scores   : F={s['f_score']:.2f}  U={s['u_score']:.2f}  "
          f"V={s['v_score']:.2f}  T={s['t_score']:.2f}  S={s_val:.2f}")
    print(f"     Formula  : min(1.0, 0.35×{s['f_score']:.2f} + 0.25×{s['u_score']:.2f} + "
          f"0.25×{s['v_score']:.2f} + 0.15×{s['t_score']:.2f} + 0.10×{s_val:.2f}) = {s['risk_score']:.3f}")
    evidence = clf["evidence"]
    print(f"     Evidence  : {evidence[:120]}{'…' if len(evidence)>120 else ''}")


def _summary(counts):
    print()
    print(C.CYAN + "─" * 78 + C.RESET)
    print(C.BOLD + "  DETECTION SUMMARY" + C.RESET)
    print(f"  Total IPs: {sum(counts.values())}")
    labels = {
        "CRITICAL":   "→ Confirmed high-confidence attack, act immediately",
        "HIGH":       "→ Immediate investigation recommended",
        "SUSPICIOUS": "→ Monitor closely",
        "NORMAL":     "→ Normal activity",
    }
    for lvl in LEVEL_ORDER:
        if counts[lvl]:
            print(f"  {LEVEL_COLOR[lvl]}{LEVEL_ICON[lvl]} {lvl:<10}: {counts[lvl]:>3}  {labels[lvl]}{C.RESET}")
    print(C.CYAN + "═" * 78 + C.RESET)


def _save(scored: list[dict], now: datetime, path: str):
    lines = ["LHBDF Detection Report",
             f"Generated : {now.strftime('%Y-%m-%d %H:%M:%S')}",
             "=" * 60, ""]
    for s in scored:
        clf   = classify(s)
        s_val = s.get("s_score", 0.0)
        succ  = s.get("successful_attempts", s["total_attempts"] - s["failed_attempts"])
        lines += [
            f"IP Address  : {s['ip_address']}",
            f"Severity    : {s['risk_level']}",
            f"Risk Score  : {s['risk_score']:.3f}",
            f"Attack Type : {clf['attack_type']} (Confidence: {clf['confidence']})",
            f"Evidence    : {clf['evidence']}",
            f"Window      : {s['window_start']} – {s['window_end']}",
            f"Attempts    : {s['total_attempts']} ({s['failed_attempts']} failures / {succ} successes / {s['unique_users']} user(s))",
            f"Scores      : F={s['f_score']} U={s['u_score']} V={s['v_score']} T={s['t_score']} S={s_val}",
            "-" * 60, ""
        ]
    with open(path, "w") as f:
        f.write("\n".join(lines))
