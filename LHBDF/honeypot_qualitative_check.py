"""
LHBDF -- Honeypot Qualitative Real-World Check
================================================
How many of an independently-sourced honeypot dataset's confirmed real
attacking IPs does LHBDF flag as HIGH/CRITICAL?

Dataset: "A 4-Month Dataset of SSH Botnet Interactions and Command
Payloads" (Boiko & Niiakyi, 2026), Zenodo DOI: 10.5281/zenodo.19629700.
Prepare the input first via scripts/adapt_honeypot_data.py.

Methodology note: every IP in this dataset is malicious by construction
(a honeypot has no legitimate users), so this is NOT a Precision/Recall/
F1 evaluation -- there is no negative class to compute a false positive
rate against. This mirrors the qualitative check already used in Section
5.9 / Table 5.11 against LogHub's unlabeled real background IPs, applied
here at much larger scale (754 confirmed attackers vs. 24) to a second,
fully independent real-world source.

A second breakdown is reported by attempt volume, since ~85% of these
attackers made only 1-3 attempts across the entire 4-month capture --
statistically indistinguishable from a single mistyped password, the
same conservative-non-alert case already documented for Table 5.11.
LHBDF's detection rate on attackers exhibiting genuinely sustained
brute-force behavior (10+ attempts) is the fairer, primary result.

Usage:
  python honeypot_qualitative_check.py [logfile]
  (default: logs/honeypot_adapted.csv)
"""
import sys
from collections import Counter

from modules.log_parser import parse_log
from modules.feature_extractor import extract_features
from modules.risk_scorer import score_all
from modules.multi_window import analyze_multi_window
from modules.slow_attack_detector import detect_slow_attacks, merge_with_fast_path

DEFAULT_LOGFILE = "logs/honeypot_adapted.csv"
ALERT_LEVELS = {"HIGH", "CRITICAL"}
SUSTAINED_THRESHOLD = 10  # attempts, for the volume-based breakdown


def best_of_multi_window(entries: list[dict]) -> dict:
    """Combine the 5-min/1hr/24hr windows into one best-of-3 result per IP,
    matching the 'Multi-Window (Best-of-3)' methodology used in Table 5.2."""
    mw = analyze_multi_window(entries)
    best_per_ip = {}
    for window_results in mw["per_window"].values():
        for ip, r in window_results.items():
            if ip not in best_per_ip or r["risk_score"] > best_per_ip[ip]["risk_score"]:
                best_per_ip[ip] = r
    return best_per_ip


def pct(n: int, total: int) -> str:
    return f"{100 * n / total:.1f}%" if total else "n/a"


def run(logfile: str) -> None:
    entries = parse_log(logfile)
    all_ips = set(e["ip_address"] for e in entries)
    attempts_per_ip = Counter(e["ip_address"] for e in entries)

    print()
    print("  LHBDF -- Honeypot Qualitative Real-World Check")
    print("  " + "=" * 48)
    print(f"  Total login-attempt entries : {len(entries)}")
    print(f"  Total distinct attacking IPs: {len(all_ips)}")
    print()

    # --- run all three detection approaches ---
    features = extract_features(entries)
    scored = score_all(features)
    fast_flagged = {r["ip_address"] for r in scored if r["severity"] in ALERT_LEVELS}

    best_per_ip = best_of_multi_window(entries)
    mw_flagged = {ip for ip, r in best_per_ip.items() if r["severity"] in ALERT_LEVELS}

    slow_results = detect_slow_attacks(entries)
    merged = merge_with_fast_path(scored, slow_results)
    merged_flagged = {r["ip_address"] for r in merged if r["severity"] in ALERT_LEVELS}

    union = fast_flagged | mw_flagged | merged_flagged

    print(f"  [Fast Path, 5-min] {len(fast_flagged):4d} / {len(all_ips)}  ({pct(len(fast_flagged), len(all_ips))})")
    print(f"  [Multi-Window]     {len(mw_flagged):4d} / {len(all_ips)}  ({pct(len(mw_flagged), len(all_ips))})")
    print(f"  [Fast+Slow Merged] {len(merged_flagged):4d} / {len(all_ips)}  ({pct(len(merged_flagged), len(all_ips))})")
    print(f"  [Union, all 3]     {len(union):4d} / {len(all_ips)}  ({pct(len(union), len(all_ips))})")

    # --- breakdown by attempt volume: the fairer, primary result ---
    sustained_ips = {ip for ip, c in attempts_per_ip.items() if c >= SUSTAINED_THRESHOLD}
    low_volume_ips = all_ips - sustained_ips
    sustained_flagged = sustained_ips & union
    low_volume_flagged = low_volume_ips & union

    print()
    print(f"  Attackers with 1-3 total attempts (4 months): "
          f"{sum(1 for c in attempts_per_ip.values() if c <= 3)} / {len(all_ips)} "
          f"({pct(sum(1 for c in attempts_per_ip.values() if c <= 3), len(all_ips))})")
    print(f"  Sustained attackers ({SUSTAINED_THRESHOLD}+ attempts): {len(sustained_ips)}")
    print(f"    -> Flagged HIGH/CRITICAL: {len(sustained_flagged)} / {len(sustained_ips)} "
          f"({pct(len(sustained_flagged), len(sustained_ips))})")
    print(f"  Low-volume attackers (<{SUSTAINED_THRESHOLD} attempts): {len(low_volume_ips)}")
    print(f"    -> Flagged HIGH/CRITICAL: {len(low_volume_flagged)} / {len(low_volume_ips)} "
          f"({pct(len(low_volume_flagged), len(low_volume_ips))})")
    print()


if __name__ == "__main__":
    logfile = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_LOGFILE
    run(logfile)
