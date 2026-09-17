"""
LHBDF - Dedicated Low-and-Slow Attack Detector
------------------------------------------------
The 5-minute (and even 1-hour) sliding window is structurally blind to an
attacker who spaces failed attempts hours apart: no single window ever
contains enough of the attack to cross the F/V thresholds. Naively
re-running the standard 5-indicator formula over a 24-hour window "fixes"
recall but drags FPR up sharply (0.204 in Table 5.2), because it also
inflates U_Score/V_Score for accounts that simply accumulate ordinary
activity over a full day.

This module targets the low-and-slow *signature* directly, instead of
just widening the existing window:

  1. Single-account persistence — attacker repeatedly targets ONE
     username, not several (a real user who mistypes their password
     does this too, but not for long; a legitimate shared/office IP
     usually touches multiple accounts over 24h).
  2. Sustained span — attempts spread over a long duration (default
     >= 6 hours), ruling out ordinary bursts.
  3. Minimum volume — >= MIN_ATTEMPTS failures, so a single forgotten
     password does not trigger it.
  4. All-or-mostly failures — near-zero success ratio.
  5. Bot-like pacing regularity — the coefficient of variation (CV) of
     inter-arrival gaps is capped, so attempts that are roughly evenly
     spaced (scripted) score higher than genuinely random, sporadic
     human retries.

Returns one scored dict per flagged (ip, username) pair, in the same
shape as modules/risk_scorer.py output, so it can be merged directly
into the existing alert/report pipeline.
"""

from datetime import datetime
from collections import defaultdict
import statistics

# NOTE ON THRESHOLD PROVENANCE (see thesis Section 4.4 for the same caveat
# applied to the primary F/U/V/T/S risk weights): the constants below are
# expert-chosen heuristics informed by the known low-and-slow signature in
# this research's dataset design (8 failures spread across ~21 hours), not
# the output of a formal grid search or optimisation procedure. Each was
# set with deliberate margin below/above the observed attack pattern —
# e.g. MIN_ATTEMPTS=4 is half the smallest known attack volume (8), and
# MIN_SPAN_HOURS=6.0 is well under the shortest observed span (~20.6h) —
# so the module is not narrowly tuned to only the exact IPs it was
# designed against. It has since been validated, unchanged, against the
# real-world hybrid dataset (Section 5.9) with identical F1=1.000 and zero
# false alarms on the 24 genuine unlabeled background IPs. Automated
# threshold calibration (e.g. via Median+3×MAD, as already used elsewhere
# in this framework) is identified as future work.
MIN_ATTEMPTS   = 4      # fewer than this is indistinguishable from a typo
MIN_SPAN_HOURS = 6.0    # minimum spread before this stops being "slow"
MAX_SUCCESS_RATIO = 0.15
MAX_CV         = 0.9    # inter-arrival coefficient of variation ceiling
                         # (CV=0 → perfectly regular/bot-like, CV>~1 → bursty/random)

SEVERITY_ALERT_LEVELS = {"HIGH", "MEDIUM"}


def _cv(gaps_seconds: list[float]) -> float:
    if len(gaps_seconds) < 2:
        return 0.0
    mean = statistics.mean(gaps_seconds)
    if mean == 0:
        return 0.0
    stdev = statistics.pstdev(gaps_seconds)
    return stdev / mean


def detect_slow_attacks(entries: list[dict],
                         min_attempts: int = MIN_ATTEMPTS,
                         min_span_hours: float = MIN_SPAN_HOURS,
                         max_success_ratio: float = MAX_SUCCESS_RATIO,
                         max_cv: float = MAX_CV) -> list[dict]:
    """
    Groups entries by (ip_address, username) and flags pairs matching the
    low-and-slow signature. Independent of, and meant to run alongside,
    the standard sliding-window pipeline (main.py / multi_window.py).
    """
    if not entries:
        return []

    by_pair = defaultdict(list)
    for e in entries:
        by_pair[(e["ip_address"], e["username"])].append(e)

    findings = []
    for (ip, username), group in by_pair.items():
        group = sorted(group, key=lambda e: e["timestamp"])
        n = len(group)
        if n < min_attempts:
            continue

        ts = [e["timestamp"] if isinstance(e["timestamp"], datetime)
              else datetime.fromisoformat(e["timestamp"]) for e in group]
        span_hours = (ts[-1] - ts[0]).total_seconds() / 3600.0
        if span_hours < min_span_hours:
            continue

        failed = sum(1 for e in group if e["login_outcome"] == "failure")
        success_ratio = (n - failed) / n
        if success_ratio > max_success_ratio:
            continue

        gaps = [(ts[i+1] - ts[i]).total_seconds() for i in range(len(ts) - 1)]
        cv = _cv(gaps)
        if cv > max_cv:
            continue

        # Confidence scales with how cleanly the signature is met.
        volume_strength   = min((n - min_attempts) / max(min_attempts, 1), 1.0)
        regularity_strength = 1.0 - min(cv / max_cv, 1.0)
        failure_strength  = 1.0 - success_ratio
        raw_score = 0.4 * failure_strength + 0.3 * regularity_strength + 0.3 * volume_strength
        risk_score = round(min(1.0, 0.55 + 0.45 * raw_score), 4)  # floor at 0.55 (always >= MEDIUM)
        severity = "HIGH" if risk_score >= 0.80 else "MEDIUM"

        findings.append({
            "ip_address": ip,
            "username": username,
            "n_attempts": n,
            "n_failed": failed,
            "span_hours": round(span_hours, 2),
            "success_ratio": round(success_ratio, 4),
            "inter_arrival_cv": round(cv, 3),
            "risk_score": risk_score,
            "severity": severity,
            "is_alert": severity in SEVERITY_ALERT_LEVELS,
            "attack_type": "LOW_AND_SLOW_BRUTE_FORCE",
            "detected_by": "slow_attack_detector",
            "evidence": (
                f"{failed}/{n} failed attempts against a single account "
                f"('{username}') spread over {span_hours:.1f}h "
                f"(inter-arrival CV={cv:.2f}, success ratio={success_ratio:.2f})."
            ),
        })

    return sorted(findings, key=lambda x: x["risk_score"], reverse=True)


def merge_with_fast_path(fast_path_results: list[dict], slow_results: list[dict]) -> list[dict]:
    """
    Combines standard (5-min/multi-window) findings with slow-attack
    findings into one alert list, keyed by IP: an IP already flagged by
    the fast path keeps its fast-path finding; a slow-only finding is
    added as a new entry, since it identifies a different account/pattern
    the fast path structurally cannot see.
    """
    fast_ips = {r["ip_address"] for r in fast_path_results}
    combined = list(fast_path_results)
    for s in slow_results:
        if s["ip_address"] not in fast_ips:
            combined.append(s)
    return sorted(combined, key=lambda x: x["risk_score"], reverse=True)
