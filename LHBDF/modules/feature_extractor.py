"""
LHBDF - Step 2: Behavioral Feature Extractor
----------------------------------------------
Groups entries by IP + sliding time window,
then extracts 5 behavioral indicator scores:

  F_Score  — Failed Login Frequency
  U_Score  — Username Diversity
  V_Score  — Login Velocity
  T_Score  — Temporal Behavior (bot-like regularity)
  S_Score  — Success Ratio (successful / total attempts)   ★ Step 17
             High S + high V + high U → stolen-credential stuffing
             Low S + high F           → conventional brute-force
"""

from datetime import datetime, timedelta
from collections import defaultdict

THRESHOLD_FAILED   = 5    # failures before suspicion
THRESHOLD_UNIQUE   = 3    # unique usernames before suspicion
THRESHOLD_VELOCITY = 10   # total attempts before suspicion
WINDOW_MINUTES     = 5    # sliding window size


def extract_features(entries: list[dict], window_minutes: int = WINDOW_MINUTES,
                      threshold_failed: float = THRESHOLD_FAILED,
                      threshold_unique: float = THRESHOLD_UNIQUE,
                      threshold_velocity: float = THRESHOLD_VELOCITY) -> list[dict]:
    """
    Extract behavioral features per IP using a sliding time window.

    threshold_failed/unique/velocity default to the fixed module
    constants, but can be overridden -- e.g. with adaptive (μ + 2σ)
    thresholds computed from a normal-behavior baseline by
    modules/adaptive_threshold.py.
    """
    if not entries:
        return []

    entries = sorted(entries, key=lambda e: e["timestamp"])
    window  = timedelta(minutes=window_minutes)
    results = []

    by_ip = defaultdict(list)
    for e in entries:
        by_ip[e["ip_address"]].append(e)

    for ip, ip_entries in by_ip.items():
        for anchor in ip_entries:
            w_start = anchor["timestamp"]
            w_end   = w_start + window

            w_entries = [e for e in ip_entries
                         if w_start <= e["timestamp"] < w_end]

            if len(w_entries) < 2:
                continue

            results.append(_compute(ip, w_start, w_end, w_entries,
                                     threshold_failed, threshold_unique, threshold_velocity))

    return _deduplicate(results)


def _compute(ip: str, start: datetime, end: datetime, entries: list[dict],
             threshold_failed: float = THRESHOLD_FAILED,
             threshold_unique: float = THRESHOLD_UNIQUE,
             threshold_velocity: float = THRESHOLD_VELOCITY) -> dict:
    total      = len(entries)
    failed     = sum(1 for e in entries if e["login_outcome"] == "failure")
    successful = total - failed
    users      = len(set(e["username"] for e in entries))

    f_score = min(failed / threshold_failed,   1.0)
    u_score = min(users  / threshold_unique,   1.0)
    v_score = min(total  / threshold_velocity, 1.0)
    t_score = _temporal_score(entries)
    s_score = round(successful / total, 4) if total > 0 else 0.0   # Success Ratio

    return {
        "ip_address":          ip,
        "window_start":        start,
        "window_end":          end,
        "total_attempts":      total,
        "failed_attempts":     failed,
        "successful_attempts": successful,
        "unique_users":        users,
        "f_score":             round(f_score, 4),
        "u_score":             round(u_score, 4),
        "v_score":             round(v_score, 4),
        "t_score":             round(t_score, 4),
        "s_score":             s_score,
    }


def _temporal_score(entries: list[dict]) -> float:
    """Low variance in gaps between attempts = bot-like = higher score."""
    if len(entries) < 3:
        return 0.0

    timestamps = sorted(e["timestamp"] for e in entries)
    gaps = [(timestamps[i+1] - timestamps[i]).total_seconds()
            for i in range(len(timestamps) - 1)]

    mean_gap = sum(gaps) / len(gaps)
    if mean_gap == 0:
        return 1.0

    variance = sum((g - mean_gap) ** 2 for g in gaps) / len(gaps)
    cv       = (variance ** 0.5) / mean_gap
    return round(max(0.0, 1.0 - min(cv, 1.0)), 4)


def _deduplicate(results: list[dict]) -> list[dict]:
    """Keep only the peak (highest attempts) window per IP."""
    best = {}
    for r in results:
        ip = r["ip_address"]
        if ip not in best or r["total_attempts"] > best[ip]["total_attempts"]:
            best[ip] = r
    return list(best.values())
