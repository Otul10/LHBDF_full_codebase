"""
LHBDF - Qualitative Background Check (Step 20)
----------------------------------------------------
The hybrid dataset's real background traffic (from a genuine,
published SSH server log -- LogHub OpenSSH_2k.log) has NO official
ground truth labels, so it cannot be used for strict Precision/
Recall/F1 scoring. However, the raw log content makes it obvious
which real IPs are malicious (repeated failed logins, username
enumeration, invalid-user scanning) -- this is exactly the kind of
internet background noise a real SSH server receives constantly.

This module provides a QUALITATIVE, supplementary check: for each
real background IP, report LHBDF's risk score, severity, and
predicted attack type, alongside the RAW behavioral evidence
(failed count, unique users) a human reviewer can use to judge
plausibility for themselves. This is explicitly NOT a substitute
for the primary, strictly-labeled evaluation (see evaluate.py on
the injected ground truth) -- it is supporting, illustrative
evidence that LHBDF's detections generalize to real attack traffic
it was never designed around.
"""

from modules.risk_scorer import is_alert_level
from modules.attack_classifier import classify


def check_background_ips(scored_by_scale: dict, background_ips: list[str]) -> list[dict]:
    """
    scored_by_scale: {"5-min": {ip: scored_dict}, "multi_window": {ip: scored_dict}}
    background_ips:  list of real (unlabeled) IPs to check

    Returns a list of result dicts, one per background IP that
    produced at least one feature window at any scale.
    """
    results = []
    five_min = scored_by_scale.get("5-min", {})
    multi     = scored_by_scale.get("multi_window", {})

    for ip in background_ips:
        s5 = five_min.get(ip)
        sm = multi.get(ip)

        if s5 is None and sm is None:
            results.append({
                "ip": ip, "scored": False,
                "reason": "Insufficient activity (fewer than 2 events, or events "
                          "too sparse to co-occur in any window scale).",
            })
            continue

        # Prefer the 5-min result if it produced an alert; otherwise fall back
        # to the multi-window result (catches sparser real attackers).
        chosen = s5 if (s5 and is_alert_level(s5["risk_level"])) else (sm or s5)
        clf = classify(chosen)

        results.append({
            "ip": ip, "scored": True,
            "risk_score": chosen["risk_score"],
            "risk_level": chosen["risk_level"],
            "is_alert": is_alert_level(chosen["risk_level"]),
            "attack_type": clf["attack_type"],
            "confidence": clf["confidence"],
            "failed_attempts": chosen["failed_attempts"],
            "unique_users": chosen["unique_users"],
            "total_attempts": chosen["total_attempts"],
            "detected_at": chosen.get("detected_at_window", "5-Min (default)"),
        })

    return results


def summarize(results: list[dict]) -> dict:
    scored = [r for r in results if r["scored"]]
    alerts = [r for r in scored if r["is_alert"]]
    return {
        "total_background_ips": len(results),
        "scored_ips": len(scored),
        "unscored_ips": len(results) - len(scored),
        "flagged_alert": len(alerts),
        "flagged_pct": round(100 * len(alerts) / len(scored), 1) if scored else 0.0,
    }
