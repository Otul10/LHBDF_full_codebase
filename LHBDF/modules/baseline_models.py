"""
LHBDF - Step 6: Baseline Detection Models
--------------------------------------------
Implements 3 conventional baseline models from the proposal,
plus a "Conventional Hybrid" model (equal-weighted version of
the same 5 indicators LHBDF uses, Step 17 update) for comparison.

Baseline Models:
  1. Static Threshold Model
       → ALERT if failed login count >= THRESHOLD_FAILED

  2. Time-Window Frequency Model
       → ALERT if total attempts in window >= THRESHOLD_VELOCITY

  3. Username Diversity Model
       → ALERT if unique usernames targeted >= THRESHOLD_UNIQUE

  4. Conventional Hybrid Model
       → Same 5 indicators as LHBDF (F, U, V, T, S), but with EQUAL
         weights (0.20 each) instead of LHBDF's differential weighting
       → Uses the same 4-tier severity thresholds as LHBDF
"""

from modules.feature_extractor import THRESHOLD_FAILED, THRESHOLD_UNIQUE, THRESHOLD_VELOCITY
from modules.risk_scorer import _classify

EQUAL_WEIGHT = 0.20  # 1 / 5 indicators (updated from 0.25 now that S_Score is included)


def evaluate_baselines(features: list[dict]) -> list[dict]:
    """Run all baseline models against each feature record."""
    return [_evaluate_one(f) for f in features]


def _evaluate_one(f: dict) -> dict:
    # 1. Static Threshold Model
    static_alert = f["failed_attempts"] >= THRESHOLD_FAILED

    # 2. Time-Window Frequency Model
    timewindow_alert = f["total_attempts"] >= THRESHOLD_VELOCITY

    # 3. Username Diversity Model
    diversity_alert = f["unique_users"] >= THRESHOLD_UNIQUE

    # 4. Conventional Hybrid Model (equal weights, 5 indicators)
    s_val = f.get("s_score", 0.0)
    hybrid_score = round(
        EQUAL_WEIGHT * (f["f_score"] + f["u_score"] + f["v_score"] + f["t_score"] + s_val),
        4
    )
    hybrid_level = _classify(hybrid_score)

    return {
        "ip_address":               f["ip_address"],
        "static_threshold":         "ALERT" if static_alert     else "NORMAL",
        "time_window":              "ALERT" if timewindow_alert else "NORMAL",
        "username_diversity":       "ALERT" if diversity_alert  else "NORMAL",
        "conventional_hybrid_score": hybrid_score,
        "conventional_hybrid_level": hybrid_level,
    }
