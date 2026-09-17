"""
LHBDF - Step 3: Risk Scoring Engine
-------------------------------------
Applies the 5-indicator weighted formula (Step 17 — Success Ratio added):

  Risk_Score = min(1.0,
                   0.35 × F_Score     ← Failed Login Frequency
                 + 0.25 × U_Score     ← Username Diversity
                 + 0.25 × V_Score     ← Login Velocity
                 + 0.15 × T_Score     ← Temporal Behavior
                 + 0.10 × S_Score)    ← Success Ratio  ★ NEW

  Design rationale for S_Score weight:
    F/U/V/T weights are UNCHANGED from the original 4-indicator formula
    on purpose, so every existing brute-force evaluation result stays
    identical (S_Score = 0 for pure-failure attacks → the additive term
    contributes nothing → formula collapses back to the original).
    S = 0.10 acts as an additive BONUS that only matters when failures
    are low/absent but successes are high -- exactly the stolen-credential
    stuffing signature -- nudging such borderline cases from SUSPICIOUS
    into HIGH without changing how any brute-force case is scored.
    Weight sum = 1.10 by design; min(score, 1.0) keeps output bounded.

  Severity Levels (4-tier):
    >= 0.80      →  CRITICAL    (Alert — confirmed high-confidence attack)
    0.60 – 0.79  →  HIGH        (Alert — investigate immediately)
    0.40 – 0.59  →  SUSPICIOUS  (Monitor closely)
    <  0.40      →  NORMAL      (Normal activity)

  An IP is treated as a positive "attack" prediction if its severity
  is HIGH or CRITICAL (i.e. risk_score >= ALERT_THRESHOLD).
"""

WEIGHTS = {
    "f_score": 0.35,
    "u_score": 0.25,
    "v_score": 0.25,
    "t_score": 0.15,
    "s_score": 0.10,   # Success Ratio — additive bonus, weight sum = 1.10
}

THRESHOLD_CRITICAL  = 0.80
THRESHOLD_HIGH      = 0.60   # = ALERT_THRESHOLD: HIGH or CRITICAL both trigger alerts
THRESHOLD_SUSPICIOUS = 0.40

ALERT_LEVELS = {"HIGH", "CRITICAL"}   # severities that count as a positive detection


def score_all(features: list[dict]) -> list[dict]:
    """Score all feature records, sorted by risk (highest first)."""
    scored = [_calculate(f) for f in features]
    return sorted(scored, key=lambda x: x["risk_score"], reverse=True)


def _calculate(f: dict) -> dict:
    raw = (
        WEIGHTS["f_score"] * f["f_score"] +
        WEIGHTS["u_score"] * f["u_score"] +
        WEIGHTS["v_score"] * f["v_score"] +
        WEIGHTS["t_score"] * f["t_score"] +
        WEIGHTS["s_score"] * f.get("s_score", 0.0)
    )
    risk_score = round(min(1.0, raw), 4)
    level = _classify(risk_score)
    return {
        **f,
        "risk_score": risk_score,
        "risk_level": level,                  # kept for backward compatibility
        "severity":   level,                  # preferred new name
        "is_alert":   level in ALERT_LEVELS,
    }


def _classify(score: float) -> str:
    if score >= THRESHOLD_CRITICAL:
        return "CRITICAL"
    elif score >= THRESHOLD_HIGH:
        return "HIGH"
    elif score >= THRESHOLD_SUSPICIOUS:
        return "SUSPICIOUS"
    return "NORMAL"


def is_alert_level(level: str) -> bool:
    """True if this severity level should be treated as a positive detection."""
    return level in ALERT_LEVELS

