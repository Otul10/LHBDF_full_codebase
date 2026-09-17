"""
LHBDF - Step 18: Attack Classifier
-------------------------------------
Classifies detected alerts into one of six categories using all
5 behavioral indicators (F, U, V, T, S) as a rule-based decision tree.

Attack Types:
  BRUTE_FORCE          — High failed attempts, single or few targets,
                         low success rate, may have regular timing
  CREDENTIAL_STUFFING  — High username diversity, moderate-to-high
                         failures, multiple target accounts
  STOLEN_CRED_STUFFING — Near-zero failures, high success rate,
                         high diversity and velocity
  LOW_AND_SLOW         — Few events in window, spread over time,
                         not visible at short window scales
  BOT_PATTERN          — Very regular inter-attempt timing (low CV),
                         moderate failed count, consistent target
  NORMAL               — Risk below alert threshold

Each classification includes:
  - attack_type  : string label
  - confidence   : LOW / MEDIUM / HIGH (based on how strongly
                   indicators match the expected profile)
  - evidence     : human-readable explanation of which indicators
                   triggered the classification (explainability)
"""

from modules.risk_scorer import is_alert_level


# ── Thresholds used for classification decisions ──────────────────────────
# (separate from detection thresholds in feature_extractor.py)
_F_HIGH      = 0.60   # F_Score: "definitely many failures"
_F_LOW       = 0.10   # F_Score: "almost no failures"
_U_HIGH      = 0.65   # U_Score: "many distinct usernames"
_V_HIGH      = 0.60   # V_Score: "high velocity"
_T_HIGH      = 0.70   # T_Score: "very regular timing (bot-like)"
_S_HIGH      = 0.70   # S_Score: "mostly successful logins"
_S_LOW       = 0.15   # S_Score: "mostly failed logins"


def classify(scored: dict) -> dict:
    """
    Classify a single scored IP record into an attack type.

    Parameters
    ----------
    scored : dict  — output of risk_scorer.score_all()  (has risk_level,
                     f_score, u_score, v_score, t_score, s_score, etc.)

    Returns
    -------
    dict with keys:
        attack_type : str
        confidence  : str  ('HIGH' | 'MEDIUM' | 'LOW')
        evidence    : str  (human-readable indicator summary)
    """
    level = scored.get("risk_level", "NORMAL")

    # Not an alert → classify as normal regardless of any indicator
    if not is_alert_level(level):
        return {
            "attack_type": "NORMAL",
            "confidence":  "HIGH",
            "evidence":    f"Risk Score {scored.get('risk_score',0):.3f} is below the alert threshold.",
        }

    f = scored.get("f_score", 0.0)
    u = scored.get("u_score", 0.0)
    v = scored.get("v_score", 0.0)
    t = scored.get("t_score", 0.0)
    s = scored.get("s_score", 0.0)
    failed  = scored.get("failed_attempts", 0)
    succ    = scored.get("successful_attempts", scored.get("total_attempts", 0) - failed)
    users   = scored.get("unique_users", 0)
    total   = scored.get("total_attempts", 0)

    # ── Rule 1: Stolen-Credential Stuffing ───────────────────────────────
    # Signature: zero/near-zero failures, high success ratio, high diversity+velocity
    if s >= _S_HIGH and f <= _F_LOW and u >= _U_HIGH:
        confidence = "HIGH" if (s >= 0.90 and f == 0.0 and users >= 5) else "MEDIUM"
        return {
            "attack_type": "STOLEN_CRED_STUFFING",
            "confidence":  confidence,
            "evidence": (
                f"S_Score={s:.2f} (high success rate, {succ}/{total} logins succeeded), "
                f"F_Score={f:.2f} (near-zero failures), "
                f"U_Score={u:.2f} ({users} distinct accounts targeted). "
                f"Pattern matches replay of previously compromised valid credentials."
            ),
        }

    # ── Rule 2: Bot-Pattern Attack ────────────────────────────────────────
    # Signature: very regular inter-attempt timing, few attempts, single user.
    # Checked BEFORE Brute-Force because the distinguishing signal is
    # T_Score (near-perfect regularity) combined with LOW velocity — a bot
    # with a fixed delay produces a small number of precisely-timed attempts,
    # NOT a flood of rapid-fire requests that classic BF produces.
    if t >= _T_HIGH and users <= 2 and v <= 0.50:
        confidence = "HIGH" if (t >= 0.90 and users == 1) else "MEDIUM"
        return {
            "attack_type": "BOT_PATTERN",
            "confidence":  confidence,
            "evidence": (
                f"T_Score={t:.2f} (highly regular inter-attempt timing — "
                f"bot-like automation detected), "
                f"V_Score={v:.2f} ({total} attempts — sparse but precisely timed), "
                f"U_Score={u:.2f} ({users} target user(s)), "
                f"F_Score={f:.2f} ({failed} failures). "
                f"Suggests automated tool with fixed delay between attempts."
            ),
        }

    # ── Rule 3: Classic Brute-Force ───────────────────────────────────────
    # Signature: high failures, high velocity (many rapid attempts),
    # single/few users, low success ratio.
    if f >= _F_HIGH and users <= 2 and s <= _S_LOW:
        confidence = "HIGH" if (f >= 0.85 and users == 1) else "MEDIUM"
        return {
            "attack_type": "BRUTE_FORCE",
            "confidence":  confidence,
            "evidence": (
                f"F_Score={f:.2f} ({failed} failed attempts), "
                f"V_Score={v:.2f} ({total} total attempts — high velocity), "
                f"U_Score={u:.2f} ({users} target user(s)), "
                f"S_Score={s:.2f} (low success rate). "
                f"Pattern matches systematic password enumeration against a single account."
            ),
        }

    # ── Rule 4: Credential Stuffing ───────────────────────────────────────
    # Signature: high diversity (many accounts), moderate failures
    if u >= _U_HIGH and f >= _F_LOW:
        confidence = "HIGH" if (u >= 0.85 and f >= 0.30) else "MEDIUM"
        return {
            "attack_type": "CREDENTIAL_STUFFING",
            "confidence":  confidence,
            "evidence": (
                f"U_Score={u:.2f} ({users} distinct accounts targeted), "
                f"F_Score={f:.2f} ({failed} failures), "
                f"S_Score={s:.2f}. "
                f"Pattern matches automated credential list enumeration across multiple accounts."
            ),
        }

    # ── Rule 5: Low-and-Slow Attack ───────────────────────────────────────
    # Signature: low total attempts in window, moderate F, low V
    if total <= 4 and f >= _F_LOW and v <= 0.30:
        return {
            "attack_type": "LOW_AND_SLOW",
            "confidence":  "MEDIUM",
            "evidence": (
                f"V_Score={v:.2f} (only {total} attempts in this window — "
                f"events are sparse, suggesting deliberately slow pacing), "
                f"F_Score={f:.2f} ({failed} failures). "
                f"Pattern matches evasion of rate-limiting detection."
            ),
        }

    # ── Fallback: Suspicious/Unclassified ────────────────────────────────
    # Risk is above threshold but no clear pattern matches
    return {
        "attack_type": "SUSPICIOUS",
        "confidence":  "LOW",
        "evidence": (
            f"F={f:.2f} U={u:.2f} V={v:.2f} T={t:.2f} S={s:.2f}. "
            f"Risk Score {scored.get('risk_score',0):.3f} exceeds threshold but "
            f"does not match a clear single attack profile. Manual review recommended."
        ),
    }


def classify_all(scored: list[dict]) -> list[dict]:
    """
    Classify every scored IP record. Returns a new list with
    'attack_type', 'confidence', and 'evidence' fields added to each dict.
    """
    result = []
    for s in scored:
        classification = classify(s)
        result.append({**s, **classification})
    return result
