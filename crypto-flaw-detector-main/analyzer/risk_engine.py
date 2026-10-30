"""Explainable risk scoring: static rules are primary, the AI score is a secondary layer."""
BASE = {"CRITICAL": 90, "HIGH": 70, "MEDIUM": 45, "LOW": 20}
ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def level_for(score):
    return "CRITICAL" if score >= 90 else "HIGH" if score >= 70 else "MEDIUM" if score >= 40 else "LOW"


def static_score(findings):
    """Worst severity sets the base; each extra finding adds 2 points (max +10)."""
    if not findings:
        return 0
    worst = next(s for s in ORDER if any(f["severity"] == s for f in findings))
    return min(100, BASE[worst] + min(10, 2 * (len(findings) - 1)))


def combine(findings, ai_result):
    """combined = 0.7 * static + 0.3 * AI. Returns the score with its explanation."""
    s = static_score(findings)
    a = ai_result["risk_score"]
    combined = round(0.7 * s + 0.3 * a)
    return {"static_score": s, "ai_score": a, "risk_score": combined, "risk_level": level_for(combined),
            "explanation": f"0.7 x static({s}) + 0.3 x AI({a}) = {combined}"}
