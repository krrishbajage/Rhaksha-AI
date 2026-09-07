"""Risk scoring engine — converts evidence into score and level."""

from __future__ import annotations

from typing import Any

from app.graph.state import InvestigationState


def calculate_risk(evidence: list[dict[str, Any]], scam_category: str | None = None) -> tuple[float, str, str]:
    score = 0.0
    for item in evidence:
        score += float(item.get("weight", 0))

    score = min(score, 100.0)

    if score >= 80:
        level = "critical"
    elif score >= 60:
        level = "high"
    elif score >= 30:
        level = "medium"
    else:
        level = "low"

    category = scam_category or "none"
    if category == "none":
        for item in evidence:
            if item.get("type") == "url" and item.get("signal") == "typosquat":
                category = "banking_impersonation"
                break
            if item.get("type") == "attachment" and item.get("signal") == "dangerous_extension":
                category = "generic_phishing"
                break

    return score, level, category


def risk_engine_node(state: InvestigationState) -> dict[str, float | str]:
    evidence = state.get("evidence") or []
    scam_category = state.get("scam_category") or (
        (state.get("message_report") or {}).get("scam_category")
    )
    score, level, category = calculate_risk(evidence, scam_category)
    return {
        "risk_score": score,
        "risk_level": level,
        "scam_category": category,
    }
