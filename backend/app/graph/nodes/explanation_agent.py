"""Explanation agent — user-facing summary from structured evidence."""

from __future__ import annotations

import json
from langchain_core.messages import HumanMessage, SystemMessage
from pydantic import BaseModel, Field

from app.graph.prompts import EXPLANATION_PROMPT
from app.graph.state import InvestigationState
from app.schemas.risk_report import RiskReport
from app.services.analysis_control import AnalysisUnavailable, get_controller


class ExplanationOutput(BaseModel):
    explanation: str = Field(description="Plain-language explanation for the user.")
    recommended_action: str = Field(description="Short recommended action for the user.")


def explanation_agent_node(state: InvestigationState) -> dict[str, object]:
    payload = {
        "risk_score": state.get("risk_score"),
        "risk_level": state.get("risk_level"),
        "scam_category": state.get("scam_category"),
        "evidence": state.get("evidence", []),
    }
    try:
        output: ExplanationOutput = get_controller().invoke_structured(
            schema=ExplanationOutput,
            request_id=state.get("request_id", state["event"].event_id),
            agent="explanation_agent",
            temperature=0.2,
            messages=[
                SystemMessage(content=EXPLANATION_PROMPT),
                HumanMessage(content=json.dumps(payload, indent=2)),
            ],
        )
        explanation, recommended_action = output.explanation, output.recommended_action
    except AnalysisUnavailable:
        top_evidence = sorted(
            state.get("evidence", []),
            key=lambda evidence: float(evidence.get("weight", 0)),
            reverse=True,
        )[:3]
        explanation = (
            "Risk factors: " + "; ".join(str(evidence.get("detail", "")) for evidence in top_evidence)
            if top_evidence
            else "No suspicious indicators detected."
        )
        recommended_action = (
            "Do not click links, share OTP/KYC details, or install any file from this message."
            if float(state.get("risk_score", 0) or 0) >= 30
            else "No action needed."
        )

    risk_report = RiskReport(
        risk_score=float(state.get("risk_score", 0.0)),
        risk_level=str(state.get("risk_level", "low")),
        scam_category=str(state.get("scam_category", "none")),
        explanation=explanation,
        recommended_action=recommended_action,
    )

    return {
        "explanation": explanation,
        "recommended_action": recommended_action,
        "risk_report": risk_report,
    }
