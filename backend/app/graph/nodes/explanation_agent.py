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
    message_report = state.get("message_report") or {}
    if state.get("run_message_agent") and message_report.get("error") and not (
        state.get("url_report") or state.get("attachment_report")
    ):
        # A text-only event cannot be safely classified without its required message analysis.
        raise AnalysisUnavailable("Message analysis is unavailable")
    payload = {
        "risk_score": state.get("risk_score"),
        "risk_level": state.get("risk_level"),
        "scam_category": state.get("scam_category"),
        "evidence": state.get("evidence", []),
    }
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

    risk_report = RiskReport(
        risk_score=float(state.get("risk_score", 0.0)),
        risk_level=str(state.get("risk_level", "low")),
        scam_category=str(state.get("scam_category", "none")),
        explanation=output.explanation,
        recommended_action=output.recommended_action,
    )

    return {
        "explanation": output.explanation,
        "recommended_action": output.recommended_action,
        "risk_report": risk_report,
    }
