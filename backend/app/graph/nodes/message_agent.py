"""Message analysis agent powered by Gemini structured output."""

from __future__ import annotations

from langchain_core.messages import HumanMessage, SystemMessage
from pydantic import BaseModel, Field

from app.graph.prompts import MESSAGE_AGENT_PROMPT
from app.graph.state import InvestigationState
from app.services.analysis_control import AnalysisUnavailable, get_controller


class MessageAnalysis(BaseModel):
    impersonation: bool = False
    urgency_detected: bool = False
    otp_request: bool = False
    kyc_request: bool = False
    payment_request: bool = False
    scam_category: str = "none"
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    indicators: list[str] = Field(default_factory=list)


def message_agent_node(state: InvestigationState) -> dict[str, dict]:
    if not state.get("run_message_agent"):
        return {}
    event = state["event"]
    try:
        analysis: MessageAnalysis = get_controller().invoke_structured(
            schema=MessageAnalysis,
            request_id=state.get("request_id", event.event_id),
            agent="message_agent",
            temperature=0,
            messages=[
            SystemMessage(content=MESSAGE_AGENT_PROMPT),
            HumanMessage(
                content=(
                    f"Sender: {event.sender or 'unknown'}\n"
                    f"Source app: {event.source_app}\n"
                    f"Message text:\n{event.message_text}"
                )
            ),
            ],
        )
    except AnalysisUnavailable as error:
        # Do not fabricate a safe result. Other agents can still contribute real evidence.
        return {"message_report": {"agent": "message_agent", "error": type(error).__name__}}

    return {
        "message_report": {
            "agent": "message_agent",
            "impersonation": analysis.impersonation,
            "urgency_detected": analysis.urgency_detected,
            "otp_request": analysis.otp_request,
            "kyc_request": analysis.kyc_request,
            "payment_request": analysis.payment_request,
            "scam_category": analysis.scam_category,
            "confidence": analysis.confidence,
            "indicators": analysis.indicators,
        },
        "scam_category": analysis.scam_category,
    }
