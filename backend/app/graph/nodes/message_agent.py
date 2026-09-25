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


SCAM_KEYWORDS: dict[str, int] = {
    "otp": 25,
    "kyc": 20,
    "account will be blocked": 20,
    "verify now": 15,
    "urgent": 10,
    "click here": 15,
    "won a prize": 20,
    "install this app": 25,
    "remote access": 25,
}


def rule_based_fallback(text: str) -> dict[str, object]:
    """Return useful local evidence when Gemini is temporarily unavailable."""
    lowered = text.lower()
    hits = [keyword for keyword in SCAM_KEYWORDS if keyword in lowered]
    return {
        "agent": "message_agent_fallback",
        "impersonation": "bank" in lowered or "kyc" in lowered,
        "urgency_detected": any(word in lowered for word in ("urgent", "immediately", "blocked today")),
        "otp_request": "otp" in lowered,
        "kyc_request": "kyc" in lowered,
        "payment_request": "upi" in lowered or "transfer" in lowered,
        "scam_category": "generic_phishing" if hits else "none",
        "confidence": 0.4,
        "indicators": hits,
    }


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
    except AnalysisUnavailable:
        fallback = rule_based_fallback(event.message_text)
        return {"message_report": fallback, "scam_category": str(fallback["scam_category"])}

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
