"""Message analysis agent powered by Gemini structured output."""

from __future__ import annotations

import os

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_google_genai import ChatGoogleGenerativeAI
from pydantic import BaseModel, Field

from app.graph.prompts import MESSAGE_AGENT_PROMPT
from app.graph.state import InvestigationState


class MessageAnalysis(BaseModel):
    impersonation: bool = False
    urgency_detected: bool = False
    otp_request: bool = False
    kyc_request: bool = False
    payment_request: bool = False
    scam_category: str = "none"
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    indicators: list[str] = Field(default_factory=list)


def _build_llm() -> ChatGoogleGenerativeAI:
    api_key = os.getenv("GOOGLE_API_KEY")
    if not api_key or not api_key.strip():
        raise RuntimeError(
            "GOOGLE_API_KEY is missing. Get a free key from https://aistudio.google.com "
            "and add it to your .env file."
        )
    return ChatGoogleGenerativeAI(
        model=os.getenv("GEMINI_MODEL", "gemini-3.6-flash"),
        google_api_key=api_key.strip(),
        temperature=0,
    )


def message_agent_node(state: InvestigationState) -> dict[str, dict]:
    if not state.get("run_message_agent"):
        return {}
    event = state["event"]
    llm = _build_llm().with_structured_output(MessageAnalysis)
    analysis: MessageAnalysis = llm.invoke(
        [
            SystemMessage(content=MESSAGE_AGENT_PROMPT),
            HumanMessage(
                content=(
                    f"Sender: {event.sender or 'unknown'}\n"
                    f"Source app: {event.source_app}\n"
                    f"Message text:\n{event.message_text}"
                )
            ),
        ]
    )

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
