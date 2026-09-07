"""Explanation agent — user-facing summary from structured evidence."""

from __future__ import annotations

import json
import os

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_google_genai import ChatGoogleGenerativeAI
from pydantic import BaseModel, Field

from app.graph.prompts import EXPLANATION_PROMPT
from app.graph.state import InvestigationState
from app.schemas.risk_report import RiskReport


class ExplanationOutput(BaseModel):
    explanation: str = Field(description="Plain-language explanation for the user.")
    recommended_action: str = Field(description="Short recommended action for the user.")


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
        temperature=0.2,
    )


def explanation_agent_node(state: InvestigationState) -> dict[str, object]:
    llm = _build_llm().with_structured_output(ExplanationOutput)
    payload = {
        "risk_score": state.get("risk_score"),
        "risk_level": state.get("risk_level"),
        "scam_category": state.get("scam_category"),
        "evidence": state.get("evidence", []),
    }
    output: ExplanationOutput = llm.invoke(
        [
            SystemMessage(content=EXPLANATION_PROMPT),
            HumanMessage(content=json.dumps(payload, indent=2)),
        ]
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
