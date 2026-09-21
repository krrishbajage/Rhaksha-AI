"""LangGraph workflow shared state."""

from typing import Annotated, Any, TypedDict

from app.schemas.risk_report import RiskReport
from app.schemas.security_event import SecurityEvent


def _merge_reports(left: dict[str, Any] | None, right: dict[str, Any] | None) -> dict[str, Any]:
    merged: dict[str, Any] = {}
    if left:
        merged.update(left)
    if right:
        merged.update(right)
    return merged


class InvestigationState(TypedDict, total=False):
    """Shared state passed between LangGraph nodes."""

    event: SecurityEvent
    request_id: str
    run_message_agent: bool
    run_url_agent: bool
    run_attachment_agent: bool
    message_report: Annotated[dict[str, Any], _merge_reports]
    url_report: Annotated[dict[str, Any], _merge_reports]
    attachment_report: Annotated[dict[str, Any], _merge_reports]
    evidence: list[dict[str, Any]]
    risk_score: float
    risk_level: str
    scam_category: str 
    explanation: str
    recommended_action: str
    risk_report: RiskReport
