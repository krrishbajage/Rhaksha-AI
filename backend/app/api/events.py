"""Security events API routes."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.graph.workflow import workflow
from app.schemas.risk_report import RiskReport
from app.schemas.security_event import SecurityEvent

router = APIRouter(prefix="/api/events", tags=["events"])


@router.post("/analyze", response_model=RiskReport)
def analyze_security_event(event: SecurityEvent) -> RiskReport:
    try:
        result = workflow.invoke({"event": event})
    except RuntimeError as exc:
        if "GOOGLE_API_KEY" in str(exc):
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    risk_report = result.get("risk_report")
    if risk_report is None:
        raise HTTPException(status_code=500, detail="Workflow did not produce a risk report.")

    if isinstance(risk_report, RiskReport):
        return risk_report
    return RiskReport.model_validate(risk_report)
