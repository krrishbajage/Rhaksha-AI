"""Security events API routes."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

import logging
import uuid

from app.graph.workflow import build_workflow
from app.schemas.risk_report import RiskReport
from app.schemas.security_event import SecurityEvent
from app.services.analysis_control import AnalysisUnavailable, get_controller

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/events", tags=["events"])


@router.post("/analyze", response_model=RiskReport)
def analyze_security_event(event: SecurityEvent) -> RiskReport:
    request_id = uuid.uuid4().hex
    logger.info("event_received request_id=%s event_id=%s", request_id, event.event_id)
    try:
        # The compiled graph and its mutable state are request-local.
        with get_controller().analysis_slot(request_id):
            result = build_workflow().invoke({"event": event, "request_id": request_id})
    except AnalysisUnavailable as exc:
        raise HTTPException(status_code=503, detail="Analysis is temporarily unavailable; please try again later.") from exc
    except RuntimeError as exc:
        if "GOOGLE_API_KEY" in str(exc):
            raise HTTPException(status_code=503, detail="Analysis service is unavailable.") from exc
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    risk_report = result.get("risk_report")
    if risk_report is None:
        raise HTTPException(status_code=500, detail="Workflow did not produce a risk report.")

    if isinstance(risk_report, RiskReport):
        return risk_report
    return RiskReport.model_validate(risk_report)
