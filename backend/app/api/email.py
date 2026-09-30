"""Endpoints for syncing and analyzing Gmail messages."""

import asyncio
import logging
from typing import Any

from app.api.events import analyze_security_event
from app.schemas.risk_report import RiskReport
from app.schemas.security_event import SecurityEvent
from app.services.gmail_fetcher import fetch_recent_messages, to_security_event
from app.services.token_store import ProcessedEmailStore, TokenStore
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/email", tags=["Email Sync"])


class EmailSyncRequest(BaseModel):
    user_email: str


class SyncedEmailReport(BaseModel):
    gmail_message_id: str
    event: SecurityEvent
    risk_report: RiskReport


MAX_EMAILS_PER_SYNC = 2  # Tune based on your Gemini RPM budget


@router.post("/sync", response_model=list[SyncedEmailReport])
async def sync_emails(payload: EmailSyncRequest):
    """Fetches recent emails, converts to SecurityEvents, runs the LangGraph engine, and deduplicates."""
    user_email = payload.user_email.strip().lower()
    if not user_email:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="user_email must not be blank.",
        )

    if not TokenStore.get_refresh_token(user_email):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=(
                f"Account {user_email} is not connected. Authenticate via"
                " /api/auth/google first."
            ),
        )

    try:
        messages = await asyncio.to_thread(
            fetch_recent_messages, user_email, max_results=MAX_EMAILS_PER_SYNC
        )
    except Exception as err:
        raise HTTPException(
            status_code=502,
            detail=f"Failed to fetch messages from Gmail API: {err}",
        )

    results: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []

    for msg in messages:
        msg_id = msg.get("id")
        if not msg_id or ProcessedEmailStore.is_processed(msg_id):
            continue
        try:
            event = to_security_event(msg)
            risk_report = await analyze_security_event(event)
            results.append({
                "gmail_message_id": msg_id,
                "event": event,
                "risk_report": risk_report,
            })
            ProcessedEmailStore.mark_processed(msg_id)
        except Exception as err:
            logger.warning("email_analysis_failed message_id=%s error=%s", msg_id, err)
            errors.append({"gmail_message_id": msg_id, "error": str(err)})
            continue

    return results