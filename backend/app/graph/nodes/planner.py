"""Planner node — decides which specialist agents to run."""

from __future__ import annotations

from app.graph.state import InvestigationState


def planner_node(state: InvestigationState) -> dict[str, bool]:
    event = state["event"]
    message_text = (event.message_text or "").strip()
    urls = event.urls or []
    attachments = event.attachments or []

    return {
        "run_message_agent": bool(message_text),
        "run_url_agent": bool(urls),
        "run_attachment_agent": bool(attachments),
    }
