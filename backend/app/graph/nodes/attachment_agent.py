"""Attachment analysis agent — dangerous extension detection."""

from __future__ import annotations

from pathlib import PurePath

from app.graph.state import InvestigationState

DANGEROUS_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".apk",
        ".exe",
        ".jar",
        ".js",
        ".bat",
        ".scr",
        ".cmd",
        ".com",
        ".msi",
        ".vbs",
        ".ps1",
    }
)


def _analyze_filename(filename: str) -> dict[str, object]:
    suffix = PurePath(filename).suffix.lower()
    dangerous = suffix in DANGEROUS_EXTENSIONS
    return {
        "filename": filename,
        "extension": suffix or None,
        "dangerous_extension": dangerous,
        "risk_reason": (
            f"Dangerous executable extension detected: {suffix}"
            if dangerous
            else "No dangerous extension detected"
        ),
    }


def attachment_agent_node(state: InvestigationState) -> dict[str, dict]:
    if not state.get("run_attachment_agent"):
        return {}
    event = state["event"]
    findings = [_analyze_filename(name) for name in (event.attachments or [])]
    dangerous_count = sum(1 for item in findings if item["dangerous_extension"])

    return {
        "attachment_report": {
            "agent": "attachment_agent",
            "attachment_count": len(findings),
            "dangerous_count": dangerous_count,
            "findings": findings,
        }
    }
