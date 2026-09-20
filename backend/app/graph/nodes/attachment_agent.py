"""Attachment analysis agent — dangerous extension detection."""

from __future__ import annotations

from pathlib import PurePath
from typing import Any

from app.graph.state import InvestigationState
from app.schemas.security_event import SecurityEvent

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


def filename_suffixes(filename: str) -> list[str]:
    name = PurePath(filename).name
    parts = name.split(".")
    if len(parts) <= 1:
        return []
    return ["." + part.lower() for part in parts[1:] if part]


def _analyze_filename(filename: str) -> dict[str, object]:
    suffixes = filename_suffixes(filename)
    last_suffix = suffixes[-1] if suffixes else None
    dangerous_last = last_suffix in DANGEROUS_EXTENSIONS if last_suffix else False
    disguised_double_extension = (
        len(suffixes) >= 2
        and any(suffix in DANGEROUS_EXTENSIONS for suffix in suffixes)
        and any(suffix not in DANGEROUS_EXTENSIONS for suffix in suffixes[:-1])
    )
    suspicious = dangerous_last or disguised_double_extension
    if disguised_double_extension:
        reason = f"Disguised double extension detected: {''.join(suffixes)}"
    elif dangerous_last:
        reason = f"Dangerous executable extension detected: {last_suffix}"
    else:
        reason = "No dangerous extension detected"

    return {
        "filename": filename,
        "extension": last_suffix,
        "suffixes": suffixes,
        "dangerous_extension": dangerous_last,
        "disguised_double_extension": disguised_double_extension,
        "suspicious": suspicious,
        "risk_reason": reason,
    }


def analyze_attachments(filenames: list[str]) -> dict[str, Any]:
    """Run attachment-agent logic on filenames only (V1 has no file bytes)."""
    event = SecurityEvent(
        event_id="attachment-agent-direct",
        source_app="test",
        sender=None,
        message_text="",
        urls=[],
        attachments=filenames,
        timestamp="1970-01-01T00:00:00Z",
    )
    return attachment_agent_node({"event": event, "run_attachment_agent": True})


def attachment_agent_node(state: InvestigationState) -> dict[str, dict]:
    if not state.get("run_attachment_agent"):
        return {}
    event = state["event"]
    findings = [_analyze_filename(name) for name in (event.attachments or [])]
    dangerous_count = sum(1 for item in findings if item["suspicious"])

    return {
        "attachment_report": {
            "agent": "attachment_agent",
            "attachment_count": len(findings),
            "dangerous_count": dangerous_count,
            "findings": findings,
        }
    }
