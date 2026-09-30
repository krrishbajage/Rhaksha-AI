"""Attachment analysis agent — dangerous extension detection and VirusTotal hash analysis."""

from __future__ import annotations

import asyncio
import logging
from pathlib import PurePath
from typing import Any

from app.graph.state import InvestigationState
from app.schemas.security_event import SecurityEvent
from app.services.gmail_fetcher import fetch_attachment_bytes
from app.tools.file_hash import sha256_bytes
from app.tools.virustotal import check_file_hash

logger = logging.getLogger(__name__)

MAX_EMAIL_ATTACHMENTS = 3
MAX_ATTACHMENT_SIZE_BYTES = 25 * 1024 * 1024  # 25 MB

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
        "virustotal_status": "unknown",
        "sha256": None,
    }


def analyze_attachments(filenames: list[str]) -> dict[str, Any]:
    """Run attachment-agent logic on filenames only (synchronous V1 fallback)."""
    findings = [_analyze_filename(name) for name in filenames]
    dangerous_count = sum(1 for item in findings if item["suspicious"])
    return {
        "attachment_report": {
            "agent": "attachment_agent",
            "attachment_count": len(findings),
            "dangerous_count": dangerous_count,
            "findings": findings,
        }
    }


async def attachment_agent_node(state: InvestigationState) -> dict[str, dict]:
    if not state.get("run_attachment_agent"):
        return {}

    event = state.get("event")
    if not event:
        return {
            "attachment_report": {
                "agent": "attachment_agent",
                "attachment_count": 0,
                "dangerous_count": 0,
                "findings": [],
            }
        }

    metadata = event.metadata or {}
    attachment_ids = metadata.get("attachment_ids")

    findings: list[dict[str, Any]] = []

    # Email events with structured attachment metadata
    if event.source_app == "email" and attachment_ids:
        user_email = (
            metadata.get("user_email")
            or getattr(event, "user_email", None)
            or (event.sender or "")
        )
        gmail_msg_id = metadata.get("gmail_message_id", "")

        for att in attachment_ids[:MAX_EMAIL_ATTACHMENTS]:
            filename = att.get("filename", "unknown")
            att_id = att.get("attachment_id", "")
            size = int(att.get("size", 0))

            finding = _analyze_filename(filename)

            # Cap file size to avoid unbounded downloads
            if size > MAX_ATTACHMENT_SIZE_BYTES:
                finding["skipped"] = True
                finding["skip_reason"] = "size_limit_exceeded"
                finding["virustotal_status"] = "unknown"
                findings.append(finding)
                continue

            if not att_id:
                findings.append(finding)
                continue

            try:
                raw_bytes = await asyncio.to_thread(
                    fetch_attachment_bytes,
                    user_email,
                    gmail_msg_id,
                    att_id,
                )
                if raw_bytes:
                    file_hash = sha256_bytes(raw_bytes)
                    finding["sha256"] = file_hash
                    vt_res = await check_file_hash(file_hash)
                    finding["virustotal"] = vt_res
                    vt_status = str(vt_res.get("status", "unknown"))
                    finding["virustotal_status"] = vt_status
                    if vt_status == "malicious":
                        finding["suspicious"] = True
                        finding["risk_reason"] = (
                            f"VirusTotal flagged attachment as malicious "
                            f"({vt_res.get('malicious_votes', 0)} detections)"
                        )
                else:
                    finding["virustotal_status"] = "unknown"
            except Exception as exc:
                logger.warning("Failed to analyze attachment %s: %s", filename, exc)
                finding["error"] = str(exc)
                finding["virustotal_status"] = "unknown"

            findings.append(finding)
    else:
        # SMS, WhatsApp, or fallback events without byte access
        findings = [_analyze_filename(name) for name in (event.attachments or [])]

    dangerous_count = sum(
        1
        for item in findings
        if item.get("suspicious") or item.get("virustotal_status") == "malicious"
    )

    return {
        "attachment_report": {
            "agent": "attachment_agent",
            "attachment_count": len(findings),
            "dangerous_count": dangerous_count,
            "findings": findings,
        }
    }