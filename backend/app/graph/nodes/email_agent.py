"""Email header analysis agent — From/Reply-To, auth-results, and brand spoofing."""

from __future__ import annotations

import re
from email.utils import parseaddr
from typing import Any

from app.graph.state import InvestigationState
from app.tools.similarity import KNOWN_BRANDS, detect_typosquat, extract_domain

_AUTH_VERDICT = re.compile(r"(spf|dkim|dmarc)=(\w+)", re.IGNORECASE)


def _empty_report(**overrides: Any) -> dict[str, Any]:
    report: dict[str, Any] = {
        "agent": "email_agent",
        "from_reply_to_mismatch": False,
        "auth_failed": False,
        "spf": None,
        "dkim": None,
        "dmarc": None,
        "display_name_mismatch": False,
        "matched_brand": None,
    }
    report.update(overrides)
    return report


def _parse_auth_results(raw: str | None) -> tuple[str | None, str | None, str | None, bool]:
    if not raw:
        return None, None, None, False
    verdicts: dict[str, str] = {}
    for match in _AUTH_VERDICT.finditer(raw):
        verdicts[match.group(1).lower()] = match.group(2).lower()
    spf = verdicts.get("spf")
    dkim = verdicts.get("dkim")
    dmarc = verdicts.get("dmarc")
    present = [value for value in (spf, dkim, dmarc) if value is not None]
    auth_failed = any(value != "pass" for value in present)
    return spf, dkim, dmarc, auth_failed


def _valid_address(address: str) -> bool:
    return bool(address) and "@" in address


def _display_name_mismatch(display_name: str, from_address: str) -> tuple[bool, str | None]:
    if not display_name or not from_address:
        return False, None
    name_lower = display_name.lower()
    compact_name = re.sub(r"[^a-z0-9]", "", name_lower)
    domain = extract_domain(from_address)
    label = domain.split(".")[0] if domain else ""
    typosquat = detect_typosquat(from_address)

    for brand in KNOWN_BRANDS:
        if brand not in name_lower and brand not in compact_name:
            continue
        if typosquat.get("typosquat_detected") and typosquat.get("similar_to") == brand:
            return True, brand
        if label != brand:
            return True, brand
    return False, None


def email_agent_node(state: InvestigationState) -> dict[str, dict]:
    if not state.get("run_email_agent"):
        return {}
    event = state["event"]
    metadata = event.metadata or {}
    try:
        from_header = str(metadata.get("from_header") or "")
        display_name, from_address = parseaddr(from_header)

        reply_to_raw = metadata.get("reply_to")
        reply_to_address = ""
        if reply_to_raw:
            _, reply_to_address = parseaddr(str(reply_to_raw))

        from_reply_to_mismatch = False
        if reply_to_raw and _valid_address(reply_to_address):
            from_reply_to_mismatch = extract_domain(reply_to_address) != extract_domain(
                from_address
            )

        spf, dkim, dmarc, auth_failed = _parse_auth_results(
            metadata.get("authentication_results")
        )
        display_mismatch, matched_brand = _display_name_mismatch(display_name, from_address)

        return {
            "email_report": _empty_report(
                from_reply_to_mismatch=from_reply_to_mismatch,
                auth_failed=auth_failed,
                spf=spf,
                dkim=dkim,
                dmarc=dmarc,
                display_name_mismatch=display_mismatch,
                matched_brand=matched_brand,
            )
        }
    except Exception as exc:  # noqa: BLE001 — malformed headers must not crash the node
        return {"email_report": _empty_report(parse_error=str(exc))}
