"""Aggregator node — flattens agent reports into a single evidence list."""

from __future__ import annotations

from typing import Any

from app.graph.state import InvestigationState


def _append_message_evidence(evidence: list[dict[str, Any]], report: dict[str, Any]) -> None:
    if report.get("impersonation"):
        evidence.append(
            {
                "type": "message",
                "signal": "impersonation",
                "weight": 20,
                "detail": "Message appears to impersonate a trusted entity.",
            }
        )
    if report.get("urgency_detected"):
        evidence.append(
            {
                "type": "message",
                "signal": "urgency",
                "weight": 15,
                "detail": "Message uses urgency or pressure tactics.",
            }
        )
    if report.get("otp_request"):
        evidence.append(
            {
                "type": "message",
                "signal": "otp_request",
                "weight": 25,
                "detail": "Message requests OTP/PIN or verification code.",
            }
        )
    if report.get("kyc_request"):
        evidence.append(
            {
                "type": "message",
                "signal": "kyc_request",
                "weight": 20,
                "detail": "Message requests KYC or identity verification.",
            }
        )
    if report.get("payment_request"):
        evidence.append(
            {
                "type": "message",
                "signal": "payment_request",
                "weight": 25,
                "detail": "Message requests payment or fund transfer.",
            }
        )
    for indicator in report.get("indicators", []):
        evidence.append(
            {
                "type": "message",
                "signal": "indicator",
                "weight": 5,
                "detail": str(indicator),
            }
        )


def _append_url_evidence(evidence: list[dict[str, Any]], report: dict[str, Any]) -> None:
    for finding in report.get("findings", []):
        url = finding.get("final_url") or finding.get("normalized_url")
        typosquat = finding.get("typosquat", {})
        if typosquat.get("typosquat_detected"):
            evidence.append(
                {
                    "type": "url",
                    "signal": "typosquat",
                    "weight": 30,
                    "detail": (
                        f"Domain {typosquat.get('domain')} resembles "
                        f"{typosquat.get('similar_to')} (score {typosquat.get('similarity_score')})."
                    ),
                    "url": url,
                }
            )

        safe = finding.get("safe_browsing", {})
        if safe.get("status") == "malicious":
            evidence.append(
                {
                    "type": "url",
                    "signal": "safe_browsing_malicious",
                    "weight": 40,
                    "detail": "Google Safe Browsing flagged this URL.",
                    "url": url,
                }
            )
        elif safe.get("status") == "unknown" and safe.get("stubbed"):
            evidence.append(
                {
                    "type": "url",
                    "signal": "safe_browsing_unknown",
                    "weight": 5,
                    "detail": "Safe Browsing check skipped (API key missing).",
                    "url": url,
                }
            )

        vt = finding.get("virustotal", {})
        if vt.get("status") == "malicious":
            evidence.append(
                {
                    "type": "url",
                    "signal": "virustotal_malicious",
                    "weight": 35,
                    "detail": (
                        f"VirusTotal reports {vt.get('malicious_votes')} malicious detections."
                    ),
                    "url": url,
                }
            )
        elif vt.get("status") == "unknown" and vt.get("stubbed"):
            evidence.append(
                {
                    "type": "url",
                    "signal": "virustotal_unknown",
                    "weight": 5,
                    "detail": "VirusTotal check skipped (API key missing).",
                    "url": url,
                }
            )

        expansion = finding.get("expansion", {})
        if int(expansion.get("redirect_count", 0)) >= 2:
            evidence.append(
                {
                    "type": "url",
                    "signal": "redirect_chain",
                    "weight": 10,
                    "detail": "URL redirects multiple times before landing.",
                    "url": url,
                }
            )


def _append_attachment_evidence(evidence: list[dict[str, Any]], report: dict[str, Any]) -> None:
    for finding in report.get("findings", []):
        if finding.get("suspicious") or finding.get("dangerous_extension"):
            evidence.append(
                {
                    "type": "attachment",
                    "signal": "dangerous_extension",
                    "weight": 35,
                    "detail": str(finding.get("risk_reason")),
                    "filename": finding.get("filename"),
                }
            )


def aggregator_node(state: InvestigationState) -> dict[str, list[dict[str, Any]]]:
    evidence: list[dict[str, Any]] = []

    message_report = state.get("message_report") or {}
    url_report = state.get("url_report") or {}
    attachment_report = state.get("attachment_report") or {}

    if message_report:
        _append_message_evidence(evidence, message_report)
    if url_report:
        _append_url_evidence(evidence, url_report)
    if attachment_report:
        _append_attachment_evidence(evidence, attachment_report)

    if not evidence:
        evidence.append(
            {
                "type": "system",
                "signal": "no_signals",
                "weight": 0,
                "detail": "No suspicious indicators were detected.",
            }
        )

    return {"evidence": evidence}
