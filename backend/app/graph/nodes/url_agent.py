"""URL analysis agent — expansion, reputation, and typosquatting checks."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse, urlunparse

from app.graph.state import InvestigationState
from app.schemas.security_event import SecurityEvent
from app.tools.safe_browsing import check_url as safe_browsing_check
from app.tools.similarity import detect_typosquat
from app.tools.url_expander import expand_url
from app.tools.virustotal import check_url as virustotal_check

THREAT_TYPE_LABELS = {
    "MALWARE": "malware",
    "SOCIAL_ENGINEERING": "phishing",
    "UNWANTED_SOFTWARE": "unwanted software",
    "POTENTIALLY_HARMFUL_APPLICATION": "potentially harmful application",
}


def normalize_url(url: str) -> str:
    raw = (url or "").strip()
    if not raw:
        return raw
    parsed = urlparse(raw)
    scheme = (parsed.scheme or "https").lower()
    host = parsed.netloc.lower()
    if host.startswith("www."):
        host = host[4:]
    path = parsed.path or "/"
    if path != "/":
        path = path.rstrip("/")
    return urlunparse((scheme, host, path, "", parsed.query, ""))


def _threat_labels(safe_browsing: dict[str, Any]) -> list[str]:
    labels: list[str] = []
    for threat in safe_browsing.get("threats") or []:
        threat_type = str(threat.get("threatType", ""))
        labels.append(THREAT_TYPE_LABELS.get(threat_type, threat_type.lower() or "unknown"))
    return labels


def _merge_reputation(results: list[dict[str, Any]], source: str) -> dict[str, Any]:
    if not results:
        return {"source": source, "status": "unknown", "stubbed": True}
    if any(item.get("status") == "malicious" for item in results):
        chosen = next(item for item in results if item.get("status") == "malicious")
        merged = dict(chosen)
        if source == "safe_browsing":
            threats = []
            threat_types: list[str] = []
            for item in results:
                threats.extend(item.get("threats") or [])
                threat_types.extend(item.get("threat_types") or [])
            merged["threats"] = threats
            merged["threat_types"] = sorted(set(threat_types))
        return merged
    if any(item.get("status") == "clean" and not item.get("stubbed") for item in results):
        return next(item for item in results if item.get("status") == "clean" and not item.get("stubbed"))
    return results[0]


def _signals_for_finding(finding: dict[str, Any]) -> list[dict[str, Any]]:
    signals: list[dict[str, Any]] = []
    url = finding.get("final_url") or finding.get("normalized_url") or finding.get("original_url")

    safe = finding.get("safe_browsing") or {}
    threat_labels = _threat_labels(safe)
    if safe.get("status") == "malicious":
        signals.append(
            {
                "signal": "safe_browsing_malicious",
                "labels": threat_labels,
                "detail": f"Safe Browsing flagged this URL ({', '.join(threat_labels) or 'malicious'}).",
                "url": url,
            }
        )
    elif safe.get("status") == "unknown" and safe.get("stubbed"):
        signals.append(
            {
                "signal": "safe_browsing_unknown",
                "labels": [],
                "detail": "Safe Browsing check skipped (API key missing).",
                "url": url,
            }
        )

    vt = finding.get("virustotal") or {}
    if vt.get("status") == "malicious":
        signals.append(
            {
                "signal": "virustotal_malicious",
                "detail": f"VirusTotal reports {vt.get('malicious_votes')} malicious detections.",
                "url": url,
            }
        )
    elif vt.get("status") == "unknown" and vt.get("stubbed"):
        signals.append(
            {
                "signal": "virustotal_unknown",
                "detail": "VirusTotal check skipped (API key missing).",
                "url": url,
            }
        )

    typosquat = finding.get("typosquat") or {}
    if typosquat.get("typosquat_detected"):
        signals.append(
            {
                "signal": "typosquat",
                "detail": (
                    f"Domain {typosquat.get('domain')} resembles "
                    f"{typosquat.get('similar_to')} (score {typosquat.get('similarity_score')})."
                ),
                "url": url,
            }
        )
    return signals


def analyze_urls(urls: list[str]) -> dict[str, Any]:
    """Run URL-agent logic on a list of URLs without the rest of the graph."""
    event = SecurityEvent(
        event_id="url-agent-direct",
        source_app="test",
        sender=None,
        message_text="",
        urls=urls,
        attachments=[],
        timestamp="1970-01-01T00:00:00Z",
    )
    return url_agent_node({"event": event, "run_url_agent": True})


def url_agent_node(state: InvestigationState) -> dict[str, dict]:
    if not state.get("run_url_agent"):
        return {}
    event = state["event"]
    findings: list[dict] = []

    for raw_url in event.urls or []:
        try:
            normalized = normalize_url(raw_url)
            expansion = expand_url(normalized) if normalized else {
                "original_url": raw_url,
                "final_url": raw_url,
                "redirect_count": 0,
                "redirect_chain": [raw_url],
                "status_code": None,
            }
            final_url = str(expansion.get("final_url") or normalized or raw_url)
            reputation_targets = []
            for candidate in (normalized, raw_url, final_url):
                if candidate and candidate not in reputation_targets:
                    reputation_targets.append(candidate)

            safe_browsing = _merge_reputation(
                [safe_browsing_check(target) for target in reputation_targets],
                "safe_browsing",
            )
            virustotal = _merge_reputation(
                [virustotal_check(target) for target in reputation_targets],
                "virustotal",
            )
            typosquat = detect_typosquat(final_url) if final_url else detect_typosquat(raw_url)
            if not typosquat.get("typosquat_detected"):
                original_typosquat = detect_typosquat(raw_url)
                if original_typosquat.get("typosquat_detected"):
                    typosquat = original_typosquat

            finding = {
                "original_url": raw_url,
                "normalized_url": normalized,
                "final_url": final_url,
                "expansion": expansion,
                "typosquat": typosquat,
                "safe_browsing": safe_browsing,
                "virustotal": virustotal,
            }
            finding["signals"] = _signals_for_finding(finding)
            findings.append(finding)
        except Exception as exc:  # noqa: BLE001 — isolation tests must never crash the agent
            findings.append(
                {
                    "original_url": raw_url,
                    "normalized_url": raw_url,
                    "final_url": raw_url,
                    "expansion": {"error": str(exc)},
                    "typosquat": {
                        "typosquat_detected": False,
                        "domain": "",
                        "similar_to": None,
                        "similarity_score": 0,
                    },
                    "safe_browsing": {
                        "source": "safe_browsing",
                        "status": "unknown",
                        "url": raw_url,
                        "threats": [],
                        "error": str(exc),
                    },
                    "virustotal": {
                        "source": "virustotal",
                        "status": "unknown",
                        "url": raw_url,
                        "error": str(exc),
                    },
                    "signals": [],
                    "handled_gracefully": True,
                }
            )

    return {
        "url_report": {
            "agent": "url_agent",
            "url_count": len(findings),
            "findings": findings,
        }
    }
