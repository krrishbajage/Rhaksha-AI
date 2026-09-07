"""URL analysis agent — expansion, reputation, and typosquatting checks."""

from __future__ import annotations

from urllib.parse import urlparse, urlunparse

from app.graph.state import InvestigationState
from app.tools.safe_browsing import check_url as safe_browsing_check
from app.tools.similarity import detect_typosquat
from app.tools.url_expander import expand_url
from app.tools.virustotal import check_url as virustotal_check


def normalize_url(url: str) -> str:
    parsed = urlparse(url.strip())
    scheme = (parsed.scheme or "https").lower()
    host = parsed.netloc.lower()
    if host.startswith("www."):
        host = host[4:]
    path = parsed.path or "/"
    if path != "/":
        path = path.rstrip("/")
    return urlunparse((scheme, host, path, "", parsed.query, ""))


def url_agent_node(state: InvestigationState) -> dict[str, dict]:
    if not state.get("run_url_agent"):
        return {}
    event = state["event"]
    findings: list[dict] = []

    for raw_url in event.urls or []:
        normalized = normalize_url(raw_url)
        expansion = expand_url(normalized)
        final_url = str(expansion.get("final_url", normalized))
        typosquat = detect_typosquat(final_url)
        safe_browsing = safe_browsing_check(final_url)
        virustotal = virustotal_check(final_url)

        findings.append(
            {
                "original_url": raw_url,
                "normalized_url": normalized,
                "final_url": final_url,
                "expansion": expansion,
                "typosquat": typosquat,
                "safe_browsing": safe_browsing,
                "virustotal": virustotal,
            }
        )

    return {
        "url_report": {
            "agent": "url_agent",
            "url_count": len(findings),
            "findings": findings,
        }
    }
