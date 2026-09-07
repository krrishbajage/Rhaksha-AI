"""Google Safe Browsing API integration with optional stub fallback."""

from __future__ import annotations

import logging
import os

import httpx

logger = logging.getLogger(__name__)

SAFE_BROWSING_ENDPOINT = (
    "https://safebrowsing.googleapis.com/v4/threatMatches:find"
)


def _get_api_key() -> str | None:
    key = os.getenv("SAFE_BROWSING_API_KEY") or os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
    return key.strip() if key and key.strip() else None


def check_url(url: str) -> dict[str, object]:
    api_key = _get_api_key()
    if not api_key:
        logger.warning(
            "SAFE_BROWSING_API_KEY missing; returning stubbed unknown result for %s",
            url,
        )
        return {
            "source": "safe_browsing",
            "status": "unknown",
            "url": url,
            "threats": [],
            "stubbed": True,
        }

    payload = {
        "client": {"clientId": "raksha-ai", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        with httpx.Client(timeout=10.0) as client:
            response = client.post(
                SAFE_BROWSING_ENDPOINT,
                params={"key": api_key},
                json=payload,
            )
            response.raise_for_status()
            data = response.json()
            matches = data.get("matches", [])
            return {
                "source": "safe_browsing",
                "status": "malicious" if matches else "clean",
                "url": url,
                "threats": matches,
                "stubbed": False,
            }
    except httpx.HTTPError as exc:
        logger.warning("Safe Browsing lookup failed for %s: %s", url, exc)
        return {
            "source": "safe_browsing",
            "status": "unknown",
            "url": url,
            "threats": [],
            "error": str(exc),
            "stubbed": False,
        }
