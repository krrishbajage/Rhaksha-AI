"""Google Safe Browsing API integration with optional stub fallback."""

from __future__ import annotations

import logging
import os
import time

import httpx

from app.tools.similarity import extract_domain

logger = logging.getLogger(__name__)

SAFE_BROWSING_ENDPOINT = (
    "https://safebrowsing.googleapis.com/v4/threatMatches:find"
)
CACHE_TTL_SECONDS = 3600
_cache: dict[str, tuple[float, dict[str, object]]] = {}


def _get_api_key() -> str | None:
    key = os.getenv("SAFE_BROWSING_API_KEY") or os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
    return key.strip() if key and key.strip() else None


def _cache_get(key: str) -> dict[str, object] | None:
    entry = _cache.get(key)
    if entry and time.time() - entry[0] < CACHE_TTL_SECONDS:
        return dict(entry[1])
    return None


def _cache_set(key: str, value: dict[str, object]) -> None:
    _cache[key] = (time.time(), dict(value))


def _unknown(url: str, *, stubbed: bool, error: str | None = None) -> dict[str, object]:
    result: dict[str, object] = {
        "source": "safe_browsing",
        "status": "unknown",
        "url": url,
        "threats": [],
        "stubbed": stubbed,
    }
    if error:
        result["error"] = error
    return result


async def check_url(url: str) -> dict[str, object]:
    api_key = _get_api_key()
    if not api_key:
        logger.warning("SAFE_BROWSING_API_KEY missing; returning stubbed unknown result")
        return _unknown(url, stubbed=True)

    cache_key = extract_domain(url)
    if cache_key:
        cached = _cache_get(cache_key)
        if cached is not None:
            cached["url"] = url
            return cached

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
        async with httpx.AsyncClient(timeout=2.0) as client:
            response = await client.post(
                SAFE_BROWSING_ENDPOINT,
                params={"key": api_key},
                json=payload,
            )
            response.raise_for_status()
            data = response.json()
            matches = data.get("matches", [])
            threat_types = sorted(
                {str(match.get("threatType")) for match in matches if match.get("threatType")}
            )
            result: dict[str, object] = {
                "source": "safe_browsing",
                "status": "malicious" if matches else "clean",
                "url": url,
                "threats": matches,
                "threat_types": threat_types,
                "stubbed": False,
            }
            if cache_key:
                _cache_set(cache_key, result)
            return result
    except httpx.HTTPError as exc:
        logger.warning("Safe Browsing lookup failed: error_type=%s", type(exc).__name__)
        return _unknown(url, stubbed=False, error=str(exc))
