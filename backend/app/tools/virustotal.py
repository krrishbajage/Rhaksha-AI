"""VirusTotal URL reputation lookup with optional stub fallback."""

from __future__ import annotations

import base64
import logging
import os
import time

import httpx

from app.tools.similarity import extract_domain

logger = logging.getLogger(__name__)

VT_URL_ENDPOINT = "https://www.virustotal.com/api/v3/urls/{url_id}"
CACHE_TTL_SECONDS = 3600
_cache: dict[str, tuple[float, dict[str, object]]] = {}

# Ignore 1–2 vendor flags: that is common background noise on popular sites.
VIRUSTOTAL_MALICIOUS_THRESHOLD = 3


def _verdict(malicious_votes: int) -> str:
    if malicious_votes >= VIRUSTOTAL_MALICIOUS_THRESHOLD:
        return "malicious"
    if malicious_votes > 0:
        return "low_confidence"
    return "clean"


def _get_api_key() -> str | None:
    key = os.getenv("VIRUSTOTAL_API_KEY")
    return key.strip() if key and key.strip() else None


def _encode_url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8").strip("=")


def _cache_get(key: str) -> dict[str, object] | None:
    entry = _cache.get(key)
    if entry and time.time() - entry[0] < CACHE_TTL_SECONDS:
        return dict(entry[1])
    return None


def _cache_set(key: str, value: dict[str, object]) -> None:
    _cache[key] = (time.time(), dict(value))


async def check_url(url: str) -> dict[str, object]:
    api_key = _get_api_key()
    if not api_key:
        logger.warning("VIRUSTOTAL_API_KEY missing; returning stubbed unknown result")
        return {
            "source": "virustotal",
            "status": "unknown",
            "url": url,
            "malicious_votes": 0,
            "total_votes": 0,
            "stubbed": True,
        }

    cache_key = extract_domain(url)
    if cache_key:
        cached = _cache_get(cache_key)
        if cached is not None:
            cached["url"] = url
            return cached

    url_id = _encode_url_id(url)
    headers = {"x-apikey": api_key}

    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            response = await client.get(VT_URL_ENDPOINT.format(url_id=url_id), headers=headers)
            if response.status_code == 404:
                return {
                    "source": "virustotal",
                    "status": "unknown",
                    "url": url,
                    "malicious_votes": 0,
                    "total_votes": 0,
                    "stubbed": False,
                }
            response.raise_for_status()
            stats = response.json()["data"]["attributes"]["last_analysis_stats"]
            malicious = int(stats.get("malicious", 0))
            total = sum(int(v) for v in stats.values())
            result: dict[str, object] = {
                "source": "virustotal",
                "status": _verdict(malicious),
                "url": url,
                "malicious_votes": malicious,
                "total_votes": total,
                "analysis_stats": stats,
                "threshold": VIRUSTOTAL_MALICIOUS_THRESHOLD,
                "stubbed": False,
            }
            if cache_key:
                _cache_set(cache_key, result)
            return result
    except httpx.HTTPError as exc:
        logger.warning("VirusTotal lookup failed: error_type=%s", type(exc).__name__)
        return {
            "source": "virustotal",
            "status": "unknown",
            "url": url,
            "malicious_votes": 0,
            "total_votes": 0,
            "error": str(exc),
            "stubbed": False,
        }
