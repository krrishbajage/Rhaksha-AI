"""VirusTotal URL reputation lookup with optional stub fallback."""

from __future__ import annotations

import base64
import logging
import os

import httpx

logger = logging.getLogger(__name__)

VT_URL_ENDPOINT = "https://www.virustotal.com/api/v3/urls/{url_id}"

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


def check_url(url: str) -> dict[str, object]:
    api_key = _get_api_key()
    if not api_key:
        logger.warning(
            "VIRUSTOTAL_API_KEY missing; returning stubbed unknown result for %s",
            url,
        )
        return {
            "source": "virustotal",
            "status": "unknown",
            "url": url,
            "malicious_votes": 0,
            "total_votes": 0,
            "stubbed": True,
        }

    url_id = _encode_url_id(url)
    headers = {"x-apikey": api_key}

    try:
        with httpx.Client(timeout=12.0) as client:
            response = client.get(VT_URL_ENDPOINT.format(url_id=url_id), headers=headers)
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
            status = _verdict(malicious)
            return {
                "source": "virustotal",
                "status": status,
                "url": url,
                "malicious_votes": malicious,
                "total_votes": total,
                "analysis_stats": stats,
                "threshold": VIRUSTOTAL_MALICIOUS_THRESHOLD,
                "stubbed": False,
            }
    except httpx.HTTPError as exc:
        logger.warning("VirusTotal lookup failed for %s: %s", url, exc)
        return {
            "source": "virustotal",
            "status": "unknown",
            "url": url,
            "malicious_votes": 0,
            "total_votes": 0,
            "error": str(exc),
            "stubbed": False,
        }
