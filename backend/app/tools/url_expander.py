"""Follow HTTP redirects to resolve a URL to its final destination."""

from __future__ import annotations

import logging

import httpx

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 8.0
MAX_REDIRECTS = 10


def expand_url(url: str) -> dict[str, object]:
    try:
        with httpx.Client(
            follow_redirects=True,
            timeout=DEFAULT_TIMEOUT,
            headers={"User-Agent": "RAKSHA-AI/1.0"},
        ) as client:
            response = client.get(url)
            chain = [str(item.url) for item in response.history] + [str(response.url)]
            return {
                "original_url": url,
                "final_url": str(response.url),
                "redirect_count": len(response.history),
                "redirect_chain": chain[: MAX_REDIRECTS + 1],
                "status_code": response.status_code,
            }
    except httpx.HTTPError as exc:
        logger.warning("URL expand failed for %s: %s", url, exc)
        return {
            "original_url": url,
            "final_url": url,
            "redirect_count": 0,
            "redirect_chain": [url],
            "status_code": None,
            "error": str(exc),
        }
