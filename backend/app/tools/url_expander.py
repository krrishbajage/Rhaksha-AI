"""Follow HTTP redirects to resolve a URL to its final destination."""

from __future__ import annotations

import logging

import httpx

logger = logging.getLogger(__name__)

# URL intelligence is supplementary evidence.  It must not hold an analysis
# slot long enough to make the Android caller time out when a network is down.
DEFAULT_TIMEOUT = 2.0
MAX_REDIRECTS = 10


def _result(url: str, response: httpx.Response) -> dict[str, object]:
    chain = [str(item.url) for item in response.history] + [str(response.url)]
    return {
        "original_url": url,
        "final_url": str(response.url),
        "redirect_count": len(response.history),
        "status_code": response.status_code,
        "redirect_chain": chain[: MAX_REDIRECTS + 1],
    }


def _failure(url: str, exc: BaseException) -> dict[str, object]:
    logger.warning("URL expansion failed: error_type=%s", type(exc).__name__)
    return {
        "original_url": url,
        "final_url": url,
        "redirect_count": 0,
        "redirect_chain": [url],
        "status_code": None,
        "error": str(exc),
    }


async def expand_url(url: str) -> dict[str, object]:
    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=DEFAULT_TIMEOUT,
            headers={"User-Agent": "RAKSHA-AI/1.0"},
        ) as client:
            response = await client.head(url)
            if response.status_code == 405:
                response = await client.get(url)
            return _result(url, response)
    except httpx.HTTPError as exc:
        return _failure(url, exc)
