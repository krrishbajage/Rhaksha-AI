"""Domain typosquatting detection using RapidFuzz."""

from __future__ import annotations

import re
from urllib.parse import urlparse

from rapidfuzz import fuzz

# High-value Indian/global brands commonly impersonated in scams.
KNOWN_BRANDS: tuple[str, ...] = (
    "hdfcbank",
    "sbi",
    "icicibank",
    "axisbank",
    "kotak",
    "paytm",
    "phonepe",
    "gpay",
    "googlepay",
    "amazon",
    "flipkart",
    "irctc",
    "uidai",
    "incometax",
    "paypal",
    "microsoft",
    "google",
    "whatsapp",
    "instagram",
    "facebook",
)

TYPOSQUAT_THRESHOLD = 82
MIN_TOKEN_LENGTH = 4


def extract_domain(url: str) -> str:
    parsed = urlparse(url if "://" in url else f"https://{url}")
    host = parsed.netloc.lower()
    if host.startswith("www."):
        host = host[4:]
    return host


def detect_typosquat(url: str) -> dict[str, object]:
    domain = extract_domain(url)
    if not domain:
        return {
            "typosquat_detected": False,
            "domain": domain,
            "similar_to": None,
            "similarity_score": 0,
            "matched_text": None,
        }

    label = domain.split(".")[0]
    tokens = [token for token in re.split(r"[-_]", label) if len(token) >= MIN_TOKEN_LENGTH]
    candidates = [label, *tokens]

    best_brand: str | None = None
    best_score = 0
    matched_text: str | None = None

    for text in candidates:
        for brand in KNOWN_BRANDS:
            if text == brand:
                continue
            # Use full-string ratio only. partial_ratio("google", "googlepay") is 100
            # and would false-positive legitimate google.com domains.
            score = fuzz.ratio(text, brand)
            if score > best_score:
                best_score = score
                best_brand = brand
                matched_text = text

    detected = (
        best_brand is not None
        and best_score >= TYPOSQUAT_THRESHOLD
        and matched_text != best_brand
    )

    return {
        "typosquat_detected": detected,
        "domain": domain,
        "similar_to": best_brand if detected else None,
        "similarity_score": best_score if detected else 0,
        "matched_text": matched_text if detected else None,
    }
