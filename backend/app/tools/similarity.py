"""Domain typosquatting detection using RapidFuzz."""

from __future__ import annotations

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
        }

    label = domain.split(".")[0]
    best_brand: str | None = None
    best_score = 0

    for brand in KNOWN_BRANDS:
        score = fuzz.ratio(label, brand)
        if score > best_score:
            best_score = score
            best_brand = brand

    detected = (
        best_brand is not None
        and best_score >= TYPOSQUAT_THRESHOLD
        and label != best_brand
    )

    return {
        "typosquat_detected": detected,
        "domain": domain,
        "similar_to": best_brand if detected else None,
        "similarity_score": best_score if detected else 0,
    }
