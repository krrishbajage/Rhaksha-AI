"""Isolated tests for the URL Agent and Attachment Agent.

These cases call the agent functions directly (not the full LangGraph, and not
the Android notification path) so failures are easy to pinpoint.

Google's official Safe Browsing test URLs (testsafebrowsing.appspot.com) are
used instead of real malicious sites because they are safe to request
repeatedly, they will not get anyone's IP flagged for visiting live malware,
and they have guaranteed consistent Safe Browsing verdicts for automated
testing. V1 attachment checks are filename-based only — WhatsApp does not
give us file bytes — so attachment cases use names, never real binaries.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from dotenv import load_dotenv

for _env_path in (
    Path("/app/.env"),
    Path(__file__).resolve().parents[1] / ".env",
    Path(__file__).resolve().parents[2] / ".env",
):
    if _env_path.is_file():
        load_dotenv(_env_path)
        break

from app.graph.nodes.attachment_agent import analyze_attachments
from app.graph.nodes.url_agent import analyze_urls, _threat_labels
from app.tools import safe_browsing, virustotal

SAFE_BROWSING_MALWARE = "http://testsafebrowsing.appspot.com/s/malware.html"
SAFE_BROWSING_PHISHING = "http://testsafebrowsing.appspot.com/s/phishing.html"
SAFE_BROWSING_UNWANTED = "http://testsafebrowsing.appspot.com/s/unwanted.html"
SAFE_URL = "https://www.google.com"
MALFORMED_URL = "not-a-real-url"
TYPOSQUAT_URL = "http://gooogle-login.com"


def _print_url_case(label: str, url: str, finding: dict) -> None:
    print(f"\n=== URL CASE: {label} ===")
    print(f"URL: {url}")
    print("Safe Browsing:")
    print(json.dumps(finding.get("safe_browsing"), indent=2, default=str))
    print("VirusTotal:")
    print(json.dumps(finding.get("virustotal"), indent=2, default=str))
    print("Similarity / typosquatting:")
    print(json.dumps(finding.get("typosquat"), indent=2, default=str))
    print("Signals:")
    print(json.dumps(finding.get("signals"), indent=2, default=str))


def _finding_for(url: str) -> dict:
    report = analyze_urls([url])["url_report"]
    assert report["findings"], f"URL agent returned no findings for {url}"
    return report["findings"][0]


def _signal_names(finding: dict) -> set[str]:
    return {str(item.get("signal")) for item in finding.get("signals") or []}


def _assert_virustotal_malicious_above_threshold(finding: dict) -> None:
    vt = finding["virustotal"]
    if vt.get("stubbed"):
        pytest.skip("VIRUSTOTAL_API_KEY missing — cannot assert vendor-count threshold live.")
    assert int(vt.get("malicious_votes") or 0) >= virustotal.VIRUSTOTAL_MALICIOUS_THRESHOLD
    assert vt["status"] == "malicious"
    assert "virustotal_malicious" in _signal_names(finding)


def test_url_agent_safe_browsing_malware():
    finding = _finding_for(SAFE_BROWSING_MALWARE)
    _print_url_case("Safe Browsing malware test URL", SAFE_BROWSING_MALWARE, finding)

    safe = finding["safe_browsing"]
    if safe.get("stubbed"):
        pytest.skip("SAFE_BROWSING_API_KEY missing — malware URL cannot be verified live.")
    labels = set(_threat_labels(safe) + [t.lower() for t in (safe.get("threat_types") or [])])
    assert safe["status"] == "malicious"
    assert "malware" in labels or "MALWARE" in (safe.get("threat_types") or [])
    assert "safe_browsing_malicious" in _signal_names(finding)
    _assert_virustotal_malicious_above_threshold(finding)


def test_url_agent_safe_browsing_phishing():
    finding = _finding_for(SAFE_BROWSING_PHISHING)
    _print_url_case("Safe Browsing phishing test URL", SAFE_BROWSING_PHISHING, finding)

    safe = finding["safe_browsing"]
    if safe.get("stubbed"):
        pytest.skip("SAFE_BROWSING_API_KEY missing — phishing URL cannot be verified live.")
    labels = set(_threat_labels(safe) + [t.lower() for t in (safe.get("threat_types") or [])])
    assert safe["status"] == "malicious"
    assert "phishing" in labels or "SOCIAL_ENGINEERING" in (safe.get("threat_types") or [])
    assert "safe_browsing_malicious" in _signal_names(finding)
    _assert_virustotal_malicious_above_threshold(finding)


def test_url_agent_safe_browsing_unwanted():
    finding = _finding_for(SAFE_BROWSING_UNWANTED)
    _print_url_case("Safe Browsing unwanted-software test URL", SAFE_BROWSING_UNWANTED, finding)

    safe = finding["safe_browsing"]
    if safe.get("stubbed"):
        pytest.skip("SAFE_BROWSING_API_KEY missing — unwanted URL cannot be verified live.")
    labels = set(_threat_labels(safe) + [t.lower() for t in (safe.get("threat_types") or [])])
    assert safe["status"] == "malicious"
    assert (
        "unwanted software" in labels
        or "UNWANTED_SOFTWARE" in (safe.get("threat_types") or [])
    )
    assert "safe_browsing_malicious" in _signal_names(finding)
    _assert_virustotal_malicious_above_threshold(finding)


def test_url_agent_known_safe_google():
    finding = _finding_for(SAFE_URL)
    _print_url_case("known-safe google.com", SAFE_URL, finding)

    safe = finding["safe_browsing"]
    if not safe.get("stubbed"):
        assert safe["status"] in {"clean", "unknown"}
        assert safe["status"] != "malicious"
    assert finding["typosquat"]["typosquat_detected"] is False
    assert "safe_browsing_malicious" not in _signal_names(finding)
    assert "typosquat" not in _signal_names(finding)
    assert "virustotal_malicious" not in _signal_names(finding)
    vt = finding["virustotal"]
    if not vt.get("stubbed") and int(vt.get("malicious_votes") or 0) > 0:
        assert vt["status"] == "low_confidence"
        assert int(vt["malicious_votes"]) < virustotal.VIRUSTOTAL_MALICIOUS_THRESHOLD


def test_url_agent_virustotal_vendor_noise_is_not_malicious():
    """Lock in the threshold: 1–2 VirusTotal vendors must not become virustotal_malicious."""
    finding = _finding_for(SAFE_URL)
    _print_url_case("VirusTotal vendor-noise (google.com live)", SAFE_URL, finding)

    vt = finding["virustotal"]
    if vt.get("stubbed"):
        pytest.skip("VIRUSTOTAL_API_KEY missing — vendor-noise case cannot be verified live.")

    votes = int(vt.get("malicious_votes") or 0)
    if votes == 0:
        assert vt["status"] == "clean"
    else:
        assert votes < virustotal.VIRUSTOTAL_MALICIOUS_THRESHOLD
        assert vt["status"] == "low_confidence"
    assert vt["status"] != "malicious"
    assert "virustotal_malicious" not in _signal_names(finding)


def test_url_agent_two_vendor_flags_are_low_confidence_not_malicious(monkeypatch: pytest.MonkeyPatch):
    """Regression lock: exactly 2 vendor flags must not emit virustotal_malicious."""

    def fake_vt(url: str):
        votes = 2
        return {
            "source": "virustotal",
            "status": virustotal._verdict(votes),
            "url": url,
            "malicious_votes": votes,
            "total_votes": 90,
            "threshold": virustotal.VIRUSTOTAL_MALICIOUS_THRESHOLD,
            "stubbed": False,
        }

    monkeypatch.setattr(
        "app.graph.nodes.url_agent.virustotal_check",
        fake_vt,
    )
    monkeypatch.setattr(
        "app.graph.nodes.url_agent.safe_browsing_check",
        lambda url: {
            "source": "safe_browsing",
            "status": "clean",
            "url": url,
            "threats": [],
            "threat_types": [],
            "stubbed": False,
        },
    )

    finding = _finding_for(SAFE_URL)
    _print_url_case("VirusTotal 2-vendor noise (mocked)", SAFE_URL, finding)

    vt = finding["virustotal"]
    assert vt["malicious_votes"] == 2
    assert vt["status"] == "low_confidence"
    assert "virustotal_malicious" not in _signal_names(finding)


def test_url_agent_malformed_input_does_not_crash():
    finding = _finding_for(MALFORMED_URL)
    _print_url_case("malformed / no-scheme input", MALFORMED_URL, finding)
    assert finding["original_url"] == MALFORMED_URL
    assert isinstance(finding.get("signals"), list)


def test_url_agent_typosquat_gooogle_login():
    finding = _finding_for(TYPOSQUAT_URL)
    _print_url_case("typosquat gooogle-login.com", TYPOSQUAT_URL, finding)

    typosquat = finding["typosquat"]
    assert typosquat["typosquat_detected"] is True
    assert typosquat["similar_to"] == "google"
    assert "typosquat" in _signal_names(finding)


def test_url_agent_missing_api_keys_degrade_to_unknown(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("SAFE_BROWSING_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_SAFE_BROWSING_API_KEY", raising=False)
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)

    sb = safe_browsing.check_url(SAFE_URL)
    vt = virustotal.check_url(SAFE_URL)
    finding = _finding_for(SAFE_URL)
    _print_url_case("API keys unset (stub fallback)", SAFE_URL, finding)

    assert sb["status"] == "unknown"
    assert sb.get("stubbed") is True
    assert vt["status"] == "unknown"
    assert vt.get("stubbed") is True
    assert finding["safe_browsing"]["status"] == "unknown"
    assert finding["virustotal"]["status"] == "unknown"
    names = _signal_names(finding)
    assert "safe_browsing_unknown" in names
    assert "virustotal_unknown" in names


def _print_attachment_case(finding: dict) -> None:
    print(
        f"filename={finding['filename']!r}  "
        f"suffixes={finding['suffixes']}  "
        f"suspicious={finding['suspicious']}"
    )


def test_attachment_agent_filename_cases():
    filenames = [
        "BankUpdate.apk",
        "invoice.pdf.apk",
        "vacation_photo.jpg",
        "script.js",
        "document.PDF",
    ]
    findings = analyze_attachments(filenames)["attachment_report"]["findings"]
    by_name = {item["filename"]: item for item in findings}

    print("\n=== ATTACHMENT AGENT (filename-only, V1) ===")
    for name in filenames:
        _print_attachment_case(by_name[name])

    apk = by_name["BankUpdate.apk"]
    assert apk["suffixes"] == [".apk"]
    assert apk["suspicious"] is True

    disguised = by_name["invoice.pdf.apk"]
    assert disguised["suffixes"] == [".pdf", ".apk"]
    assert disguised["suspicious"] is True
    assert disguised["disguised_double_extension"] is True

    photo = by_name["vacation_photo.jpg"]
    assert photo["suffixes"] == [".jpg"]
    assert photo["suspicious"] is False

    script = by_name["script.js"]
    assert script["suffixes"] == [".js"]
    assert script["suspicious"] is True

    pdf = by_name["document.PDF"]
    assert pdf["suffixes"] == [".pdf"]
    assert pdf["suspicious"] is False
    assert pdf["extension"] == ".pdf"
