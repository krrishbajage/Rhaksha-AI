"""Isolated asynchronous URL-agent and attachment-agent tests."""

from __future__ import annotations

import asyncio

import pytest

from app.graph.nodes.attachment_agent import analyze_attachments
from app.graph.nodes.url_agent import analyze_urls
from app.tools import safe_browsing, virustotal


def run(coroutine):
    return asyncio.run(coroutine)


def test_attachment_agent_filename_cases():
    findings = analyze_attachments(["BankUpdate.apk", "invoice.pdf.apk", "photo.jpg"])["attachment_report"]["findings"]
    by_name = {item["filename"]: item for item in findings}
    assert by_name["BankUpdate.apk"]["suspicious"] is True
    assert by_name["invoice.pdf.apk"]["disguised_double_extension"] is True
    assert by_name["photo.jpg"]["suspicious"] is False


def test_url_agent_runs_lookup_agents_concurrently(monkeypatch: pytest.MonkeyPatch):
    async def fake_expand(url: str):
        await asyncio.sleep(0.03)
        return {"original_url": url, "final_url": url, "redirect_count": 0, "redirect_chain": [url], "status_code": 200}

    async def fake_safe(url: str):
        await asyncio.sleep(0.03)
        return {"source": "safe_browsing", "status": "clean", "url": url, "threats": [], "threat_types": [], "stubbed": False}

    async def fake_vt(url: str):
        await asyncio.sleep(0.03)
        return {"source": "virustotal", "status": "clean", "url": url, "malicious_votes": 0, "total_votes": 10, "stubbed": False}

    monkeypatch.setattr("app.graph.nodes.url_agent.expand_url", fake_expand)
    monkeypatch.setattr("app.graph.nodes.url_agent.safe_browsing_check", fake_safe)
    monkeypatch.setattr("app.graph.nodes.url_agent.virustotal_check", fake_vt)
    report = run(analyze_urls(["https://gooogle-login.example", "https://example.org"]))["url_report"]
    assert report["url_count"] == 2
    assert report["findings"][0]["typosquat"]["typosquat_detected"] is True


def test_url_agent_missing_keys_degrade_to_unknown(monkeypatch: pytest.MonkeyPatch):
    safe_browsing._cache.clear()
    virustotal._cache.clear()
    monkeypatch.delenv("SAFE_BROWSING_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_SAFE_BROWSING_API_KEY", raising=False)
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    report = run(analyze_urls(["https://example.org"]))["url_report"]
    finding = report["findings"][0]
    assert finding["safe_browsing"]["status"] == "unknown"
    assert finding["virustotal"]["status"] == "unknown"


def test_reputation_cache_is_domain_scoped(monkeypatch: pytest.MonkeyPatch):
    safe_browsing._cache.clear()
    monkeypatch.setenv("SAFE_BROWSING_API_KEY", "test-key")
    calls = 0

    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return {}

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            return None

        async def post(self, *_args, **_kwargs):
            nonlocal calls
            calls += 1
            return Response()

    monkeypatch.setattr(safe_browsing.httpx, "AsyncClient", lambda **_kwargs: Client())
    run(safe_browsing.check_url("https://example.org/one"))
    run(safe_browsing.check_url("https://example.org/two"))
    assert calls == 1
