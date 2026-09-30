"""Isolated asynchronous URL-agent and attachment-agent tests."""

from __future__ import annotations

import asyncio

import pytest

from app.graph.nodes.aggregator import _append_attachment_evidence
from app.graph.nodes.attachment_agent import analyze_attachments, attachment_agent_node
from app.graph.nodes.url_agent import analyze_urls
from app.schemas.security_event import SecurityEvent
from app.tools import safe_browsing, virustotal


def run(coroutine):
    return asyncio.run(coroutine)


def test_attachment_agent_filename_cases():
    findings = analyze_attachments(["BankUpdate.apk", "invoice.pdf.apk", "photo.jpg"])["attachment_report"]["findings"]
    by_name = {item["filename"]: item for item in findings}
    assert by_name["BankUpdate.apk"]["suspicious"] is True
    assert by_name["invoice.pdf.apk"]["disguised_double_extension"] is True
    assert by_name["photo.jpg"]["suspicious"] is False


def test_attachment_agent_email_malicious_hash(monkeypatch: pytest.MonkeyPatch):
    event = SecurityEvent(
        event_id="test-att-01",
        source_app="email",
        sender="attacker@example.com",
        message_text="See attached invoice",
        urls=[],
        attachments=["invoice.pdf"],
        timestamp="2026-09-30T10:00:00Z",
        metadata={
            "user_email": "victim@example.com",
            "gmail_message_id": "msg_01",
            "attachment_ids": [
                {"filename": "invoice.pdf", "attachment_id": "att_01", "size": 1024}
            ],
        },
    )

    monkeypatch.setattr(
        "app.graph.nodes.attachment_agent.fetch_attachment_bytes",
        lambda user_email, msg_id, att_id: b"malicious executable payload",
    )

    async def fake_vt_hash(file_hash: str):
        return {
            "source": "virustotal",
            "status": "malicious",
            "hash": file_hash,
            "malicious_votes": 15,
            "total_votes": 70,
            "stubbed": False,
        }

    monkeypatch.setattr("app.graph.nodes.attachment_agent.check_file_hash", fake_vt_hash)

    report = run(attachment_agent_node({"event": event, "run_attachment_agent": True}))["attachment_report"]
    assert report["attachment_count"] == 1
    assert report["dangerous_count"] == 1
    finding = report["findings"][0]
    assert finding["filename"] == "invoice.pdf"
    assert finding["virustotal_status"] == "malicious"
    assert finding["sha256"] is not None
    assert finding["suspicious"] is True

    # Confirm aggregator emits vt_malicious_hash with weight 35
    evidence: list[dict] = []
    _append_attachment_evidence(evidence, report)
    vt_evidence = [e for e in evidence if e["signal"] == "vt_malicious_hash"]
    assert len(vt_evidence) == 1
    assert vt_evidence[0]["weight"] == 35


def test_attachment_agent_email_clean_hash(monkeypatch: pytest.MonkeyPatch):
    event = SecurityEvent(
        event_id="test-att-02",
        source_app="email",
        sender="colleague@example.com",
        message_text="Here is the report",
        urls=[],
        attachments=["report.pdf"],
        timestamp="2026-09-30T10:00:00Z",
        metadata={
            "user_email": "user@example.com",
            "gmail_message_id": "msg_02",
            "attachment_ids": [
                {"filename": "report.pdf", "attachment_id": "att_02", "size": 2048}
            ],
        },
    )

    monkeypatch.setattr(
        "app.graph.nodes.attachment_agent.fetch_attachment_bytes",
        lambda user_email, msg_id, att_id: b"clean pdf document data",
    )

    async def fake_vt_hash(file_hash: str):
        return {
            "source": "virustotal",
            "status": "clean",
            "hash": file_hash,
            "malicious_votes": 0,
            "total_votes": 70,
            "stubbed": False,
        }

    monkeypatch.setattr("app.graph.nodes.attachment_agent.check_file_hash", fake_vt_hash)

    report = run(attachment_agent_node({"event": event, "run_attachment_agent": True}))["attachment_report"]
    assert report["attachment_count"] == 1
    assert report["dangerous_count"] == 0
    finding = report["findings"][0]
    assert finding["virustotal_status"] == "clean"
    assert finding["suspicious"] is False


def test_attachment_agent_email_oversized_skipped(monkeypatch: pytest.MonkeyPatch):
    fetch_invoked = False

    def fake_fetch(user_email, msg_id, att_id):
        nonlocal fetch_invoked
        fetch_invoked = True
        return b"content"

    monkeypatch.setattr("app.graph.nodes.attachment_agent.fetch_attachment_bytes", fake_fetch)

    event = SecurityEvent(
        event_id="test-att-03",
        source_app="email",
        sender="sender@example.com",
        message_text="Heavy file",
        urls=[],
        attachments=["backup.zip"],
        timestamp="2026-09-30T10:00:00Z",
        metadata={
            "user_email": "user@example.com",
            "gmail_message_id": "msg_03",
            "attachment_ids": [
                {"filename": "backup.zip", "attachment_id": "att_03", "size": 30 * 1024 * 1024}
            ],
        },
    )

    report = run(attachment_agent_node({"event": event, "run_attachment_agent": True}))["attachment_report"]
    assert fetch_invoked is False
    assert report["attachment_count"] == 1
    finding = report["findings"][0]
    assert finding.get("skipped") is True
    assert finding.get("skip_reason") == "size_limit_exceeded"
    assert finding["virustotal_status"] == "unknown"


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
    virustotal._file_cache.clear()
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