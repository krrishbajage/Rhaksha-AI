"""End-to-end tests for POST /api/events/analyze."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from dotenv import load_dotenv
from fastapi.testclient import TestClient

for _env_path in (
    Path("/app/.env"),
    Path(__file__).resolve().parents[1] / ".env",
    Path(__file__).resolve().parents[2] / ".env",
):
    if _env_path.is_file():
        load_dotenv(_env_path)
        break

from app.main import app
from app.api import events
from app.graph.nodes import explanation_agent, message_agent
from app.schemas.risk_report import RiskReport

SCAM_EVENT = {
    "event_id": "test-hdfc-apk-001",
    "source_app": "com.whatsapp",
    "sender": "HDFC Alerts",
    "message_text": (
        "Dear customer, your HDFC account will be blocked within 24 hours. "
        "Verify immediately at https://hdfc-bank-verify.xyz/login and share OTP. "
        "Install security_update.apk to continue banking."
    ),
    "urls": ["https://hdfc-bank-verify.xyz/login"],
    "attachments": ["security_update.apk"],
    "timestamp": "2026-09-07T08:00:00Z",
    "metadata": {"channel": "whatsapp"},
}

BENIGN_EVENT = {
    "event_id": "test-dinner-002",
    "source_app": "com.whatsapp",
    "sender": "Priya",
    "message_text": "hey, dinner at 8 tonight?",
    "urls": [],
    "attachments": [],
    "timestamp": "2026-09-07T08:05:00Z",
    "metadata": {"channel": "whatsapp"},
}


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


def _require_google_api_key() -> None:
    if not os.getenv("GOOGLE_API_KEY", "").strip():
        pytest.skip("GOOGLE_API_KEY not set — add it to .env to run the full Gemini workflow test.")


def _print_report(label: str, report: dict) -> None:
    print(f"\n--- RiskReport ({label}) ---")
    print(json.dumps(report, indent=2))


def test_analyze_scam_event_returns_high_risk_report(client: TestClient):
    _require_google_api_key()

    response = client.post("/api/events/analyze", json=SCAM_EVENT)
    assert response.status_code == 200, response.text

    report = response.json()
    _print_report("scam: HDFC URL + APK", report)

    assert report["risk_score"] >= 30
    assert report["risk_level"] in {"medium", "high", "critical"}
    assert report["explanation"]
    assert report["recommended_action"]


def test_analyze_benign_event_returns_low_risk_report(client: TestClient):
    _require_google_api_key()

    response = client.post("/api/events/analyze", json=BENIGN_EVENT)
    assert response.status_code == 200, response.text

    report = response.json()
    _print_report("benign: dinner plans", report)

    assert report["risk_score"] < 30
    assert report["risk_level"] == "low"
    assert report["scam_category"] == "none"
    assert report["explanation"]
    assert report["recommended_action"]


def test_analyze_sms_event_returns_risk_report(client: TestClient, monkeypatch: pytest.MonkeyPatch):
    class Controller:
        def analysis_slot(self, _request_id: str):
            from contextlib import nullcontext

            return nullcontext()

        def invoke_structured(self, *, schema: type, **_kwargs: object):
            if schema.__name__ == "MessageAnalysis":
                return schema(impersonation=True)
            return schema(
                explanation="SMS event analyzed.",
                recommended_action="Verify the sender independently.",
            )

    controller = Controller()
    monkeypatch.setattr(events, "get_controller", lambda: controller)
    monkeypatch.setattr(message_agent, "get_controller", lambda: controller)
    monkeypatch.setattr(explanation_agent, "get_controller", lambda: controller)

    response = client.post(
        "/api/events/analyze",
        json={
            "event_id": "sms-endpoint-test",
            "source_app": "sms",
            "sender": "+919876543210",
            "message_text": "Your bank account is blocked",
            "urls": [],
            "attachments": [],
            "timestamp": "2026-09-26T00:00:00Z",
            "metadata": {"channel": "sms"},
        },
    )

    assert response.status_code == 200, response.text
    assert response.json()["risk_score"] == 40
    assert response.json()["risk_level"] == "medium"
