import base64
from unittest.mock import AsyncMock, patch
from app.schemas.risk_report import RiskReport
from app.services.gmail_fetcher import to_security_event
import pytest


def _encode(text: str) -> str:
  return base64.urlsafe_b64encode(text.encode("utf-8")).decode("utf-8")


@pytest.fixture
def sample_message_with_reply_to_and_attachments():
  return {
      "id": "msg_test_001",
      "internalDate": "1727500000000",
      "payload": {
          "headers": [
              {"name": "From", "value": "State Bank Support <support@sbi-alert.com>"},
              {"name": "Subject", "value": "Urgent: Complete your KYC verification"},
              {"name": "Reply-To", "value": "fraudster_inbox@gmail.com"},
              {
                  "name": "Authentication-Results",
                  "value": "mx.google.com; dkim=fail; spf=softfail",
              },
          ],
          "parts": [
              {
                  "mimeType": "text/plain",
                  "body": {
                      "data": _encode(
                          "Dear Customer, update your profile immediately at"
                          " https://phishing-portal.com/login"
                      )
                  },
              },
              {
                  "mimeType": "application/pdf",
                  "filename": "VerificationForm.pdf",
                  "body": {"attachmentId": "att_blob_999", "size": 24500},
              },
          ],
      },
  }


@pytest.fixture
def sample_message_standard_no_reply_to():
  return {
      "id": "msg_test_002",
      "internalDate": "1727500000000",
      "payload": {
          "headers": [
              {"name": "From", "value": "no-reply@company.com"},
              {"name": "Subject", "value": "Quarterly Statement"},
          ],
          "parts": [
              {
                  "mimeType": "text/plain",
                  "body": {"data": _encode("Your statement is available.")},
              }
          ],
      },
  }


def test_to_security_event_with_reply_to_and_attachments(sample_message_with_reply_to_and_attachments):
  event = to_security_event(sample_message_with_reply_to_and_attachments)

  assert event.source_app == "email"
  assert event.sender == "support@sbi-alert.com"
  assert "Urgent: Complete your KYC verification" in event.message_text
  assert "https://phishing-portal.com/login" in event.urls
  assert "VerificationForm.pdf" in event.attachments

  # Metadata validation
  meta = event.metadata
  assert meta["gmail_message_id"] == "msg_test_001"
  assert meta["reply_to"] == "fraudster_inbox@gmail.com"
  assert "dkim=fail" in meta["authentication_results"]
  assert len(meta["attachment_ids"]) == 1
  assert meta["attachment_ids"][0]["filename"] == "VerificationForm.pdf"
  assert meta["attachment_ids"][0]["attachment_id"] == "att_blob_999"


def test_to_security_event_without_reply_to(sample_message_standard_no_reply_to):
  event = to_security_event(sample_message_standard_no_reply_to)

  assert event.source_app == "email"
  assert event.sender == "no-reply@company.com"
  assert event.metadata["reply_to"] is None
  assert event.metadata["authentication_results"] is None
  assert len(event.attachments) == 0
  assert len(event.metadata["attachment_ids"]) == 0


@pytest.mark.asyncio
async def test_email_sync_endpoint(client=None):
  mock_messages = [{
      "id": "gmail_sync_001",
      "internalDate": "1727500000000",
      "payload": {
          "headers": [
              {"name": "From", "value": "test@domain.com"},
              {"name": "Subject", "value": "Test Subject"},
          ],
          "parts": [
              {
                  "mimeType": "text/plain",
                  "body": {"data": _encode("Hello world")},
              }
          ],
      },
  }]

  mock_report = RiskReport(
      risk_score=85,
      risk_level="high",
      scam_category="phishing",
      explanation="High-risk phishing email detected.",
      recommended_action="Do not open the link.",
  )

  with patch("app.api.email.TokenStore.get_refresh_token", return_value="mock_token"), \
       patch("app.api.email.fetch_recent_messages", return_value=mock_messages), \
       patch("app.api.email.ProcessedEmailStore.is_processed", return_value=False), \
       patch("app.api.email.ProcessedEmailStore.mark_processed") as mock_mark, \
       patch("app.api.email.analyze_security_event", new_callable=AsyncMock) as mock_analyze:

    mock_analyze.return_value = mock_report

    from httpx import ASGITransport, AsyncClient
    from app.main import app

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
      response = await ac.post("/api/email/sync", json={"user_email": "test@domain.com"})

    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["gmail_message_id"] == "gmail_sync_001"
    assert data[0]["risk_report"]["risk_score"] == 85
    mock_mark.assert_called_once_with("gmail_sync_001")
