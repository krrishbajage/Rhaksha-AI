"""Service for retrieving Gmail messages and converting them to SecurityEvent schemas."""

import base64
from datetime import datetime, timezone
import email.utils
import html
import re
from typing import Any
import uuid
from app.schemas.security_event import SecurityEvent
from app.services.google_auth import build_gmail_client

_URL_REGEX = re.compile(
    r"https?://[a-zA-Z0-9\-\._~:/?#\[\]@!$&\'()*+,;=%]+", re.IGNORECASE
)
_HTML_TAG_REGEX = re.compile(r"<[^>]+>")


def _clean_html(raw_html: str) -> str:
  text = _HTML_TAG_REGEX.sub(" ", raw_html)
  return re.sub(r"\s+", " ", html.unescape(text)).strip()


def _decode_body_data(data: str) -> str:
  if not data:
    return ""
  try:
    # Gmail's URL-safe Base64 data may omit its padding.
    padded = data + "=" * (-len(data) % 4)
    decoded_bytes = base64.urlsafe_b64decode(padded.encode("utf-8"))
    return decoded_bytes.decode("utf-8", errors="replace")
  except (ValueError, UnicodeError):
    return ""


def _extract_body_and_attachments(
    payload: dict[str, Any],
) -> tuple[str, list[str], list[dict[str, Any]]]:
  """Recursively extracts plain text (or fallback HTML), attachment names, and attachment metadata."""
  body_plain = ""
  body_html = ""
  attachment_names: list[str] = []
  attachment_ids: list[dict[str, Any]] = []

  def walk_parts(part: dict[str, Any]):
    nonlocal body_plain, body_html
    mime_type = part.get("mimeType", "")
    filename = part.get("filename", "")
    body_info = part.get("body", {})
    attachment_id = body_info.get("attachmentId")

    # Attachment detection
    if filename and (attachment_id or body_info.get("size", 0) > 0):
      attachment_names.append(filename)
      attachment_ids.append({
          "filename": filename,
          "attachment_id": attachment_id or "",
          "size": body_info.get("size", 0),
      })
      return

    # Text content extraction
    data = body_info.get("data", "")
    if mime_type == "text/plain" and data and not body_plain:
      body_plain = _decode_body_data(data)
    elif mime_type == "text/html" and data and not body_html:
      body_html = _decode_body_data(data)

    for child in part.get("parts", []):
      walk_parts(child)

  walk_parts(payload)

  selected_body = body_plain.strip() or _clean_html(body_html)
  return selected_body, attachment_names, attachment_ids


def fetch_recent_messages(
    user_email: str, max_results: int = 10
) -> list[dict[str, Any]]:
  """Retrieves unread/recent inbox messages from the past day."""
  service = build_gmail_client(user_email)
  response = (
      service.users()
      .messages()
      .list(
          userId="me",
          q="newer_than:1d in:inbox",
          maxResults=max(1, min(max_results, 50)),
      )
      .execute()
  )

  message_items = response.get("messages", [])
  detailed_messages: list[dict[str, Any]] = []

  for item in message_items:
    msg = (
        service.users()
        .messages()
        .get(userId="me", id=item["id"], format="full")
        .execute()
    )
    detailed_messages.append(msg)

  return detailed_messages


def to_security_event(message: dict[str, Any]) -> SecurityEvent:
  """Converts a raw Gmail API message dict into a RAKSHA SecurityEvent."""
  payload = message.get("payload", {})
  headers_list = payload.get("headers", [])

  headers: dict[str, str] = {}
  for h in headers_list:
    name = h.get("name", "").lower()
    value = h.get("value", "")
    headers[name] = value

  from_header = headers.get("from", "")
  parsed_name, parsed_email = email.utils.parseaddr(from_header)
  sender = parsed_email.strip() if parsed_email else from_header.strip()

  subject = headers.get("subject", "").strip()
  reply_to = headers.get("reply-to", "").strip() or None
  auth_results = headers.get("authentication-results", "").strip() or None

  body_text, attachment_names, attachment_ids = _extract_body_and_attachments(
      payload
  )
  full_message_text = f"{subject}\n{body_text}".strip()

  urls = list(dict.fromkeys(_URL_REGEX.findall(full_message_text)))

  # Parse internalDate (epoch ms) to ISO-8601 UTC
  internal_date_raw = message.get("internalDate")
  if internal_date_raw and internal_date_raw.isdigit():
    timestamp = datetime.fromtimestamp(
        int(internal_date_raw) / 1000, tz=timezone.utc
    ).isoformat()
  else:
    timestamp = datetime.now(timezone.utc).isoformat()

  metadata = {
      "from_header": from_header,
      "reply_to": reply_to,
      "authentication_results": auth_results,
      "gmail_message_id": message.get("id"),
      "attachment_ids": attachment_ids,
  }

  return SecurityEvent(
      event_id=str(uuid.uuid4()),
      source_app="email",
      sender=sender or None,
      message_text=full_message_text,
      urls=urls,
      attachments=attachment_names,
      timestamp=timestamp,
      metadata=metadata,
  )
