"""Small thread-safe JSON stores for Gmail OAuth state."""

import json
from pathlib import Path
import os
import threading
from typing import Optional

DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data"
TOKENS_FILE = DATA_DIR / "tokens.json"
PROCESSED_FILE = DATA_DIR / "processed_emails.json"

_lock = threading.Lock()
MAX_PROCESSED_EMAILS = 500


def _ensure_data_dir() -> None:
  DATA_DIR.mkdir(parents=True, exist_ok=True)


def _write_json_atomically(path: Path, value: object) -> None:
  """Avoid leaving a half-written token file if the process stops mid-write."""
  temporary = path.with_suffix(path.suffix + ".tmp")
  temporary.write_text(json.dumps(value, indent=2), encoding="utf-8")
  os.replace(temporary, path)


class TokenStore:

  @staticmethod
  def save_refresh_token(user_email: str, refresh_token: str) -> None:
    with _lock:
      _ensure_data_dir()
      data: dict[str, str] = {}
      if TOKENS_FILE.exists():
        try:
          data = json.loads(TOKENS_FILE.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
          data = {}

      data[user_email.strip().lower()] = refresh_token
      _write_json_atomically(TOKENS_FILE, data)

  @staticmethod
  def get_refresh_token(user_email: str) -> Optional[str]:
    with _lock:
      if not TOKENS_FILE.exists():
        return None
      try:
        data = json.loads(TOKENS_FILE.read_text(encoding="utf-8"))
        return data.get(user_email.strip().lower())
      except (json.JSONDecodeError, OSError):
        return None


class ProcessedEmailStore:

  @staticmethod
  def is_processed(gmail_message_id: str) -> bool:
    with _lock:
      if not PROCESSED_FILE.exists():
        return False
      try:
        ids = json.loads(PROCESSED_FILE.read_text(encoding="utf-8"))
        return gmail_message_id in ids
      except (json.JSONDecodeError, OSError):
        return False

  @staticmethod
  def mark_processed(gmail_message_id: str) -> None:
    with _lock:
      _ensure_data_dir()
      ids: list[str] = []
      if PROCESSED_FILE.exists():
        try:
          ids = list(json.loads(PROCESSED_FILE.read_text(encoding="utf-8")))
        except (json.JSONDecodeError, OSError):
          ids = []

      ids = [item for item in ids if item != gmail_message_id]
      ids.append(gmail_message_id)
      # This is only a lightweight sync cache, not an audit database.
      _write_json_atomically(
          PROCESSED_FILE,
          ids[-MAX_PROCESSED_EMAILS:],
      )
