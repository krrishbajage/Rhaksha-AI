"""Security event schema."""

from typing import Any

from pydantic import BaseModel, Field


class SecurityEvent(BaseModel):
    event_id: str
    source_app: str
    sender: str | None = None
    message_text: str = ""
    urls: list[str] = Field(default_factory=list)
    attachments: list[str] = Field(default_factory=list)
    timestamp: str
    metadata: dict[str, Any] = Field(default_factory=dict)
