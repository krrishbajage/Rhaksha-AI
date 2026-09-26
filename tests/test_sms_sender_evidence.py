from __future__ import annotations

import pytest

from app.graph.nodes.aggregator import aggregator_node
from app.schemas.security_event import SecurityEvent


@pytest.mark.parametrize(
    ("source_app", "sender", "impersonation", "has_mismatch"),
    [
        ("sms", "+919876543210", True, True),
        ("sms", "AD-SBIINB", True, False),
        ("com.whatsapp", "+919876543210", True, False),
        ("sms", "+919876543210", False, False),
    ],
)
def test_sender_mismatch_requires_sms_impersonation_from_phone(
    source_app: str,
    sender: str,
    impersonation: bool,
    has_mismatch: bool,
):
    event = SecurityEvent(
        event_id="sms-sender-test",
        source_app=source_app,
        sender=sender,
        message_text="Your bank account is blocked",
        timestamp="2026-09-26T00:00:00Z",
    )

    result = aggregator_node({"event": event, "message_report": {"impersonation": impersonation}})

    mismatches = [item for item in result["evidence"] if item["signal"] == "sender_mismatch"]
    assert bool(mismatches) is has_mismatch
    if has_mismatch:
        assert mismatches == [
            {
                "type": "sms",
                "signal": "sender_mismatch",
                "weight": 20,
                "detail": (
                    "Message claims to impersonate a trusted entity but was sent from a phone number, "
                    "not a registered DLT header."
                ),
            }
        ]