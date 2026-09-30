from __future__ import annotations

from app.graph.nodes.aggregator import aggregator_node
from app.graph.nodes.email_agent import email_agent_node
from app.schemas.security_event import SecurityEvent


def _email_event(**metadata: object) -> SecurityEvent:
    return SecurityEvent(
        event_id="email-agent-test",
        source_app="email",
        sender="service@paypal.com",
        message_text="Please review your account.",
        timestamp="2026-09-30T00:00:00Z",
        metadata=metadata,
    )


def _run_agent(event: SecurityEvent) -> dict:
    return email_agent_node({"event": event, "run_email_agent": True})


def test_email_agent_noop_when_not_scheduled():
    event = _email_event(from_header="PayPal <service@paypal.com>")
    assert email_agent_node({"event": event, "run_email_agent": False}) == {}


def test_reply_to_domain_mismatch_report_and_evidence():
    event = _email_event(
        from_header="Support <billing@example.com>",
        reply_to="Help Desk <help@unrelated-domain.net>",
    )
    result = _run_agent(event)
    report = result["email_report"]
    assert report["agent"] == "email_agent"
    assert report["from_reply_to_mismatch"] is True
    assert report["auth_failed"] is False
    assert report["display_name_mismatch"] is False
    assert report["spf"] is None
    assert report["dkim"] is None
    assert report["dmarc"] is None

    evidence = aggregator_node({"event": event, **result})["evidence"]
    mismatch = [item for item in evidence if item["signal"] == "from_reply_to_mismatch"]
    assert mismatch == [
        {
            "type": "email",
            "signal": "from_reply_to_mismatch",
            "weight": 25,
            "detail": "Reply-To domain does not match the From domain.",
        }
    ]
    assert sum(item["weight"] for item in evidence if item["type"] == "email") == 25


def test_auth_failures_report_and_evidence():
    event = _email_event(
        from_header="Support <billing@example.com>",
        authentication_results="mx.google.com; dkim=fail; spf=softfail",
    )
    result = _run_agent(event)
    report = result["email_report"]
    assert report["from_reply_to_mismatch"] is False
    assert report["auth_failed"] is True
    assert report["spf"] == "softfail"
    assert report["dkim"] == "fail"
    assert report["dmarc"] is None
    assert report["display_name_mismatch"] is False

    evidence = aggregator_node({"event": event, **result})["evidence"]
    auth = [item for item in evidence if item["signal"] == "auth_failed"]
    assert auth == [
        {
            "type": "email",
            "signal": "auth_failed",
            "weight": 20,
            "detail": "SPF, DKIM, or DMARC authentication did not pass.",
        }
    ]
    assert sum(item["weight"] for item in evidence if item["type"] == "email") == 20


def test_clean_email_has_no_flags_or_email_evidence():
    event = _email_event(from_header="Support <billing@example.com>")
    result = _run_agent(event)
    report = result["email_report"]
    assert report == {
        "agent": "email_agent",
        "from_reply_to_mismatch": False,
        "auth_failed": False,
        "spf": None,
        "dkim": None,
        "dmarc": None,
        "display_name_mismatch": False,
        "matched_brand": None,
    }

    evidence = aggregator_node({"event": event, **result})["evidence"]
    email_items = [item for item in evidence if item["type"] == "email"]
    assert email_items == []
    assert evidence[0]["signal"] == "no_signals"
    assert evidence[0]["weight"] == 0
