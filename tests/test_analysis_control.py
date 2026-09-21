"""Concurrency and Gemini rate-limit tests; all provider calls are faked."""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
from pydantic import BaseModel

from app.api import events
from app.schemas.risk_report import RiskReport
from app.schemas.security_event import SecurityEvent
from app.services.analysis_control import AnalysisController, AnalysisUnavailable, ControlSettings


class Output(BaseModel):
    value: str


def settings(**overrides: object) -> ControlSettings:
    defaults: dict[str, object] = {
        "max_concurrent_analyses": 5,
        "max_analysis_queue_wait_seconds": 2.0,
        "max_concurrent_llm_requests": 2,
        "max_llm_requests_per_minute": 100,
        "llm_timeout_seconds": 1.0,
        "llm_retry_count": 0,
        "llm_retry_base_seconds": 0.01,
        "model_cooldown_seconds": 0.01,
    }
    defaults.update(overrides)
    return ControlSettings(**defaults)  # type: ignore[arg-type]


class FakeClient:
    def __init__(self, model: str, outcomes: dict[str, list[object]], **_: object):
        self.model = model
        self.outcomes = outcomes

    def with_structured_output(self, _: type[BaseModel]) -> "FakeClient":
        return self

    def invoke(self, _: list[object]) -> Output:
        outcome = self.outcomes[self.model].pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return Output(value=str(outcome))


def factory(outcomes: dict[str, list[object]]):
    return lambda **kwargs: FakeClient(outcomes=outcomes, **kwargs)


def test_rate_limited_model_falls_back_to_next_model(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("GOOGLE_API_KEY", "test-key")
    monkeypatch.setenv("GEMINI_MODELS", "model-a,model-b")
    result = AnalysisController(settings()).invoke_structured(
        schema=Output, messages=[], temperature=0, request_id="a", agent="test",
        factory=factory({"model-a": [RuntimeError("429 RESOURCE_EXHAUSTED")], "model-b": ["ok"]}),
    )
    assert result.value == "ok"


def test_multiple_rate_limited_models_reach_available_model(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("GOOGLE_API_KEY", "test-key")
    monkeypatch.setenv("GEMINI_MODELS", "model-a,model-b,model-c")
    result = AnalysisController(settings()).invoke_structured(
        schema=Output, messages=[], temperature=0, request_id="a", agent="test",
        factory=factory({
            "model-a": [RuntimeError("429")], "model-b": [RuntimeError("rate limit")], "model-c": ["ok"],
        }),
    )
    assert result.value == "ok"


def test_all_models_exhausted_is_bounded(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("GOOGLE_API_KEY", "test-key")
    monkeypatch.setenv("GEMINI_MODELS", "model-a,model-b")
    controller = AnalysisController(settings(llm_retry_count=0, max_analysis_queue_wait_seconds=0.1))
    with pytest.raises(AnalysisUnavailable):
        controller.invoke_structured(
            schema=Output, messages=[], temperature=0, request_id="a", agent="test",
            factory=factory({"model-a": [RuntimeError("429")], "model-b": [RuntimeError("429")]}),
        )


def test_timeout_is_bounded_and_not_reported_as_result(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("GOOGLE_API_KEY", "test-key")
    monkeypatch.setenv("GEMINI_MODELS", "model-a")
    with pytest.raises(AnalysisUnavailable):
        AnalysisController(settings(llm_retry_count=0)).invoke_structured(
            schema=Output, messages=[], temperature=0, request_id="a", agent="test",
            factory=factory({"model-a": [TimeoutError("provider timed out")]}),
        )


def test_burst_is_bounded_and_all_events_get_independent_slots():
    controller = AnalysisController(settings(max_concurrent_analyses=5))
    active = 0
    peak = 0
    lock = threading.Lock()

    def run(event_id: int) -> int:
        nonlocal active, peak
        with controller.analysis_slot(str(event_id)):
            with lock:
                active += 1
                peak = max(peak, active)
            time.sleep(0.02)
            with lock:
                active -= 1
        return event_id

    with ThreadPoolExecutor(max_workers=10) as executor:
        assert sorted(executor.map(run, range(10))) == list(range(10))
    assert peak == 5


def test_concurrent_endpoint_calls_keep_event_contexts_independent(monkeypatch: pytest.MonkeyPatch):
    controller = AnalysisController(settings(max_concurrent_analyses=5))

    class Workflow:
        def invoke(self, state: dict[str, object]) -> dict[str, RiskReport]:
            event = state["event"]
            assert isinstance(event, SecurityEvent)
            return {"risk_report": RiskReport(
                risk_score=float(len(event.message_text)), risk_level="low",
                scam_category="none", explanation=event.event_id,
                recommended_action=event.timestamp,
            )}

    monkeypatch.setattr(events, "get_controller", lambda: controller)
    monkeypatch.setattr(events, "build_workflow", lambda: Workflow())

    def submit(index: int) -> RiskReport:
        event = SecurityEvent(
            event_id=f"event-{index}", source_app="com.whatsapp", sender=f"sender-{index}",
            message_text=f"message-{index}", urls=[f"https://{index}.example"], attachments=[],
            timestamp=f"2026-01-01T00:00:0{index}Z", metadata={},
        )
        return events.analyze_security_event(event)

    with ThreadPoolExecutor(max_workers=5) as executor:
        reports = list(executor.map(submit, range(5)))
    assert {report.explanation for report in reports} == {f"event-{index}" for index in range(5)}
    assert {report.recommended_action for report in reports} == {
        f"2026-01-01T00:00:0{index}Z" for index in range(5)
    }
