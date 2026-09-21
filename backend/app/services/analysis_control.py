"""Bounded, thread-safe scheduling for analyses and Gemini calls."""

from __future__ import annotations

import logging
import os
import random
import threading
import time
from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Callable, Iterator, TypeVar

from langchain_google_genai import ChatGoogleGenerativeAI

logger = logging.getLogger(__name__)
T = TypeVar("T")


class AnalysisUnavailable(RuntimeError):
    """A transient provider/queue failure; never represents a safe result."""


def _positive_int(name: str, default: int) -> int:
    try:
        return max(1, int(os.getenv(name, default)))
    except ValueError:
        return default


def _positive_float(name: str, default: float) -> float:
    try:
        return max(0.1, float(os.getenv(name, default)))
    except ValueError:
        return default


def _non_negative_int(name: str, default: int) -> int:
    try:
        return max(0, int(os.getenv(name, default)))
    except ValueError:
        return default


@dataclass(frozen=True)
class ControlSettings:
    max_concurrent_analyses: int
    max_analysis_queue_wait_seconds: float
    max_concurrent_llm_requests: int
    max_llm_requests_per_minute: int
    llm_timeout_seconds: float
    llm_retry_count: int
    llm_retry_base_seconds: float
    model_cooldown_seconds: float

    @classmethod
    def from_env(cls) -> "ControlSettings":
        return cls(
            max_concurrent_analyses=_positive_int("MAX_CONCURRENT_ANALYSES", 5),
            max_analysis_queue_wait_seconds=_positive_float("MAX_ANALYSIS_QUEUE_WAIT_SECONDS", 180),
            max_concurrent_llm_requests=_positive_int("MAX_CONCURRENT_LLM_REQUESTS", 2),
            max_llm_requests_per_minute=_positive_int("MAX_LLM_REQUESTS_PER_MINUTE", 10),
            llm_timeout_seconds=_positive_float("GEMINI_TIMEOUT_SECONDS", 25),
            llm_retry_count=_non_negative_int("GEMINI_RETRY_COUNT", 2),
            llm_retry_base_seconds=_positive_float("GEMINI_RETRY_BASE_SECONDS", 1),
            model_cooldown_seconds=_positive_float("GEMINI_MODEL_COOLDOWN_SECONDS", 60),
        )


def configured_models(agent: str | None = None) -> tuple[str, ...]:
    agent_key = f"GEMINI_MODELS_{agent.upper()}" if agent else ""
    configured = (os.getenv(agent_key) if agent_key else None) or os.getenv("GEMINI_MODELS") or os.getenv("GEMINI_MODEL", "gemini-3.6-flash")
    models = tuple(dict.fromkeys(item.strip() for item in configured.split(",") if item.strip()))
    if not models:
        raise AnalysisUnavailable("No Gemini model is configured")
    return models


def configured_model_rpm() -> dict[str, int]:
    """Read `model:requests-per-minute` entries without hard-coding account capabilities."""
    limits: dict[str, int] = {}
    for entry in os.getenv("GEMINI_MODEL_RPM", "").split(","):
        model, separator, raw_limit = entry.strip().rpartition(":")
        if not separator:
            continue
        try:
            limits[model.strip()] = max(1, int(raw_limit))
        except ValueError:
            logger.warning("Ignoring invalid GEMINI_MODEL_RPM entry")
    return limits


def is_rate_limited(error: BaseException) -> bool:
    text = str(error).lower()
    status = getattr(error, "status_code", None) or getattr(getattr(error, "response", None), "status_code", None)
    return status == 429 or any(marker in text for marker in ("429", "resource_exhausted", "rate limit", "quota", "too many requests"))


class AnalysisController:
    """Global provider capacity only; request event/state never lives here."""

    def __init__(self, settings: ControlSettings | None = None, clock: Callable[[], float] = time.monotonic):
        self.settings = settings or ControlSettings.from_env()
        self._clock = clock
        self._analysis_slots = threading.BoundedSemaphore(self.settings.max_concurrent_analyses)
        self._llm_slots = threading.BoundedSemaphore(self.settings.max_concurrent_llm_requests)
        self._lock = threading.Lock()
        self._request_times: dict[str, deque[float]] = {}
        self._cooldowns: dict[str, float] = {}
        self._cursor = 0

    @contextmanager
    def analysis_slot(self, request_id: str) -> Iterator[None]:
        if not self._analysis_slots.acquire(timeout=self.settings.max_analysis_queue_wait_seconds):
            raise AnalysisUnavailable("Analysis queue wait limit reached")
        logger.info("analysis_started request_id=%s", request_id)
        try:
            yield
            logger.info("analysis_completed request_id=%s", request_id)
        except Exception:
            logger.exception("analysis_failed request_id=%s", request_id)
            raise
        finally:
            self._analysis_slots.release()

    def _mark_rate_limited(self, model: str) -> None:
        with self._lock:
            self._cooldowns[model] = self._clock() + self.settings.model_cooldown_seconds

    def _reserve_model_rate_slot(self, models: tuple[str, ...], deadline: float) -> str:
        while True:
            now = self._clock()
            with self._lock:
                rates = configured_model_rpm()
                soonest_wait: float | None = None
                for offset in range(len(models)):
                    index = (self._cursor + offset) % len(models)
                    model = models[index]
                    if self._cooldowns.get(model, 0) > now:
                        wait = self._cooldowns[model] - now
                    else:
                        request_times = self._request_times.setdefault(model, deque())
                        while request_times and now - request_times[0] >= 60:
                            request_times.popleft()
                        limit = rates.get(model, self.settings.max_llm_requests_per_minute)
                        if len(request_times) < limit:
                            request_times.append(now)
                            self._cursor = (index + 1) % len(models)
                            return model
                        wait = 60 - (now - request_times[0])
                    soonest_wait = wait if soonest_wait is None else min(soonest_wait, wait)
            wait_seconds = max(0.01, soonest_wait or self.settings.llm_retry_base_seconds)
            if now + wait_seconds > deadline:
                raise AnalysisUnavailable("Gemini rate queue wait limit reached")
            time.sleep(min(wait_seconds, 1.0))

    def invoke_structured(
        self,
        *,
        schema: type[T],
        messages: list[Any],
        temperature: float,
        request_id: str,
        agent: str,
        factory: Callable[..., Any] = ChatGoogleGenerativeAI,
    ) -> T:
        api_key = os.getenv("GOOGLE_API_KEY", "").strip()
        if not api_key:
            raise AnalysisUnavailable("GOOGLE_API_KEY is missing")
        models = configured_models(agent)
        deadline = self._clock() + self.settings.max_analysis_queue_wait_seconds
        attempts = 0
        last_error: BaseException | None = None
        max_attempts = max(len(models), 1) * (self.settings.llm_retry_count + 1)

        while attempts < max_attempts and self._clock() < deadline:
            model = self._reserve_model_rate_slot(models, deadline)
            attempts += 1
            if not self._llm_slots.acquire(timeout=max(0.0, deadline - self._clock())):
                break
            try:
                logger.info("agent_started request_id=%s agent=%s model=%s attempt=%s", request_id, agent, model, attempts)
                client = factory(model=model, google_api_key=api_key, temperature=temperature,
                    timeout=self.settings.llm_timeout_seconds, max_retries=0)
                result = client.with_structured_output(schema).invoke(messages)
                logger.info("agent_completed request_id=%s agent=%s model=%s", request_id, agent, model)
                return result
            except Exception as error:  # provider exceptions differ by SDK version
                last_error = error
                if is_rate_limited(error):
                    self._mark_rate_limited(model)
                    logger.warning("rate_limit request_id=%s agent=%s model=%s", request_id, agent, model)
                else:
                    logger.warning("agent_retry request_id=%s agent=%s model=%s error_type=%s", request_id, agent, model, type(error).__name__)
                if attempts < max_attempts:
                    delay = self.settings.llm_retry_base_seconds * (2 ** min(attempts - 1, 4))
                    time.sleep(min(delay + random.uniform(0, delay * 0.2), max(0.0, deadline - self._clock())))
            finally:
                self._llm_slots.release()
        raise AnalysisUnavailable("Gemini analysis unavailable after bounded retries") from last_error


_controller_lock = threading.Lock()
_controller: AnalysisController | None = None
_controller_signature: tuple[tuple[str, str | None], ...] | None = None


def get_controller() -> AnalysisController:
    global _controller, _controller_signature
    keys = ("MAX_CONCURRENT_ANALYSES", "MAX_ANALYSIS_QUEUE_WAIT_SECONDS", "MAX_CONCURRENT_LLM_REQUESTS",
        "MAX_LLM_REQUESTS_PER_MINUTE", "GEMINI_TIMEOUT_SECONDS", "GEMINI_RETRY_COUNT",
        "GEMINI_RETRY_BASE_SECONDS", "GEMINI_MODEL_COOLDOWN_SECONDS")
    signature = tuple((key, os.getenv(key)) for key in keys)
    with _controller_lock:
        if _controller is None or signature != _controller_signature:
            _controller = AnalysisController()
            _controller_signature = signature
        return _controller
