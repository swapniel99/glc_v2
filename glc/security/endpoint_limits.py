"""Hard request budgets and replica-safe endpoint rate-limit interface."""

from __future__ import annotations

import asyncio
import math
import threading
import time
from collections import deque
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field

from fastapi import HTTPException, Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

MIB = 1024 * 1024

ENDPOINT_RATE_LIMITS: dict[str, int] = {
    "chat": 60,
    "chat_batch": 10,
    "vision": 20,
    "embed": 120,
    "speak": 30,
    "transcribe": 20,
}

ENDPOINT_DAILY_QUOTAS: dict[str, int] = {
    "chat": 1_000,
    "chat_batch": 100,
    "vision": 250,
    "embed": 5_000,
    "speak": 500,
    "transcribe": 250,
}

ENDPOINT_BODY_LIMITS: dict[str, int] = {
    "/v1/chat": 8 * MIB,
    "/v1/chat/batch": 8 * MIB,
    "/v1/vision": 8 * MIB,
    "/v1/embed": 32 * 1024,
    "/v1/speak": 64 * 1024,
    "/v1/transcribe": 36 * MIB,
}

MAX_IMAGE_BYTES = 5 * MIB
MAX_IMAGE_DATA_URL_CHARS = 7 * MIB
MAX_SPEAK_TEXT_CHARS = 20_000
MAX_TRANSCRIBE_AUDIO_BYTES = 25 * MIB
MAX_TRANSCRIBE_AUDIO_B64_CHARS = 35 * MIB


@dataclass
class _EndpointWindows:
    minute: deque[float] = field(default_factory=deque)
    day: deque[float] = field(default_factory=deque)


class EndpointRateLimiter:
    """Thread-safe local sliding-window limiter used outside Modal."""

    def __init__(
        self,
        limits: Mapping[str, int] | None = None,
        daily_quotas: Mapping[str, int] | None = None,
        *,
        window_seconds: int = 60,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.limits = dict(limits or ENDPOINT_RATE_LIMITS)
        self.daily_quotas = dict(daily_quotas or ENDPOINT_DAILY_QUOTAS)
        self.window_seconds = window_seconds
        self._clock = clock
        self._events: dict[str, _EndpointWindows] = {}
        self._lock = threading.Lock()

    def check(self, endpoint: str) -> tuple[bool, int]:
        limit = self.limits.get(endpoint)
        daily_quota = self.daily_quotas.get(endpoint)
        if limit is None or limit < 1 or daily_quota is None or daily_quota < 1:
            raise ValueError(f"unknown or invalid endpoint limit: {endpoint}")

        now = self._clock()
        minute_cutoff = now - self.window_seconds
        day_cutoff = now - 86_400
        with self._lock:
            windows = self._events.setdefault(endpoint, _EndpointWindows())
            while windows.minute and windows.minute[0] <= minute_cutoff:
                windows.minute.popleft()
            while windows.day and windows.day[0] <= day_cutoff:
                windows.day.popleft()

            waits = []
            if len(windows.minute) >= limit:
                waits.append(windows.minute[0] + self.window_seconds - now)
            if len(windows.day) >= daily_quota:
                waits.append(windows.day[0] + 86_400 - now)
            if waits:
                retry_after = max(1, math.ceil(max(waits)))
                return False, retry_after
            windows.minute.append(now)
            windows.day.append(now)
        return True, 0

    async def acheck(self, endpoint: str) -> tuple[bool, int]:
        return self.check(endpoint)


_endpoint_limiter: EndpointRateLimiter | None = None


def get_endpoint_rate_limiter() -> EndpointRateLimiter:
    global _endpoint_limiter
    if _endpoint_limiter is None:
        _endpoint_limiter = EndpointRateLimiter()
    return _endpoint_limiter


def endpoint_rate_limit(endpoint: str) -> Callable[[Request], Awaitable[None]]:
    if endpoint not in ENDPOINT_RATE_LIMITS:
        raise ValueError(f"unknown endpoint limit: {endpoint}")

    async def enforce(request: Request) -> None:
        limiter = getattr(request.app.state, "endpoint_rate_limiter", None)
        if limiter is None:
            limiter = get_endpoint_rate_limiter()
        allowed, retry_after = await limiter.acheck(endpoint)
        if not allowed:
            raise HTTPException(
                status_code=429,
                detail="endpoint rate limit exceeded",
                headers={"Retry-After": str(retry_after)},
            )

    return enforce


class RequestBodyLimitMiddleware:
    """Buffer bounded costly-route bodies, including chunked requests."""

    def __init__(
        self,
        app: ASGIApp,
        limits: Mapping[str, int] | None = None,
    ) -> None:
        self.app = app
        self.limits = dict(limits or ENDPOINT_BODY_LIMITS)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("method") != "POST":
            await self.app(scope, receive, send)
            return

        limit = self.limits.get(scope.get("path", ""))
        if limit is None:
            await self.app(scope, receive, send)
            return

        content_length = _content_length(scope)
        if content_length is not None and content_length > limit:
            await _too_large_response(scope, receive, send)
            return

        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body.extend(message.get("body", b""))
            if len(body) > limit:
                await _too_large_response(scope, receive, send)
                return
            if not message.get("more_body", False):
                break

        replayed = False

        async def replay() -> Message:
            nonlocal replayed
            if replayed:
                await asyncio.sleep(0)
                return {"type": "http.request", "body": b"", "more_body": False}
            replayed = True
            return {"type": "http.request", "body": bytes(body), "more_body": False}

        await self.app(scope, replay, send)


def _content_length(scope: Scope) -> int | None:
    for name, value in scope.get("headers", []):
        if name.lower() == b"content-length":
            try:
                parsed = int(value)
            except ValueError:
                return None
            return parsed if parsed >= 0 else None
    return None


async def _too_large_response(scope: Scope, receive: Receive, send: Send) -> None:
    response = JSONResponse(status_code=413, content={"detail": "request body too large"})
    await response(scope, receive, send)
