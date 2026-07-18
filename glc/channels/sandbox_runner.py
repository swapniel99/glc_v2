"""JSON-lines adapter worker for a Modal Sandbox.

One process owns one adapter instance. The gateway sends ``on_message`` and
``send`` operations over stdin/stdout, preserving per-request adapter state
without giving adapter code access to gateway secrets, state, or PID space.
"""

from __future__ import annotations

import asyncio
import base64
import importlib
import json
import re
import sys
from typing import Any

from glc.channels.base import ChannelAdapter
from glc.channels.envelope import ChannelReply

_CHANNEL_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_MAX_LINE_BYTES = 1_000_000


def _load_adapter(name: str) -> ChannelAdapter:
    if not _CHANNEL_RE.fullmatch(name):
        raise ValueError("invalid adapter name")
    module = importlib.import_module(f"glc.channels.catalogue.{name}.adapter")
    cls = getattr(module, "Adapter", None)
    if not isinstance(cls, type) or not issubclass(cls, ChannelAdapter):
        raise ValueError("adapter class not found")
    return cls(config=None)


def _decode_raw(value: Any) -> Any:
    if not isinstance(value, dict) or "body_b64" not in value:
        return value
    body_b64 = value.get("body_b64")
    headers = value.get("headers")
    if not isinstance(body_b64, str) or not isinstance(headers, dict):
        raise ValueError("invalid webhook input")
    return {
        "raw_body": base64.b64decode(body_b64, validate=True),
        "headers": {str(key): str(item) for key, item in headers.items()},
    }


def _write_response(payload: dict[str, Any]) -> None:
    encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    if len(encoded.encode()) > _MAX_LINE_BYTES:
        encoded = '{"ok":false,"error":"adapter response too large"}'
    print(encoded, flush=True)


async def _handle(adapter: ChannelAdapter, request: dict[str, Any]) -> Any:
    operation = request.get("op")
    if operation == "on_message":
        message = await adapter.on_message(_decode_raw(request.get("raw")))
        return None if message is None else message.model_dump(mode="json")
    if operation == "send":
        reply = ChannelReply.model_validate(request.get("reply"))
        return await adapter.send(reply)
    raise ValueError("unsupported adapter operation")


async def _run(name: str) -> None:
    adapter = _load_adapter(name)
    while line := await asyncio.to_thread(sys.stdin.readline):
        if len(line.encode()) > _MAX_LINE_BYTES:
            _write_response({"ok": False, "error": "adapter request too large"})
            continue
        try:
            request = json.loads(line)
            if not isinstance(request, dict):
                raise ValueError("adapter request must be an object")
            result = await _handle(adapter, request)
            _write_response({"ok": True, "result": result})
        except Exception as exc:
            print(f"adapter operation failed: {exc!r}", file=sys.stderr, flush=True)
            _write_response({"ok": False, "error": "adapter operation failed"})


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: python -m glc.channels.sandbox_runner <adapter>")
    asyncio.run(_run(sys.argv[1]))


if __name__ == "__main__":
    main()
