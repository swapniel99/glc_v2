"""Adapter execution boundary used by channel webhook routes.

Local development keeps the existing in-process adapter behavior. Modal
injects a sandbox-backed factory into ``app.state`` so deployed webhook
requests never import or execute adapter code in the gateway process.
"""

from __future__ import annotations

from typing import Any, Protocol

from glc.channels import registry
from glc.channels.envelope import ChannelMessage, ChannelReply


class AdapterSession(Protocol):
    async def on_message(self, raw: Any) -> ChannelMessage | None: ...

    async def send(self, reply: ChannelReply) -> Any: ...

    async def close(self) -> None: ...


class AdapterSessionFactory(Protocol):
    async def open(self, name: str) -> AdapterSession: ...


class LocalAdapterSession:
    """Development-only compatibility path; Modal replaces this factory."""

    def __init__(self, name: str) -> None:
        self._adapter = registry.instantiate(name)

    async def on_message(self, raw: Any) -> ChannelMessage | None:
        return await self._adapter.on_message(raw)

    async def send(self, reply: ChannelReply) -> Any:
        return await self._adapter.send(reply)

    async def close(self) -> None:
        return None


async def open_adapter_session(state: Any, name: str) -> AdapterSession:
    factory: AdapterSessionFactory | None = getattr(state, "adapter_session_factory", None)
    if factory is not None:
        return await factory.open(name)
    return LocalAdapterSession(name)
