"""Modal deployment for the gateway and isolated channel adapters."""

import asyncio
import base64
import json
import logging
import os
import re
import time
from pathlib import Path
from typing import Any

import modal

from glc.channels.envelope import ChannelMessage, ChannelReply

# The Modal "app" is just a namespace for everything we deploy under this name.
app = modal.App("glc-v1-gateway")

# Path to the glc package next to this file. We copy the whole package (not just
# .py files) so its data files travel too: policy.yaml, channels.yaml,
# audit/schema.sql, and the channel catalogue.
PROJECT_ROOT = Path(__file__).resolve().parent
LOCAL_GLC = PROJECT_ROOT / "glc"
PYPROJECT = PROJECT_ROOT / "pyproject.toml"
UV_LOCK = PROJECT_ROOT / "uv.lock"

if not UV_LOCK.is_file():
    raise RuntimeError("uv.lock is required for reproducible Modal image builds")

# Pin the amd64 Debian manifest so upstream tag changes cannot alter deployed
# images. Keep uv pinned too; uv_sync otherwise copies uv:latest.
BASE_IMAGE = (
    "debian:bookworm-slim@sha256:"
    "63a496b5d3b99214b39f5ed70eb71a61e590a77979c79cbee4faf991f8c0783e"
)
UV_VERSION = "0.11.29"
base_image = modal.Image.from_registry(BASE_IMAGE, add_python="3.12")

# The image = a Linux box with Python 3.12, dependency versions from uv.lock,
# the glc package copied in, and GLC_CONFIG_DIR pointed at the Volume mount so
# all databases land on persistent storage instead of the throwaway container
# filesystem. The manifest is also mounted because this container resolves the
# adapter Sandbox image dynamically at request time.
gateway_image = (
    base_image.uv_sync(
        uv_project_dir=str(PROJECT_ROOT),
        frozen=True,
        uv_version=UV_VERSION,
        extra_options="--no-dev",
    )
    .env({"GLC_CONFIG_DIR": "/data/glc"})
    .add_local_dir(str(LOCAL_GLC), remote_path="/root/glc")
    .add_local_file(str(PYPROJECT), remote_path="/root/pyproject.toml")
)

# Sandboxes receive code and dependencies, but no gateway Volume or provider
# Secret. Their filesystem and process namespace are separate from the gateway.
adapter_image = (
    base_image.uv_sync(
        uv_project_dir=str(PROJECT_ROOT),
        frozen=True,
        uv_version=UV_VERSION,
        extra_options="--no-dev",
    )
    .env({"GLC_CONFIG_DIR": "/tmp/glc", "GLC_ENV": "production"})
    .add_local_dir(str(LOCAL_GLC), remote_path="/root/glc")
)

# A persistent Volume. The audit db, pairing db, and install token live here and
# survive restarts and redeploys. Without this, every restart wipes them.
data_volume = modal.Volume.from_name("glc-data", create_if_missing=True)

# The provider keys, injected as environment variables at runtime. Created
# separately with `modal secret create glc-llm-keys ...` (mock values for now).
llm_secret = modal.Secret.from_name("glc-llm-keys")

# Credential signing material is gateway-only and separate from provider keys.
capability_secret = modal.Secret.from_name("glc-capability-signing-key")
capability_nonces = modal.Dict.from_name("glc-capability-nonces", create_if_missing=True)

logger = logging.getLogger(__name__)
_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_DOMAIN_RE = re.compile(r"^(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$")
_MAX_PROTOCOL_BYTES = 1_000_000

# Empty tuple means zero egress via block_network=True. Deployments needing a
# dynamic provider host must opt in through GLC_MODAL_ADAPTER_EGRESS_JSON.
_DEFAULT_ADAPTER_EGRESS: dict[str, tuple[str, ...]] = {
    "discord": ("discord.com", "gateway.discord.gg"),
    "gmail": ("gmail.googleapis.com", "oauth2.googleapis.com", "www.googleapis.com"),
    "imap": (),
    "line": ("api.line.me",),
    "local_mic": (),
    "matrix": (),
    "signal": (),
    "slack": ("slack.com",),
    "teams": ("login.microsoftonline.com", "*.trafficmanager.net", "*.botframework.com"),
    "telegram": ("api.telegram.org",),
    "twilio_sms": ("api.twilio.com",),
    "twilio_voice": ("api.twilio.com",),
    "webhook": (),
    "webui": (),
    "whatsapp": ("graph.facebook.com", "api.twilio.com"),
}


def _load_json_mapping(env_name: str) -> dict[str, Any]:
    raw = os.getenv(env_name, "").strip()
    if not raw:
        return {}
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError(f"{env_name} must contain a JSON object")
    return value


def _load_adapter_egress() -> dict[str, tuple[str, ...]]:
    configured = dict(_DEFAULT_ADAPTER_EGRESS)
    for name, domains in _load_json_mapping("GLC_MODAL_ADAPTER_EGRESS_JSON").items():
        if name not in configured or not isinstance(domains, list):
            raise ValueError("invalid adapter egress configuration")
        normalized = tuple(str(domain).lower() for domain in domains)
        if any(not _DOMAIN_RE.fullmatch(domain) for domain in normalized):
            raise ValueError(f"invalid outbound domain configured for {name}")
        configured[name] = normalized
    return configured


def _load_adapter_secrets() -> dict[str, modal.Secret]:
    secrets: dict[str, modal.Secret] = {}
    for name, secret_name in _load_json_mapping("GLC_MODAL_ADAPTER_SECRETS_JSON").items():
        if name not in _DEFAULT_ADAPTER_EGRESS or not isinstance(secret_name, str) or not secret_name:
            raise ValueError("invalid adapter secret configuration")
        expected_name = f"glc-adapter-{name.replace('_', '-')}"
        if secret_name != expected_name:
            raise ValueError(f"adapter {name} must use secret {expected_name}")
        secrets[name] = modal.Secret.from_name(secret_name)
    return secrets


ADAPTER_EGRESS = _load_adapter_egress()
ADAPTER_SECRETS = _load_adapter_secrets()


class ModalNonceStore:
    """Distributed atomic replay store shared by all gateway replicas."""

    async def consume(self, nonce: str, expires_at: int) -> bool:
        return await capability_nonces.put.aio(nonce, expires_at, skip_if_exists=True)


@app.function(image=gateway_image, schedule=modal.Period(days=1))
async def purge_expired_capability_nonces() -> None:
    """Bound replay-ledger growth without making live nonces reusable."""

    now = int(time.time())
    async for nonce, expires_at in capability_nonces.items.aio():
        if isinstance(expires_at, int) and expires_at <= now:
            await capability_nonces.pop.aio(nonce, None)


class ModalAdapterSession:
    def __init__(self, sandbox: modal.Sandbox) -> None:
        self._sandbox = sandbox
        self._stdout = iter(sandbox.stdout)

    @classmethod
    async def create(cls, name: str) -> "ModalAdapterSession":
        if not _NAME_RE.fullmatch(name) or name not in ADAPTER_EGRESS:
            raise KeyError(name)

        domains = ADAPTER_EGRESS[name]
        network_options: dict[str, Any]
        if domains:
            network_options = {"outbound_domain_allowlist": list(domains)}
        else:
            network_options = {"block_network": True}

        secrets = [ADAPTER_SECRETS[name]] if name in ADAPTER_SECRETS else []
        sandbox = await asyncio.to_thread(
            modal.Sandbox.create,
            "python",
            "-m",
            "glc.channels.sandbox_runner",
            name,
            app=app,
            image=adapter_image,
            secrets=secrets,
            timeout=60,
            idle_timeout=30,
            cpu=0.5,
            memory=512,
            **network_options,
        )
        return cls(sandbox)

    def _request_sync(self, payload: dict[str, Any]) -> Any:
        encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
        if len(encoded.encode()) > _MAX_PROTOCOL_BYTES:
            raise ValueError("adapter request too large")
        self._sandbox.stdin.write(encoded + "\n")
        self._sandbox.stdin.drain()
        line = next(self._stdout)
        if len(line.encode()) > _MAX_PROTOCOL_BYTES:
            raise RuntimeError("adapter response too large")
        response = json.loads(line)
        if not isinstance(response, dict) or response.get("ok") is not True:
            raise RuntimeError("adapter operation failed")
        return response.get("result")

    async def on_message(self, raw: Any) -> ChannelMessage | None:
        if isinstance(raw, dict) and isinstance(raw.get("raw_body"), bytes):
            raw = {
                "body_b64": base64.b64encode(raw["raw_body"]).decode("ascii"),
                "headers": raw.get("headers", {}),
            }
        result = await asyncio.to_thread(self._request_sync, {"op": "on_message", "raw": raw})
        return None if result is None else ChannelMessage.model_validate(result)

    async def send(self, reply: ChannelReply) -> Any:
        return await asyncio.to_thread(
            self._request_sync,
            {"op": "send", "reply": reply.model_dump(mode="json")},
        )

    async def close(self) -> None:
        try:
            await asyncio.to_thread(self._sandbox.terminate, wait=True)
        except Exception:
            logger.exception("failed to terminate adapter sandbox")


class ModalAdapterSessionFactory:
    async def open(self, name: str) -> ModalAdapterSession:
        return await ModalAdapterSession.create(name)


@app.function(
    image=gateway_image,
    volumes={"/data": data_volume},
    secrets=[llm_secret, capability_secret],
    min_containers=0,  # scale to zero when idle -> protects the free tier
)
@modal.asgi_app()
def fastapi_app():
    # The gateway writes its databases and install token here on startup, so the
    # folder must exist on the mounted Volume before the app's lifespan runs.
    os.makedirs("/data/glc", exist_ok=True)

    from glc.main import app as web  # the real glc_v1 app, imported as-is
    from glc.security.scoped_credentials import (
        ScopedActionAuthorizer,
        ScopedCredentialAuthority,
        signing_key_from_environment,
    )

    web.state.adapter_session_factory = ModalAdapterSessionFactory()
    web.state.scoped_action_authorizer = ScopedActionAuthorizer(
        ScopedCredentialAuthority(signing_key_from_environment(), ModalNonceStore())
    )
    return web
