"""WS /v1/channels/{name} — adapter control plane.

Adapters connect over WebSocket and exchange JSON-serialised ChannelMessage
and ChannelReply envelopes. Connections require a short-lived credential
scoped to the route channel and presented in the Authorization header.

This endpoint is the contract surface adapters speak to. The gateway
processes incoming messages through the rate limiter, allowlist,
trust-level classifier, policy engine, and (eventually) the agent
runtime. For S11 the agent runtime is a stub that echoes the message
back so adapter authors can verify their wire is plumbed correctly.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
import os
import time

from fastapi import APIRouter, HTTPException, Request, WebSocket, WebSocketDisconnect, status
from fastapi.responses import JSONResponse, PlainTextResponse

from glc.audit import append as audit_append
from glc.channels.envelope import ChannelMessage, ChannelReply
from glc.channels.execution import open_adapter_session
from glc.security.allowlists import allowed
from glc.security.channel_credentials import InvalidChannelCredential, verify_channel_credential
from glc.security.pairing import get_pairing_store
from glc.security.rate_limits import get_rate_limiter

router = APIRouter()
logger = logging.getLogger(__name__)


@router.websocket("/v1/channels/{name}")
async def channel_ws(websocket: WebSocket, name: str):
    header_auth = websocket.headers.get("authorization") or websocket.headers.get("Authorization")
    presented = ""
    if header_auth and header_auth.startswith("Bearer "):
        presented = header_auth.removeprefix("Bearer ").strip()
    try:
        credential_claims = verify_channel_credential(presented, channel=name)
    except InvalidChannelCredential:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await websocket.accept()
    state = websocket.app.state
    registered = list(getattr(state, "registered_channels", []))
    if name not in registered:
        registered.append(name)
        state.registered_channels = registered

    limiter = get_rate_limiter()
    pairings = get_pairing_store()
    owners = [p.channel_user_id for p in pairings.owners(channel=name)]

    try:
        while True:
            remaining_seconds = credential_claims.expires_at - time.time()
            if remaining_seconds <= 0:
                await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
                return
            try:
                raw = await asyncio.wait_for(
                    websocket.receive_text(),
                    timeout=remaining_seconds,
                )
            except TimeoutError:
                await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
                return
            try:
                payload = json.loads(raw)
                env = ChannelMessage.model_validate(payload)
            except Exception as e:
                await websocket.send_text(json.dumps({"error": f"invalid envelope: {e}"}))
                continue

            if env.channel != name:
                audit_append(
                    channel=name,
                    channel_user_id=env.channel_user_id,
                    trust_level=env.trust_level,
                    event_type="channel_mismatch",
                    result={"envelope_channel": env.channel},
                )
                await websocket.send_text(json.dumps({"error": "channel does not match route"}))
                continue

            ok, why = allowed(
                env.channel,
                env.channel_user_id,
                owner_ids=owners,
                is_public_channel=bool(env.metadata.get("is_public_channel", False)),
                was_mentioned=bool(env.metadata.get("was_mentioned", False)),
            )
            if not ok:
                audit_append(
                    channel=env.channel,
                    channel_user_id=env.channel_user_id,
                    trust_level=env.trust_level,
                    event_type="allowlist_drop",
                    result={"reason": why},
                )
                await websocket.send_text(json.dumps({"error": f"dropped: {why}"}))
                continue

            ok, why = limiter.check_message(env.channel, env.channel_user_id)
            if not ok:
                audit_append(
                    channel=env.channel,
                    channel_user_id=env.channel_user_id,
                    trust_level=env.trust_level,
                    event_type="rate_limit",
                    result={"reason": why},
                )
                await websocket.send_text(json.dumps({"status": 429, "error": why}))
                continue

            audit_append(
                channel=env.channel,
                channel_user_id=env.channel_user_id,
                trust_level=env.trust_level,
                event_type="inbound_message",
                params={"text": env.text, "thread_id": env.thread_id},
            )

            # S11 stub agent: echo the text back so adapter authors can
            # verify the wire end-to-end. The real agent runtime hooks
            # in here in subsequent sessions.
            reply = ChannelReply(
                channel=env.channel,
                channel_user_id=env.channel_user_id,
                text=f"[glc echo] {env.text or ''}",
                thread_id=env.thread_id,
            )
            await websocket.send_text(reply.model_dump_json())
    except WebSocketDisconnect:
        return


@router.get("/v1/channels/{name}/webhook")
async def channel_webhook_verify(name: str, request: Request):
    params = dict(request.query_params)
    mode = params.get("hub.mode", "")
    token = params.get("hub.verify_token", "")
    challenge = params.get("hub.challenge", "")
    expected = os.environ.get(f"{name.upper()}_VERIFY_TOKEN", "")
    if mode == "subscribe" and hmac.compare_digest(token, expected):
        return PlainTextResponse(challenge)
    raise HTTPException(status_code=403)


@router.post("/v1/channels/{name}/webhook")
async def channel_webhook(name: str, request: Request):
    try:
        adapter = await open_adapter_session(request.app.state, name)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"unknown channel: {name}") from None
    except Exception:
        logger.exception("failed to start channel adapter channel=%s", name)
        raise HTTPException(status_code=502, detail="channel adapter unavailable") from None

    try:
        raw = {
            "raw_body": await request.body(),
            "headers": dict(request.headers),
        }
        msg = await adapter.on_message(raw)
        if msg is None:
            return {"status": "ok"}
        if msg.channel != name:
            logger.warning("adapter channel mismatch route=%s envelope=%s", name, msg.channel)
            raise HTTPException(status_code=502, detail="channel adapter returned an invalid response")

        limiter = get_rate_limiter()
        pairings = get_pairing_store()
        owners = [p.channel_user_id for p in pairings.owners(channel=name)]

        ok, why = allowed(
            msg.channel,
            msg.channel_user_id,
            owner_ids=owners,
            is_public_channel=bool(msg.metadata.get("is_public_channel", False)),
            was_mentioned=bool(msg.metadata.get("was_mentioned", False)),
        )
        if not ok:
            audit_append(
                channel=msg.channel,
                channel_user_id=msg.channel_user_id,
                trust_level=msg.trust_level,
                event_type="allowlist_drop",
                result={"reason": why},
            )
            return {"status": "ok"}

        ok, why = limiter.check_message(msg.channel, msg.channel_user_id)
        if not ok:
            audit_append(
                channel=msg.channel,
                channel_user_id=msg.channel_user_id,
                trust_level=msg.trust_level,
                event_type="rate_limit",
                result={"reason": why},
            )
            return JSONResponse(status_code=429, content={"error": why})

        audit_append(
            channel=msg.channel,
            channel_user_id=msg.channel_user_id,
            trust_level=msg.trust_level,
            event_type="inbound_message",
            params={"text": msg.text, "thread_id": msg.thread_id, "provider": msg.metadata.get("provider")},
        )

        reply = ChannelReply(
            channel=msg.channel,
            channel_user_id=msg.channel_user_id,
            text=f"[glc echo] {msg.text or ''}",
            thread_id=msg.thread_id,
        )
        await adapter.send(reply)
        return {"status": "ok"}
    except HTTPException:
        raise
    except Exception:
        logger.exception("channel adapter failed channel=%s", name)
        raise HTTPException(status_code=502, detail="channel adapter unavailable") from None
    finally:
        try:
            await adapter.close()
        except Exception:
            logger.exception("failed to close channel adapter channel=%s", name)
