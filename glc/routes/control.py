"""Out-of-band control plane: /v1/control/kill, /v1/control/pair,
/v1/control/pair/confirm, /v1/control/presence.

All endpoints require the installation token (Authorization: Bearer ...).
The kill endpoint binds 127.0.0.1 only; the host check is enforced here.
"""

from __future__ import annotations

import os
import signal
import time

from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel, Field

from glc.security.auth import require_install_token
from glc.security.channel_credentials import (
    CHANNEL_CREDENTIAL_TTL_SECONDS,
    MAX_CHANNEL_CREDENTIAL_TTL_SECONDS,
    InvalidChannelCredential,
    issue_channel_credential,
)
from glc.security.pairing import CODE_TTL_SECONDS, PairingLockedOut, get_pairing_store

router = APIRouter()


class PairRequest(BaseModel):
    channel: str
    channel_user_id: str
    user_handle: str = ""
    trust_level: str = "user_paired"


class PairResponse(BaseModel):
    code: str
    expires_at: float
    ttl_seconds: int


class PairConfirmRequest(BaseModel):
    code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


class ChannelCredentialRequest(BaseModel):
    ttl_seconds: int = Field(
        default=CHANNEL_CREDENTIAL_TTL_SECONDS,
        ge=1,
        le=MAX_CHANNEL_CREDENTIAL_TTL_SECONDS,
    )


class ChannelCredentialResponse(BaseModel):
    credential: str
    channel: str
    expires_at: int
    ttl_seconds: int


@router.post(
    "/v1/control/channels/{channel}/credential",
    response_model=ChannelCredentialResponse,
)
async def channel_credential(
    channel: str,
    req: ChannelCredentialRequest,
    authorization: str | None = Header(default=None),
):
    require_install_token(authorization)
    try:
        credential, claims = issue_channel_credential(channel, ttl_seconds=req.ttl_seconds)
    except InvalidChannelCredential as exc:
        raise HTTPException(400, str(exc)) from exc
    return ChannelCredentialResponse(
        credential=credential,
        channel=claims.channel,
        expires_at=claims.expires_at,
        ttl_seconds=claims.expires_at - claims.issued_at,
    )


@router.post("/v1/control/pair", response_model=PairResponse)
async def pair(req: PairRequest, authorization: str | None = Header(default=None)):
    require_install_token(authorization)
    if req.trust_level not in ("user_paired", "owner_paired"):
        raise HTTPException(400, f"trust_level must be user_paired or owner_paired, got {req.trust_level!r}")
    code, expires_at = get_pairing_store().issue_code(
        req.channel,
        req.channel_user_id,
        req.user_handle,
        requested_trust_level=req.trust_level,
    )
    return PairResponse(code=code, expires_at=expires_at, ttl_seconds=CODE_TTL_SECONDS)


@router.post("/v1/control/pair/confirm")
async def pair_confirm(
    req: PairConfirmRequest,
    request: Request,
    authorization: str | None = Header(default=None),
):
    require_install_token(authorization)
    attempt_key = request.client.host if request.client is not None else "unknown"
    try:
        rec = get_pairing_store().confirm_code(req.code, attempt_key=attempt_key)
    except PairingLockedOut as exc:
        raise HTTPException(
            429,
            "pairing confirmation temporarily locked",
            headers={"Retry-After": str(exc.retry_after)},
        ) from exc
    if rec is None:
        raise HTTPException(404, "code unknown or expired")
    return {
        "channel": rec.channel,
        "channel_user_id": rec.channel_user_id,
        "user_handle": rec.user_handle,
        "trust_level": rec.trust_level,
        "paired_at": rec.paired_at,
    }


@router.get("/v1/control/presence")
async def presence(request: Request, authorization: str | None = Header(default=None)):
    require_install_token(authorization)
    state = request.app.state
    started = getattr(state, "started_at", time.time())
    pairings = get_pairing_store().all_pairings()
    return {
        "channels": getattr(state, "registered_channels", []),
        "paired_users": [
            {
                "channel": p.channel,
                "channel_user_id": p.channel_user_id,
                "user_handle": p.user_handle,
                "trust_level": p.trust_level,
            }
            for p in pairings
        ],
        "uptime_s": int(time.time() - started),
    }


@router.post("/v1/control/kill")
async def kill(request: Request, authorization: str | None = Header(default=None)):
    require_install_token(authorization)
    client_host = request.client.host if request.client else "unknown"
    if os.getenv("GLC_KILL_ALLOW_REMOTE") != "1" and client_host not in ("127.0.0.1", "::1", "localhost"):
        raise HTTPException(
            403,
            f"kill is restricted to loopback (got {client_host}). "
            "Set GLC_KILL_ALLOW_REMOTE=1 to override (not recommended).",
        )
    # Send SIGTERM to ourselves shortly after returning so the client gets a 200.
    import asyncio

    async def _shoot() -> None:
        await asyncio.sleep(0.2)
        os.kill(os.getpid(), signal.SIGTERM)

    asyncio.create_task(_shoot())
    return {"status": "terminating", "pid": os.getpid()}
