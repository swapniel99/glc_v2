"""POST /v1/transcribe — STT through the voice routing layer."""

from __future__ import annotations

import base64
import logging
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from glc.security.auth import require_install_token
from glc.voice.stt import STTError, transcribe

logger = logging.getLogger(__name__)

_CLIENT_STT_ERROR = "Transcription service temporarily unavailable"

router = APIRouter(dependencies=[Depends(require_install_token)])


class TranscribeRequest(BaseModel):
    audio_b64: str
    mime: str = "audio/wav"
    agent: str | None = None
    prefer: Literal["default", "local", "streaming"] = "default"


class TranscribeResponse(BaseModel):
    text: str
    language: str
    duration_ms: int
    provider: str
    cost_usd: float = Field(default=0.0)


@router.post("/v1/transcribe", response_model=TranscribeResponse)
async def transcribe_route(req: TranscribeRequest):
    try:
        audio = base64.b64decode(req.audio_b64)
    except Exception as e:
        raise HTTPException(400, f"audio_b64 is not valid base64: {e}") from e
    try:
        r = await transcribe(audio, req.mime, prefer=req.prefer)
    except STTError as e:
        logger.error("Transcription failed upstream_error=%s", e)
        raise HTTPException(
            400 if req.prefer == "streaming" else e.status or 502, _CLIENT_STT_ERROR
        ) from None
    return TranscribeResponse(
        text=r.text,
        language=r.language,
        duration_ms=r.duration_ms,
        provider=r.provider,
        cost_usd=r.cost_usd,
    )
