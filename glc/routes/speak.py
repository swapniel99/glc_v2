"""POST /v1/speak — TTS through the voice routing layer."""

from __future__ import annotations

import logging
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from glc.security.auth import require_install_token
from glc.voice.tts import TTSError, synthesize

logger = logging.getLogger(__name__)

_CLIENT_TTS_ERROR = "Speech synthesis service temporarily unavailable"

router = APIRouter(dependencies=[Depends(require_install_token)])


class SpeakRequest(BaseModel):
    text: str
    voice_id: str | None = None
    agent: str | None = None
    prefer: Literal["default", "quality", "streaming", "realtime", "fallback"] = "default"


class SpeakResponse(BaseModel):
    audio_b64: str
    mime: str
    sample_rate: int
    provider: str
    cost_usd: float = 0.0


@router.post("/v1/speak", response_model=SpeakResponse)
async def speak_route(req: SpeakRequest):
    try:
        r = await synthesize(req.text, voice_id=req.voice_id, prefer=req.prefer)
    except TTSError as e:
        logger.error("Speech synthesis failed upstream_error=%s", e)
        raise HTTPException(e.status or 502, _CLIENT_TTS_ERROR) from None
    return SpeakResponse(
        audio_b64=r.audio_b64,
        mime=r.mime,
        sample_rate=r.sample_rate,
        provider=r.provider,
        cost_usd=r.cost_usd,
    )
