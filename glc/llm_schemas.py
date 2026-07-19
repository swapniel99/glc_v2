"""Pydantic v2 request/response models for llm_gatewayV9."""

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

MAX_CHAT_INPUT_TOKENS = 64_000
MAX_CHAT_OUTPUT_TOKENS = 8_192
MAX_BATCH_CALLS = 16
MAX_BATCH_CONCURRENCY = 4
MAX_BATCH_OUTPUT_TOKENS = 32_768


class ToolDef(BaseModel):
    """Canonical tool definition. Schema is JSON-Schema (typically from Pydantic)."""

    name: str
    description: str = ""
    input_schema: dict[str, Any] = Field(default_factory=dict)


class ToolCall(BaseModel):
    id: str
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    # Optional opaque per-provider metadata (e.g. Gemini thoughtSignature)
    # that must be echoed back when sending the assistant turn.
    provider_meta: dict[str, Any] | None = None

    model_config = ConfigDict(extra="allow")


class CacheableSystemBlock(BaseModel):
    text: str
    cache: bool = False


class ResponseFormat(BaseModel):
    type: Literal["json_schema", "json_object"] = "json_schema"
    schema_: dict[str, Any] | None = Field(default=None, alias="schema")
    name: str = "out"
    strict: bool = True

    model_config = ConfigDict(populate_by_name=True)


class ChatRequest(BaseModel):
    """Backward-compatible request — every new field is optional."""

    messages: list[dict[str, Any]] | None = None
    prompt: str | None = None
    system: str | list[CacheableSystemBlock] | None = None
    provider: str | None = None
    model: str | None = None
    max_tokens: int = Field(default=2048, ge=1, le=MAX_CHAT_OUTPUT_TOKENS)
    temperature: float = Field(default=0.7, ge=0, le=2)
    stream: bool = False

    # New in V2:
    tools: list[ToolDef] | None = None
    tool_choice: str | dict[str, Any] | None = None  # "auto" | "none" | {name}
    cache_system: bool | None = None
    reasoning: Literal["off", "low", "medium", "high"] | None = None
    response_format: ResponseFormat | None = None

    # New in V3: when set, the gateway runs a router LLM first to pick a worker tier.
    # Role labels track which cognitive layer is asking. The worker is picked
    # from a tier-to-order table; router never sees system, tools, schemas.
    auto_route: Literal["perception", "memory", "decision"] | None = None

    # New in V8: agent tag (which skill is calling) and session tag (which
    # flow-run). Used for cost-by-agent rollups and provider pinning via
    # agent_routing.yaml. Both are free-form strings; the gateway logs them
    # but does not validate them against any whitelist.
    agent: str | None = None
    session: str | None = None


class RouterDecision(BaseModel):
    """What the router agent decided. Echoed back on the worker response so the
    agentic-world caller can see which model was picked and why."""

    role: Literal["perception", "memory", "decision"]
    tier: Literal["TINY", "LARGE", "HUGE"]
    estimated_tokens: int
    router_provider: str
    router_model: str
    router_latency_ms: int
    chosen_worker_provider: str | None = None
    chosen_worker_model: str | None = None
    fallback_used: bool = False  # true if router LLM failed and tier was decided by token-count rule


class EmbedRequest(BaseModel):
    """Request for POST /v1/embed. The model is fixed per deployment (see
    README); only the text, task type, and an optional explicit provider
    are caller-controlled."""

    text: str
    task_type: Literal["retrieval_document", "retrieval_query"] = "retrieval_document"
    provider: str | None = None  # "ollama" | configured fallback name


class EmbedResponse(BaseModel):
    provider: str
    model: str
    embedding: list[float]
    dim: int
    latency_ms: int = 0
    attempted: list[dict[str, Any]] = Field(default_factory=list)


class ChatResponse(BaseModel):
    provider: str
    model: str
    text: str = ""
    tool_calls: list[ToolCall] = Field(default_factory=list)
    stop_reason: Literal["tool_use", "end_turn", "max_tokens", "error"] = "end_turn"
    input_tokens: int = 0
    output_tokens: int = 0
    cache_creation_input_tokens: int = 0
    cache_read_input_tokens: int = 0
    latency_ms: int = 0
    tool_call_dialect: Literal["native", "prompted_fallback", "none"] = "none"
    reasoning_applied: bool = False
    parsed: dict[str, Any] | None = None  # set when response_format used
    attempted: list[dict[str, Any]] = Field(default_factory=list)
    # New in V3: present only when auto_route was used
    router_decision: RouterDecision | None = None
    # New in V8: how many automatic retries fired before success (or final fail).
    retries: int = 0


class BatchChatRequest(BaseModel):
    """V8 batch endpoint. The gateway dispatches the inner calls with
    bounded parallelism so providers' rate limits are respected centrally."""

    calls: list[ChatRequest] = Field(min_length=1, max_length=MAX_BATCH_CALLS)
    max_concurrency: int = Field(default=4, ge=1, le=MAX_BATCH_CONCURRENCY)

    @model_validator(mode="after")
    def output_budget_is_bounded(self) -> "BatchChatRequest":
        if sum(call.max_tokens for call in self.calls) > MAX_BATCH_OUTPUT_TOKENS:
            raise ValueError(f"batch output budget exceeds {MAX_BATCH_OUTPUT_TOKENS} tokens")
        return self


class VisionRequest(BaseModel):
    """V9: typed shim for single-image vision calls. Lower-ceremony than
    /v1/chat for the set-of-marks loop — callers send one image, one prompt,
    and (optionally) a JSON schema for typed output, and the gateway forces
    routing to a vision-capable provider.

    Accepts either a data: URL (base64) or an http(s) URL for `image`.
    The gateway pre-resolves http URLs the same way /v1/chat does.
    """

    image: str = Field(
        max_length=7 * 1024 * 1024,
        description="data: URL or http(s) URL of the image",
    )
    prompt: str = Field(min_length=1, max_length=256 * 1024)
    system: str | None = Field(default=None, max_length=256 * 1024)
    schema_: dict[str, Any] | None = Field(default=None, alias="schema")
    schema_name: str = "out"
    model: str | None = None
    provider: str | None = None
    max_tokens: int = Field(default=1024, ge=1, le=MAX_CHAT_OUTPUT_TOKENS)
    temperature: float = Field(default=0.0, ge=0, le=2)
    agent: str | None = None
    session: str | None = None

    model_config = ConfigDict(populate_by_name=True)
