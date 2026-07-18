# Security Findings

Scope: findings fixed or identified in this worktree. Status describes repository state, not Modal deployment state. No real provider credentials used.

## Recording Guidelines

- Record only reproducible findings with concrete code, test, or deployment evidence; keep unverified ideas in `HYPOTHESIS.md`.
- Give every finding a stable ID, short title, attacker role, affected endpoint/component, and approved invariant reference. Use only REFERENCE roles: `Outsider`, `Normal channel user`, `Compromised adapter`, or `Gateway code execution`.
- Choose attacker role from pre-fix capability. Record token, network, or other access prerequisites separately; do not invent roles such as "authenticated client".
- State impact and exact fix separately. Link changed code and tests; do not claim deployment verification until remote probe passes.
- Use explicit status: `Identified`, `Fixed locally; deployment re-check pending`, or `Verified deployed`.
- Record exact verification command and result in Verification record after each material fix.
- Never include real credentials, tokens, request bodies containing secrets, or raw upstream error detail. Keep those server-side only.
- Do not merge distinct root causes into one finding. Cross-reference related findings instead.

## Approved Invariant Key

Only invariants from [REFERENCE.md](REFERENCE.md) Section 5 appear below.

1. Adapters must never see provider API keys.
2. Every action must be checked against actual user, tenant, and final arguments.
3. External content must be data, never instructions.
4. A credential must work only for one specific tool call.
5. Each tenant must have separate memory, and every stored fact must record provenance.
6. Dangerous actions must be approved with final parameters.
7. Components must not edit or delete their own audit logs.
8. Every run must have hard limits on time, tokens, tool calls, and cost.

## Confirmed / Fixed Assignment Findings

## F-001: Production API Reconnaissance

- Finding: Production served API documentation and OpenAPI schema, enabling unauthenticated endpoint reconnaissance.
- Reference invariant(s): 1, 8.
- Attacker role: Outsider.
- Status: Fixed locally; deployment re-check pending.
- Evidence / fix: [`glc/main.py`](glc/main.py) enables API-discovery surfaces only when `GLC_ENV=development`:
  - `/docs` (Swagger UI)
  - `/redoc` (ReDoc)
  - `/openapi.json` (OpenAPI schema)
  - [`test_docs_disabled_in_production`](tests/test_v9_compat.py) verifies all three return 404 in production and root page does not advertise `/docs`.

## F-002: Unauthenticated Read Endpoints

- Finding: Read endpoints exposed internal configuration and operational data, including `/v1/status`, `/v1/providers` and `/v1/capabilities`, without caller authentication.
- Reference invariant(s): 1, 8.
- Attacker role: Outsider.
- Status: Fixed locally; deployment re-check pending.
- Evidence / fix: [`chat` router](glc/routes/chat.py) applies `require_install_token` to all read routes:
  - `/v1/embedders`
  - `/v1/cost/by_agent`
  - `/v1/providers`
  - `/v1/capabilities`
  - `/v1/status`
  - `/v1/routers`
  - `/v1/calls`
  - [`test_read_endpoints_enforce_auth`](tests/test_v9_compat.py) verifies every route returns 401 without a token and 403 for an invalid token.

## F-003: Unauthenticated Model Data Plane

- Finding: Model data-plane endpoints could accept unauthenticated requests.
- Reference invariant(s): 8.
- Attacker role: Outsider.
- Status: Fixed locally; deployment re-check pending.
- Evidence / fix: Install-token authentication now protects:
  - Model data plane: `/v1/chat`, `/v1/chat/batch`, `/v1/vision`, and `/v1/embed` via the [`chat` router](glc/routes/chat.py).
  - Voice data plane: `/v1/transcribe` via the [`transcribe` router](glc/routes/transcribe.py), and `/v1/speak` via the [`speak` router](glc/routes/speak.py).
  - Control plane: `/v1/control/pair`, `/v1/control/pair/confirm`, `/v1/control/presence`, and `/v1/control/kill` via [`control` handlers](glc/routes/control.py).
  - [`test_data_plane_endpoints_require_bearer_token`](tests/test_v9_compat.py) verifies all six data-plane routes reject missing credentials; [`test_chat_requires_valid_bearer_token`](tests/test_v9_compat.py) verifies invalid chat credentials return 403.

## F-004: Image URL SSRF

- Finding: `/v1/chat` and `/v1/vision` fetched caller-supplied `http(s)` image URLs. Redirects could reach loopback, private, or link-local addresses.
- Reference invariant(s): 1, 3.
- Attacker role: Outsider or Normal channel user.
- Status: Fixed locally; deployment re-check pending.
- Evidence / fix: [`_resolve_image_urls`](glc/routes/chat.py) protects both image-capable endpoints:
  - `/v1/chat` accepts image blocks in `messages`.
  - `/v1/vision` converts its caller-supplied image URL into an image block, then uses the same chat resolver.
  - Accepts only `http(s)` URLs with a host; rejects URL credentials and invalid ports.
  - Resolves every hostname and rejects any private, loopback, link-local, reserved, or otherwise non-global IPv4/IPv6 result.
  - Pins each connection to validated address while preserving `Host` and TLS SNI; disables proxy-environment use.
  - Re-validates each redirect destination and caps redirects at five.
  - Returns generic image-retrieval error for upstream fetch failures; raw detail stays server-side.
  - [`tests/test_image_url_ssrf.py`](tests/test_image_url_ssrf.py) covers private IPv4/IPv6, private DNS, redirect revalidation, and public-image success. [`test_image_fetch_hides_upstream_error`](tests/test_api_error_privacy.py) verifies error-detail redaction.

## F-005: Upstream Error Detail Disclosure

- Finding: Public data-plane responses exposed provider, network, and stored failure details. This included chat failures and streams, embed fallback attempts, speech and transcription errors, image fetch errors, and `/v1/calls` diagnostic records.
- Reference invariant(s): 1, 3, 8.
- Attacker role: Outsider or Normal channel user.
- Status: Fixed locally; deployment re-check pending.
- Evidence / fix: Generic client errors now cover every external-service failure path:
  - Chat: `/v1/chat` provider failures, exhausted fallback, structured-output validation, SSE stream failures, and fallback `attempted` metadata.
  - Chat derivatives: `/v1/chat/batch` unexpected per-call failures and `/v1/vision` LLM-provider failures; image-fetch failures are also redacted (F-004).
  - Embeddings: `/v1/embed` explicit-provider failures, exhausted fallback, and successful-fallback `attempted` metadata; `/v1/embedders` redacts active backoff reason.
  - Voice: `/v1/speak` TTS provider failures and `/v1/transcribe` STT provider failures, including unsupported streaming transcription requests.
  - Diagnostics: `/v1/calls` replaces stored `error` and `attempted` detail with generic values.
  - Access prerequisite before F-003: public data-plane access; after F-003, a valid install token is required.
  - Raw provider/network detail is retained in server logs. Chat and embed failures remain in internal call ledger records; TTS and STT routes log their exception detail.
  - [`tests/test_chat_error_privacy.py`](tests/test_chat_error_privacy.py) covers chat response/log separation, fallback redaction, and streaming. [`tests/test_api_error_privacy.py`](tests/test_api_error_privacy.py) covers embeddings, TTS, STT, batch, image fetch, and diagnostics redaction.

## Verification record

- Local regression suite after F-005: `uv run pytest` → `271 passed`.
- Lint after F-005: `uv run ruff check glc/routes/chat.py glc/routes/speak.py glc/routes/transcribe.py glc/embedders.py tests/test_api_error_privacy.py tests/test_chat_error_privacy.py` → clean.
- Required deployment reproductions remain: run assigned curl probes against personal Modal URL after deployment, record failure status here, and commit each fix with invariant in commit message.
