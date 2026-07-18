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
- Status: Verified deployed.
- Evidence / fix: [`glc/main.py`](glc/main.py) enables API-discovery surfaces only when `GLC_ENV=development`:
  - `/docs` (Swagger UI)
  - `/redoc` (ReDoc)
  - `/openapi.json` (OpenAPI schema)
  - [`test_docs_disabled_in_production`](tests/test_v9_compat.py) verifies all three return 404 in production and root page does not advertise `/docs`.

## F-002: Unauthenticated Read Endpoints

- Finding: Read endpoints exposed internal configuration and operational data, including `/v1/status`, `/v1/providers` and `/v1/capabilities`, without caller authentication.
- Reference invariant(s): 1, 8.
- Attacker role: Outsider.
- Status: Verified deployed.
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
- Status: Verified deployed.
- Evidence / fix: Install-token authentication now protects:
  - Model data plane: `/v1/chat`, `/v1/chat/batch`, `/v1/vision`, and `/v1/embed` via the [`chat` router](glc/routes/chat.py).
  - Voice data plane: `/v1/transcribe` via the [`transcribe` router](glc/routes/transcribe.py), and `/v1/speak` via the [`speak` router](glc/routes/speak.py).
  - Control plane: `/v1/control/pair`, `/v1/control/pair/confirm`, `/v1/control/presence`, and `/v1/control/kill` via [`control` handlers](glc/routes/control.py).
  - [`test_data_plane_endpoints_require_bearer_token`](tests/test_v9_compat.py) verifies all six data-plane routes reject missing credentials; [`test_chat_requires_valid_bearer_token`](tests/test_v9_compat.py) verifies invalid chat credentials return 403.

## F-004: Image URL SSRF

- Finding: `/v1/chat` and `/v1/vision` fetched caller-supplied `http(s)` image URLs. Redirects could reach loopback, private, or link-local addresses.
- Reference invariant(s): 1, 3.
- Attacker role: Outsider or Normal channel user.
- Status: Verified deployed.
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
- Status: Verified deployed.
- Evidence / fix: Generic client errors now cover every external-service failure path:
  - Chat: `/v1/chat` provider failures, exhausted fallback, structured-output validation, SSE stream failures, and fallback `attempted` metadata.
  - Chat derivatives: `/v1/chat/batch` unexpected per-call failures and `/v1/vision` LLM-provider failures; image-fetch failures are also redacted (F-004).
  - Embeddings: `/v1/embed` explicit-provider failures, exhausted fallback, and successful-fallback `attempted` metadata; `/v1/embedders` redacts active backoff reason.
  - Voice: `/v1/speak` TTS provider failures and `/v1/transcribe` STT provider failures, including unsupported streaming transcription requests.
  - Diagnostics: `/v1/calls` replaces stored `error` and `attempted` detail with generic values.
  - Access prerequisite before F-003: public data-plane access; after F-003, a valid install token is required.
  - Raw provider/network detail is retained in server logs. Chat and embed failures remain in internal call ledger records; TTS and STT routes log their exception detail.
  - [`tests/test_chat_error_privacy.py`](tests/test_chat_error_privacy.py) covers chat response/log separation, fallback redaction, and streaming. [`tests/test_api_error_privacy.py`](tests/test_api_error_privacy.py) covers embeddings, TTS, STT, batch, image fetch, and diagnostics redaction.

## F-006: Unbounded Adapter Egress

- Finding: Modal deployed the gateway and in-process webhook adapters in one Function without an adapter egress boundary. Compromised adapter code could contact arbitrary outbound hosts from the gateway trust domain.
- Reference invariant(s): 1, 8.
- Attacker role: Compromised adapter.
- Status: Verified deployed.
- Evidence / fix:
  - [`modal_app.py`](modal_app.py) creates request-scoped Modal Sandboxes for webhook adapters. Each adapter gets either an explicit `outbound_domain_allowlist` or `block_network=True`, plus CPU, memory, idle, and wall-clock limits.
  - Sandboxes receive a separate adapter image and no gateway data Volume or provider-key Secret. Optional adapter-specific mock secrets are configured independently.
  - [`glc/channels/sandbox_runner.py`](glc/channels/sandbox_runner.py) runs one selected adapter behind a bounded JSON-lines protocol. It preserves `on_message()` / `send()` state without sharing gateway process or filesystem state.
  - [`glc/routes/channels.py`](glc/routes/channels.py) uses the injected sandbox session factory in Modal, validates returned `ChannelMessage` objects, rejects route/channel mismatches, and returns generic startup/operation failures.
  - [`tests/test_adapter_sandbox.py`](tests/test_adapter_sandbox.py) verifies allowlisted and network-blocked sandbox creation, absence of inherited gateway secrets/volumes, byte-safe webhook transport, injected factory use, mismatch rejection, cleanup, and error redaction.
- Deployment verification: A live WhatsApp adapter Sandbox reported no gateway provider secrets and no gateway data Volume. Modal denied outbound access to unapproved `example.com`; the adapter observed `ConnectError`, and the Sandbox protocol completed successfully with a null message result.

## F-007: Shared Adapter And Tool Credentials

- Finding: Migration originally mounted one provider-key Secret on the same Function that executed adapter code. A compromised adapter could read every provider key, and future action dispatch had no credential bound to one user, tenant, tool, or final argument set.
- Reference invariant(s): 1, 2, 4, 6.
- Attacker role: Compromised adapter.
- Status: Verified deployed.
- Evidence / fix:
  - [`modal_app.py`](modal_app.py) keeps provider and capability-signing Secrets on the gateway Function only. Adapter Sandboxes receive neither gateway Secret nor gateway Volume. Adapter Secret mappings must exactly match `glc-adapter-<adapter-name>`, preventing provider, signing, or cross-adapter Secret mapping.
  - [`glc/channels/execution.py`](glc/channels/execution.py) rejects the in-process adapter fallback outside development, so a missing production Sandbox factory fails closed.
  - [`glc/security/scoped_credentials.py`](glc/security/scoped_credentials.py) evaluates policy against gateway-verified identity and final arguments. Issued credentials bind adapter, user, tenant, trust level, tool, tool-call ID, canonical argument hash, audience, expiry, and random nonce. `deny` and `require_approval` issue nothing.
  - Modal redemption uses `Dict.put(skip_if_exists=True)` as an atomic distributed consume operation, preventing replay across autoscaled gateway replicas. Expired nonce records are purged daily.
  - Current chat `tool_calls` remain proposals and are not executed. No adapter-facing credential-mint endpoint exists; future action handlers must use the injected gateway authorizer.
  - [`tests/test_scoped_credentials.py`](tests/test_scoped_credentials.py) covers signature tampering, changed tool/call/arguments, wrong adapter/user/tenant/trust/audience, expiry, replay, concurrent redemption, policy denial, atomic Modal consumption, strict Secret mapping, and production fallback rejection.
- Deployment verification: deployed gateway returned `200 OK` from `/healthz` with no signing-key configuration error in Modal logs. Inside the live gateway container, the scoped-credential probe rejected changed final arguments, accepted the correctly scoped first redemption, and rejected replay of the consumed credential. Earlier live adapter evidence also confirmed no gateway provider Secrets or gateway Volume were visible from the WhatsApp Sandbox.

## F-008: Non-Reproducible Modal Images

- Finding: Modal gateway and adapter images used a mutable Debian base and installed dependency ranges from `pyproject.toml`, allowing image contents and resolved package versions to drift between reviewed deployments.
- Reference invariant(s): 8.
- Attacker role: Outsider.
- Access prerequisite: Ability to alter dependency resolution or mutable upstream image content through a compromised package or registry release path.
- Status: Fixed locally; deployment re-check pending.
- Fix commit: `ab3592d`.
- Evidence / fix:
  - [`modal_app.py`](modal_app.py) pins the Debian `bookworm-slim` Linux amd64 manifest by SHA-256 digest for both gateway and adapter images.
  - Both images use Modal `uv_sync(..., frozen=True)` with the committed [`uv.lock`](uv.lock), replacing `pip_install_from_pyproject` dependency-range resolution.
  - Import fails if `uv.lock` is absent. The image builder also pins `uv` to `0.11.29` and excludes development dependencies.
- Verification record:
  - `docker-buildx imagetools inspect debian:bookworm-slim` confirmed the pinned digest is the current `linux/amd64` manifest.
  - `UV_CACHE_DIR=/tmp/glc-v2-uv-cache uv lock --check --offline` resolved all 167 locked packages without changing the lockfile.
  - `ruff check modal_app.py`, `git diff --check`, syntax parsing, and importing `modal_app` passed locally.
  - Remote Modal image build and deployment verification remain pending.

## F-009: Concurrent SQLite Audit Writers

- Finding: An autoscaled Modal gateway could create multiple SQLite writers for one audit file, while Volume changes lacked explicit reload and commit operations. This could split or lose audit history.
- Reference invariant(s): 7.
- Attacker role: Compromised component or concurrent gateway traffic.
- Status: Fixed locally; deployment re-check pending.
- Evidence / fix:
  - [`modal_app.py`](modal_app.py) gives audit storage a dedicated `glc-audit` Volume mounted only by `audit_writer`.
  - `audit_writer` is capped at one container and one concurrent input. Autoscaled gateway replicas use a store-compatible remote proxy and never mount or open the audit SQLite file.
  - Writer reloads its Volume before every operation, closes SQLite connections, then explicitly commits the Volume snapshot.
  - [`tests/test_modal_audit_writer.py`](tests/test_modal_audit_writer.py) verifies reload/commit durability behavior, remote forwarding, and gateway/audit Volume separation.

## Inherited Leak Remediations

### Leak 4: Adapter Access To Installation/Control Token

- Source: [`ISSUES_TO_FIX.md`](ISSUES_TO_FIX.md), inherited Leak 4; not a new Part 2 finding.
- Finding: Legacy WebSocket adapter bridges loaded the installation token directly, and `/v1/channels/{name}` accepted that master token through either an Authorization header or query parameter. Compromising one such adapter exposed a credential valid across gateway control and data-plane routes.
- Reference invariant(s): 2, 4.
- Attacker role: Compromised adapter.
- Status: Fixed locally; deployment re-check pending.
- Evidence / fix:
  - [`glc/security/channel_credentials.py`](glc/security/channel_credentials.py) issues HMAC-signed WebSocket credentials bound to one channel, a fixed audience, issue and expiry times, and a random nonce. Default lifetime is 60 seconds; maximum lifetime is five minutes.
  - [`glc/routes/control.py`](glc/routes/control.py) exposes credential minting only through `/v1/control/channels/{channel}/credential`, authenticated with the installation token. Adapter processes receive only the resulting scoped credential.
  - [`glc/routes/channels.py`](glc/routes/channels.py) rejects missing credentials, the installation token itself, query-string credentials, invalid signatures, expired credentials, and credentials scoped to another channel. Active WebSocket sessions close when their credential expires.
  - Route/channel mismatch is rejected and audited, preventing a valid credential for one route from carrying an envelope for another channel.
  - External Twilio SMS, Telegram, and Discord bridge code now reads only `GLC_CHANNEL_CREDENTIAL`; no channel adapter code imports or calls `get_or_create_install_token()`.
  - [`README.md`](README.md) documents operator-side minting and passing only the scoped credential to an adapter.
- Verification record:
  - [`tests/test_channel_credentials.py`](tests/test_channel_credentials.py) covers channel binding, tampering, excessive lifetime, authenticated issuance, rejection of missing/master/query/wrong-channel credentials, successful scoped authentication, cross-channel envelope rejection, and active-session expiry.
  - [`glc/channels/catalogue/twilio_sms/tests/test_webhook_route.py`](glc/channels/catalogue/twilio_sms/tests/test_webhook_route.py) verifies the bridge fails closed without `GLC_CHANNEL_CREDENTIAL` instead of loading the installation token.
  - Focused security suite: 31 passed.
  - Full suite with an explicit writable test ledger (`GLC_GATEWAY_DB=/private/tmp/glc-v2-full-suite.sqlite`): 311 passed.
  - Focused Ruff checks and `git diff --check` passed.
