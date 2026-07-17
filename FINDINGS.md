# Security Findings

Scope: findings fixed or identified in this worktree. Status describes repository state, not Modal deployment state. No real provider credentials used.

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
- Evidence / fix: [`glc/main.py`](glc/main.py) enables `/docs`, `/redoc`, and `/openapi.json` only when `GLC_ENV=development`. [`test_docs_disabled_in_production`](tests/test_v9_compat.py) verifies production requests return 404.

## F-002: Unauthenticated Read Endpoints

- Finding: Read endpoints exposed internal configuration and operational data, including `/v1/status` and `/v1/providers`, without caller authentication.
- Reference invariant(s): 1, 8.
- Attacker role: Outsider.
- Status: Fixed locally; deployment re-check pending.
- Evidence / fix: [`chat` router](glc/routes/chat.py) applies `require_install_token` to all routes. [`test_read_endpoints_enforce_auth`](tests/test_v9_compat.py) verifies missing token returns 401 and invalid token returns 403.

## F-003: Unauthenticated Model Data Plane

- Finding: Model data-plane endpoints could accept unauthenticated requests.
- Reference invariant(s): 8.
- Attacker role: Outsider.
- Status: Fixed locally; deployment re-check pending.
- Evidence / fix: [`chat` router](glc/routes/chat.py), [`transcribe` router](glc/routes/transcribe.py), [`speak` router](glc/routes/speak.py), and control handlers use install-token authentication. [`test_data_plane_endpoints_require_bearer_token`](tests/test_v9_compat.py) verifies protected data-plane routes reject missing credentials.

## F-004: Image URL SSRF

- Finding: `/v1/chat` and `/v1/vision` fetched caller-supplied `http(s)` image URLs. Redirects could reach loopback, private, or link-local addresses.
- Reference invariant(s): 1, 3.
- Attacker role: Outsider or normal channel user.
- Status: Fixed locally; deployment re-check pending.
- Evidence / fix: [`_resolve_image_urls`](glc/routes/chat.py) permits only globally routable IPv4/IPv6 addresses, resolves and pins destination address, disables proxy environment, and validates every redirect (maximum five). [`tests/test_image_url_ssrf.py`](tests/test_image_url_ssrf.py) covers IPv4, IPv6, private DNS, redirect, and public image cases.

## Unverified Security Hypotheses

These are audit leads, not assignment findings yet. They have no recorded invariant until a fresh-checkout reproduction proves attacker control and an exact mapping to Reference invariants 1–8.

## H-001: Teams Reply URL SSRF

- Finding: Teams adapter stores inbound `serviceUrl`, then posts reply plus Bot Framework bearer token to it. Repository contains no Teams activity/JWT validation at this boundary.
- Attacker role: Outsider or normal channel user.
- Status: Unverified. Exposure depends on live Teams receiver passing raw activities into this adapter.
- Evidence / fix: [`teams/adapter.py`](glc/channels/catalogue/teams/adapter.py) reads `serviceUrl` from inbound payload and later posts to it with `Authorization: Bearer`. Fix: validate Bot Framework activity/JWT before `on_message`; require HTTPS and allowlist official connector hosts before caching/POSTing `serviceUrl`; add SSRF and credential-forwarding tests.

## H-002: Twilio Media URL SSRF

- Finding: Twilio SMS adapter downloads webhook `MediaUrl` with Twilio Basic credentials and no destination validation.
- Attacker role: Normal channel user; outsider if signature bypass enabled.
- Status: Unverified. Normal webhook receiver validates Twilio signature, but adapter has no URL allowlist; risk rises if signature bypass is enabled or adapter is called directly.
- Evidence / fix: [`twilio_sms/adapter.py`](glc/channels/catalogue/twilio_sms/adapter.py) passes `MediaUrl` to `httpx` with Basic auth. Fix: allowlist Twilio media host(s), reject non-HTTPS/private IPs, disable proxy environment, pin DNS result, and test credential is never sent to attacker URL.

## H-003: Alternate Image URL Bypass

- Finding: Image resolver handles only `image_url`. `image` and `input_image` blocks containing URLs can pass unchanged to OpenAI-compatible model providers.
- Attacker role: Outsider or normal channel user.
- Status: Unverified. Model-side URL fetching, not direct gateway-origin SSRF.
- Evidence / fix: [`chat.py`](glc/routes/chat.py) resolves only `image_url`; [`providers.py`](glc/providers.py) forwards multimodal lists unchanged. Fix: normalize `image`, `input_image`, and nested `source.url` forms through same resolver, or reject non-`data:` URLs. Add provider-payload test proving no external URL leaves gateway.

## Verification record

- Local regression suite after F-004: `uv run pytest` → `261 passed`.
- Lint after F-004: `uv run ruff check glc/routes/chat.py tests/test_image_url_ssrf.py` → clean.
- Required deployment reproductions remain: run assigned curl probes against personal Modal URL after deployment, record failure status here, and commit each fix with invariant in commit message.
