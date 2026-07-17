# Session 12 Assignment Reference: Containers, Sandboxes, and the Adversary's Mindset

Source lesson: https://axiom.theschoolofai.in/courses/cmox5yhwl000107pgrjx41sqk/sessions/cmr3392m901ao09po79jnggcf/lesson?zen=1

This document is a standalone reference for solving the Session 12 assignment. It condenses the assignment brief, the security model, the required migration/hardening work, and a practical workflow for finding new bugs that can score in Part 2.

## 1. Assignment At A Glance

You are working only with `glc_v2`. Treat `glc_v2` as the source repository for all assignment work. Pull requests against `glc_v1` will not be evaluated.

The assignment has two parts.

### Part 1: Migrate And Harden

Required floor for everyone.

You must:

1. Deploy your own `glc_v2` clone to your own Modal account.
2. Use mock/random API keys, not real provider keys.
3. Confirm the gateway is live.
4. Reproduce every finding from lesson Sections 6 and 7 against your own deployment/local harness.
5. Fix all catalogued findings in your clone.
6. Submit your hardened repository link.
7. Include a short note for every finding explaining:
   - Which of the 8 invariants it broke.
   - Which attacker role could reach it.
   - What fix you implemented.
   - How you verified the exploit now fails.

You do not need to submit PRs for Part 1 catalogued issues. Fix them in your clone.

### Part 2: Find Something New

Scoring section.

Each genuinely new bug is worth 100 points if it:

1. Breaks one of the 8 invariants.
2. Is not already named in lesson Sections 6 or 7.
3. Is submitted as a PR against `glc_v2`.
4. Includes a short bug description.
5. Includes a reproduction script or numbered reproduction steps from a fresh checkout.
6. Includes the fix.

Duplicate findings are awarded to the first PR opened. A bug report without a working reproduction or without a fix does not score.

## 2. Rules And Safety

Follow these strictly:

- Attack only your own deployment and your own clone.
- Do not attack another student's Modal account.
- Do not attack school infrastructure or unrelated properties.
- Do not attack real upstream providers.
- Use mock/random provider keys.
- Keep exploits inside the assignment environment.
- Discussing approaches is allowed, but duplicate PRs do not score.
- Deadline: one week from the Saturday referenced in class.
- Late PRs are accepted for 48 hours with a 30 percent penalty.

## 3. Core Threat Model

The assignment is about learning to see misplaced trust.

### Principals

A principal is anything that can act and whose authority must be checked.

In `glc_v2`, important principals include:

- Human user.
- Channel adapter.
- Gateway.
- Policy engine.
- Agent runtime.
- Upstream model/tool providers.
- Operator/deployer.

### Assets

An asset is anything worth protecting.

Key assets:

- Provider API keys.
- Per-installation control token.
- Credential-signing key.
- Audit history.
- Pairing database.
- Cost ledger.
- User message privacy.
- Tenant memory and context.

### Data Flows

Typical message flow:

1. User sends message.
2. Channel adapter receives it.
3. Adapter sends it to gateway, often over WebSocket.
4. Gateway passes it through policy.
5. Agent runtime decides what to do.
6. Gateway calls providers/tools.
7. Result returns through gateway and adapter.
8. User receives reply.

Security work focuses on crossings between different trust levels.

### Trust Boundaries

Important boundaries:

- Adapter to gateway.
- Gateway to provider.
- User/tenant A to user/tenant B.
- Agent-proposed action to deterministic authorizer.
- Untrusted external content to model context.
- Component logs/state to audit writer.

## 4. Attacker Roles

Use these roles when writing findings.

| Role | Capability |
|---|---|
| Outsider | Public internet attacker with no credentials. |
| Normal channel user | Controls only message text or normal channel input. |
| Compromised adapter | Has code execution inside one adapter/container. |
| Gateway code execution | Has code execution inside the gateway process. |

The best findings climb the ladder, for example: normal channel user to gateway-impacting behavior.

## 5. The 8 Security Invariants

Every valid finding should name one or more of these.

| # | Invariant | Prevents |
|---|---|---|
| 1 | Adapters must never see provider API keys. | Credential theft by adapter code. |
| 2 | Every action must be checked against actual user, tenant, and final arguments. | Acting for the wrong user or with changed parameters. |
| 3 | External content must be data, never instructions. | Prompt injection and tool-output instruction hijack. |
| 4 | A credential must work only for one specific tool call. | Token reuse, replay, or cross-tool abuse. |
| 5 | Each tenant must have separate memory, and every stored fact must record provenance. | Cross-tenant memory bleed and untrusted facts. |
| 6 | Dangerous actions must be approved with final parameters. | Approval time-of-check/time-of-use bugs. |
| 7 | Components must not edit or delete their own audit logs. | Compromised code hiding its actions. |
| 8 | Every run must have hard limits on time, tokens, tool calls, and cost. | DoS, infinite loops, runaway API usage, and cost exhaustion. |

## 6. Modal Migration Reference

### What You Are Migrating

`glc_v2` is a `uv` Python project with a FastAPI app at:

```text
glc.main:app
```

Locally it runs on port `8111`, typically via:

```bash
uv run glc serve
```

State normally lives under:

```text
~/.glc/
```

The app supports moving that config/state directory with:

```bash
GLC_CONFIG_DIR=/some/path
```

Provider keys are read from environment variables.

### Modal Setup

From the project folder:

```bash
uv add modal
uv run modal setup
```

`modal setup` opens a browser so you can authenticate your Modal account.

### Wrapper Shape

Your `modal_app.py` should:

- Import the unchanged FastAPI app.
- Attach a Modal Volume for persistent config/state.
- Set `GLC_CONFIG_DIR` to the mounted data path.
- Attach a Modal Secret for mock provider keys.
- Expose the FastAPI app through `@modal.asgi_app()`.
- Avoid baking secrets into the image.

Example skeleton:

```python
import os
from pathlib import Path

import modal

app = modal.App("glc-v2-gateway")

image = (
    modal.Image.debian_slim(python_version="3.11")
    .pip_install(
        "fastapi>=0.110",
        "uvicorn[standard]>=0.27",
        "httpx>=0.27",
        "python-dotenv>=1.0",
        "pydantic>=2.6",
        "jsonschema>=4.21",
        "pyyaml>=6.0",
        "websockets>=12.0",
    )
    .env({"GLC_CONFIG_DIR": "/data/glc"})
    .add_local_dir(str(Path(__file__).parent / "glc"), remote_path="/root/glc")
)

data_volume = modal.Volume.from_name("glc-data", create_if_missing=True)
llm_secret = modal.Secret.from_name("glc-llm-keys")


@app.function(
    image=image,
    volumes={"/data": data_volume},
    secrets=[llm_secret],
    min_containers=0,
)
@modal.asgi_app()
def fastapi_app():
    os.makedirs("/data/glc", exist_ok=True)
    from glc.main import app as web

    return web
```

Create the Modal Secret with mock values:

```bash
uv run modal secret create glc-llm-keys \
  GEMINI_API_KEY=mock-not-real \
  GITHUB_ACCESS_TOKEN=mock-not-real \
  GROQ_API_KEY=mock-not-real \
  NVIDIA_API_KEY=mock-not-real \
  CEREBRAS_API_KEY=mock-not-real \
  OPEN_ROUTER_API_KEY=mock-not-real
```

Deploy:

```bash
uv run modal deploy modal_app.py
```

Verify:

```bash
curl <modal-url>/healthz
open <modal-url>/docs
```

Expected health result should look like a successful JSON response, usually including `"ok": true`.

## 7. What Modal Migration Changes

The first migration mostly relocates the app. It does not automatically harden internal trust boundaries.

Important consequences:

- The gateway moves from local-only `localhost:8111` to a public internet URL.
- Config/state moves to a Modal Volume.
- Provider keys move to a Modal Secret.
- The whole app may still run as one Modal Function.
- If the whole app shares one process and one Secret, in-process code can still read everything.
- Modal Function alone does not provide the same untrusted-code boundary as Modal Sandbox.

This is why Part 1 requires more than "it deploys."

## 8. Required Findings From Section 6

These are already known, so fixing them is Part 1. Re-reporting them for Part 2 earns nothing.

### A. Introduced Or Elevated By Migration

| ID | Finding | Impact | Fix Direction |
|---|---|---|---|
| A1 | Public data plane has no auth: `/v1/chat`, `/chat/batch`, `/embed`, `/vision`, `/speak`, `/transcribe`. | Anyone can trigger provider calls, cost, and DoS. | Add authentication or keep deployment private. |
| A2 | Unauthenticated info disclosure: `/v1/status`, `/v1/providers`, `/v1/capabilities`, `/v1/cost/by_agent`, `/v1/calls`, `/docs`, `/openapi.json`. | Leaks route map, provider config, usage, limits. | Gate admin/info endpoints; disable Swagger in production. |
| A3 | Single Function has no egress wall. | Compromised code can call arbitrary outbound hosts. | Put untrusted parts in Modal Sandboxes with egress allowlists. |
| A4 | One Secret mounted to whole Function. | Any in-process code can read all provider keys. | Separate adapters/components; give least-privilege secrets only where needed. |
| A5 | Non-reproducible image/dependencies. | Supply-chain drift and unreviewed dependency changes. | Pin dependencies, use lockfile, pin base image by digest. |
| A6 | Audit DB on shared Volume with autoscale/concurrency risk. | SQLite writer conflicts, corrupted/split audit trail. | Single append-only writer or real DB; make audit immutable/hash-chained. |

### B. Inherited In-Process Leaks Still Open

These overlap with the ten code leaks in Section 7:

- Environment contains all keys.
- Audit DB can be modified by in-process code.
- Pairing database/owner state can be modified.
- Install token can be read in-process.
- Policy engine can be monkey-patched.
- In-process code can terminate gateway.
- Cost ledger can be poisoned.
- Shell/subprocess access exists.

### C. Endpoint And Logic Issues Now Internet-Reachable

| ID | Finding | Impact | Fix Direction |
|---|---|---|---|
| C1 | SSRF via `/v1/vision` fetching arbitrary image URLs with redirects. | Gateway can fetch attacker-chosen URLs from its network position. | URL allowlist; block private/link-local IPv4 and IPv6; re-check after redirects. |
| C2 | Cross-channel envelope spoofing. | One adapter can claim another channel identity. | Reject WebSocket messages where envelope channel does not match route channel. |
| C3 | WebSocket token in query string. | Token leaks into logs/history. | Header-only auth; short-lived tokens. |
| C4 | Verbose upstream errors. | Leaks provider endpoint/details. | Generic client errors; detailed server logs only. |
| C5 | No rate limits or budgets on public data plane. | DoS and denial-of-wallet. | Per-endpoint rate limits, quotas, hard budgets. |
| C6 | Pairing-code brute force candidate. | Weak 6-digit code may be guessable if not rate-limited. | Confirm reachable path; add attempt limits, expiry, lockout. |

## 9. The Ten Code Leaks From Section 7

These are known. Fix in Part 1; do not submit as Part 2 discoveries.

| Leak | Bug | Broken Invariant(s) | Why It Works | Fix Direction |
|---|---|---|---|---|
| 1 | Shared process environment exposes provider keys. | 1 | Adapters/gateway share env and process. | Separate adapters; least-privilege secrets; scoped credentials. |
| 2 | Audit DB writable by in-process code. | 7 | Same Unix user/process can open SQLite file. | Gateway-only audit writer; append-only, hash-chained log. |
| 3 | Pairing DB and `force_pair_owner()` reachable in-process. | 2, 4 | Internal method is callable by any code in process. | Process boundary; expose only checked control path. |
| 4 | Install token readable in-process. | 2, 4 | File/secret readable by same process/user. | Gateway-only control secret; no adapter mount. |
| 5 | Policy engine monkey-patching. | 2, 6 | Python module function can be rebound at runtime. | Isolate policy service; immutable decision path. |
| 6 | Unbounded network egress. | 1, 3, 8 | No outbound allowlist for untrusted code. | Modal Sandboxes plus domain allowlists. |
| 7 | Unrestricted subprocess/shell access. | 1, 8 | Monolithic image has shell/tools and shared privileges. | Minimal images, non-root, read-only FS, sandboxing, syscall limits. |
| 8 | Adapter can kill gateway process. | 8 | Same PID namespace/process. | Separate process/PID namespace per adapter. |
| 9 | Cross-channel envelope spoofing. | 2 | Gateway trusts envelope channel field. | Check `env.channel` equals route channel. |
| 10 | Cost ledger poisoning. | 7, 8 | `log_call()` accepts arbitrary token counts/status. | Gateway-owned signed writer; validate metrics source. |

## 10. Required Part 1 Verification Matrix

Use a table like this in your Part 1 notes.

| Finding | Reproduced Before Fix? | Broken Invariant | Attacker Role | Fix Commit | Verification After Fix |
|---|---:|---|---|---|---|
| A1 public data plane | Yes/No | 8 | Outsider | `<hash>` | Unauth request returns 401/403. |
| A2 info disclosure | Yes/No | 1/8 | Outsider | `<hash>` | `/docs` and info endpoints gated. |
| A3 no egress wall | Yes/No | 1/8 | Compromised adapter | `<hash>` | Adapter cannot call unapproved domain. |
| A4 shared Secret | Yes/No | 1 | Compromised adapter | `<hash>` | Adapter env lacks provider keys. |
| A5 drift | Yes/No | 8 | Supply-chain attacker | `<hash>` | Build uses pinned lock/digest. |
| A6 audit concurrency | Yes/No | 7 | Compromised/gateway code | `<hash>` | Audit writer design prevents split/corruption. |
| C1 SSRF | Yes/No | 1/3 | Outsider or user | `<hash>` | Private/link-local/redirect URLs rejected. |
| C2 spoofing | Yes/No | 2 | Compromised adapter | `<hash>` | Mismatched channel rejected and audited. |
| C3 query token | Yes/No | 4 | Log reader | `<hash>` | Token accepted only in header/short-lived form. |
| C4 verbose errors | Yes/No | 1 | Outsider/user | `<hash>` | Client gets generic error. |
| C5 rate/budget | Yes/No | 8 | Outsider/user | `<hash>` | Limits enforced under repeated calls. |
| C6 pairing brute force | Yes/No | 2/4 | Outsider/user | `<hash>` | Attempts limited; code expires. |
| Leak 1 | Yes/No | 1 | Compromised adapter | `<hash>` | Adapter cannot read provider keys. |
| Leak 2 | Yes/No | 7 | Compromised adapter | `<hash>` | Adapter cannot write audit store. |
| Leak 3 | Yes/No | 2/4 | Compromised adapter | `<hash>` | Pairing mutation blocked. |
| Leak 4 | Yes/No | 2/4 | Compromised adapter | `<hash>` | Install token inaccessible. |
| Leak 5 | Yes/No | 2/6 | Gateway code execution | `<hash>` | Policy cannot be monkey-patched by adapter. |
| Leak 6 | Yes/No | 1/8 | Compromised adapter | `<hash>` | Egress allowlist blocks attacker host. |
| Leak 7 | Yes/No | 1/8 | Compromised adapter | `<hash>` | Shell/subprocess blast radius removed/reduced. |
| Leak 8 | Yes/No | 8 | Compromised adapter | `<hash>` | Adapter kill affects only adapter container. |
| Leak 9 | Yes/No | 2 | Compromised adapter | `<hash>` | Route/envelope mismatch rejected. |
| Leak 10 | Yes/No | 7/8 | Compromised adapter | `<hash>` | Only trusted writer records cost. |

## 11. Practical Hardening Architecture

Most Part 1 fixes cluster into a few architectural moves.

### Move 1: Auth Gate For Public Endpoints

Add authentication before:

- Chat/generation endpoints.
- Embedding/vision/speech/transcription endpoints.
- Provider/status/capability/cost/calls endpoints.
- OpenAPI docs in production.

Use:

- Short-lived bearer tokens or signed requests.
- Constant-time token comparison.
- Per-user/per-tenant identity extraction.
- Explicit unauthenticated health endpoint only if needed.

### Move 2: Split Trusted And Untrusted Components

Gateway should hold:

- Provider credentials.
- Audit writer.
- Pairing state writer.
- Control token.
- Credential-signing key.
- Policy enforcement.

Adapters should not hold:

- Provider API keys.
- Install/control token.
- Audit DB write access.
- Pairing DB write access.
- Cost ledger write access.

### Move 3: Per-Adapter Containers/Sandboxes

Each adapter should get:

- Its own process.
- Its own PID namespace.
- Its own filesystem view.
- Minimal image.
- Non-root user.
- Only its own token/secret.
- Explicit network egress allowlist.
- CPU/memory/process/time limits.

### Move 4: Scoped Credentials

Instead of broad long-lived secrets, issue credentials that bind:

- Tool/action name.
- User identity.
- Tenant.
- Final arguments or argument hash.
- Expiry.
- Nonce/idempotency key.
- Audience/component.

### Move 5: Immutable Audit Path

Audit should be:

- Gateway-owned.
- Append-only.
- Hash-chained if possible.
- Written by one trusted writer.
- Not mounted into adapter containers.
- Protected against delete/update/drop by design.

### Move 6: Deterministic Authorization

Do not let model text, tool descriptions, or adapter claims authorize actions.

Authorization should check:

- Actual user.
- Tenant.
- Calling component.
- Tool/action.
- Final arguments.
- Approval record if high impact.
- Credential scope and expiry.

## 12. Part 2 Hunting Workflow

Part 2 is not about re-finding the known list. It is about finding an uncatalogued way to break the invariants.

### Step 1: Recon The Codebase

Start with:

```bash
find . -maxdepth 3 -type f | sort
```

Read:

- `docs/ARCHITECTURE.md`
- `modal_app.py`
- app/router files
- WebSocket handlers
- adapter implementations
- policy engine
- auth/security modules
- database/storage modules
- provider clients
- Containerfiles/Dockerfiles
- CI/workflow files

List exposed HTTP routes:

```bash
curl <url>/openapi.json > openapi.json
```

Search for security-sensitive code:

```bash
grep -R "os.environ" -n .
grep -R "Secret.from_name" -n .
grep -R "subprocess" -n .
grep -R "eval(" -n .
grep -R "exec(" -n .
grep -R "pickle" -n .
grep -R "sqlite3.connect" -n .
grep -R "httpx." -n .
grep -R "requests." -n .
grep -R "WebSocket" -n .
grep -R "Authorization" -n .
grep -R "token" -n glc
grep -R "tenant" -n glc
```

If available, prefer `rg` over `grep`:

```bash
rg "os\.environ|Secret\.from_name|subprocess|eval\(|exec\(|pickle|sqlite3\.connect|httpx\.|requests\.|WebSocket|Authorization|token|tenant"
```

### Step 2: Map Components

For each component, write:

| Component | Trust Level | Inputs | Outputs | Secrets | State | Network Access |
|---|---|---|---|---|---|---|
| Gateway | High | HTTP/WS/tool results | Provider calls/replies | Provider keys/control tokens | Audit/pairing/cost | Broad |
| Adapter | Low/medium | Channel data | Gateway envelopes | Adapter token only | Adapter local state | Should be restricted |
| Policy engine | High | Proposed action | allow/deny | policy config | policy state | minimal |
| Agent runtime | Medium/high | prompts/tools/context | tool calls/replies | scoped creds only | run state | controlled |

Then look for mismatches, especially low-trust components with high-trust assets.

### Step 3: Walk STRIDE

For each component, ask:

| STRIDE | Question | Examples To Check |
|---|---|---|
| Spoofing | Can one principal pretend to be another? | Channel names, user IDs, tenant IDs, adapter tokens. |
| Tampering | Can unauthorized data/state be changed? | Audit, cost, pairing, memory, policy config. |
| Repudiation | Can action history be denied or erased? | Missing audit entries, mutable logs, clock/source gaps. |
| Information disclosure | Can secrets/private data leak? | Env vars, errors, logs, tool output, cross-tenant memory. |
| Denial of service | Can the system be exhausted? | Large payloads, loops, retries, file uploads, cold starts. |
| Elevation of privilege | Can a weaker role gain stronger authority? | User to adapter, adapter to gateway, tenant A to tenant B. |

### Step 4: Check OWASP/Agentic Categories

Use these as coverage checks after STRIDE:

- Prompt injection.
- Sensitive information disclosure.
- Supply-chain compromise.
- Data/model poisoning.
- Improper output handling.
- Excessive agency.
- System prompt leakage.
- Vector/embedding weaknesses.
- Misinformation/integrity failure.
- Unbounded consumption.
- Tool misuse.
- Identity and privilege abuse.
- Unexpected code execution.
- Memory/context poisoning.
- Insecure inter-agent communication.
- Cascading failures.
- Human-agent trust exploitation.

### Step 5: Prefer Chains

The strongest findings often combine two ordinary weaknesses.

Example chain shapes:

- Channel user input -> prompt injection -> unauthorized tool proposal -> weak final-argument check.
- Public endpoint -> SSRF-like fetch -> internal metadata/token leak -> reply exfiltration.
- Tool output -> model follows instruction -> action approval mismatch.
- Adapter identity spoof -> tenant confusion -> memory/cost/audit mutation.
- Long-running request -> retries/cold starts -> budget exhaustion.

## 13. Bug Ideas That May Be New If Not Already Catalogued

Do not assume these are valid. Treat them as hypotheses to verify against `glc_v2`.

### Identity And Authorization

- Tenant ID supplied by client is trusted without server-side binding.
- User ID in envelope is accepted without checking channel identity.
- Adapter token is accepted for routes/actions outside that adapter.
- Provider selection lets user force a more privileged backend.
- Admin/control route checks auth but not caller role.
- Token comparison uses plain `==`, enabling timing oracle.
- Expired/revoked tokens remain valid across container restarts.

### Approval And TOCTOU

- User approves one set of final arguments, but execution uses mutated arguments.
- Approval is keyed only by action name, not action plus arguments.
- Retried tool call reuses old approval for new parameters.
- Model-generated plan is approved, then code executes a different normalized form.

### Prompt/Tool Boundary

- Tool descriptions or schemas contain instruction text that changes model behavior.
- Tool output is reintroduced into context without untrusted labeling.
- Retrieved webpage/file/email text can override system/tool policy.
- Model can choose hidden/system tools based on user-controlled labels.

### Memory And Tenant Isolation

- Memory key omits tenant ID.
- Cache key omits tenant, user, or provider.
- Stored fact lacks provenance/source.
- One user's conversation appears in another user's context.
- Deletion/right-to-erasure path removes visible memory but not embeddings/cache.

### Web And API Surface

- CORS wildcard allows browser-based abuse with user tokens.
- Request body size is unbounded.
- File upload allows path traversal or unsafe MIME assumptions.
- Redirect handling bypasses URL allowlist.
- IPv6/private ranges are not blocked in SSRF defense.
- DNS rebinding bypasses host allowlist.
- WebSocket accepts messages before authentication completes.

### Audit And Ledger

- Failed auth attempts are not audited.
- Security-relevant rejects are not audited.
- Audit event source is caller-controlled.
- Audit timestamps are caller-controlled.
- Cost ledger accepts negative or overflow token counts.
- Audit/cost rows can be created for another user/tenant.

### Supply Chain

- Dependency install runs untrusted scripts.
- CI workflow can be modified by PR to expose secrets.
- Base image tag is mutable.
- Optional dependency import path can be hijacked.
- Local plugin/adapter loading trusts filename/module name from config.

### Denial Of Service

- Huge image/audio payload causes memory blow-up.
- Recursive tool loop lacks max depth.
- Batch endpoint multiplies requests without budget check.
- Streaming/WebSocket connection can be held forever.
- Repeated cold starts exhaust budget.
- Retry logic amplifies provider failures.

## 14. Tooling

Install/use as appropriate.

### Static Analysis

```bash
uv add --dev bandit semgrep pip-audit
uv run bandit -r glc
uv run semgrep --config auto .
uv run pip-audit
```

What they catch:

- `bandit`: insecure Python patterns.
- `semgrep`: configurable code patterns.
- `pip-audit`: vulnerable packages.

### Container/Image Scanning

```bash
trivy image <image>
grype <image>
dockle <image>
```

What they catch:

- Known CVEs.
- Risky base image contents.
- Root user / weak image hygiene.

### Dynamic Testing

Use:

- `curl`
- `httpie`
- `websocat`
- `mitmproxy`
- Caido/Burp-style proxy

Test:

- Unauthenticated access.
- Header variations.
- Tenant/user spoofing.
- WebSocket auth behavior.
- Large payloads.
- Replay.
- Redirects.
- Error verbosity.

### Fuzzing

```bash
uv add --dev hypothesis
```

Good targets:

- URL validators.
- Envelope parsers.
- Policy decision functions.
- Token parsers.
- Route parameter validation.
- File/media metadata handling.

### LLM/Prompt Testing

Useful tools:

- `garak`
- `promptfoo`

Good tests:

- Prompt injection.
- Tool-output injection.
- Tool-description poisoning.
- System prompt leakage.
- Excessive agency.
- Jailbreaks that cause tool misuse.

## 15. Part 2 PR Template

Use this structure in every scoring PR.

```markdown
# Bug: <short name>

## Summary

<One paragraph. Name the broken invariant and the affected component.>

## Broken Invariant

- Invariant: <number and wording>
- Attacker role: <outsider / channel user / compromised adapter / gateway code execution>

## Impact

<What asset is reached or what boundary is crossed?>

## Reproduction

Fresh checkout:

```bash
git clone <repo>
cd <repo>
uv sync
```

Steps:

1. <step>
2. <step>
3. <expected vulnerable result>

Or script:

```bash
python scripts/repro_<bug>.py --url <url>
```

## Root Cause

<Explain the exact trust mistake. Include file/function references.>

## Fix

<Explain the code change and why it closes the root cause.>

## Verification

Before fix:

```text
<exploit succeeds>
```

After fix:

```text
<exploit fails safely>
```

## Notes

<Mention why this is not one of the catalogued Section 6/7 findings.>
```

## 16. Part 1 Hardened Repo Note Template

Use this for the note submitted with your hardened clone.

```markdown
# Part 1 Hardening Notes

Repository: <your clone URL>
Modal URL: <your own deployment URL>
Keys used: mock/random only

## Verification Summary

- `/healthz`: pass
- `/docs`: gated/disabled in production
- Public data endpoints: require auth
- Provider keys: not visible to adapters
- Audit log: gateway-owned append path
- Adapter egress: allowlisted
- Rate/budget limits: enforced

## Findings Fixed

| Finding | Invariant | Attacker Role | Fix Commit | Before | After |
|---|---|---|---|---|---|
| A1 public data plane | 8 | Outsider | `<hash>` | unauth call ran | unauth call rejected |
| ... | ... | ... | ... | ... | ... |

## Residual Risks

<List anything intentionally deferred or partially mitigated. Be honest.>
```

## 17. Suggested One-Week Plan

### Day 1: Deploy And Reproduce

- Set up Modal.
- Deploy `glc_v2`.
- Confirm `/healthz`.
- Save `/openapi.json`.
- Reproduce Section 6 findings.
- Reproduce Section 7 leaks with local/in-process harnesses.

### Days 2-3: Fix Part 1

- Add auth gates.
- Gate/disable docs and info endpoints.
- Separate adapter/gateway privileges.
- Move secrets to least-privilege mounts.
- Add egress allowlists for untrusted components.
- Add rate limits and budgets.
- Fix SSRF, WebSocket channel mismatch, query tokens, verbose errors.
- Harden audit/cost/pairing paths.

### Day 4: Build Your Hunting Map

- Read architecture.
- List routes and WebSockets.
- Search for security-sensitive code.
- Draw principals/assets/data flows.
- Walk STRIDE component by component.
- Rank top 5 hypotheses by impact and reproducibility.

### Days 5-6: Hunt And PR

- Chase highest-impact hypotheses.
- Stop after roughly two hours if one idea is not landing.
- Write minimal repros.
- Fix the confirmed bug.
- Open PR quickly if the bug is valid.
- Watch for duplicates.

### Day 7: Polish

- Re-run reproductions.
- Re-run tests/static checks.
- Clean up PR explanations.
- Verify Part 1 notes are complete.
- Confirm all submitted bugs explicitly map to the 8 invariants.

## 18. Quick Success Checklist

Before submitting, confirm:

- You used `glc_v2`, not `glc_v1`.
- Your Modal deployment uses mock keys.
- You attacked only your own deployment.
- Part 1 fixes every Section 6 and Section 7 issue.
- Every Part 1 note names an invariant and attacker role.
- Every Part 2 PR is new relative to Sections 6 and 7.
- Every Part 2 PR includes reproduction and fix.
- Every Part 2 bug breaks one of the 8 invariants.
- You did not rely on real provider secrets or real external targets.

## 19. Mental Model To Keep

Ask these questions for every endpoint, adapter, and tool:

1. Who is the principal?
2. What asset is reachable?
3. Which trust boundary is crossed?
4. Is the boundary enforced by code/OS/runtime, or only assumed?
5. Which invariant would fail if this went wrong?
6. Which attacker role can reach it?
7. Can two harmless-looking weaknesses combine into a stronger chain?

The assignment rewards proof. A precise, reproducible, fixed bug beats a broad security claim every time.
