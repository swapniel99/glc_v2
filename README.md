# glc_v2 — Session 12 reference repository

This is the reference repository for **Part 2** of the Session 12 assignment. It is the glc gateway (the Session 11 `glc_v1` code plus the Modal wrapper `modal_app.py`), left with its security flaws in place on purpose. It is the shared target you open pull requests against when you find a new bug.

## The assignment in one screen

- **Part 1 (required), on your own clone of `glc_v1`.** Migrate it to Modal as Section 6 of the session walks it, then fix every finding in Sections 6 and 7. You submit your hardened repository. This part does not happen here.
- **Part 2 (100 points per new bug), here.** Find a bug that Sections 6 and 7 do not already name, and open a pull request against this repository that describes it, reproduces it from a fresh checkout, and fixes it. The pull-request template walks you through the four things it needs. On duplicates, the first pull request filed wins, so check the open pull requests first.

The full brief is in [`ASSIGNMENT.md`](ASSIGNMENT.md).

## Run it

This is a `uv` project.

```sh
uv sync
uv run glc serve        # gateway on http://localhost:8111
```

To deploy on Modal, see `modal_app.py` and Session 12 Section 6. Use mock keys only, and never put real provider keys on Modal.

### Modal adapter isolation

Webhook adapters run in request-scoped Modal Sandboxes. Each sandbox receives
an explicit outbound-domain allowlist, no gateway data Volume, and no provider
secret. Adapters with an empty domain list have networking disabled.

Deployment-specific domains and per-adapter mock secrets can be supplied while
deploying. Values are JSON maps keyed by adapter name; domains contain hostnames
only, without schemes, paths, or ports.

```sh
export GLC_MODAL_ADAPTER_EGRESS_JSON='{"imap":["imap.example.test","smtp.example.test"]}'
export GLC_MODAL_ADAPTER_SECRETS_JSON='{"telegram":"glc-adapter-telegram"}'
uv run modal deploy modal_app.py
```

Adapter Secret names are enforced as `glc-adapter-<adapter-name>` (underscores
become hyphens). Put only that adapter's platform credentials in it. Gateway
Secrets such as `glc-llm-keys` and another adapter's Secret are rejected. A
missing adapter Secret remains fail-closed rather than inheriting one.

External WebSocket adapters never receive the installation/control token.
An authenticated operator mints a short-lived credential scoped to one channel,
then passes only that credential to the adapter:

```sh
INSTALL_TOKEN="$(uv run glc token)"
export GLC_CHANNEL_CREDENTIAL="$(
  curl -fsS -X POST http://localhost:8111/v1/control/channels/telegram/credential \
    -H "Authorization: Bearer $INSTALL_TOKEN" \
    -H 'Content-Type: application/json' \
    -d '{"ttl_seconds":300}' | jq -r .credential
)"
unset INSTALL_TOKEN
```

Credentials expire after at most five minutes and cannot authenticate another
channel. WebSocket query-string authentication and installation-token
authentication are rejected.

Audit writes use a separate `glc-audit` Volume mounted only by a single
`audit_writer` Function. Autoscaled gateway replicas call that writer remotely;
the writer reloads the Volume before SQLite access and commits after every
operation.

Create a separate policy-service-only signing Secret before deployment.
Generate at least 32 random bytes locally, then paste the value into this
command:

```sh
uv run modal secret create glc-capability-signing-key \
  GLC_CAPABILITY_SIGNING_KEY='<random-value>'
```

Modal runs policy evaluation, capability signing, and redemption in a dedicated
`policy_credential_service` Function. It receives the signing Secret but no
gateway Volume or provider keys. Gateway containers hold only a remote proxy,
so rebinding their local Python policy functions cannot produce a valid
credential. Credentials bind adapter, actual user, tenant, trust level, tool,
tool-call ID, argument hash, audience, expiry, and nonce. An atomic distributed
nonce ledger permits one redemption across all containers. Model `tool_calls`
are proposals only in the current scaffold; they are returned to the
authenticated caller and are not executed. Any future tool runner must redeem
through `app.state.scoped_action_authorizer` immediately before dispatch.

## Where to look

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — trust boundaries and data flows. Start here for recon.
- `glc/` — the gateway source.
- `modal_app.py` — the Modal deployment wrapper.
- `/openapi.json` and `/docs` on a running gateway — the full route inventory.

## License

MIT, see [`LICENSE`](LICENSE).
