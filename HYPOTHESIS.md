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
