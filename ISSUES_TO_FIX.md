You need to fix every Section 6 finding and all 10 Section 7 code leaks (Section 6’s B-list duplicates those leaks).

**Migration / public-exposure issues**

- A1: Require authentication for all data-plane endpoints, or make deployment private.
- A2: Gate status/provider/cost/calls endpoints; disable Swagger/OpenAPI in production.
- A3 / Leak 6: Put untrusted adapters in Modal Sandboxes with an outbound-domain allowlist.
- A4 / Leak 1: Stop sharing one Function/Secret; isolate adapters and use per-tool-call scoped credentials.
- A5: Build from `uv.lock`; pin the base image by digest.
- A6: Replace unsafe autoscaled SQLite-on-Volume writes with a single append-only writer or real database.
- C1: Fix `/v1/vision` SSRF: URL allowlist, block private/loopback/link-local IPv4/IPv6, and validate redirects.
- C2 / Leak 9: Reject WebSocket messages where `env.channel` differs from the route channel.
- C3: Remove WebSocket tokens from query strings; use short-lived header-based tokens.
- C4: Return generic upstream errors to clients; retain details only in logs.
- C5: Add per-endpoint rate limits and hard budgets.
- C6: Investigate and, if reachable, rate-limit/protect pairing-code attempts.

**The 10 inherited code leaks**

1. Isolate adapters so they cannot read provider keys; issue narrowly scoped credentials per tool call.
2. Make audit storage gateway-only, append-only, and hash-chained.
3. Prevent adapters from writing pairing data or calling `force_pair_owner()` via process/component isolation.
4. Keep the install/control token accessible only to the gateway.
5. Run the policy engine in a separate process so adapters cannot monkey-patch it.
6. Restrict adapter egress through Sandbox allowlists.
7. Reduce subprocess/shell risk with minimal images, sandboxing, non-root users, read-only filesystems, syscall filtering, and egress limits.
8. Separate adapter and gateway PID namespaces so an adapter cannot terminate the gateway.
9. Enforce channel-route matching at the WebSocket boundary and audit failed attempts.
10. Protect the cost ledger with a gateway-held signed writer; do not accept arbitrary token counts from components.

The course’s intended consolidation is: isolated per-adapter containers/secrets, scoped credentials, sandbox egress controls, authenticated public endpoints, plus the individual endpoint and logic fixes above. Sections 9 onward are reference material, not required scope.
