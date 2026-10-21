# Changelog

All notable changes to `@aiyoplane/mcp-authz` are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.1.0] — 2026-10-20

Additive release. No change to receipt format, canonicalization, signing, verification, or any existing API shape. 1.0.0 code is source- and binary-compatible.

### Added
- **`AiyoEscalation` error class.** First-class ESCALATE verdict (AEAP §6.2), distinct from `AiyoDenied`. Fields: `name: 'AiyoEscalation'`, `code: 'ESCALATE'`, `reason`, `rule_id`, `intentId`, `escalationId`. Message prefix `"ESCALATE: "` preserves backward-compat with downstream `/escalat/i` message-text matching.
- **`authorizationTimeoutMs` config option on `createAiyoMcpAuthz`.** Positive integer up to Node's `TIMEOUT_MAX` (2 147 483 647 ms). Values outside this range — negative, `NaN`, `Infinity`, or above `TIMEOUT_MAX` — throw `AiyoConfigError` at construction. Omitted or `0` → no timeout applied (1.0.0 behavior preserved). **Production consumers that need a bounded wait on `rdp.evaluate()` must set a finite value explicitly.** On fire, the wrapped handler rejects with `AiyoUnreachable { code: 'TIMEOUT' }`; the gated handler never runs. The timeout bounds the caller's wait; it does not cancel the underlying `rdp.evaluate()` work (JS Promises are not cancellable).
- **`escalate` as a valid rule effect in `evaluatePolicy`.** `createLocalRdp` surfaces ESCALATE as an `AiyoEscalation` throw. All three canonical AEAP verdicts (`allow`/`escalate`/`deny`) are accepted as `default_effect` values; non-canonical rule effects fail closed to `deny`.
- **AEAP wire-format error translation.** RDPs that throw a plain `Error` with `code: 'BLOCK'` or `verdict: 'BLOCK'` (or ESCALATE equivalents) are promoted to the matching typed error. If `code` and `verdict` are both present and **disagree**, the decision representation is treated as ambiguous: `AiyoUnreachable` is raised and the gated handler never runs — fail closed per AEAP §2.2 invariant 5.

### Fail-closed invariant
No new path permits the gated handler to run: timeout fire, `AiyoEscalation` throw, ambiguous wire-format decision, and `TIMEOUT_MAX` boundary rejection are all fail-closed. The behavioral suite in `test/escalation-and-timeout.test.js` asserts these directly against the shipped middleware source.

### Changed
- `test/pattern-41-conformance.test.js` adapter factory exercises native `authorizationTimeoutMs` and native typed-error promotion; the previous harness-side timeout wrapper is removed.

### Not changed
No change to receipt format, canonicalization, signing, verification, `exp` handling, JWKS surface, the Pattern 41 ordering invariant, or the Pattern 42 args-reference-identity properties.

## [0.1.0] — Preview release

### Added
- **`createAiyoMcpAuthz({ rdp, toolConfig })`** middleware factory. Takes any RDP provider implementing `{ evaluate, close, verifyReceipt }` and returns `{ wrap, verifyReceipt }`.
- **`wrap(toolName, handler)`** function to gate an MCP tool handler through the RDP with fail-closed behavior at every failure mode.
- **`createLocalRdp({ policy, merchantId?, signingKey?, ttlSeconds?, clockSkewSeconds? })`** — in-process demo RDP. Evaluates a small policy locally, issues v1 HMAC-signed execution receipts with a per-process signing key. Zero credentials, zero network. Intended for demos, tests, examples, and local development.
- **`createHostedRdp({ apiBaseUrl, apiKey, jwksUrl?, hmacKey?, ... })`** — production RDP provider. POSTs intents to Aiyo's RDP evaluate endpoint, verifies returned v2 Ed25519 receipts against Aiyo's Ed25519 public key(s) fetched from `/.well-known/aiyo-jwks.json`. Automatic JWKS cache with rotation-grace refresh. No shared secret required. Legacy v1 (HMAC) receipts accepted when `hmacKey` is provided for migration windows.
- **`verifyReceipt(token, keyMaterial, options?)`** standalone verifier. Version-dispatches on the token prefix: v1 (HMAC) verified against a string key; v2 (Ed25519) verified against a Node KeyObject, JWK, or JWKS-shaped `{ keys: [...] }`.
- **`evaluatePolicy(intent, policy)`** small deterministic policy evaluator used by the local RDP. First-match wins, `default_effect: 'deny'` fail-closed default.
- **Small policy evaluator with a demo policy** (`policy.example.json`) showing action-type matching, target matching, amount thresholds, and per-rule reasons.
- **Typed error classes**: `AiyoDenied`, `AiyoUnreachable`, `AiyoReceiptInvalid`, `AiyoConfigError`.
- **Default intent builder** handling both non-payment tools (`amount: 0`) and payment tools (dynamic `amount` and `currency`).
- **Apache 2.0 license** + `NOTICE` file establishing the package's license from initial release.
- **Reference example** (`examples/mcp-server-basic`) demonstrating five decision paths in one demo run: ungated bypass, non-payment ALLOW, non-payment DENY, payment ALLOW, payment DENY. Runs against the local RDP with zero credentials.
- **`npm run demo`** script at the repo root that installs and runs the reference example end-to-end.
- **Full composition pattern documented** in `docs/ARCHITECTURE.md`, including the two invariants (one authorization decision per consequential action; decision strictly between intent and execution) and the alternatives-considered comparison table.

### Receipt format
- **v2 (current — Ed25519, public-key verification):** `v2.<base64url(payload)>.<base64url(ed25519_sig)>`. Signed by Aiyo's private Ed25519 key; verified against the corresponding public key served at `${apiBaseUrl}/.well-known/aiyo-jwks.json` (standard JWKS format). Merchants never hold Aiyo signing material.
- **v1 (legacy — HMAC-SHA-256):** `v1.<base64url(payload)>.<hex(hmac_sha256_sig)>`. Retained for backward compatibility with receipts issued before September 2026, and used by the local demo RDP where signer and verifier live in the same process.
- **Payload claims** (identical across versions): `{ iid, cid, mid, exp, iat }` — intent id, content/action id, merchant id, expiry, issued-at. Short keys keep tokens compact.
- **Version prefix hardcodes the signing algorithm** — no negotiation, no downgrade path, no `alg=none` vulnerability by construction. Future signing algorithms would take a new prefix (`v3.…`) rather than extending v2.

### Endpoint
- SDK uses the neutral action-agnostic path `/v1/intents` (backend behavior-identical to the historical `/v1/payment_intents` alias, which continues to work forever).

### Architectural claim demonstrated
Same authorization primitive governs consequential tool invocations whether or not those invocations move money — **action-agnostic** execution authorization at the MCP protocol boundary.

### Not in this release
- Payment-gated tools that require on-rail settlement wait before authorization. `createHostedRdp` throws `AiyoUnreachable` if the RDP returns `requires_payment`. Use non-payment (`amount: 0`) tools in v0.1; settlement-wait support arrives in v0.2.
- An MCP server implementation. Bring your own — the package composes above whatever MCP server you already run.
