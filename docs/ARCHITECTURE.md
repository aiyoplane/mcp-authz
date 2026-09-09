# Architecture — `@aiyoplane/mcp-authz`

The composition pattern in one page.

---

## The architectural question

MCP makes it easy for an autonomous agent to invoke a tool. But **permission to invoke a tool is not necessarily equivalent to authorization for the consequential action that invocation will cause.**

A production deploy is a consequential action. A CRM write on behalf of a customer is a consequential action. A paid third-party API invocation is a consequential action. Each has runtime conditions — policy, budget, human approval, change-freeze state, incident state, on-call state, capability lifetime, cumulative rate — that are independent of whether the agent is generally allowed to call the tool.

That is where Aiyo's Runtime Decision Point (RDP) sits. This package composes the RDP at the MCP protocol boundary.

---

## The composition, drawn

```
   AGENT
     │
     │ MCP tool call
     ▼
   MCP SERVER
     │
     │ (wrapped by @aiyoplane/mcp-authz)
     ▼
   ┌──────────────────────────────────────┐
   │  authz.wrap(toolName, handler)       │
   │                                      │
   │   1. build intent from toolConfig    │
   │   2. rdp.evaluate(intent) ──────────┼────► AIYO RUNTIME DECISION POINT
   │   3. interpret verdict               │        (evaluates policy, budget,
   │      • DENY → throw AiyoDenied       │         evidence signals, etc.)
   │      • ALLOW → verify receipt        │        ◄──── signed execution receipt
   │   4. invoke handler(args, ctx)       │
   │   5. rdp.close(intentId, outcome) ──┼────► AIYO (closes lineage)
   └──────────────────────────────────────┘
     │
     │ result flows back to agent via MCP
     ▼
   AGENT
```

The MCP protocol between the agent and the MCP server is unchanged. The wrap layer sits inside the MCP server, invisible to the agent.

---

## Why the MCP tool-call boundary is the correct granularity

Two conditions must hold for any RDP composition to be architecturally clean:

1. **One authorization decision per consequential action.** Not one per session, not one per workflow, not one aggregated across multiple actions. The RDP is a decision at the moment before execution.
2. **The decision must occur strictly between intent and execution.** If the tool has already run when the RDP evaluates, the authorization was too late.

MCP tool invocations satisfy both. Each `tools/call` MCP request is one intended consequential action. The MCP server has the request in hand before invoking the underlying implementation — the natural interception point.

Contrast with alternatives that don't satisfy the invariants:

- **Session-level authorization** (authorize once at agent connect, then execute freely) — fails invariant 1. One decision, many consequential actions.
- **Post-hoc authorization** (execute, then check whether it should have been allowed) — fails invariant 2. Rollback is not always possible for consequential actions.
- **Tool-registration-time authorization** (declare at server start which tools the agent may call, no per-call check) — fails both. A tool that is generally allowed may still be denied on a specific invocation because the budget is exhausted, a change-freeze is active, or the target environment is in incident.

The MCP tool-call boundary is the right one.

---

## Fail-closed by default

Every failure mode in the middleware defaults to fail-closed:

| Failure | Behavior |
|---|---|
| Intent creation network error | Throw `AiyoUnreachable`. Tool does not execute. |
| Intent status is `denied` | Throw `AiyoDenied` with reason + field. Tool does not execute. |
| Receipt signature mismatch | Throw `AiyoReceiptInvalid`. Tool does not execute. |
| Receipt expired | Throw `AiyoReceiptInvalid`. Tool does not execute. |
| Unexpected intent status | Throw `AiyoUnreachable`. Tool does not execute. |

The one exception is the execution-result close call (step 5). It runs as fire-and-forget after the handler completes — a failure to close the lineage should never itself cause the tool call to fail. The Aiyo dashboard's lineage panel treats missing close events as an observability signal (surface it) rather than an authorization signal (fail retroactively).

Operators who want fail-open behavior for specific classes of failure (e.g. treat `AiyoUnreachable` as allow-and-log during Aiyo API outages) should implement that policy in their MCP server's error handler around the wrapped tool call, not inside this middleware. Fail-open is a deliberate operator choice with real risk trade-offs and should be explicit at the integration site.

---

## Non-payment vs. payment tools

The RDP evaluates the same shape of decision for both. The difference is one field.

**Non-payment tool** (this reference's primary example):

```js
{
  aiyo_gated: true,
  action: { type: 'deploy', target: 'production' },
  // amount defaults to 0
}
```

The intent is created with `amount: 0`. The RDP evaluates the merchant-declared policy (allowed action types, per-agent permissions, freeze windows, on-call notification, review-pack status) against the intent's action and attribution. No settlement check. Immediate authorization or denial.

**Payment tool**:

```js
{
  aiyo_gated: true,
  action: { type: 'payment' },
  amount: (args) => args.amount_cents,
  currency: 'usd',
}
```

The intent is created with the dynamic amount. Depending on the merchant's policy and the payment flow, the RDP may issue the receipt immediately (for authorized amounts under a pre-committed budget) or return `requires_settlement` (for amounts that need on-rail settlement verification before authorization). The v0.1 preview of this package does not implement the settlement-wait path — payment tools that require the wait are the natural v0.2 addition.

**Both use the same primitive.** That's the architectural claim this reference makes visible.

---

## The receipt contract

The execution receipt returned inside the intent is a cryptographically-signed artifact. Two compact formats coexist. The verifier dispatches on the version prefix.

**v2 (current — Ed25519, public-key verification):**

```
v2.<base64url(json_payload)>.<base64url(ed25519_sig)>
```

- `v2` — version marker. The signing algorithm is fixed by the prefix; no negotiation, no downgrade path, no alg=none vulnerability.
- `base64url(payload)` — URL-safe base64, no padding. Payload is a JSON object with claims `{ iid, cid, mid, exp, iat }` (short keys keep the token compact).
- `base64url(sig)` — Ed25519 signature over the string `"v2." + base64url(payload)`, produced with Aiyo's private key.

**Verification is public-key-based.** Aiyo publishes its Ed25519 public key(s) as a standard [JWKS](https://datatracker.ietf.org/doc/html/rfc7517) at `${apiBaseUrl}/.well-known/aiyo-jwks.json`. The hosted-RDP provider fetches the JWKS the first time it verifies a receipt, caches the keys, and refreshes on demand if a verification fails against the current cache (key rotation is handled gracefully). Merchants never hold Aiyo signing material, and key rotation propagates through the published key set without distributing new secrets.

**v1 (legacy — HMAC-SHA-256):**

```
v1.<base64url(json_payload)>.<hex(hmac_sha256_sig)>
```

Retained for backward compatibility with receipts issued before September 2026. Also used by the local RDP demo (`createLocalRdp`) with a per-process randomly-generated HMAC key — signer and verifier live in the same process, so the shared-secret model is safe (no cross-party trust boundary). Hosted-RDP integrators can opt into v1 acceptance by passing `hmacKey` on the config; needed only if you have in-flight v1 receipts to accept across the migration.

**Both versions share the same payload claims and clock-skew semantics.** The verifier splits the token, verifies the signature (Ed25519 or HMAC depending on version), decodes the payload, validates required claims (`iid`, `cid`, `mid`, `exp`, `iat`), and enforces expiry with a configurable clock-skew leeway (default 30s). Any deviation from the server-side signing convention surfaces as a signature mismatch — fails closed.

Future signing algorithms would take a new prefix (`v3.…`), never extend v2.

---

## What this package is not

- Not an MCP server. Bring your own — the reference SDK, a community framework, or your own implementation.
- Not a replacement for Aiyo's HTTP API. It calls it.
- Not an MCP authorization standard. It's a composition example.
- Not stateful. Every gated tool call is a fresh authorization decision.
- Not economic-logic. Pricing, billing, and settlement live server-side on Aiyo.

---

## Learn more

- Aiyo — [aiyoplane.com](https://aiyoplane.com)
- Category: Economic Execution Authorization plane for autonomous systems
- Invariant: **Verify First. Execute Second.**
- Named architectural primitive: Runtime Decision Point (RDP)
