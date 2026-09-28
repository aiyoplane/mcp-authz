# @aiyoplane/mcp-authz

**Reference middleware for composing Aiyo — the settlement-verified Economic Execution Authorization plane for autonomous systems — above an MCP server. Verify First. Execute Second. Learn more at [aiyoplane.com](https://aiyoplane.com).**

---

## What this package is

`@aiyoplane/mcp-authz` is a small, Apache 2.0-licensed reference implementation of one pattern: composing an independent authorization decision between an autonomous agent's tool-call intent and the tool's actual execution, at the MCP protocol boundary.

MCP makes it easy for an autonomous agent to invoke a tool. Permission to invoke a tool, however, is not necessarily the same thing as authorization for the consequential action that invocation will cause. A production deploy, a database write, a paid third-party API invocation, a CRM change on behalf of a customer — each is a consequential action whose runtime conditions (policy, budget, approval, freeze window, on-call state, capability lifetime, cumulative rate) may be independent of whether the agent is generally allowed to call the tool.

Aiyo's Runtime Decision Point (RDP) sits at exactly that boundary. This package is a thin adapter: wrap your MCP tool handler with `authz.wrap(...)`, and every invocation flows through an RDP before the tool runs.

The reference is deliberately small. It demonstrates the composition pattern rather than attempting to become an MCP authorization standard or replace MCP itself.

---

## The one-paragraph architectural claim

MCP tool invocations are the correct semantic granularity for an execution-authorization decision — one authorization per tool call, at the boundary where consequential action begins. Payment settlement is one possible evidence signal an RDP can consume; the primitive works when the consequential action doesn't move money at all. This package's default demo exercises the non-payment case as the primary example, because that is what makes the architectural claim structural rather than payment-adjacent.

---

## Run the demo in 60 seconds

```bash
git clone https://github.com/aiyoplane/mcp-authz.git
cd mcp-authz
npm install
npm run demo
```

You'll see five labeled sections showing an ungated bypass, a non-payment ALLOW (deploy to staging), a non-payment DENY (deploy to production), a payment ALLOW ($10), and a payment DENY ($100). The same Runtime Decision Point governs all four gated calls.

No credentials. No environment variables. No network round-trip. The demo runs against a **local, in-process RDP** that evaluates a small policy from `policy.example.json` at the repo root and signs receipts with a per-process key. The receipt format is byte-for-byte the same as Aiyo's production server-side signer, so the middleware's verifier code path is exercised identically to how it runs in production.

---

## Two modes: local RDP and hosted RDP

The middleware takes an `rdp` provider. Two providers ship in this package.

### Local RDP — for demos, tests, examples, local development

```js
import { createAiyoMcpAuthz, createLocalRdp } from '@aiyoplane/mcp-authz';
import policy from './policy.example.json' with { type: 'json' };

const authz = createAiyoMcpAuthz({
  rdp: createLocalRdp({ policy }),
  toolConfig: {
    deploy_to_production: {
      aiyo_gated: true,
      action: { type: 'deploy', target: 'production' },
    },
    search_docs: { aiyo_gated: false },
  },
});

const deploy = authz.wrap('deploy_to_production', async (args, ctx) => {
  // Runs only if the RDP returned ALLOW; ctx.receipt is the verified receipt.
  return await actuallyDeploy(args);
});
```

Zero credentials. The RDP evaluates `policy.example.json` in-process and issues receipts against a locally-generated signing key. Use this for `examples/`, tests, and local iteration.

### Hosted RDP — for gating against your production Aiyo policy

```js
import { createAiyoMcpAuthz, createHostedRdp } from '@aiyoplane/mcp-authz';

const authz = createAiyoMcpAuthz({
  rdp: createHostedRdp({
    apiBaseUrl: 'https://api.aiyoplane.com',
    apiKey: process.env.AIYO_API_KEY,
  }),
  toolConfig: { /* ... */ },
});
```

**No shared secret is required for verification.** Aiyo signs receipts with an Ed25519 private key it holds; the public key is published as a standard [JWKS](https://datatracker.ietf.org/doc/html/rfc7517) at `https://api.aiyoplane.com/.well-known/aiyo-jwks.json`. The middleware fetches the JWKS the first time it verifies a receipt and caches the keys, refreshing on demand if verification fails against the current cache (key rotation is handled gracefully). Non-custodial by construction — nothing custodial ever leaves Aiyo.

Access to production Aiyo credentials (the `apiKey` for creating intents) is granted through the Early Access surface at [aiyoplane.com](https://aiyoplane.com).

**The wrap-and-execute flow is identical in both modes.** The composition pattern is real whether the RDP is local or hosted. That's the point of the reference.

---

## What happens on a gated tool call

1. **Intent.** The MCP server receives a tool call. `authz.wrap(...)` intercepts, extracts the tool's action metadata from `toolConfig`, and builds an intent payload including any `attribution` context you pass (`workflow_id`, `agent_id`).
2. **RDP evaluation.** The middleware calls `rdp.evaluate(intentPayload)`. The local RDP evaluates the policy in-process. The hosted RDP `POST`s the intent to the RDP evaluate endpoint on your configured Aiyo API base URL.
3. **Verdict.**
   - **DENY** → the RDP throws `AiyoDenied` with the rule/field that failed. Your MCP server catches this and returns an error to the agent.
   - **ALLOW** → the RDP resolves with a signed execution receipt. The middleware verifies the receipt locally against the RDP's signing key — no round-trip.
4. **Execute.** The middleware invokes your original tool handler, passing the verified receipt on `ctx.receipt`, the decoded payload on `ctx.receiptPayload`, and the parent intent's id on `ctx.intentId`.
5. **Close the lineage.** Once the handler returns (or throws), the middleware calls `rdp.close(intentId, outcome)`. Local RDP is a no-op; hosted RDP POSTs the outcome to the RDP so the Aiyo dashboard's lineage panel renders the full chain from agent intent through RDP verdict through tool invocation through outcome. The close call is fire-and-forget — a close failure never itself causes the tool call to fail.

Same shape whether the tool is a payment tool or a non-payment tool. Payment tools set `action.type: 'payment'` and pass an `amount`; non-payment tools default to `amount: 0`.

---

## The action-agnostic proof

The `examples/mcp-server-basic` folder ships four tools: a mock production deploy (denied by policy), a mock staging deploy (allowed), a payment tool (allow/deny by amount), and an ungated read-only search. Neither of the non-payment tools moves money. Both flow through the RDP. Both produce an execution receipt in the lineage.

That is the point of this reference: to show, in inspectable code, that Aiyo's authorization primitive sits above the execution surface — not intrinsically inside a payment flow.

---

## Execution-receipt token format

Two compact formats coexist. New receipts are v2. The verifier accepts both.

**v2 (current — Ed25519, public-key verification):**

```
v2.<base64url(json_payload)>.<base64url(ed25519_sig)>
```

Aiyo signs with a private Ed25519 key. Verifiers use the corresponding public key published at [`api.aiyoplane.com/.well-known/aiyo-jwks.json`](https://api.aiyoplane.com/.well-known/aiyo-jwks.json) in standard [JWKS](https://datatracker.ietf.org/doc/html/rfc7517) format. Merchants never hold Aiyo signing material, and key rotation propagates through the published key set without distributing new secrets.

**v1 (legacy — HMAC-SHA-256):**

```
v1.<base64url(json_payload)>.<hex(hmac_sha256_sig)>
```

Retained for backward compatibility with receipts issued before September 2026. The local RDP demo also uses v1 with a per-process randomly-generated HMAC key — that's safe because signer and verifier are in the same process (no cross-party trust boundary). Hosted-RDP integrators can opt into v1 acceptance by passing `hmacKey` on `createHostedRdp` config; this is only needed if you have in-flight v1 receipts to accept across the migration.

**Both versions carry the same payload claims:** `{ iid, cid, mid, exp, iat }`. Expiry is enforced with a configurable clock-skew leeway (default 30 seconds). The version prefix hardcodes the signing algorithm — no negotiation, no downgrade path, no alg=none vulnerability.

---

## Configuration

`createAiyoMcpAuthz(config)` accepts:

| Field | Required | Description |
|---|---|---|
| `rdp` | yes | RDP provider from `createLocalRdp(...)` or `createHostedRdp(...)`, or your own object implementing `{ evaluate, close, verifyReceipt }`. |
| `toolConfig` | yes | Object keyed by tool name. Each entry declares either `aiyo_gated: false` (skip the RDP) or `aiyo_gated: true` with an `action` object naming the consequential action. Optional `amount` (number or function of args) and `currency` fields make the tool a payment tool. |
| `intentBuilder` | no | Function `(toolName, args, ctx, toolDef) => intentPayload` for full control over intent shape. Defaults to a sensible builder. |
| `logger` | no | Logger with `.info` and `.error`. Defaults to `console`. |
| `verifyReceiptOnAllow` | no | Verify the receipt after ALLOW (default: `true`). |

`createLocalRdp(opts)` accepts: `policy` (required), `merchantId` (default `'demo-merchant'`), `signingKey` (default: random 32 bytes), `ttlSeconds` (default 300), `clockSkewSeconds` (default 30), `logger`.

`createHostedRdp(opts)` accepts: `apiBaseUrl`, `apiKey` (both required); optional `jwksUrl` (defaults to `${apiBaseUrl}/.well-known/aiyo-jwks.json`), `hmacKey` (accepts legacy v1 receipts), `fetch`, `timeoutMs`, `clockSkewSeconds`.

The `authz.wrap(toolName, handler)` function returns a wrapped async handler with signature `(args, ctx) => Promise<result>`. Pass `attribution: { workflow_id, agent_id }` on `ctx` for two-actor attribution.

---

## What this reference does NOT do

- It does not implement an MCP server. Bring your own — the reference SDK, a community framework, or your own implementation.
- It does not replace Aiyo's HTTP API. The hosted-RDP provider calls it.
- It does not maintain long-lived session state or sticky policy caches. Every gated tool call is a fresh authorization decision.
- It does not implement pricing, billing, or economic settlement logic. Those live on the Aiyo backend.
- It does not attempt to become an authorization standard for MCP. It is a small composition example demonstrating one architectural pattern.

---

## Development

```bash
npm install
npm test        # runs the unit tests
npm run demo    # runs the reference demo (no credentials required)
```

The test suite uses `node:test`. No Aiyo credentials, no live backend, no network calls required.

See `docs/ARCHITECTURE.md` for the full composition pattern, including the lineage-close flow and error semantics.

---

## Versioning + stability

This is a **preview release** at `v0.1`. The public API surface (`createAiyoMcpAuthz`, `createLocalRdp`, `createHostedRdp`, `wrap`, `verifyReceipt`, error classes) may evolve through the `v0.x` line. `v1.0` locks the API.

Feedback, issues, and PRs welcome.

---

## License

Apache 2.0. See `LICENSE` and `NOTICE`.

---

## About Aiyo

Aiyo is the settlement-verified Economic Execution Authorization plane for autonomous systems. **Verify First. Execute Second.** Its Runtime Decision Point evaluates policy, authority, budget, approval, payment settlement (where relevant), and other runtime conditions at the moment a consequential action is about to execute, and issues a portable, cryptographically-signed execution receipt when — and only when — the conditions hold. Quadruple-agnostic: actor-agnostic, rail-agnostic, wallet-agnostic, action-agnostic. Learn more at [aiyoplane.com](https://aiyoplane.com).
