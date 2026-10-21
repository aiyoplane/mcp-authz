# Operation-Field Design Note — `@aiyoplane/mcp-authz`

This note documents the operation-identifying fields considered for binding to Execution Receipts in `@aiyoplane/mcp-authz`. It serves as pre-work for a future receipt-format revision that would extend operation binding beyond the current `intent_id` + `intent_digest` layer.

Scope: covers `@aiyoplane/mcp-authz` at the current `src/` tree. The analysis is adapter-specific; Composition Boundary Adapters that compose above this package (e.g., `@aiyoplane/langchain`, `@aiyoplane/langgraph`) have different composition shapes and require their own analyses.

---

## 1. The question this note answers

A failure mode exists where a human or policy decision is recorded for one operation (A), but the operation actually released is different (B), because the authorization system binds the decision to something other than the complete operation executed. A future receipt-format revision — whether to carry a canonical operation hash in the signed payload — depends on knowing, per adapter, *which fields actually determine the consequential action and where they can diverge between the authorization decision and the executing tool call.*

The note's output is a field-by-field matrix with code citations, plus a recommendation for which fields enter the canonical operation hash under a future receipt-format revision for this specific adapter.

---

## 2. Execution path, exactly as shipped

The authorization-to-execution path in `@aiyoplane/mcp-authz` (`src/create-middleware.js` `wrap` function) runs:

1. **Ungated short-circuit** (`src/create-middleware.js`). Tools whose `toolConfig[toolName].aiyo_gated !== true` call the underlying handler directly with the original args. No RDP involvement.

2. **Intent construction** (`src/create-middleware.js`, delegating to `src/intent-builder.js:buildIntentPayload`). The default builder reads `(toolName, args, ctx, toolDef)` and produces the intent payload the RDP sees. **Not every field of `args` enters the intent payload** — only `amount` (via `toolDef.amount` function or literal) and anything the integrator explicitly surfaces by passing a custom `intentBuilder` in config.

3. **RDP evaluation** (`src/create-middleware.js`). `rdp.evaluate(intentPayload)` returns `{ intentId, receipt }` on ALLOW or throws `AiyoDenied` on DENY. Any other failure (`AiyoUnreachable`) fails closed.

4. **Receipt verification** (`src/create-middleware.js`). On ALLOW, `rdp.verifyReceipt(receipt.token)` is called locally. Default-on via `verifyReceiptOnAllow`. Current v2 verification is pure cryptographic — it checks signature, required payload fields, and expiry; it does not compare the receipt against the executing operation's fields.

5. **Handler invocation** (`src/create-middleware.js`). The underlying tool handler is called as `handler(args, { ...ctx, receipt, receiptPayload, intentId })`. **The `args` passed to the handler are the exact same object the agent passed in — unmodified by the authorization decision.**

6. **Lineage close** (`src/create-middleware.js`). Fire-and-forget `rdp.close(intentId, outcome)`. Does not participate in the authorization decision.

**Authorization enforcement point:** step 3 (`rdp.evaluate`). ALLOW is a precondition for step 5 (handler invocation). On any error before step 5 the handler never runs.

---

## 3. Field-by-field matrix

The columns are:

- **Field** — the named field in the system
- **Source** — where the field's value originates
- **In Intent?** — does this field appear in the intent payload the RDP sees
- **In v2 Receipt?** — does this field appear in the signed v2 receipt payload (`{iid, cid, mid, exp, iat}`)
- **Mutable between decision and execution?** — can this field's value change in the microseconds between `rdp.evaluate` returning ALLOW and `handler(args, ctx)` being called
- **Determines consequential action?** — does the inner tool handler read this field to decide what to do

| Field | Source | In Intent? | In v2 Receipt? | Mutable? | Determines action? |
|---|---|---|---|---|---|
| `toolName` | `wrap(toolName, handler)` closure variable | Yes — `intent.metadata.tool_name` (`intent-builder.js`) | Indirectly via `cid` (digest-of-payload) | No — closure over wrap-time binding | Yes — the handler closure is per-tool; `toolName` *is* the handler |
| `args` (full object) | Agent-supplied per call | **No** by default; only via custom `intentBuilder` | No | No — passed by reference, same object | **Yes** — the handler reads `args` to decide what to do |
| `args.*` individual fields | Agent-supplied | **No** by default; only if the integrator wires them through `intentBuilder` or through `toolDef.amount` (for `amount` only) | No | No | **Yes** — individually consequential |
| `toolDef.amount` (function or number) | Static per tool, from `toolConfig[toolName]` | Yes — `intent.amount` (`intent-builder.js`) | Indirectly via `cid` | Yes if `toolConfig` is mutated after wrap (unlikely in practice; integrator discipline question) | For payment tools, yes |
| `toolDef.currency` | Static per tool | Yes — `intent.currency` (`intent-builder.js`) | Indirectly via `cid` | Same as `toolDef.amount` | For payment tools, yes |
| `toolDef.action.type` | Static per tool | Yes — `intent.action.type` (`intent-builder.js`) | Indirectly via `cid` | Same as `toolDef.amount` | Yes — the RDP typically policies on this |
| `toolDef.action.*` (extra fields) | Static per tool | Yes — `intent.action.*` (`intent-builder.js`) | Indirectly via `cid` | Same as `toolDef.amount` | Yes if the handler reads them from `ctx` or via closure |
| `ctx.attribution.workflow_id` | Caller-supplied via `ctx` to the wrapped handler | Yes — `intent.attribution.workflow_id` (`intent-builder.js`) | Indirectly via `cid` | **Yes** — `ctx` is a per-call object; another middleware above `wrap` could in principle mutate it between evaluate and handler steps | No (attribution is lineage, not instruction) |
| `ctx.attribution.agent_id` | Same | Yes — `intent.attribution.agent_id` (`intent-builder.js`) | Indirectly via `cid` | Same as `workflow_id` | No |
| `ctx.metadata.*` | Same | Yes — `intent.metadata.*` (`intent-builder.js`) | Indirectly via `cid` | Same as `ctx.attribution` | Depends — can carry instruction-shaped fields if integrator wires them |
| `ctx.receipt` (returned on ALLOW) | Produced by `rdp.evaluate` | N/A — this is the RDP's output, not input | N/A | N/A | No — a signed artifact, not an input |
| `ctx.receiptPayload` | Produced by `rdp.verifyReceipt` | N/A | N/A | N/A | No |
| `ctx.intentId` | Produced by `rdp.evaluate` | N/A | N/A | N/A | No |

### Observations

**O-1: `args` is not seen by the RDP by default.** The default `intentBuilder` passes `args` into `toolDef.amount(args)` to derive the intent's `amount` — nothing else. An agent can supply `args` fields that drive consequential behavior in the inner handler without the RDP ever evaluating them.

**O-2: The receipt is not operation-field-bound.** v2 payload is `{iid, cid, mid, exp, iat}`. `cid` is produced by `buildCid(intentPayload)` in `local-rdp.js:evaluate` and may digest some payload fields, but the v2 verification contract does not re-read the operation at verification time. The receipt is a pointer to the intent id.

**O-3: `action.type` and `action.target` are tool-definition-static, not per-call.** The RDP policies on `action.type` from `toolDef`, which is set at wrap time and not re-derived from `args`. Two different `args` combinations through the same tool produce the same `action.type` in the intent.

**O-4: Mutation window is in-process and short.** For an attacker without JS runtime access, the window between `rdp.evaluate` returning ALLOW and `handler(args, ctx)` being called is microseconds and inaccessible. For an attacker *with* JS runtime access (compromised process, malicious middleware above `wrap`), `args` and `ctx` are reachable in principle. That threat model (compromised JS runtime) is outside the enforcement scope regardless — the attacker has already won once they can mutate the executing process memory.

**O-5: The real decision-vs-execution divergence surface is `args`.** The agent-supplied `args` object is the single most consequential input to the handler and is simultaneously *not* authorization-material by default. An integrator who wants strict operation-field binding needs a custom `intentBuilder` that surfaces args into the intent payload *and* a future receipt format that binds to a canonical hash over the args surfaced.

---

## 4. Recommendation for a future receipt-format revision

A future receipt format carrying an operation-binding claim should cover a canonicalization of the **effective arguments** the handler receives — specifically, a digest over the args the integrator deems operation-identifying, surfaced into the Intent via a custom `intentBuilder` and bound in the signed receipt payload.

The current `wrap()` path makes this feasible: reference identity between `intentBuilder`-time args and handler-time args is preserved (verified behaviorally in `test/pattern-42-args-digest-effective-coverage.test.js`), and no in-process mutation occurs on the shipped path.

Open design decisions for a future revision:

1. **Field selection surface.** Should the integrator declare operation-identifying fields via `toolConfig[toolName].operationFields: ['field1', 'field2']`, or via a canonicalization function similar to `toolDef.amount`? The former is declarative and auditable; the latter is more flexible but harder to audit.
2. **Canonicalization algorithm.** JSON canonicalization (RFC 8785 JCS, already used for the receipt payload) is the natural choice. Edge cases (undefined values, non-serializable types) need explicit rules.
3. **Receipt payload shape.** Adding `op_digest` as a new short-key claim preserves the compact v2 payload shape. A new version prefix (e.g., `v3.`) would be required.
4. **Verification contract.** A verifier that observes the effective operation at the Composition Boundary must compute the digest the same way the RDP computed it at signing time and reject on mismatch. This is a verifier-side obligation, not a receipt-format-only property.

Composition hazards above `wrap()` (hostile middleware mutating args between the Composition Boundary and the inner handler) are outside the receipt format's remit and need their own control.

---

## 5. Known gaps and follow-on work

- Per-adapter equivalent analyses for Composition Boundary Adapters that compose above `@aiyoplane/mcp-authz` have different composition shapes (e.g., LangGraph composes over `(state) → stateUpdate` node functions). Each adapter needs its own operation-field matrix.
- The `buildCid` implementation and its exact digest input are referenced in observation O-2 but not fully specified in this note; a follow-on audit of `src/local-rdp.js:buildCid` and `src/verify-receipt.js` would close that gap.
- Policy-authoring surface for declaring per-action operation-field requirements is a separate design track and is not addressed here.
