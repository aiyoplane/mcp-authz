# Pattern 41 Behavioral Conformance Evidence — `@aiyoplane/mcp-authz`

This document records the behavioral conformance of `@aiyoplane/mcp-authz` against two AEAP properties:

1. **Pattern 41 — Enforcement Before Irreversibility.** The gated tool handler MUST NOT be invoked until the authorization condition has succeeded for the specific Intent that the dispatch would act on.
2. **Pattern 42 — effective-arguments coverage.** The arguments the handler consumes at invocation are the same arguments the Intent was built from, with reference identity preserved and no in-process mutation between Intent construction and handler invocation.

Both suites exercise the shipped `src/` of this package directly (`import { createAiyoMcpAuthz } from '../src/index.js'`). No mocks of the module under test; only the `rdp` collaborator is a test double, which is correct — the invariants under test are properties of `createAiyoMcpAuthz`'s `wrap()`, not of the RDP implementation.

**Runtime at time of record:** Node v22.23.2.

**Reproducer:**

```
node --test test/pattern-41-ordering-release-blocker.test.js
node --test test/pattern-42-args-digest-effective-coverage.test.js
```

---

## Pattern 41 — ordering invariant

### Statement

For a gated tool call (`toolConfig[name].aiyo_gated === true`), the underlying handler MUST NOT be invoked until BOTH:

(a) `rdp.evaluate()` has resolved with an ALLOW-shaped result (`{ intentId, receipt: { token } }`); AND
(b) if `verifyReceiptOnAllow` is true (default), `rdp.verifyReceipt()` has resolved without throwing.

Any error at (a) or (b) MUST prevent the handler from running.

### Scenarios and what each one proves

| # | Scenario | What it proves | Mechanism of proof |
|---|----------|----------------|--------------------|
| 1 | Timing ordering with a slow `evaluate` and a slow `verifyReceipt` | Handler does not run before `evaluate` resolves and does not run before `verifyReceipt` resolves | `process.hrtime.bigint()` timestamps recorded at `evaluate_called`, `evaluate_resolved`, `verifyReceipt_resolved`, `handler_called`; asserts `evaluate_resolved < handler_called` and `verifyReceipt_resolved < handler_called` |
| 2 | `evaluate` throws `AiyoDenied` | Handler never runs on the BLOCK path | A boolean the handler would set is asserted false after `wrapped()` rejects |
| 3 | `evaluate` throws a non-`AiyoDenied` generic error | Fail-closed on indeterminate / unreachable RDP (AEAP §2.2 invariant 5) | Same boolean mechanism as Case 2 |
| 4a | `evaluate` resolves with `{ receipt: { token } }` but no `intentId` | Malformed ALLOW shape fails closed, handler does not run | Same boolean mechanism |
| 4b | `evaluate` resolves with `{ intentId, receipt: {} }` (no `token`) | Malformed receipt fails closed, handler does not run | Same boolean mechanism |
| 5 | `verifyReceiptOnAllow` default; `verifyReceipt` throws | Belt-and-braces check actually gates the handler when enabled | Same boolean mechanism; `wrapped()` rejects, handler flag is false |
| 6 | Two concurrent `wrapped()` invocations with per-call `evaluate` latency | Each invocation consults `evaluate` independently; no cached-decision shortcut | `evaluate_calls` counter equals 2; `handler_invocation_count` equals 2 |

### What this suite does NOT establish

- **Not full adapter conformance.** Case coverage is targeted at the ordering invariant. The suite does not exercise `rdp.close()` lineage closure, does not exercise ungated tools, does not exercise the receipt-attachment ctx fields consumed by downstream handlers.
- **Not a proof against all possible mutation windows.** The suite proves the handler does not run before `evaluate` and `verifyReceipt` resolve on the exercised paths. A hostile wrapper above `wrap()` that mutated the handler reference between evaluation and invocation is NOT within scope here (that is a composition-hazard concern addressed by the Pattern 42 detection pattern below).
- **Not a proof for configurations other than the default.** `verifyReceiptOnAllow: false` is not exercised; nor is a custom `rdp` object that returns Promises other than through `async`.
- **Not a cross-adapter claim.** This evidence covers `@aiyoplane/mcp-authz` only. Composition Boundary Adapters that compose above this package (`@aiyoplane/langchain`, `@aiyoplane/langgraph`, etc.) each need their own evidence records.

---

## Pattern 42 — effective-arguments coverage

### What this suite establishes

The suite proves four distinct properties about `wrap(toolName, handler)` with respect to the `args` object:

1. **Reference identity.** The `args` object passed to `wrapped(args)` is the same JavaScript object reference that reaches `intentBuilder(args, ctx)` and the same reference that reaches `handler(args, ctx)`. Proven by wrapping `args` in a `Proxy` whose `get` trap records every property read with a per-call tag; the same proxy instance is observed at intentBuilder time and at handler time.
2. **No in-process mutation between intentBuilder and handler.** The Proxy records any property write, delete, or defineProperty. On the shipped `wrap()` path, no such operation is recorded between intentBuilder return and handler invocation.
3. **Composition hazard — custom intentBuilder subset view.** When a custom `intentBuilder` projects only a subset of fields into the Intent payload, the handler still receives the full args; the Intent payload is a subset view. This is a design finding: a future receipt format carrying an operation hash derived from Intent-payload fields alone would not cover args the handler reads.
4. **Detection pattern.** A Proxy-wrapped args, when passed through a hostile middleware above `wrap()` that mutates a tracked field, surfaces the mutation on the Proxy's trap record. This is a diagnostic technique, not a protocol guarantee; it demonstrates that composition hazards above `wrap()` are observable at the handler.

### Design implication for future receipt-format work

An operation hash intended to bind the receipt to the exact arguments the handler receives should cover a canonicalization of the **effective arguments** the handler consumes, not derived Intent-payload fields. The current `wrap()` path makes this feasible: reference identity holds, and no in-process mutation occurs on the shipped path. Composition hazards above `wrap()` are a separate concern and require their own control.

### What this suite does NOT establish

- **Not a proof that no mutation window exists in any configuration.** The suite proves no in-process mutation on the shipped `wrap()` path with the default options. A caller that mutates `args` from outside the wrapped call after `wrap()` returns, a transform applied by a middleware above `wrap()`, or an exotic engine semantics are out of scope.
- **Not a cross-adapter claim.** Adapters that compose above `@aiyoplane/mcp-authz` (for example, over `(state) → stateUpdate` node functions rather than tool handlers with args) have a materially different composition shape; the args-digest reasoning does not transfer and each adapter needs its own analysis.
- **Not a proof that any Policy's binding requirement is well-formed.** This evidence is about adapter-level feasibility. Whether a given Policy correctly specifies which attributes of the effective operation must be bound is a Policy-authoring concern.
- **Not a shipped implementation.** A receipt format carrying an operation hash claim has not been implemented; this record supports a future design track.

---

## Cross-cutting notes

- Both suites run with no network, no RDP server, no signing material. The `rdp` collaborator is a plain-object test double; the properties under test are entirely local to `createAiyoMcpAuthz`'s control flow.
- Both suites verify behavior rather than inspect source — assertions check whether `handler_called` was recorded and in what order (ordering suite), or whether the Proxy's trap record captured a specific property operation at a specific touchpoint (args-digest suite).
- No release-blocking finding emerged from either suite at the time of this record.

### Known coverage gap

The scenarios here exercise policy rules whose only match field is `action_type`. The `action_type` value reaching the matcher comes from `toolConfig.<tool>.action.type` (static per `createAiyoMcpAuthz` configuration). These scenarios do NOT exercise `target`-based or `amount_max`/`amount_min`-based policy rules whose matcher input must come from per-call args. Target- and amount-based policy matching with per-call-dynamic args requires either a top-level `intentBuilder` override on `createAiyoMcpAuthz` or the `toolConfig.<tool>.amount` function hook; adopters using those features should write their own vectors covering them.
