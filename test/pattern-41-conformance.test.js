// Pattern 41 (Enforcement Before Irreversibility) — @aiyoplane/mcp-authz conformance.
//
// Invokes the AEAP Pattern 41 adapter-contract harness against the real
// production createAiyoMcpAuthz code path. Six invariants: Positive, BLOCK,
// ESCALATE, Unavailable RDP, Timeout, Retry. Plus mcp-authz-specific bypass
// tests at the end.
//
// Harness source: `./pattern-41-adapter-contract.js` (reusable across
// adapters; a future release may factor this into a shared
// `@aiyoplane/aeap-conformance-tests` package).
//
// Behavioral conformance against the real @aiyoplane/mcp-authz source.
// All six invariants pass natively as of 1.1.0 (the earlier ESCALATE and
// Timeout cases were previously unmet; see CHANGELOG for the native
// AiyoEscalation + authorizationTimeoutMs additions).
//
// Run:
//   node --test test/pattern-41-conformance.test.js

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  runPattern41Conformance,
  allowingRdp,
  blockingRdp,
} from './pattern-41-adapter-contract.js';
import { createAiyoMcpAuthz } from '../src/index.js';
import { AiyoDenied } from '../src/errors.js';

// ─── Adapter factory ─────────────────────────────────────────────────────
//
// The harness calls `adapterFactory({ rdp, authorizationTimeoutMs? })` and
// expects back something with a `wrap(toolName, handler)` method. Build
// one around the real createAiyoMcpAuthz, passing the test's rdp through.
//
// Error-shape mapping as of @aiyoplane/mcp-authz 1.1.0:
//
//   - mcp-authz throws AiyoDenied on BLOCK. Harness assertion
//     `err.code === 'BLOCK' || err.verdict === 'BLOCK' || err.name === 'AiyoDenied'`
//     is satisfied by AiyoDenied (name) and also by the wire-format
//     translation path (code).
//   - mcp-authz throws AiyoEscalation on ESCALATE. Harness assertion
//     `err.code === 'ESCALATE' || err.verdict === 'ESCALATE'` is satisfied
//     by AiyoEscalation.code === 'ESCALATE'.
//   - mcp-authz bounds rdp.evaluate() natively via authorizationTimeoutMs.
//     The harness's Timeout test exercises the native path directly; no
//     harness-side guard is needed.
//   - mcp-authz throws AiyoUnreachable on evaluate failure outside the
//     Policy ternary (BLOCK / ALLOW / ESCALATE). The harness Unavailable
//     RDP test expects some error; any throw passes.

function mcpAuthzAdapterFactory({ rdp, authorizationTimeoutMs }) {
  const authz = createAiyoMcpAuthz({
    rdp,
    toolConfig: {
      demo_tool: {
        aiyo_gated: true,
        action: { type: 'demo_action' },
      },
      ungated_tool: {
        aiyo_gated: false,
      },
    },
    // Default verifyReceiptOnAllow is true; the harness's `allowingRdp`
    // mock returns a verifyReceipt that resolves with a bare object.
    verifyReceiptOnAllow: false,  // skip local verification against the mock
                                   // receipt token; the mock doesn't produce a
                                   // real signed token.
    // Pass the harness-requested timeout through to the middleware's native
    // handling. In 1.0.0 this option was ignored and the harness had to
    // wrap rdp.evaluate itself to simulate the timeout; in 1.1.0 mcp-authz
    // implements the timeout natively.
    authorizationTimeoutMs: authorizationTimeoutMs || 0,
  });

  return {
    wrap(toolName, handler) {
      return authz.wrap(toolName, handler);
    },
  };
}

// ─── Run the six-invariant harness ──────────────────────────────────────
//
// Expected outcomes against @aiyoplane/mcp-authz 1.1.0 (all six pass):
//   - Positive, BLOCK, ESCALATE, Unavailable RDP, Timeout, Retry → pass
//
// 1.0.0 note: ESCALATE and Timeout were known gaps against the harness —
// ESCALATE was missing a typed error class and the middleware had no native
// timeout. Both are closed in 1.1.0; see src/errors.js (AiyoEscalation) and
// src/create-middleware.js (evaluateWithTimeout).

runPattern41Conformance({
  name: 'aiyoplane-mcp-authz',
  adapterFactory: mcpAuthzAdapterFactory,
});

// ─── mcp-authz-specific bypass tests ────────────────────────────────────
//
// The generic harness covers that the inner handler never runs on
// BLOCK/ESCALATE/Unavailable/Timeout. These additional tests cover
// mcp-authz-specific code paths that could in principle let a gated tool
// run without the RDP.

describe('[aiyoplane-mcp-authz] Pattern 41 bypass tests', () => {

  test('Ungated tools bypass the RDP entirely — the explicit opt-out path', async () => {
    // Design intent: tools with aiyo_gated: false run exactly like
    // un-wrapped handlers. This is the "explicit opt-out" semantics the
    // package documents. The test confirms the bypass is explicit (keyed
    // on aiyo_gated: false) rather than implicit (keyed on absence of
    // config).
    let inner_called = false;
    const adapter = mcpAuthzAdapterFactory({ rdp: blockingRdp() });
    const wrapped = adapter.wrap('ungated_tool', async () => {
      inner_called = true;
      return 'ran';
    });
    const result = await wrapped({});
    assert.equal(inner_called, true, 'ungated_tool runs without consulting the RDP');
    assert.equal(result, 'ran');
    // The explicit meaning: this is NOT a Pattern 41 violation. aiyo_gated:
    // false is a declaration that the tool is NOT a consequential action
    // requiring authorization. If the integrator misclassifies a
    // consequential tool as ungated, the fault is in the integrator's
    // toolConfig, not in the authorization boundary.
  });

  test('Missing from toolConfig is a hard refusal, not a silent bypass', async () => {
    // Design intent: wrap() refuses to wrap a tool that isn't in toolConfig.
    // This is the "no silent default" discipline — an un-declared tool
    // doesn't accidentally become ungated.
    const authz = createAiyoMcpAuthz({
      rdp: allowingRdp(),
      toolConfig: {},
      verifyReceiptOnAllow: false,
    });
    assert.throws(
      () => authz.wrap('undeclared_tool', async () => 'never'),
      (err) => /not found in toolConfig/.test(err.message),
      'wrap() must throw if the tool is not declared'
    );
  });

  test('verifyReceiptOnAllow=false is a conscious opt-out, not a default', async () => {
    // Design intent: default is verifyReceiptOnAllow=true. The receipt is
    // locally re-verified against the RDP's signing key after ALLOW. This
    // test confirms the default is on; the harness turned it off only
    // because the mock RDP produces a trivial token.
    const authz = createAiyoMcpAuthz({
      rdp: {
        async evaluate() {
          return {
            intentId: 'test-intent',
            receipt: { token: 'invalid-token-will-fail-verify' },
          };
        },
        async close() {},
        async verifyReceipt(_token) {
          throw new Error('deliberate verify failure');
        },
      },
      toolConfig: { demo_tool: { aiyo_gated: true, action: { type: 'demo' } } },
      // verifyReceiptOnAllow omitted → default true
    });
    let inner_called = false;
    const wrapped = authz.wrap('demo_tool', async () => { inner_called = true; return 'ran'; });
    await assert.rejects(
      () => wrapped({}),
      'verify failure must prevent handler invocation'
    );
    assert.equal(inner_called, false,
      'handler must not run when receipt verification throws (fail closed)');
  });

  test('AiyoUnreachable is the fail-closed shape for non-AiyoDenied evaluate errors', async () => {
    // The harness Unavailable RDP test asserts "something throws." This
    // test tightens the assertion for the mcp-authz surface specifically:
    // non-DENY errors become AiyoUnreachable, which is a stable error
    // class the integrator can catch and classify.
    const authz = createAiyoMcpAuthz({
      rdp: {
        async evaluate() {
          const err = new Error('network partition');
          err.code = 'UNAVAILABLE';
          throw err;
        },
        async close() {},
        async verifyReceipt() { throw new Error('n/a'); },
      },
      toolConfig: { demo_tool: { aiyo_gated: true, action: { type: 'demo' } } },
      verifyReceiptOnAllow: false,
    });
    let inner_called = false;
    const wrapped = authz.wrap('demo_tool', async () => { inner_called = true; return 'ran'; });
    try {
      await wrapped({});
      assert.fail('wrapped handler must throw on RDP unavailable');
    } catch (err) {
      // mcp-authz specifically throws AiyoUnreachable; check the class.
      assert.ok(err instanceof Error, 'any Error subclass is acceptable');
      // The tighter mcp-authz-specific assertion:
      assert.ok(
        err.constructor.name === 'AiyoUnreachable' || err.message.includes('RDP'),
        `expected AiyoUnreachable-shaped error, got ${err.constructor.name}: ${err.message}`
      );
    }
    assert.equal(inner_called, false, 'handler must not run on fail-closed path');
  });

  test('AiyoDenied from the RDP propagates without being wrapped as AiyoUnreachable', async () => {
    // Design intent: AiyoDenied (DENY from the RDP) is a FIRST-CLASS
    // outcome, not an error that fails closed. It propagates to the
    // caller with its own type. The handler never runs — same observable
    // result as fail-closed, different error class.
    const authz = createAiyoMcpAuthz({
      rdp: {
        async evaluate() {
          throw new AiyoDenied('policy denied', 'rule-1', 'intent-123');
        },
        async close() {},
        async verifyReceipt() { throw new Error('n/a'); },
      },
      toolConfig: { demo_tool: { aiyo_gated: true, action: { type: 'demo' } } },
      verifyReceiptOnAllow: false,
    });
    let inner_called = false;
    const wrapped = authz.wrap('demo_tool', async () => { inner_called = true; return 'ran'; });
    await assert.rejects(
      () => wrapped({}),
      (err) => err instanceof AiyoDenied,
      'AiyoDenied must propagate as-is, not become AiyoUnreachable'
    );
    assert.equal(inner_called, false);
  });

});

// ─── Conformance findings ────────────────────────────────────────────────
//
// Based on the above tests, the Pattern 41 conformance report for
// @aiyoplane/mcp-authz as of 2026-10-19:
//
//   Positive path                   : PASS (via generic harness)
//   BLOCK                           : PASS (via generic harness + bypass test)
//   ESCALATE                        : FAIL — mcp-authz does not surface
//                                     ESCALATE as a distinct verdict in its
//                                     thrown error contract. AiyoDenied is
//                                     the only "non-ALLOW" error.
//                                     Resolving requires either (a) adding
//                                     a distinct AiyoEscalation error class
//                                     to src/errors.js and surfacing it when
//                                     evaluate() returns a decision with
//                                     effect === 'escalate', or (b) explicit
//                                     documentation that mcp-authz is a two-
//                                     verdict adapter and the AEAP spec's
//                                     ternary verdict is a cross-adapter
//                                     generalization not implemented here.
//   Unavailable RDP                 : PASS (via generic harness + bypass test)
//   Timeout                         : CONDITIONAL PASS — the harness-side
//                                     timeout wrapper makes the generic test
//                                     pass; mcp-authz itself does not
//                                     implement adapter-side timeout. Fix
//                                     would be an authorizationTimeoutMs
//                                     config option on createAiyoMcpAuthz.
//   Retry                           : PASS (via generic harness)
//   Ungated bypass is explicit      : PASS
//   Undeclared tool is a hard throw : PASS
//   verifyReceiptOnAllow default on : PASS
//   AiyoDenied vs AiyoUnreachable   : PASS
//
// Overall: 7/9 pass, 1 conditional pass, 1 fail. Two findings for the
// next mcp-authz release:
//
//   1. Add AiyoEscalation error class and ESCALATE verdict handling.
//   2. Add authorizationTimeoutMs config option and bound evaluate() in
//      the wrap flow.
//
// These are both backward-compatible additions. Deferring neither; both
// should land before AEAP Appendix A promotion of the Pattern 41 invariant.
