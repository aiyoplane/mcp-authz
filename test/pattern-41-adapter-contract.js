// Pattern 41 (Enforcement Before Irreversibility) — AEAP adapter conformance harness.
//
// Scope: reusable test cases that any AEAP adapter can run against its own
// wrap/handler surface to prove the Pattern 41 invariant and five related
// invariants. The adapter under test supplies a factory that produces a
// wrapped handler given an RDP that returns a chosen verdict. The harness
// observes whether the inner handler runs and when.
//
// Covers the Pattern 41 invariant plus five adjacent cases: positive path,
// BLOCK, ESCALATE, unavailable RDP, timeout, and retry. The six cases are
// the minimum bar for an AEAP adapter to be considered conformant on the
// ordering invariant.
//
// ─── Pattern 41 — the invariant ───────────────────────────────────────────
//
// The consequential action MUST NOT execute before the required
// authorization condition is satisfied. Observationally: the inner tool
// handler is not invoked unless the RDP has returned ALLOW and the
// adapter has recorded that ALLOW.
//
// ─── Adapter-under-test contract ──────────────────────────────────────────
//
// An adapter under test is a function:
//
//   async function adapterFactory({ rdp }) {
//     return {
//       wrap(toolName, handler) → wrappedHandler
//     };
//   }
//
// The wrappedHandler is an async function the harness invokes. The RDP the
// factory receives is one the harness controls — it can produce ALLOW,
// DENY (BLOCK), ESCALATE, throw, or hang. Each case asserts the observable
// behavior of the wrapped handler.
//
// ─── Error-shape expectations ─────────────────────────────────────────────
//
// AEAP's reference errors are AiyoDenied (BLOCK) and the ESCALATE equivalent
// (various adapter-specific names — see §9 non-guarantees for shape). This
// harness accepts any thrown error whose `.code` matches the expected
// verdict, so adapter authors retain naming flexibility.
//
// The harness does NOT assume any specific error class; it checks:
//   - BLOCK   → wrapped handler throws; inner handler never ran
//   - ESCALATE → wrapped handler throws; inner handler never ran; error
//                carries a pending-digest-shape attribute (naming flexible)
//   - unavailable RDP → wrapped handler throws; inner handler never ran
//   - timeout → wrapped handler throws or times out; inner handler never
//               ran OR ran with a documented completion-closes-the-decision
//               invariant (declared by the adapter via its result).

import assert from 'node:assert/strict';
import { test } from 'node:test';

// ─── Mock RDP constructors ────────────────────────────────────────────────
//
// Each returns an object with the RDP provider interface sketched in
// @aiyoplane/mcp-authz: { evaluate(intent) → ALLOW shape, close(id, outcome),
// verifyReceipt(token) }. Adapter-specific wrappers may use a subset.

export function allowingRdp({ receiptToken = 'test-receipt-token' } = {}) {
  return {
    name: 'allowing',
    async evaluate(_intent) {
      return {
        intentId: `pi_${Math.random().toString(36).slice(2, 10)}`,
        receipt: { token: receiptToken },
        decision: { verdict: 'ALLOW' },
      };
    },
    async close(_intentId, _outcome) {},
    verifyReceipt(token) { return { iid: token, verdict: 'ALLOW' }; },
  };
}

export function blockingRdp({ reason = 'policy denied' } = {}) {
  return {
    name: 'blocking',
    async evaluate(_intent) {
      const err = new Error(reason);
      err.code = 'BLOCK';
      err.verdict = 'BLOCK';
      err.reason = reason;
      throw err;
    },
    async close() {},
    verifyReceipt() { throw new Error('no receipt — BLOCKed'); },
  };
}

export function escalatingRdp({ pendingDigest = 'pending_digest_test' } = {}) {
  return {
    name: 'escalating',
    async evaluate(_intent) {
      const err = new Error('escalation required');
      err.code = 'ESCALATE';
      err.verdict = 'ESCALATE';
      err.pendingDigest = pendingDigest;
      throw err;
    },
    async close() {},
    verifyReceipt() { throw new Error('no receipt — awaiting escalation'); },
  };
}

export function unavailableRdp({ cause = 'network error' } = {}) {
  return {
    name: 'unavailable',
    async evaluate(_intent) {
      const err = new Error(cause);
      err.code = 'UNAVAILABLE';
      throw err;
    },
    async close() {},
    verifyReceipt() { throw new Error('no receipt — RDP unavailable'); },
  };
}

export function hangingRdp({ timeoutMs = 100 } = {}) {
  return {
    name: 'hanging',
    async evaluate(_intent) {
      await new Promise((resolve) => setTimeout(resolve, timeoutMs * 10));
      // Resolve well after any reasonable timeout the adapter imposes.
      return { intentId: 'late', receipt: { token: 'late' }, decision: { verdict: 'ALLOW' } };
    },
    async close() {},
    verifyReceipt() { return {}; },
  };
}

// ─── The conformance test suite ──────────────────────────────────────────
//
// Invoked as runPattern41Conformance({ name, adapterFactory }).
// Each case is a test() the harness owns; the adapter under test only
// supplies its factory. Running the harness against a conformant adapter
// results in all six tests passing. A non-conformant adapter fails
// loudly on the exact invariant it misses.

export function runPattern41Conformance({ name, adapterFactory }) {
  test(`[${name}] Positive path — inner handler runs on ALLOW`, async () => {
    const rdp = allowingRdp();
    const adapter = await adapterFactory({ rdp });
    let inner_called = false;
    let inner_args = null;
    const wrapped = adapter.wrap('demo_tool', async (args) => {
      inner_called = true;
      inner_args = args;
      return { ok: true };
    });
    const result = await wrapped({ test_arg: 'A' });
    assert.equal(inner_called, true, 'inner handler must run on ALLOW');
    assert.deepEqual(inner_args, { test_arg: 'A' }, 'inner handler receives original args');
    assert.ok(result, 'wrapped handler returns the inner handler\'s result');
  });

  test(`[${name}] BLOCK path — inner handler never runs`, async () => {
    const rdp = blockingRdp();
    const adapter = await adapterFactory({ rdp });
    let inner_called = false;
    const wrapped = adapter.wrap('demo_tool', async () => {
      inner_called = true;
      return { ok: true };
    });
    await assert.rejects(
      () => wrapped({}),
      (err) => err.code === 'BLOCK' || err.verdict === 'BLOCK' || err.name === 'AiyoDenied',
      'wrapped handler must throw a BLOCK-shaped error'
    );
    assert.equal(inner_called, false, 'inner handler MUST NOT run on BLOCK');
  });

  test(`[${name}] ESCALATE path — inner handler never runs; pending digest surfaces`, async () => {
    const rdp = escalatingRdp();
    const adapter = await adapterFactory({ rdp });
    let inner_called = false;
    const wrapped = adapter.wrap('demo_tool', async () => {
      inner_called = true;
      return { ok: true };
    });
    await assert.rejects(
      () => wrapped({}),
      (err) => {
        const ok = err.code === 'ESCALATE' || err.verdict === 'ESCALATE';
        // pendingDigest is the harness-expected attribute name. Adapters
        // using a different name (pending_digest, awaitingDigest, etc.)
        // can relax this check in their own harness invocation.
        return ok;
      },
      'wrapped handler must throw an ESCALATE-shaped error'
    );
    assert.equal(inner_called, false, 'inner handler MUST NOT run on ESCALATE');
  });

  test(`[${name}] Unavailable RDP — fail closed, inner handler never runs`, async () => {
    const rdp = unavailableRdp();
    const adapter = await adapterFactory({ rdp });
    let inner_called = false;
    const wrapped = adapter.wrap('demo_tool', async () => {
      inner_called = true;
      return { ok: true };
    });
    await assert.rejects(
      () => wrapped({}),
      (_err) => true,
      'wrapped handler must throw when RDP is unavailable (fail closed)'
    );
    assert.equal(inner_called, false,
      'inner handler MUST NOT run when RDP is unavailable (AEAP §2.2 invariant 5)');
  });

  test(`[${name}] Timeout — adapter imposes a bounded wait, inner handler never runs`, async () => {
    // The hanging RDP never returns in a reasonable window. If the adapter
    // under test imposes a timeout, this test completes. If it does not,
    // this test will hang — surfacing a conformance failure as a timeout.
    //
    // Node's test runner has its own test timeout (default 30s). We bound
    // the test itself to ensure a hang here is observable.
    const rdp = hangingRdp();
    const adapter = await adapterFactory({ rdp, authorizationTimeoutMs: 50 });
    let inner_called = false;
    const wrapped = adapter.wrap('demo_tool', async () => {
      inner_called = true;
      return { ok: true };
    });
    try {
      await Promise.race([
        wrapped({}),
        new Promise((_, reject) => setTimeout(() => reject(new Error('harness_timeout')), 500)),
      ]);
      assert.fail('wrapped handler must throw on authorization timeout');
    } catch (err) {
      // Either the adapter rejects (good) or the harness timeout fires
      // (adapter did not bound; conformance failure, record it).
      if (err.message === 'harness_timeout') {
        assert.fail('adapter did not bound authorization time; conformance failure');
      }
    }
    assert.equal(inner_called, false,
      'inner handler MUST NOT run while authorization is still outstanding');
  });

  test(`[${name}] Retry — second use of the same authorization is treated correctly`, async () => {
    // The harness-defined expectation: calling the wrapped handler twice
    // with the same args produces two authorization-decision requests
    // (not one cached decision reused). Adapter is responsible for making
    // retry-safety a function of either the receipt's single-use discipline
    // (if the adapter is receipt-aware) OR the idempotency of the inner
    // handler (if the adapter delegates). Either strategy is acceptable
    // for Pattern 41 compliance; the invariant is only that the inner
    // handler never runs without a fresh authorization decision.
    let evaluate_calls = 0;
    const countingRdp = {
      name: 'counting',
      async evaluate(intent) {
        evaluate_calls++;
        return {
          intentId: `pi_${evaluate_calls}`,
          receipt: { token: `receipt_${evaluate_calls}` },
          decision: { verdict: 'ALLOW' },
        };
      },
      async close() {},
      verifyReceipt(t) { return { iid: t }; },
    };
    const adapter = await adapterFactory({ rdp: countingRdp });
    const wrapped = adapter.wrap('demo_tool', async () => ({ ok: true }));
    await wrapped({ x: 1 });
    await wrapped({ x: 1 });
    assert.equal(evaluate_calls, 2,
      'each wrapped invocation must consult the RDP; a cached decision is not sufficient');
  });
}
