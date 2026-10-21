// AiyoEscalation + authorizationTimeoutMs — behavioral tests.
//
// Exercises the two capabilities added in @aiyoplane/mcp-authz 1.1.0 against
// the real shipped source (no mocks of the module under test):
//
//   - AiyoEscalation is a first-class error class on ESCALATE verdicts;
//     downstream Composition Boundary Adapters can use instanceof instead
//     of the brittle `/escalat/i` message string matching that preceded this.
//   - authorizationTimeoutMs bounds rdp.evaluate() natively; a hung RDP no
//     longer hangs the gated handler. Fail-closed per AEAP §2.2 invariant 5.
//
// Run:  node --test test/escalation-and-timeout.test.js

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { createAiyoMcpAuthz, createLocalRdp, AiyoEscalation, AiyoDenied } from '../src/index.js';
import { _internals } from '../src/create-middleware.js';

// ─── Section A — AiyoEscalation ──────────────────────────────────────────────

test('[escalation] createLocalRdp with policy effect=escalate throws AiyoEscalation', async () => {
  const rdp = createLocalRdp({
    policy: {
      default_effect: 'deny',
      rules: [
        {
          id: 'escalate-over-100',
          match: { action_type: 'demo_action' },
          amount_min: 100,
          effect: 'escalate',
          reason: 'amount >= 100 requires human approval',
          escalation_id: 'approve-workflow-v1',
        },
      ],
    },
  });

  const authz = createAiyoMcpAuthz({
    rdp,
    toolConfig: {
      demo_tool: {
        aiyo_gated: true,
        action: { type: 'demo_action' },
        // The default intentBuilder reads toolDef.amount; declare it as a
        // function of args so this test's { amount: 500 } flows through.
        amount: (args) => args.amount,
      },
    },
    verifyReceiptOnAllow: false,
  });

  let handler_called = false;
  const wrapped = authz.wrap('demo_tool', async () => {
    handler_called = true;
    return 'ran';
  });

  await assert.rejects(
    () => wrapped({ amount: 500 }),
    (err) => {
      // Primary contract: downstream adapters should use instanceof.
      assert.ok(err instanceof AiyoEscalation, 'err must be an AiyoEscalation');
      // Secondary contract: name + code for cross-language parity.
      assert.equal(err.name, 'AiyoEscalation');
      assert.equal(err.code, 'ESCALATE');
      // Correlation fields.
      assert.equal(err.rule_id, 'escalate-over-100');
      assert.equal(err.escalationId, 'approve-workflow-v1');
      assert.ok(typeof err.intentId === 'string' && err.intentId.length > 0);
      // Backward-compat: existing /escalat/i downstream detection still works
      // because the message begins with "ESCALATE:".
      assert.match(err.message, /escalat/i);
      return true;
    },
    'wrapped handler must reject with AiyoEscalation'
  );

  assert.equal(handler_called, false,
    'INVARIANT: handler must not run on ESCALATE (AEAP §6.2 Composition Boundary must hold).');
});

test('[escalation] AiyoEscalation is distinct from AiyoDenied', async () => {
  const rdp = createLocalRdp({
    policy: {
      default_effect: 'deny',
      rules: [{ id: 'escalate-all', match: { action_type: 'x' }, effect: 'escalate' }],
    },
  });

  const authz = createAiyoMcpAuthz({
    rdp,
    toolConfig: { tool: { aiyo_gated: true, action: { type: 'x' } } },
    verifyReceiptOnAllow: false,
  });

  const wrapped = authz.wrap('tool', async () => 'should-not-run');

  await assert.rejects(() => wrapped({}), (err) => {
    assert.ok(err instanceof AiyoEscalation, 'must be AiyoEscalation');
    assert.ok(!(err instanceof AiyoDenied),
      'INVARIANT: AiyoEscalation and AiyoDenied are distinct error classes. ' +
      'Downstream adapters that catch AiyoDenied must not accidentally catch ESCALATE.');
    return true;
  });
});

test('[escalation] default_effect=escalate escalates when no rule matches', async () => {
  // `escalate` is one of the three canonical AEAP verdicts (§6). A Policy
  // that explicitly declares default_effect: 'escalate' is a legitimate
  // workflow choice — "sandbox mode" / "new-tenant onboarding" / "maximum-
  // caution rollout" — where every unmatched intent routes to human
  // approval rather than fail closed. This test asserts that behavior.
  //
  // Related test below (`unknown rule effect collapses to deny`) asserts the
  // boundary: a non-canonical effect value is NOT honored; it fails closed.
  const rdp = createLocalRdp({
    policy: {
      default_effect: 'escalate',
      rules: [], // no rules; everything falls through to default
    },
  });

  const authz = createAiyoMcpAuthz({
    rdp,
    toolConfig: { tool: { aiyo_gated: true, action: { type: 'anything' } } },
    verifyReceiptOnAllow: false,
  });

  const wrapped = authz.wrap('tool', async () => 'should-not-run');

  await assert.rejects(() => wrapped({}), (err) => {
    assert.ok(err instanceof AiyoEscalation,
      'INVARIANT: default_effect=escalate must escalate on no-rule-match. ' +
      'All three canonical AEAP verdicts (allow/escalate/deny) are permitted ' +
      'as default_effect values.');
    return true;
  });
});

test('[escalation] unknown rule effect collapses to deny (fail-closed)', async () => {
  // A rule effect that is not one of allow/escalate/deny collapses to deny.
  const rdp = createLocalRdp({
    policy: {
      default_effect: 'deny',
      rules: [{ id: 'malformed', match: { action_type: 'y' }, effect: 'maybe' }],
    },
  });

  const authz = createAiyoMcpAuthz({
    rdp,
    toolConfig: { tool: { aiyo_gated: true, action: { type: 'y' } } },
    verifyReceiptOnAllow: false,
  });

  const wrapped = authz.wrap('tool', async () => 'should-not-run');

  await assert.rejects(() => wrapped({}), (err) => {
    assert.ok(err instanceof AiyoDenied,
      'INVARIANT: unknown rule.effect must fail-closed to deny, not escalate.');
    return true;
  });
});

// ─── Section B — authorizationTimeoutMs ──────────────────────────────────────

test('[timeout] rdp.evaluate exceeding authorizationTimeoutMs rejects with code=TIMEOUT; handler never runs', async () => {
  let handler_called = false;

  const rdp = {
    async evaluate(_intent) {
      // Hang for longer than the configured timeout. The timeout timer uses
      // unref() so this does not keep the test process alive.
      await new Promise((r) => setTimeout(r, 5000));
      // If the timeout works, the test completes before this returns.
      return {
        intentId: 'unreachable',
        receipt: { token: 'should-never-be-used' },
      };
    },
    async close() {},
    async verifyReceipt() { return {}; },
  };

  const authz = createAiyoMcpAuthz({
    rdp,
    toolConfig: { tool: { aiyo_gated: true, action: { type: 'demo' } } },
    verifyReceiptOnAllow: false,
    authorizationTimeoutMs: 50,
  });

  const wrapped = authz.wrap('tool', async () => {
    handler_called = true;
    return 'ran';
  });

  const t0 = process.hrtime.bigint();
  await assert.rejects(() => wrapped({}), (err) => {
    assert.equal(err.name, 'AiyoUnreachable');
    assert.equal(err.code, 'TIMEOUT');
    assert.match(err.message, /authorizationTimeoutMs=50/);
    return true;
  });
  const elapsedMs = Number(process.hrtime.bigint() - t0) / 1e6;

  assert.ok(elapsedMs < 500,
    `INVARIANT: timeout must fire promptly. Observed elapsed=${elapsedMs.toFixed(1)}ms, expected < 500ms.`);

  assert.equal(handler_called, false,
    'INVARIANT: handler must not run on authorization timeout (fail-closed, AEAP §2.2 invariant 5).');
});

test('[timeout] authorizationTimeoutMs=0 (or omitted) applies no timeout', async () => {
  let evaluate_calls = 0;
  const rdp = {
    async evaluate(_intent) {
      evaluate_calls += 1;
      // Deliberate short delay — the test asserts the delay is tolerated.
      await new Promise((r) => setTimeout(r, 30));
      return { intentId: 'ok', receipt: { token: 'v2.fake.sig' } };
    },
    async close() {},
    async verifyReceipt() { return {}; },
  };

  const authz = createAiyoMcpAuthz({
    rdp,
    toolConfig: { tool: { aiyo_gated: true, action: { type: 'demo' } } },
    verifyReceiptOnAllow: false,
    // authorizationTimeoutMs: 0 is default; be explicit to document the test.
    authorizationTimeoutMs: 0,
  });

  const wrapped = authz.wrap('tool', async () => 'ran');
  const result = await wrapped({});

  assert.equal(result, 'ran');
  assert.equal(evaluate_calls, 1);
});

test('[timeout] authorizationTimeoutMs validation — invalid values rejected at construction', () => {
  const rdp = { async evaluate() {}, async close() {}, async verifyReceipt() {} };
  const toolConfig = { tool: { aiyo_gated: true, action: { type: 'demo' } } };

  // Node's single-timer maximum. Delays greater than this are silently clamped
  // to 1ms by node:timers, which would convert a long-timeout configuration
  // into an immediate-fire bug — hence validation rejects at construction.
  const TIMEOUT_MAX = 2147483647;

  assert.throws(
    () => createAiyoMcpAuthz({ rdp, toolConfig, authorizationTimeoutMs: -5 }),
    /authorizationTimeoutMs must be a non-negative finite number/,
    'negative value must reject'
  );
  assert.throws(
    () => createAiyoMcpAuthz({ rdp, toolConfig, authorizationTimeoutMs: NaN }),
    /authorizationTimeoutMs must be a non-negative finite number/,
    'NaN must reject'
  );
  assert.throws(
    () => createAiyoMcpAuthz({ rdp, toolConfig, authorizationTimeoutMs: Infinity }),
    /authorizationTimeoutMs must be a non-negative finite number/,
    'Infinity must reject'
  );
  assert.throws(
    () => createAiyoMcpAuthz({ rdp, toolConfig, authorizationTimeoutMs: TIMEOUT_MAX + 1 }),
    /authorizationTimeoutMs must be a non-negative finite number/,
    `value above Node's TIMEOUT_MAX (${TIMEOUT_MAX}) must reject`
  );
  // Boundary value must be accepted.
  assert.doesNotThrow(
    () => createAiyoMcpAuthz({ rdp, toolConfig, authorizationTimeoutMs: TIMEOUT_MAX }),
    `boundary value TIMEOUT_MAX (${TIMEOUT_MAX}) must be accepted`
  );
});

test('[timeout] evaluate resolves before timeout — timer is cleared (deterministic)', async () => {
  // Deterministic cleanup assertion: instrument the module-level timer hook
  // so we can observe setTimeout and clearTimeout calls directly. The S2
  // version of this test relied on "process did not hang" which is NOT a
  // valid signal — with the previous .unref()'d timer, a leaked timer
  // wouldn't keep the process alive either way.
  //
  // Instrumentation strategy: swap _internals.setTimeout and clearTimeout
  // with counting wrappers that still delegate to the real timers. After
  // the wrapped() call resolves, assert that every started timer has been
  // cleared.
  const realSet = _internals.setTimeout;
  const realClear = _internals.clearTimeout;

  const started = new Set();
  const cleared = new Set();
  _internals.setTimeout = (fn, ms) => {
    const h = realSet(fn, ms);
    started.add(h);
    return h;
  };
  _internals.clearTimeout = (h) => {
    cleared.add(h);
    return realClear(h);
  };

  try {
    const rdp = {
      async evaluate() {
        await new Promise((r) => realSet(r, 10));
        return { intentId: 'ok', receipt: { token: 'v2.fake.sig' } };
      },
      async close() {},
      async verifyReceipt() { return {}; },
    };

    const authz = createAiyoMcpAuthz({
      rdp,
      toolConfig: { tool: { aiyo_gated: true, action: { type: 'demo' } } },
      verifyReceiptOnAllow: false,
      authorizationTimeoutMs: 500,
    });

    const wrapped = authz.wrap('tool', async () => 'ran');
    const result = await wrapped({});
    assert.equal(result, 'ran');

    assert.equal(started.size, 1,
      `INVARIANT: evaluateWithTimeout must schedule exactly 1 timer per gated call. Observed=${started.size}.`);
    assert.equal(cleared.size, 1,
      `INVARIANT: evaluateWithTimeout must clear exactly 1 timer per gated call. Observed=${cleared.size}.`);
    for (const h of started) {
      assert.ok(cleared.has(h),
        'INVARIANT: every scheduled timer must be cleared on the resolve path. ' +
        'A missing clearTimeout would leak a .ref()\'d timer and could delay process exit.');
    }
  } finally {
    _internals.setTimeout = realSet;
    _internals.clearTimeout = realClear;
  }
});

test('[timeout] timer is cleared on the timeout-fire path as well', async () => {
  // Companion to the previous test: cleanup on the error path. When the
  // timeout fires, Promise.race rejects with AiyoUnreachable; the finally
  // block must still call clearTimeout. (In practice this is a no-op after
  // the timer has already fired, but the clearTimeout call MUST happen —
  // see the production code's finally block.)
  const realSet = _internals.setTimeout;
  const realClear = _internals.clearTimeout;

  const started = new Set();
  const cleared = new Set();
  _internals.setTimeout = (fn, ms) => {
    const h = realSet(fn, ms);
    started.add(h);
    return h;
  };
  _internals.clearTimeout = (h) => {
    cleared.add(h);
    return realClear(h);
  };

  try {
    const rdp = {
      async evaluate() {
        await new Promise((r) => realSet(r, 1000)); // longer than timeout
        return { intentId: 'ok', receipt: { token: 'late' } };
      },
      async close() {},
      async verifyReceipt() { return {}; },
    };

    const authz = createAiyoMcpAuthz({
      rdp,
      toolConfig: { tool: { aiyo_gated: true, action: { type: 'demo' } } },
      verifyReceiptOnAllow: false,
      authorizationTimeoutMs: 25,
    });

    const wrapped = authz.wrap('tool', async () => 'should-not-run');
    await assert.rejects(() => wrapped({}), (err) => err.code === 'TIMEOUT');

    assert.equal(started.size, 1, 'exactly one timer scheduled');
    assert.equal(cleared.size, 1,
      'INVARIANT: clearTimeout must be called in the finally block even on the timeout-fire path.');
  } finally {
    _internals.setTimeout = realSet;
    _internals.clearTimeout = realClear;
  }
});

// ─── Section C — Wire-format error translation ──────────────────────────────
//
// An RDP that throws a plain Error carrying the AEAP wire-format verdict
// code is promoted to the matching typed error. If `code` and `verdict`
// are both present and disagree, the decision representation is ambiguous
// and the middleware fails closed (handler never runs) rather than silently
// picking one field. These tests pin that boundary.

const makeAuthz = (rdp) =>
  createAiyoMcpAuthz({
    rdp,
    toolConfig: { tool: { aiyo_gated: true, action: { type: 'demo' } } },
    verifyReceiptOnAllow: false,
  });

function rdpThrowingWire(err) {
  return {
    async evaluate() { throw err; },
    async close() {},
    async verifyReceipt() { throw new Error('unused'); },
  };
}

test('[wire] code=BLOCK alone → AiyoDenied; handler never runs', async () => {
  let handler_called = false;
  const err = Object.assign(new Error('policy denied'), { code: 'BLOCK' });
  const wrapped = makeAuthz(rdpThrowingWire(err)).wrap('tool', async () => { handler_called = true; });

  await assert.rejects(() => wrapped({}), (e) => {
    assert.ok(e instanceof AiyoDenied, 'must promote to AiyoDenied');
    return true;
  });
  assert.equal(handler_called, false);
});

test('[wire] verdict=BLOCK alone → AiyoDenied; handler never runs', async () => {
  let handler_called = false;
  const err = Object.assign(new Error('policy denied'), { verdict: 'BLOCK' });
  const wrapped = makeAuthz(rdpThrowingWire(err)).wrap('tool', async () => { handler_called = true; });

  await assert.rejects(() => wrapped({}), (e) => e instanceof AiyoDenied);
  assert.equal(handler_called, false);
});

test('[wire] code=BLOCK and verdict=BLOCK (agreeing) → AiyoDenied', async () => {
  let handler_called = false;
  const err = Object.assign(new Error('policy denied'), { code: 'BLOCK', verdict: 'BLOCK' });
  const wrapped = makeAuthz(rdpThrowingWire(err)).wrap('tool', async () => { handler_called = true; });

  await assert.rejects(() => wrapped({}), (e) => e instanceof AiyoDenied);
  assert.equal(handler_called, false);
});

test('[wire] code=ESCALATE alone → AiyoEscalation; handler never runs', async () => {
  let handler_called = false;
  const err = Object.assign(new Error('escalation required'), {
    code: 'ESCALATE',
    rule_id: 'rule-42',
    escalationId: 'approve-123',
  });
  const wrapped = makeAuthz(rdpThrowingWire(err)).wrap('tool', async () => { handler_called = true; });

  await assert.rejects(() => wrapped({}), (e) => {
    assert.ok(e instanceof AiyoEscalation);
    assert.equal(e.code, 'ESCALATE');
    assert.equal(e.rule_id, 'rule-42');
    assert.equal(e.escalationId, 'approve-123');
    return true;
  });
  assert.equal(handler_called, false);
});

test('[wire] contradictory code=BLOCK + verdict=ESCALATE → fail closed (AiyoUnreachable); NOT silently resolved', async () => {
  let handler_called = false;
  const err = Object.assign(new Error('contradictory'), { code: 'BLOCK', verdict: 'ESCALATE' });
  const wrapped = makeAuthz(rdpThrowingWire(err)).wrap('tool', async () => { handler_called = true; });

  await assert.rejects(() => wrapped({}), (e) => {
    assert.equal(e.name, 'AiyoUnreachable',
      'INVARIANT: ambiguous decision shape must not be silently resolved to either verdict. ' +
      'Fail-closed per AEAP §2.2 invariant 5.');
    assert.ok(!(e instanceof AiyoDenied),
      'INVARIANT: ambiguous must NOT be promoted to AiyoDenied (would silently pick code over verdict).');
    assert.ok(!(e instanceof AiyoEscalation),
      'INVARIANT: ambiguous must NOT be promoted to AiyoEscalation (would silently pick verdict over code).');
    assert.match(e.message, /code and verdict disagree/,
      'error message must name the ambiguity explicitly for diagnostic clarity');
    return true;
  });
  assert.equal(handler_called, false,
    'INVARIANT: ambiguous decision representation must NOT invoke the gated handler.');
});

test('[wire] contradictory code=ESCALATE + verdict=BLOCK → fail closed; same invariant', async () => {
  let handler_called = false;
  const err = Object.assign(new Error('contradictory other direction'), {
    code: 'ESCALATE',
    verdict: 'BLOCK',
  });
  const wrapped = makeAuthz(rdpThrowingWire(err)).wrap('tool', async () => { handler_called = true; });

  await assert.rejects(() => wrapped({}), (e) => {
    assert.equal(e.name, 'AiyoUnreachable');
    assert.ok(!(e instanceof AiyoDenied));
    assert.ok(!(e instanceof AiyoEscalation));
    return true;
  });
  assert.equal(handler_called, false);
});

test('[wire] non-verdict error (e.g. network partition) → AiyoUnreachable; handler never runs', async () => {
  // Baseline: an error that carries no verdict signal (no BLOCK/ESCALATE on
  // either code or verdict) falls to the generic AiyoUnreachable path.
  let handler_called = false;
  const err = Object.assign(new Error('ECONNRESET'), { code: 'UNAVAILABLE' });
  const wrapped = makeAuthz(rdpThrowingWire(err)).wrap('tool', async () => { handler_called = true; });

  await assert.rejects(() => wrapped({}), (e) => {
    assert.equal(e.name, 'AiyoUnreachable');
    return true;
  });
  assert.equal(handler_called, false);
});

test('[wire] translated AiyoDenied preserves reason, rule_id, intentId from the wire error', async () => {
  const err = Object.assign(new Error('policy says no'), {
    code: 'BLOCK',
    reason: 'amount > limit',
    rule_id: 'rule-limit-exceeded',
    intentId: 'intent-abc-123',
  });
  const wrapped = makeAuthz(rdpThrowingWire(err)).wrap('tool', async () => 'x');

  await assert.rejects(() => wrapped({}), (e) => {
    assert.ok(e instanceof AiyoDenied);
    assert.equal(e.reason, 'amount > limit');
    assert.equal(e.field, 'rule-limit-exceeded');  // AiyoDenied second param is stored as .field
    assert.equal(e.intentId, 'intent-abc-123');
    return true;
  });
});
