// Pattern 41 ordering invariant — release-blocking behavioral check.
//
// Verifies the shipped @aiyoplane/mcp-authz code does not permit a wrapped
// tool handler to run before the required authorization condition is
// satisfied. The property under test is observed behaviorally — assertions
// check whether the handler's recorded invocation happened and in what
// order. If any assertion in this file fails, the finding is release-
// blocking and the next release is held until the ordering violation is
// fixed.
//
// What "ordering invariant" means precisely:
//
//   For a gated tool call (toolConfig[name].aiyo_gated === true), the
//   underlying handler MUST NOT be invoked until BOTH:
//     (a) rdp.evaluate() has resolved with an ALLOW-shaped result
//         ({ intentId, receipt: { token } }); AND
//     (b) if verifyReceiptOnAllow is true (default), rdp.verifyReceipt()
//         has resolved without throwing.
//
//   Any error at (a) or (b) MUST prevent the handler from running.
//
// Six behavioral cases are tested below. Each would fail LOUDLY if the
// invariant breaks — not from source inspection, but from observing
// whether the handler's recorded invocation happened and in what order.
//
// Run:  node --test test/pattern-41-ordering-release-blocker.test.js

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { createAiyoMcpAuthz } from '../src/index.js';
import { AiyoDenied } from '../src/errors.js';

// Helper: a timestamp recorder that preserves ordering across async yields.
function recorder() {
    const events = [];
    const record = (name) => events.push({ name, t: process.hrtime.bigint() });
    const beforeAll = (otherName) => (name) => {
        const self = events.find(e => e.name === name);
        const other = events.find(e => e.name === otherName);
        if (!self || !other) return false;
        return self.t < other.t;
    };
    return { events, record };
}

// ─── Case 1 — timing ordering ──────────────────────────────────────────────
//
// The simplest ordering check: a slow rdp.evaluate must not permit the
// handler to run before it resolves. A plain Promise returned from
// evaluate must be awaited before handler fires.

test('[release-blocker] handler does not run before rdp.evaluate resolves (timing)', async () => {
    const { events, record } = recorder();

    const rdp = {
        async evaluate(_intent) {
            record('evaluate_called');
            // Simulate a slow decision — anything that forces evaluate to
            // require real await semantics. If the wrap() path is somehow
            // scheduling the handler without awaiting, this delay surfaces it.
            await new Promise(r => setTimeout(r, 50));
            record('evaluate_resolved');
            return {
                intentId: 'test-intent-1',
                receipt: { token: 'v2.fake.sig' },
                decision: { verdict: 'ALLOW' },
            };
        },
        async close() {},
        async verifyReceipt(_token) {
            record('verifyReceipt_resolved');
            return { iid: 'test-intent-1' };
        },
    };

    const authz = createAiyoMcpAuthz({
        rdp,
        toolConfig: { demo_tool: { aiyo_gated: true, action: { type: 'demo' } } },
    });

    const handler = async (_args, _ctx) => {
        record('handler_called');
        return 'ok';
    };
    const wrapped = authz.wrap('demo_tool', handler);

    const result = await wrapped({ test: true });
    record('wrapped_returned');

    // Assertions about ordering.
    const t = (name) => events.find(e => e.name === name)?.t;

    assert.ok(t('evaluate_called') !== undefined, 'evaluate must have been called');
    assert.ok(t('evaluate_resolved') !== undefined, 'evaluate must have resolved');
    assert.ok(t('handler_called') !== undefined, 'handler must have been called on ALLOW');
    assert.ok(t('evaluate_resolved') < t('handler_called'),
        'INVARIANT VIOLATION: handler ran before evaluate resolved. This is a Pattern 41 ordering failure.');
    assert.ok(t('verifyReceipt_resolved') < t('handler_called'),
        'INVARIANT VIOLATION: handler ran before verifyReceipt resolved. verifyReceiptOnAllow default is true; the receipt must verify before the handler runs.');
    assert.equal(result, 'ok');
});

// ─── Case 2 — AiyoDenied path ──────────────────────────────────────────────
//
// When evaluate rejects with AiyoDenied, the handler must never run. A
// recorder catches a stray handler invocation; the test fails if the
// recorder picked up anything.

test('[release-blocker] handler does not run when evaluate throws AiyoDenied', async () => {
    let handler_called = false;

    const rdp = {
        async evaluate(_intent) {
            throw new AiyoDenied('policy denied this call', 'rule-1', 'intent-1');
        },
        async close() {},
        async verifyReceipt() { throw new Error('unreachable'); },
    };

    const authz = createAiyoMcpAuthz({
        rdp,
        toolConfig: { demo_tool: { aiyo_gated: true, action: { type: 'demo' } } },
    });

    const wrapped = authz.wrap('demo_tool', async () => {
        handler_called = true;
        return 'ran';
    });

    await assert.rejects(
        () => wrapped({}),
        (err) => err instanceof AiyoDenied,
        'wrapped handler must reject with AiyoDenied'
    );
    assert.equal(handler_called, false,
        'INVARIANT VIOLATION: handler ran despite AiyoDenied. Pattern 41 ordering failure on the BLOCK path.');
});

// ─── Case 3 — generic throw path (fail-closed AiyoUnreachable) ─────────────
//
// Any evaluate error that is not AiyoDenied must result in AiyoUnreachable
// AND the handler must not run. Fail-closed is AEAP §2.2 invariant 5.

test('[release-blocker] handler does not run when evaluate throws a non-AiyoDenied error (fail closed)', async () => {
    let handler_called = false;

    const rdp = {
        async evaluate(_intent) {
            const err = new Error('network partition');
            err.code = 'UNAVAILABLE';
            throw err;
        },
        async close() {},
        async verifyReceipt() { throw new Error('unreachable'); },
    };

    const authz = createAiyoMcpAuthz({
        rdp,
        toolConfig: { demo_tool: { aiyo_gated: true, action: { type: 'demo' } } },
    });

    const wrapped = authz.wrap('demo_tool', async () => {
        handler_called = true;
        return 'ran';
    });

    await assert.rejects(() => wrapped({}), (_err) => true);
    assert.equal(handler_called, false,
        'INVARIANT VIOLATION: handler ran despite evaluate throwing. Fail-closed invariant breached (AEAP §2.2).');
});

// ─── Case 4 — malformed ALLOW shape ────────────────────────────────────────
//
// If evaluate resolves with a shape that is NOT { intentId, receipt: { token } },
// the handler must not run. mcp-authz's documented contract requires this
// explicit shape; a misconfigured RDP that returns something else must fail
// closed, not silently invoke the handler.

test('[release-blocker] handler does not run when evaluate resolves with malformed shape (missing intentId)', async () => {
    let handler_called = false;

    const rdp = {
        async evaluate(_intent) {
            return { receipt: { token: 'v2.fake.sig' } }; // missing intentId
        },
        async close() {},
        async verifyReceipt() { throw new Error('unreachable'); },
    };

    const authz = createAiyoMcpAuthz({
        rdp,
        toolConfig: { demo_tool: { aiyo_gated: true, action: { type: 'demo' } } },
    });

    const wrapped = authz.wrap('demo_tool', async () => {
        handler_called = true;
        return 'ran';
    });

    await assert.rejects(() => wrapped({}), (_err) => true,
        'wrapped handler must reject when ALLOW shape is malformed');
    assert.equal(handler_called, false,
        'INVARIANT VIOLATION: handler ran against a malformed evaluate result. The ALLOW contract must be strict; a missing intentId must fail closed.');
});

test('[release-blocker] handler does not run when evaluate resolves with malformed shape (missing receipt.token)', async () => {
    let handler_called = false;

    const rdp = {
        async evaluate(_intent) {
            return { intentId: 'test-intent-1', receipt: {} }; // missing token
        },
        async close() {},
        async verifyReceipt() { throw new Error('unreachable'); },
    };

    const authz = createAiyoMcpAuthz({
        rdp,
        toolConfig: { demo_tool: { aiyo_gated: true, action: { type: 'demo' } } },
    });

    const wrapped = authz.wrap('demo_tool', async () => {
        handler_called = true;
        return 'ran';
    });

    await assert.rejects(() => wrapped({}), (_err) => true,
        'wrapped handler must reject when receipt.token is missing');
    assert.equal(handler_called, false,
        'INVARIANT VIOLATION: handler ran against a malformed receipt shape.');
});

// ─── Case 5 — verifyReceipt rejects (verifyReceiptOnAllow=true default) ────
//
// The default verifyReceiptOnAllow=true runs a local verification after
// evaluate's ALLOW. If verifyReceipt throws, the handler must not run.
// This confirms the belt-and-braces check actually gates the handler.

test('[release-blocker] handler does not run when verifyReceipt throws (default verifyReceiptOnAllow=true)', async () => {
    let handler_called = false;

    const rdp = {
        async evaluate(_intent) {
            return {
                intentId: 'test-intent-1',
                receipt: { token: 'v2.fake.sig' },
            };
        },
        async close() {},
        async verifyReceipt(_token) {
            throw new Error('token signature invalid');
        },
    };

    const authz = createAiyoMcpAuthz({
        rdp,
        toolConfig: { demo_tool: { aiyo_gated: true, action: { type: 'demo' } } },
        // verifyReceiptOnAllow omitted — default is true
    });

    const wrapped = authz.wrap('demo_tool', async () => {
        handler_called = true;
        return 'ran';
    });

    await assert.rejects(() => wrapped({}), (_err) => true);
    assert.equal(handler_called, false,
        'INVARIANT VIOLATION: handler ran despite verifyReceipt throwing. The belt-and-braces check must gate the handler when enabled.');
});

// ─── Case 6 — concurrent gated calls do not share a decision ───────────────
//
// Each wrapped() invocation must independently await its own rdp.evaluate.
// A race where two concurrent calls share a cached ALLOW decision (and
// thereby one call runs its handler without its own evaluate completing)
// would be a Pattern 41 violation at the many-calls-per-second regime.

test('[release-blocker] concurrent gated calls each consult evaluate independently', async () => {
    let evaluate_calls = 0;
    const callStartTimes = new Map();

    const rdp = {
        async evaluate(intent) {
            const n = ++evaluate_calls;
            callStartTimes.set(n, process.hrtime.bigint());
            // Deliberate per-call latency so a bug that shortcuts the second
            // call to a cached decision would surface by handler running
            // before this evaluate's own promise resolves.
            await new Promise(r => setTimeout(r, 30));
            return {
                intentId: `test-intent-${n}`,
                receipt: { token: `v2.fake.sig.${n}` },
            };
        },
        async close() {},
        async verifyReceipt(_token) { return { iid: 'ok' }; },
    };

    const authz = createAiyoMcpAuthz({
        rdp,
        toolConfig: { demo_tool: { aiyo_gated: true, action: { type: 'demo' } } },
    });

    let handler_invocation_count = 0;
    const wrapped = authz.wrap('demo_tool', async () => {
        handler_invocation_count++;
        return 'ok';
    });

    // Two concurrent calls.
    const [r1, r2] = await Promise.all([wrapped({ a: 1 }), wrapped({ a: 2 })]);

    assert.equal(evaluate_calls, 2, 'each wrapped invocation must call evaluate independently');
    assert.equal(handler_invocation_count, 2, 'each wrapped invocation must call its own handler');
    assert.equal(r1, 'ok');
    assert.equal(r2, 'ok');
});
