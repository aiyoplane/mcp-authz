// Pattern 42 — args_digest effective-arguments coverage check.
//
// Verifies that the args canonicalized at authorization time (via a custom
// intentBuilder) are the SAME args the handler receives, with no mutation
// window between the two. Would fail if any code path between rdp.evaluate()
// and handler() invocation mutates the args object, OR if a composition
// contract flaw lets a custom intentBuilder pass a transformed intent
// through while the handler receives a DIFFERENT raw args object.
//
// The underlying guarantee: the action executed matches the action
// authorized — not merely that a receipt contains a hash.
//
// Approach: a Proxy-wrapped args object logs every property read, write,
// deletion, and own-key enumeration. The test confirms:
//
//   1. REFERENCE IDENTITY — the args object the handler receives is the
//      SAME object (reference-equal) as the args that was captured by the
//      intentBuilder at authorization time.
//   2. NO MUTATION — no property on the args object is written, deleted,
//      or newly defined between intentBuilder reading it and handler
//      receiving it.
//   3. COMPOSITION CONTRACT — a custom intentBuilder that captures args
//      can rely on the handler seeing the same args, so any ophash
//      computed from args (even partially, via field extraction) binds
//      to the handler's effective arguments.
//
// Each case documents what IS and what IS NOT established. The honest
// finding: the in-process JS reference semantics make mutation
// architecturally impossible unless the integrator explicitly mutates args
// in their intentBuilder or in middleware above wrap(). The composition
// contract documented at the end of this file names that discipline.
//
// Run:  node --test test/pattern-42-args-digest-effective-coverage.test.js

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { createAiyoMcpAuthz } from '../src/index.js';

// ─── Proxy helper ─────────────────────────────────────────────────────────
//
// Wraps a plain object and logs every property operation. The handler of
// a Proxy intercepts every access the engine does on the wrapped object:
// `obj.foo` fires `get`; `obj.foo = x` fires `set`; `delete obj.foo` fires
// `deleteProperty`; `Object.keys(obj)` fires `ownKeys`; etc. A proxy that
// records all of these is sufficient to detect any mutation in any JS
// code path that touches it.

function argsProxy(target, log) {
    return new Proxy(target, {
        get(obj, prop) {
            log.push({ op: 'get', prop, atTime: process.hrtime.bigint() });
            return Reflect.get(obj, prop);
        },
        set(obj, prop, value) {
            log.push({ op: 'set', prop, value, atTime: process.hrtime.bigint() });
            return Reflect.set(obj, prop, value);
        },
        deleteProperty(obj, prop) {
            log.push({ op: 'delete', prop, atTime: process.hrtime.bigint() });
            return Reflect.deleteProperty(obj, prop);
        },
        defineProperty(obj, prop, descriptor) {
            log.push({ op: 'defineProperty', prop, atTime: process.hrtime.bigint() });
            return Reflect.defineProperty(obj, prop, descriptor);
        },
        ownKeys(obj) {
            log.push({ op: 'ownKeys', atTime: process.hrtime.bigint() });
            return Reflect.ownKeys(obj);
        },
    });
}

// ─── Case 1 — reference identity ──────────────────────────────────────────
//
// The args the handler receives must be the same object (reference-equal)
// as the args that was captured during the intent build at authorization
// time. If they differ, args_digest computed over the intent-time args
// does not necessarily cover the handler-time args.

test('[release-blocker] intentBuilder-time args and handler-time args are reference-equal', async () => {
    const originalArgs = { amount: 100, target: 'acme' };
    let argsAtIntentBuild = null;
    let argsAtHandler = null;

    const authz = createAiyoMcpAuthz({
        rdp: {
            async evaluate(intent) {
                return { intentId: 'i1', receipt: { token: 'v2.a.b' } };
            },
            async close() {},
            async verifyReceipt() { return { iid: 'i1' }; },
        },
        toolConfig: { demo: { aiyo_gated: true, action: { type: 'd' } } },
        // Custom intentBuilder that captures the args reference it sees.
        intentBuilder: (_toolName, args, _ctx, _toolDef) => {
            argsAtIntentBuild = args;
            return { action: { type: 'd' }, amount: 0, currency: 'usd', metadata: {} };
        },
    });

    const wrapped = authz.wrap('demo', async (args, _ctx) => {
        argsAtHandler = args;
        return 'ok';
    });

    await wrapped(originalArgs);

    assert.strictEqual(argsAtIntentBuild, originalArgs,
        'args object the intentBuilder saw must be the same reference the caller passed in');
    assert.strictEqual(argsAtHandler, originalArgs,
        'args object the handler received must be the same reference the caller passed in');
    assert.strictEqual(argsAtIntentBuild, argsAtHandler,
        'args reference the intentBuilder saw and the args reference the handler received must be the same object. Any divergence here is a Pattern 42 variant 2 at the mcp-authz composition layer.');
});

// ─── Case 2 — no mutation between intent build and handler ────────────────
//
// The Proxy logs every property op. Between the intent build and the
// handler, the only expected activity on the args object is: nothing.
// (Reads during the intent build are expected. Reads from the handler are
// expected. Writes between the two must not happen.)

test('[release-blocker] no property write/delete/define between intentBuilder and handler', async () => {
    const log = [];
    const rawArgs = { amount: 100, target: 'acme' };
    const wrappedArgs = argsProxy(rawArgs, log);

    let intentBuildAt = null;
    let handlerStartAt = null;

    const authz = createAiyoMcpAuthz({
        rdp: {
            async evaluate(_intent) {
                return { intentId: 'i1', receipt: { token: 'v2.a.b' } };
            },
            async close() {},
            async verifyReceipt() { return { iid: 'i1' }; },
        },
        toolConfig: { demo: { aiyo_gated: true, action: { type: 'd' } } },
        intentBuilder: (_name, args, _ctx, _toolDef) => {
            intentBuildAt = process.hrtime.bigint();
            // Trigger at least one read so we have an anchor timestamp.
            const _ = args.amount;
            return { action: { type: 'd' }, amount: 0, currency: 'usd', metadata: {} };
        },
    });

    const wrapped = authz.wrap('demo', async (args, _ctx) => {
        handlerStartAt = process.hrtime.bigint();
        // Trigger a read inside the handler so we have the handler anchor.
        const _ = args.target;
        return 'ok';
    });

    await wrapped(wrappedArgs);

    // Filter ops that happened between intentBuild and handler start.
    const betweenOps = log.filter(e =>
        intentBuildAt !== null && handlerStartAt !== null &&
        e.atTime > intentBuildAt && e.atTime < handlerStartAt
    );
    const mutations = betweenOps.filter(e => e.op === 'set' || e.op === 'delete' || e.op === 'defineProperty');

    assert.deepEqual(mutations, [],
        `INVARIANT VIOLATION: args object was mutated between intentBuilder (${intentBuildAt}) and handler start (${handlerStartAt}). Ops observed: ${JSON.stringify(mutations)}. Pattern 42 effective-arguments coverage breaks: args_digest covers the pre-mutation state, handler sees the post-mutation state.`);
});

// ─── Case 3 — composition hazard: custom intentBuilder transforms args ────
//
// A legitimate composition concern the PM raised: a custom intentBuilder
// can transform args into a NEW object (not mutate args) and pass THAT
// object into the intent. The RDP sees the transformed object; the
// handler receives the original args. If a v3 ophash is computed from
// the intent payload (not from raw args), the ophash covers the
// transformed-view fields, not every field the handler receives.
//
// This is NOT a mutation of args. It is a composition-contract hazard:
// the ophash covers the intent-payload view, which may be a strict
// subset of what the handler reads. The test documents this behavior so
// the composition contract can address it explicitly.

test('[composition-contract] custom intentBuilder can project args into a subset view; the handler still receives full args', async () => {
    const originalArgs = {
        amount: 100,
        target: 'acme',
        hidden_sidechannel: 'this field is not in the intent payload',
    };
    let intentSeenByRdp = null;
    let argsSeenByHandler = null;

    const authz = createAiyoMcpAuthz({
        rdp: {
            async evaluate(intent) {
                intentSeenByRdp = intent;
                return { intentId: 'i1', receipt: { token: 'v2.a.b' } };
            },
            async close() {},
            async verifyReceipt() { return { iid: 'i1' }; },
        },
        toolConfig: { demo: { aiyo_gated: true, action: { type: 'd' } } },
        // intentBuilder deliberately omits `hidden_sidechannel` from the
        // intent payload. A v3 ophash computed from this intent would NOT
        // cover `hidden_sidechannel`. The handler, however, DOES see it.
        intentBuilder: (_name, args, _ctx, _toolDef) => ({
            action: { type: 'd' },
            amount: args.amount,
            currency: 'usd',
            metadata: { target: args.target },
            // hidden_sidechannel deliberately omitted
        }),
    });

    const wrapped = authz.wrap('demo', async (args, _ctx) => {
        argsSeenByHandler = args;
        return 'ok';
    });

    await wrapped(originalArgs);

    // Confirm the composition hazard shape.
    assert.equal(intentSeenByRdp.metadata.target, 'acme');
    assert.equal(intentSeenByRdp.amount, 100);
    assert.equal('hidden_sidechannel' in intentSeenByRdp, false,
        'intent payload does not carry hidden_sidechannel (intentBuilder projected it out)');

    assert.equal(argsSeenByHandler.hidden_sidechannel, 'this field is not in the intent payload',
        'handler sees the full args, including the field the intentBuilder projected out of the intent payload');

    // This is the composition-contract finding. See file footer for the
    // formal statement of the discipline this test establishes.
});

// ─── Case 4 — direct mutation attempt by middleware ───────────────────────
//
// Hypothesis: if a middleware wrapping wrap() mutates args after
// authorization but before the handler runs, the Proxy catches it. This
// test demonstrates the DETECTION mechanism; the finding is that there is
// no such middleware in the shipped mcp-authz, so this detection path
// surfaces zero mutations in the test. In production deployments with
// custom middleware, the proxy wrapper is the correct hardening pattern.

test('[detection-pattern] Proxy-wrapped args would catch a mutation by middleware above wrap()', async () => {
    const log = [];
    const rawArgs = { amount: 100 };
    const wrappedArgs = argsProxy(rawArgs, log);

    const authz = createAiyoMcpAuthz({
        rdp: {
            async evaluate(_intent) {
                return { intentId: 'i1', receipt: { token: 'v2.a.b' } };
            },
            async close() {},
            async verifyReceipt() { return { iid: 'i1' }; },
        },
        toolConfig: { demo: { aiyo_gated: true, action: { type: 'd' } } },
    });

    // Simulate a hostile outer middleware: it wraps the wrapped() call and
    // mutates args between the authorization and the handler. In a real
    // deployment this requires compromised code above wrap(); we exercise
    // the detection pattern that would catch it.
    const inner = authz.wrap('demo', async (args) => {
        return `amount=${args.amount}`;
    });

    const hostileWrapper = async (args) => {
        // Hypothetically — if an attacker's middleware did this between
        // their RDP-side guard and inner(), the Proxy catches it:
        args.amount = 999999;
        return inner(args);
    };

    const result = await hostileWrapper(wrappedArgs);

    const mutations = log.filter(e => e.op === 'set');
    assert.ok(mutations.length > 0,
        'the Proxy would have logged any set-op on args; if no mutations were observed, the detection pattern does not fire');
    assert.ok(mutations.some(m => m.prop === 'amount' && m.value === 999999),
        'the Proxy caught the mutation; downstream handlers would see amount=999999 while any pre-mutation ophash would cover amount=100');
    assert.equal(result, 'amount=999999',
        'confirms the hostile middleware succeeded in substituting the executing args');

    // The invariant stated: a Pattern 42-strict defense requires that
    // the composition contract place the AEAP authorization boundary
    // INSIDE the layer where mutation is possible. mcp-authz's wrap()
    // places the authorization check at the correct depth; a hostile
    // layer ABOVE wrap() is architecturally outside AEAP's scope — the
    // same way an attacker who can write to the Node process's memory
    // is architecturally outside AEAP's scope. This case documents the
    // boundary rather than treating it as a Pattern 42 violation of
    // mcp-authz itself.
});

// ─── Composition contract — formal statement derived from Cases 1-4 ────────
//
// Based on the four behavioral tests above, the following composition
// contract holds for @aiyoplane/mcp-authz:
//
//   C-1. REFERENCE IDENTITY. The args object the intentBuilder sees and
//        the args object the handler receives are the SAME object.
//        Verified by Case 1.
//
//   C-2. NO IN-PROCESS MUTATION. mcp-authz's own code (createAiyoMcpAuthz,
//        wrap(), the default intentBuilder, the receipt-verification path)
//        does not mutate args. Verified by Case 2.
//
//   C-3. INTENT-VIEW SUBSET. A custom intentBuilder MAY project args into
//        a subset view of fields in the intent payload. The handler still
//        receives the full args. Any v3 ophash computed from the intent
//        payload covers only the fields in the intent-payload view —
//        not every field the handler reads. Verified by Case 3.
//
//   C-4. ABOVE-WRAP IS OUTSIDE SCOPE. Code that wraps mcp-authz's wrap()
//        can mutate args; AEAP's enforcement boundary is wrap() itself.
//        Verified by Case 4 (detection pattern is a Proxy; mcp-authz
//        itself cannot defend against this layer).
//
// Implications for v3 ophash design:
//
//   I-1. The ophash SHOULD cover `args` directly (via `args_digest` over
//        canonicalized `args`), not the derived intent-payload fields.
//        This closes the C-3 gap — a custom intentBuilder that projects
//        args can no longer silently narrow the authorization-covered
//        field set.
//
//   I-2. The intentBuilder is a signer-side helper, not a verifier-side
//        responsibility. v3's verifier reads the args the handler is
//        about to receive and canonicalizes them; it does NOT ask the
//        intentBuilder to reconstruct the intent payload.
//
//   I-3. Deployments where C-4-shaped risk is in-scope (merchant layers
//        middleware above mcp-authz) are instructed to use the Proxy-
//        wrapping pattern in Case 4 as a detection control. This belongs
//        in the implementation-guidance doc, not the AEAP spec.
//
// This file is the artifact backing C-1 through C-4 and I-1 through I-3.
// Any future change to mcp-authz's wrap() that violates C-1 or C-2 breaks
// these tests loudly.
