// Middleware behavior tests.
//
// Uses a small fake RDP provider so the tests focus on the wrap() flow itself:
// ungated bypass, ALLOW → handler invoked with verified payload, DENY → handler
// never runs, verification failure → handler never runs, lineage close fires.
//
// Provider-specific behavior (HTTP shape, local policy evaluation) lives in
// hosted-rdp.test.js and local-rdp.test.js respectively.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac, randomUUID } from 'node:crypto';
import { createAiyoMcpAuthz } from '../src/create-middleware.js';
import {
  AiyoDenied,
  AiyoUnreachable,
  AiyoReceiptInvalid,
  AiyoConfigError,
} from '../src/errors.js';

const KEY = 'test-verification-key';

// ─── Test helpers: v1 token + fake RDP provider ─────────────────────────────

function base64urlEncode(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function signToken(payload, key = KEY) {
  const payloadPart = base64urlEncode(JSON.stringify(payload));
  const signingInput = `v1.${payloadPart}`;
  const sig = createHmac('sha256', key).update(signingInput, 'utf8').digest('hex');
  return `${signingInput}.${sig}`;
}
function futurePayload(over = {}) {
  const now = Math.floor(Date.now() / 1000);
  return { iid: 'intent-uuid', cid: 'deploy:abc12345', mid: 'merchant-uuid', iat: now, exp: now + 3600, ...over };
}

/**
 * Build a fake RDP provider whose evaluate/close/verifyReceipt behavior is
 * controlled by the passed-in options.
 */
function fakeRdp(opts = {}) {
  const {
    evaluate = async (intent) => {
      const intentId = randomUUID();
      const payload = { ...futurePayload(), iid: intentId };
      const token = signToken(payload);
      return {
        intentId,
        receipt: {
          id: randomUUID(),
          object: 'execution_receipt',
          intent_id: intentId,
          token,
          issued_at: new Date().toISOString(),
          expires_at: new Date(Date.now() + 3600_000).toISOString(),
        },
      };
    },
    close = async () => {},
    verifyReceipt = (token) => {
      // Local HMAC verify — mirrors production verifier shape.
      const parts = token.split('.');
      if (parts.length !== 3) throw new AiyoReceiptInvalid('malformed');
      const expected = createHmac('sha256', KEY).update(`${parts[0]}.${parts[1]}`, 'utf8').digest('hex');
      if (expected !== parts[2]) throw new AiyoReceiptInvalid('signature mismatch');
      return JSON.parse(Buffer.from(parts[1].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'));
    },
  } = opts;

  const calls = { evaluate: [], close: [], verifyReceipt: [] };
  return {
    calls,
    async evaluate(intent) { calls.evaluate.push(intent); return evaluate(intent); },
    async close(intentId, outcome) { calls.close.push({ intentId, outcome }); return close(intentId, outcome); },
    verifyReceipt(token) { calls.verifyReceipt.push(token); return verifyReceipt(token); },
  };
}

// ─── Config validation ─────────────────────────────────────────────────────

test('config validation — throws when required fields missing', () => {
  assert.throws(() => createAiyoMcpAuthz(), AiyoConfigError);
  assert.throws(() => createAiyoMcpAuthz({}), AiyoConfigError);
  assert.throws(
    () => createAiyoMcpAuthz({ toolConfig: {} }),
    /config\.rdp is required/
  );
  assert.throws(
    () => createAiyoMcpAuthz({ rdp: { evaluate() {} }, toolConfig: {} }),
    /missing required method/
  );
  assert.throws(
    () => createAiyoMcpAuthz({ rdp: fakeRdp() }),
    /toolConfig object is required/
  );
});

test('wrap — throws when tool is not in toolConfig', () => {
  const authz = createAiyoMcpAuthz({
    rdp: fakeRdp(),
    toolConfig: { known: { aiyo_gated: false } },
  });
  assert.throws(() => authz.wrap('unknown', async () => {}), AiyoConfigError);
});

// ─── Ungated tools bypass the RDP ───────────────────────────────────────────

test('ungated tools bypass the RDP entirely — no evaluate call', async () => {
  const rdp = fakeRdp();
  const authz = createAiyoMcpAuthz({
    rdp,
    toolConfig: { search: { aiyo_gated: false } },
  });
  const handler = authz.wrap('search', async (args) => ({ results: [args.q] }));
  const result = await handler({ q: 'hello' });
  assert.deepStrictEqual(result, { results: ['hello'] });
  assert.strictEqual(rdp.calls.evaluate.length, 0);
  assert.strictEqual(rdp.calls.close.length, 0);
});

// ─── ALLOW path ────────────────────────────────────────────────────────────

test('gated tool — ALLOW path invokes handler with verified receipt payload', async () => {
  const rdp = fakeRdp();
  const authz = createAiyoMcpAuthz({
    rdp,
    toolConfig: { deploy: { aiyo_gated: true, action: { type: 'deploy' } } },
  });

  let receivedCtx;
  const handler = authz.wrap('deploy', async (args, ctx) => {
    receivedCtx = ctx;
    return { ok: true, deployed: args.pr };
  });

  const result = await handler({ pr: 42 });
  assert.deepStrictEqual(result, { ok: true, deployed: 42 });
  assert.ok(receivedCtx.intentId, 'intentId on ctx');
  assert.strictEqual(receivedCtx.receipt.object, 'execution_receipt');
  assert.ok(receivedCtx.receiptPayload.iid, 'verified payload on ctx');
  assert.strictEqual(rdp.calls.evaluate.length, 1);
  assert.strictEqual(rdp.calls.verifyReceipt.length, 1);
});

// ─── DENY path ─────────────────────────────────────────────────────────────

test('gated tool — DENY throws AiyoDenied and handler never runs', async () => {
  const rdp = fakeRdp({
    async evaluate() {
      throw new AiyoDenied('daily budget exhausted', 'max_daily_intent_amount_cents', 'pi_x');
    },
  });
  const authz = createAiyoMcpAuthz({
    rdp,
    toolConfig: { deploy: { aiyo_gated: true, action: { type: 'deploy' } } },
  });

  let handlerCalled = false;
  const handler = authz.wrap('deploy', async () => { handlerCalled = true; });

  await assert.rejects(
    handler({ pr: 42 }),
    (err) => {
      assert.ok(err instanceof AiyoDenied);
      assert.strictEqual(err.reason, 'daily budget exhausted');
      assert.strictEqual(err.field, 'max_daily_intent_amount_cents');
      assert.strictEqual(err.intentId, 'pi_x');
      return true;
    }
  );
  assert.strictEqual(handlerCalled, false);
});

// ─── Receipt verification failure ──────────────────────────────────────────

test('gated tool — verification failure throws AiyoReceiptInvalid and handler never runs', async () => {
  const rdp = fakeRdp({
    verifyReceipt() { throw new AiyoReceiptInvalid('signature does not match'); },
  });
  const authz = createAiyoMcpAuthz({
    rdp,
    toolConfig: { deploy: { aiyo_gated: true, action: { type: 'deploy' } } },
  });

  let handlerCalled = false;
  const handler = authz.wrap('deploy', async () => { handlerCalled = true; });

  await assert.rejects(handler({}), AiyoReceiptInvalid);
  assert.strictEqual(handlerCalled, false);
});

// ─── evaluate() throwing a non-AiyoDenied error → AiyoUnreachable ──────────

test('gated tool — evaluate() throwing a generic error is wrapped in AiyoUnreachable', async () => {
  const rdp = fakeRdp({
    async evaluate() { throw new Error('ECONNREFUSED'); },
  });
  const authz = createAiyoMcpAuthz({
    rdp,
    toolConfig: { deploy: { aiyo_gated: true, action: { type: 'deploy' } } },
    logger: { info() {}, error() {} },
  });

  const handler = authz.wrap('deploy', async () => ({ ok: true }));
  await assert.rejects(handler({}), AiyoUnreachable);
});

// ─── evaluate returning malformed result ───────────────────────────────────

test('gated tool — evaluate() returning a bad shape throws AiyoUnreachable', async () => {
  const rdp = fakeRdp({
    async evaluate() { return { intentId: 'x' /* missing receipt */ }; },
  });
  const authz = createAiyoMcpAuthz({
    rdp,
    toolConfig: { deploy: { aiyo_gated: true, action: { type: 'deploy' } } },
  });
  const handler = authz.wrap('deploy', async () => ({ ok: true }));
  await assert.rejects(handler({}), AiyoUnreachable);
});

// ─── verifyReceiptOnAllow: false skips verification ────────────────────────

test('verifyReceiptOnAllow: false skips receipt verification (opt-out)', async () => {
  const rdp = fakeRdp({
    verifyReceipt() { throw new Error('should not be called'); },
  });
  const authz = createAiyoMcpAuthz({
    rdp,
    toolConfig: { deploy: { aiyo_gated: true, action: { type: 'deploy' } } },
    verifyReceiptOnAllow: false,
  });
  const handler = authz.wrap('deploy', async () => ({ ok: true }));
  const result = await handler({});
  assert.deepStrictEqual(result, { ok: true });
});

// ─── Attribution flows into intent ─────────────────────────────────────────

test('attribution flows into the intent payload passed to evaluate', async () => {
  const rdp = fakeRdp();
  const authz = createAiyoMcpAuthz({
    rdp,
    toolConfig: { deploy: { aiyo_gated: true, action: { type: 'deploy' } } },
  });
  const handler = authz.wrap('deploy', async () => ({ ok: true }));
  await handler({}, { attribution: { workflow_id: 'wf', agent_id: 'ag' } });

  const intent = rdp.calls.evaluate[0];
  assert.deepStrictEqual(intent.attribution, { workflow_id: 'wf', agent_id: 'ag' });
});

// ─── Lineage close ─────────────────────────────────────────────────────────

test('lineage close fires with ok:true after successful handler', async () => {
  const rdp = fakeRdp();
  const authz = createAiyoMcpAuthz({
    rdp,
    toolConfig: { deploy: { aiyo_gated: true, action: { type: 'deploy' } } },
  });
  const handler = authz.wrap('deploy', async () => ({ ok: true }));
  await handler({});
  await new Promise((r) => setTimeout(r, 10));
  assert.strictEqual(rdp.calls.close.length, 1);
  assert.strictEqual(rdp.calls.close[0].outcome.ok, true);
});

test('lineage close fires with ok:false + error message when handler throws', async () => {
  const rdp = fakeRdp();
  const authz = createAiyoMcpAuthz({
    rdp,
    toolConfig: { deploy: { aiyo_gated: true, action: { type: 'deploy' } } },
  });
  const handler = authz.wrap('deploy', async () => {
    throw new Error('deploy blew up at pod 3');
  });
  await assert.rejects(handler({}));
  await new Promise((r) => setTimeout(r, 10));
  assert.strictEqual(rdp.calls.close.length, 1);
  assert.strictEqual(rdp.calls.close[0].outcome.ok, false);
  assert.match(rdp.calls.close[0].outcome.error, /pod 3/);
});

test('lineage close failure does not surface to the caller (fire-and-forget)', async () => {
  const rdp = fakeRdp({
    async close() { throw new Error('close network error'); },
  });
  const authz = createAiyoMcpAuthz({
    rdp,
    toolConfig: { deploy: { aiyo_gated: true, action: { type: 'deploy' } } },
    logger: { info() {}, error() {} },
  });
  const handler = authz.wrap('deploy', async () => ({ ok: true }));
  const result = await handler({});
  assert.deepStrictEqual(result, { ok: true });
  await new Promise((r) => setTimeout(r, 10));
});

// ─── Custom intent-builder ─────────────────────────────────────────────────

test('custom intentBuilder is invoked and its output flows to evaluate', async () => {
  const rdp = fakeRdp();
  const authz = createAiyoMcpAuthz({
    rdp,
    toolConfig: { deploy: { aiyo_gated: true, action: { type: 'deploy' } } },
    intentBuilder: (toolName) => ({ custom: true, tool: toolName, amount: 0, action: { type: 'deploy' } }),
  });
  const handler = authz.wrap('deploy', async () => ({ ok: true }));
  await handler({});
  assert.deepStrictEqual(rdp.calls.evaluate[0], {
    custom: true, tool: 'deploy', amount: 0, action: { type: 'deploy' },
  });
});
