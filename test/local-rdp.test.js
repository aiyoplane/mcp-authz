// Local RDP tests — the in-process demo RDP.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createLocalRdp } from '../src/local-rdp.js';
import { AiyoDenied, AiyoConfigError, AiyoReceiptInvalid } from '../src/errors.js';

const DEMO_POLICY = {
  merchant_id: 'demo-merchant',
  default_effect: 'deny',
  rules: [
    { id: 'allow-deploy-staging', match: { action_type: 'deploy', target: 'staging' }, effect: 'allow' },
    { id: 'deny-deploy-production', match: { action_type: 'deploy', target: 'production' }, effect: 'deny', reason: 'prod deploy denied' },
    { id: 'allow-small-payment', match: { action_type: 'payment' }, amount_max: 5000, effect: 'allow' },
    { id: 'deny-large-payment', match: { action_type: 'payment' }, amount_min: 5001, effect: 'deny', reason: 'above threshold' },
  ],
};

test('createLocalRdp requires a policy object', () => {
  assert.throws(() => createLocalRdp({}), AiyoConfigError);
});

test('createLocalRdp allows a permitted intent and returns a valid receipt', async () => {
  const rdp = createLocalRdp({ policy: DEMO_POLICY });
  const { intentId, receipt } = await rdp.evaluate({
    amount: 0,
    currency: 'usd',
    action: { type: 'deploy', target: 'staging' },
  });
  assert.ok(intentId, 'intentId present');
  assert.ok(receipt.token.startsWith('v1.'), 'v1 compact token');
  const parts = receipt.token.split('.');
  assert.strictEqual(parts.length, 3);

  const payload = rdp.verifyReceipt(receipt.token);
  assert.strictEqual(payload.iid, intentId);
  assert.strictEqual(payload.mid, 'demo-merchant');
});

test('createLocalRdp denies a rule-matched deny with the rule reason', async () => {
  const rdp = createLocalRdp({ policy: DEMO_POLICY });
  await assert.rejects(
    rdp.evaluate({ amount: 0, currency: 'usd', action: { type: 'deploy', target: 'production' } }),
    (err) => {
      assert.ok(err instanceof AiyoDenied);
      assert.strictEqual(err.reason, 'prod deploy denied');
      assert.strictEqual(err.field, 'deny-deploy-production');
      return true;
    }
  );
});

test('createLocalRdp denies with a default reason when no rule matches (fail-closed)', async () => {
  const rdp = createLocalRdp({ policy: DEMO_POLICY });
  await assert.rejects(
    rdp.evaluate({ amount: 0, currency: 'usd', action: { type: 'unknown_action_type' } }),
    (err) => {
      assert.ok(err instanceof AiyoDenied);
      assert.strictEqual(err.field, '__default__');
      return true;
    }
  );
});

test('createLocalRdp respects amount conditions on payment rules', async () => {
  const rdp = createLocalRdp({ policy: DEMO_POLICY });
  const allowed = await rdp.evaluate({ amount: 1000, currency: 'usd', action: { type: 'payment' } });
  assert.ok(allowed.receipt.token, 'small payment allowed');

  await assert.rejects(
    rdp.evaluate({ amount: 10000, currency: 'usd', action: { type: 'payment' } }),
    (err) => err instanceof AiyoDenied
  );
});

test('createLocalRdp accepts a custom signing key and verifies tokens signed with it', async () => {
  const rdp = createLocalRdp({ policy: DEMO_POLICY, signingKey: 'custom-signing-key-123' });
  const { receipt } = await rdp.evaluate({
    amount: 0,
    currency: 'usd',
    action: { type: 'deploy', target: 'staging' },
  });
  const payload = rdp.verifyReceipt(receipt.token);
  assert.ok(payload.iid);
});

test('createLocalRdp verifyReceipt rejects a tampered token', async () => {
  const rdp = createLocalRdp({ policy: DEMO_POLICY });
  const { receipt } = await rdp.evaluate({
    amount: 0,
    currency: 'usd',
    action: { type: 'deploy', target: 'staging' },
  });
  const tampered = receipt.token.slice(0, -1) + '0';
  assert.throws(() => rdp.verifyReceipt(tampered), AiyoReceiptInvalid);
});

test('createLocalRdp close() is a no-op that resolves', async () => {
  const rdp = createLocalRdp({ policy: DEMO_POLICY });
  const result = await rdp.close('any-id', { ok: true });
  assert.strictEqual(result, undefined);
});

test('createLocalRdp receipt expires per configured TTL', async () => {
  const rdp = createLocalRdp({ policy: DEMO_POLICY, ttlSeconds: 1, clockSkewSeconds: 0 });
  const { receipt } = await rdp.evaluate({
    amount: 0,
    currency: 'usd',
    action: { type: 'deploy', target: 'staging' },
  });
  // Immediately verify — should be fine.
  rdp.verifyReceipt(receipt.token);
  // Wait long enough to guarantee we cross the 1-second exp boundary in
  // unix-seconds granularity, plus a safety margin for CI timing jitter.
  await new Promise((r) => setTimeout(r, 2500));
  assert.throws(() => rdp.verifyReceipt(receipt.token), /expired/i);
});
