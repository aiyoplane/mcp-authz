import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { verifyReceipt } from '../src/verify-receipt.js';
import { AiyoReceiptInvalid } from '../src/errors.js';

const KEY = 'test-verification-key-do-not-use-in-production';

// ─── Match Aiyo's server-side token signer byte-for-byte ────────────────────

function base64urlEncode(buf) {
  return Buffer.from(buf).toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function makeToken(payload, key = KEY) {
  const payloadPart = base64urlEncode(JSON.stringify(payload));
  const signingInput = `v1.${payloadPart}`;
  const sig = createHmac('sha256', key).update(signingInput, 'utf8').digest('hex');
  return `${signingInput}.${sig}`;
}

function futurePayload(overrides = {}) {
  const now = Math.floor(Date.now() / 1000);
  return {
    iid: 'intent-uuid-1',
    cid: 'deploy:abc12345',
    mid: 'merchant-uuid-1',
    iat: now,
    exp: now + 3600, // 1 hour
    ...overrides,
  };
}

// ─── Happy path ─────────────────────────────────────────────────────────────

test('verifyReceipt accepts a correctly signed, unexpired token', () => {
  const payload = futurePayload();
  const token = makeToken(payload);

  const decoded = verifyReceipt(token, KEY);
  assert.strictEqual(decoded.iid, payload.iid);
  assert.strictEqual(decoded.cid, payload.cid);
  assert.strictEqual(decoded.mid, payload.mid);
  assert.strictEqual(decoded.iat, payload.iat);
  assert.strictEqual(decoded.exp, payload.exp);
});

// ─── Malformed inputs ───────────────────────────────────────────────────────

test('verifyReceipt rejects a missing token', () => {
  assert.throws(() => verifyReceipt('', KEY), AiyoReceiptInvalid);
  assert.throws(() => verifyReceipt(null, KEY), AiyoReceiptInvalid);
  assert.throws(() => verifyReceipt(undefined, KEY), AiyoReceiptInvalid);
});

test('verifyReceipt rejects a missing verification key for v1 tokens', () => {
  const token = makeToken(futurePayload());
  assert.throws(() => verifyReceipt(token, ''), /HMAC key/);
});

test('verifyReceipt rejects a malformed token (wrong part count)', () => {
  assert.throws(() => verifyReceipt('just-one-part', KEY), /3 dot-separated parts/);
  assert.throws(() => verifyReceipt('two.parts', KEY), /3 dot-separated parts/);
  assert.throws(() => verifyReceipt('a.b.c.d', KEY), /3 dot-separated parts/);
});

test('verifyReceipt rejects an unsupported version', () => {
  const payload = futurePayload();
  const payloadPart = base64urlEncode(JSON.stringify(payload));
  const badVersion = `v99.${payloadPart}.${'a'.repeat(64)}`;
  assert.throws(() => verifyReceipt(badVersion, KEY), /Unsupported receipt token version/);
});

// ─── Signature integrity ────────────────────────────────────────────────────

test('verifyReceipt rejects a tampered signature', () => {
  const token = makeToken(futurePayload());
  // Corrupt the last byte of the signature part.
  const corrupted = token.slice(0, -1) + (token.endsWith('0') ? '1' : '0');
  assert.throws(() => verifyReceipt(corrupted, KEY), /signature does not match/);
});

test('verifyReceipt rejects a tampered payload (signature no longer matches)', () => {
  const original = makeToken(futurePayload({ iid: 'original-intent' }));
  const tamperedPayload = base64urlEncode(JSON.stringify(futurePayload({ iid: 'attacker-chosen-intent' })));
  const originalSig = original.split('.')[2];
  const tampered = `v1.${tamperedPayload}.${originalSig}`;
  assert.throws(() => verifyReceipt(tampered, KEY), /signature does not match/);
});

test('verifyReceipt rejects a token signed with a different key', () => {
  const token = makeToken(futurePayload(), 'attacker-key');
  assert.throws(() => verifyReceipt(token, KEY), /signature does not match/);
});

// ─── Expiry ─────────────────────────────────────────────────────────────────

test('verifyReceipt rejects an expired token', () => {
  const now = Math.floor(Date.now() / 1000);
  const token = makeToken({
    iid: 'i', cid: 'c', mid: 'm',
    iat: now - 7200,
    exp: now - 3600, // expired 1 hour ago
  });
  assert.throws(() => verifyReceipt(token, KEY), /expired/);
});

test('verifyReceipt accepts a barely-expired token within default clock skew', () => {
  const now = Math.floor(Date.now() / 1000);
  const token = makeToken({
    iid: 'i', cid: 'c', mid: 'm',
    iat: now - 100,
    exp: now - 10, // expired 10s ago; default skew is 30s
  });
  // Should NOT throw — within skew.
  const decoded = verifyReceipt(token, KEY);
  assert.strictEqual(decoded.iid, 'i');
});

test('verifyReceipt rejects a future-issued token (clock drift signal)', () => {
  const now = Math.floor(Date.now() / 1000);
  const token = makeToken({
    iid: 'i', cid: 'c', mid: 'm',
    iat: now + 3600, // issued 1 hour in the future
    exp: now + 7200,
  });
  assert.throws(() => verifyReceipt(token, KEY), /issued in the future/);
});

test('verifyReceipt respects a custom clockSkewSeconds', () => {
  const now = Math.floor(Date.now() / 1000);
  const token = makeToken({
    iid: 'i', cid: 'c', mid: 'm',
    iat: now - 100,
    exp: now - 60, // expired 60s ago
  });
  // Default skew (30s) → rejected.
  assert.throws(() => verifyReceipt(token, KEY), /expired/);
  // Skew 120s → accepted.
  const decoded = verifyReceipt(token, KEY, { clockSkewSeconds: 120 });
  assert.strictEqual(decoded.iid, 'i');
});

// ─── Payload validation ─────────────────────────────────────────────────────

test('verifyReceipt rejects a payload missing required claims', () => {
  const now = Math.floor(Date.now() / 1000);
  // Missing 'mid'.
  const token = makeToken({ iid: 'i', cid: 'c', iat: now, exp: now + 3600 });
  assert.throws(() => verifyReceipt(token, KEY), /missing required claim: mid/);
});

test('verifyReceipt rejects a payload with non-numeric exp or iat', () => {
  const token = makeToken({ iid: 'i', cid: 'c', mid: 'm', iat: 'not-a-number', exp: 999999999 });
  assert.throws(() => verifyReceipt(token, KEY), /must be numeric unix seconds/);
});

test('verifyReceipt rejects a payload that fails to decode as JSON', () => {
  const badPayloadPart = base64urlEncode('this-is-not-json{{{');
  const signingInput = `v1.${badPayloadPart}`;
  const sig = createHmac('sha256', KEY).update(signingInput, 'utf8').digest('hex');
  const token = `${signingInput}.${sig}`;
  assert.throws(() => verifyReceipt(token, KEY), /could not be decoded/);
});
