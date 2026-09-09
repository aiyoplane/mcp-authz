// Ed25519 + JWKS verification tests.
//
// Covers:
//   * v2 token verification against a Node Ed25519 KeyObject
//   * v2 token verification against a JWKS-shaped object { keys: [...] }
//   * JWKS with multiple keys (rotation grace) — signature against any of them verifies
//   * hosted-rdp.js JWKS fetch, cache, and refresh-on-verify-failure behavior
//   * Round-trip: sign v2 token, fetch JWKS, verify
//   * v2 rejection: wrong key, tampered signature, tampered payload

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import { verifyReceipt } from '../src/verify-receipt.js';
import { createHostedRdp } from '../src/hosted-rdp.js';
import { AiyoReceiptInvalid } from '../src/errors.js';

// ─── Helpers ────────────────────────────────────────────────────────────────

function base64urlEncode(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function makeV2Token(payload, privateKey) {
  const encodedPayload = base64urlEncode(JSON.stringify(payload));
  const signingInput = `v2.${encodedPayload}`;
  const sig = cryptoSign(null, Buffer.from(signingInput, 'utf8'), privateKey);
  return `${signingInput}.${base64urlEncode(sig)}`;
}

function jwksFromPublicKey(publicKey, kid = 'test-key') {
  const der = publicKey.export({ format: 'der', type: 'spki' });
  const raw = der.slice(der.length - 32); // last 32 bytes = Ed25519 public key
  return {
    kty: 'OKP', crv: 'Ed25519',
    x: base64urlEncode(raw),
    kid, use: 'sig', alg: 'EdDSA',
  };
}

function futurePayload(over = {}) {
  const now = Math.floor(Date.now() / 1000);
  return { iid: 'intent-v2', cid: 'deploy:x', mid: 'merchant-v2', iat: now, exp: now + 3600, ...over };
}

// ─── verifyReceipt: v2 against a KeyObject ──────────────────────────────────

test('v2 token verifies against a Node Ed25519 KeyObject', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const token = makeV2Token(futurePayload(), privateKey);
  const payload = verifyReceipt(token, publicKey);
  assert.strictEqual(payload.iid, 'intent-v2');
});

test('v2 token verifies against a JWK', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const jwk = jwksFromPublicKey(publicKey);
  const token = makeV2Token(futurePayload(), privateKey);
  const payload = verifyReceipt(token, jwk);
  assert.strictEqual(payload.iid, 'intent-v2');
});

test('v2 token verifies against a JWKS-shaped object', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const jwks = { keys: [jwksFromPublicKey(publicKey, 'primary')] };
  const token = makeV2Token(futurePayload(), privateKey);
  const payload = verifyReceipt(token, jwks);
  assert.strictEqual(payload.iid, 'intent-v2');
});

test('v2 token verifies against a multi-key JWKS (rotation grace)', () => {
  const primary = generateKeyPairSync('ed25519');
  const previous = generateKeyPairSync('ed25519');
  const jwks = {
    keys: [
      jwksFromPublicKey(primary.publicKey, 'primary'),
      jwksFromPublicKey(previous.publicKey, 'previous'),
    ],
  };
  // Token signed with the PREVIOUS key still verifies because it's in the JWKS.
  const tokenSignedWithPrevious = makeV2Token(futurePayload(), previous.privateKey);
  const payload = verifyReceipt(tokenSignedWithPrevious, jwks);
  assert.strictEqual(payload.iid, 'intent-v2');
});

test('v2 token rejected when signed with a key NOT in the JWKS', () => {
  const inJwks = generateKeyPairSync('ed25519');
  const rogue  = generateKeyPairSync('ed25519');
  const jwks = { keys: [jwksFromPublicKey(inJwks.publicKey)] };
  const rogueToken = makeV2Token(futurePayload(), rogue.privateKey);
  assert.throws(() => verifyReceipt(rogueToken, jwks), AiyoReceiptInvalid);
});

test('v2 token rejected when signature is tampered', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const token = makeV2Token(futurePayload(), privateKey);
  const tampered = token.slice(0, -3) + 'AAA';
  assert.throws(() => verifyReceipt(tampered, publicKey), AiyoReceiptInvalid);
});

test('v2 token rejected when payload is tampered (signature no longer valid)', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const original = makeV2Token(futurePayload(), privateKey);
  const parts = original.split('.');
  const badPayload = base64urlEncode(JSON.stringify(futurePayload({ mid: 'EVIL' })));
  const tampered = `${parts[0]}.${badPayload}.${parts[2]}`;
  assert.throws(() => verifyReceipt(tampered, publicKey), AiyoReceiptInvalid);
});

test('v2 verification rejects a v2 token with no public key material provided', () => {
  const { privateKey } = generateKeyPairSync('ed25519');
  const token = makeV2Token(futurePayload(), privateKey);
  assert.throws(() => verifyReceipt(token, null), AiyoReceiptInvalid);
});

test('v2 verification rejects an expired token', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const now = Math.floor(Date.now() / 1000);
  const expired = makeV2Token({ iid: 'a', cid: 'b', mid: 'c', iat: now - 3600, exp: now - 60 }, privateKey);
  assert.throws(
    () => verifyReceipt(expired, publicKey, { clockSkewSeconds: 0 }),
    /expired/i
  );
});

// ─── createHostedRdp: JWKS fetch + cache + refresh ──────────────────────────

function fakeFetchWithJwks(jwksResponse, evaluateResponse = null) {
  const calls = [];
  const fn = async (url, options) => {
    calls.push({ url, options });
    if (String(url).endsWith('/.well-known/aiyo-jwks.json')) {
      return {
        ok: true, status: 200,
        text: async () => JSON.stringify(jwksResponse),
        json: async () => jwksResponse,
      };
    }
    return {
      ok: true, status: 201,
      text: async () => JSON.stringify(evaluateResponse || {}),
    };
  };
  fn.calls = calls;
  return fn;
}

test('createHostedRdp fetches JWKS on first verifyReceipt call for v2 tokens', async () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const jwksResponse = { keys: [jwksFromPublicKey(publicKey, 'primary')] };
  const fn = fakeFetchWithJwks(jwksResponse);
  const rdp = createHostedRdp({
    apiBaseUrl: 'https://api.aiyoplane.com',
    apiKey: 'k',
    fetch: fn,
  });
  // Wait for the eager warm to settle before asserting call count.
  await new Promise((r) => setTimeout(r, 20));
  const token = makeV2Token(futurePayload(), privateKey);
  const payload = await rdp.verifyReceipt(token);
  assert.strictEqual(payload.iid, 'intent-v2');
  const jwksCalls = fn.calls.filter((c) => String(c.url).endsWith('/.well-known/aiyo-jwks.json'));
  assert.ok(jwksCalls.length >= 1, 'JWKS was fetched at least once');
});

test('createHostedRdp v2 verify rejects tokens signed with an unknown key', async () => {
  const { publicKey } = generateKeyPairSync('ed25519');
  const rogue = generateKeyPairSync('ed25519');
  const jwksResponse = { keys: [jwksFromPublicKey(publicKey, 'primary')] };
  const fn = fakeFetchWithJwks(jwksResponse);
  const rdp = createHostedRdp({
    apiBaseUrl: 'https://api.aiyoplane.com',
    apiKey: 'k',
    fetch: fn,
  });
  const rogueToken = makeV2Token(futurePayload(), rogue.privateKey);
  await assert.rejects(rdp.verifyReceipt(rogueToken), AiyoReceiptInvalid);
});

test('createHostedRdp refetches JWKS if verification fails against stale cache', async () => {
  // Simulate rotation: first JWKS response has key A. Second response has
  // key B. Sign a token with key B. First verify fails, refetch, second
  // verify succeeds.
  const keyA = generateKeyPairSync('ed25519');
  const keyB = generateKeyPairSync('ed25519');
  let fetchCount = 0;
  const fn = async (url) => {
    if (String(url).endsWith('/.well-known/aiyo-jwks.json')) {
      fetchCount += 1;
      const keys = fetchCount === 1
        ? [jwksFromPublicKey(keyA.publicKey, 'primary')]
        : [jwksFromPublicKey(keyB.publicKey, 'primary')];
      return {
        ok: true, status: 200,
        text: async () => JSON.stringify({ keys }),
        json: async () => ({ keys }),
      };
    }
    return { ok: true, status: 201, text: async () => JSON.stringify({}) };
  };
  const rdp = createHostedRdp({
    apiBaseUrl: 'https://api.aiyoplane.com',
    apiKey: 'k',
    fetch: fn,
  });
  await new Promise((r) => setTimeout(r, 20));
  const tokenSignedWithB = makeV2Token(futurePayload(), keyB.privateKey);
  const payload = await rdp.verifyReceipt(tokenSignedWithB);
  assert.strictEqual(payload.iid, 'intent-v2');
  assert.ok(fetchCount >= 2, 'JWKS was refetched after stale-cache miss');
});

test('createHostedRdp still accepts v1 (HMAC) tokens when hmacKey is configured', async () => {
  const { publicKey } = generateKeyPairSync('ed25519');
  const jwksResponse = { keys: [jwksFromPublicKey(publicKey)] };
  const fn = fakeFetchWithJwks(jwksResponse);
  const rdp = createHostedRdp({
    apiBaseUrl: 'https://api.aiyoplane.com',
    apiKey: 'k',
    hmacKey: 'legacy-hmac-key',
    fetch: fn,
  });
  // Build a v1 token by hand.
  const { createHmac } = await import('node:crypto');
  const payload = futurePayload();
  const encoded = base64urlEncode(JSON.stringify(payload));
  const signingInput = `v1.${encoded}`;
  const sig = createHmac('sha256', 'legacy-hmac-key').update(signingInput, 'utf8').digest('hex');
  const v1Token = `${signingInput}.${sig}`;
  const result = await rdp.verifyReceipt(v1Token);
  assert.strictEqual(result.iid, 'intent-v2');
});

test('createHostedRdp v2 verify without hmacKey rejects incoming v1 tokens', async () => {
  const { publicKey } = generateKeyPairSync('ed25519');
  const jwksResponse = { keys: [jwksFromPublicKey(publicKey)] };
  const fn = fakeFetchWithJwks(jwksResponse);
  const rdp = createHostedRdp({
    apiBaseUrl: 'https://api.aiyoplane.com',
    apiKey: 'k',
    fetch: fn,
  });
  const { createHmac } = await import('node:crypto');
  const payload = futurePayload();
  const encoded = base64urlEncode(JSON.stringify(payload));
  const signingInput = `v1.${encoded}`;
  const sig = createHmac('sha256', 'some-key').update(signingInput, 'utf8').digest('hex');
  const v1Token = `${signingInput}.${sig}`;
  await assert.rejects(rdp.verifyReceipt(v1Token), /no hmacKey/);
});
