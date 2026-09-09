// Hosted RDP tests — the HTTP-backed provider.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { createHostedRdp } from '../src/hosted-rdp.js';
import { AiyoDenied, AiyoUnreachable, AiyoConfigError, AiyoReceiptInvalid } from '../src/errors.js';

const KEY = 'test-verification-key';

function base64urlEncode(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function signToken(payload) {
  const payloadPart = base64urlEncode(JSON.stringify(payload));
  const signingInput = `v1.${payloadPart}`;
  const sig = createHmac('sha256', KEY).update(signingInput, 'utf8').digest('hex');
  return `${signingInput}.${sig}`;
}
function futurePayload(over = {}) {
  const now = Math.floor(Date.now() / 1000);
  return { iid: 'intent-uuid', cid: 'deploy:abc', mid: 'merchant-uuid', iat: now, exp: now + 3600, ...over };
}

function makeReceipt() {
  return {
    id: 'rcpt_uuid',
    object: 'execution_receipt',
    intent_id: 'pi_uuid',
    token: signToken(futurePayload()),
    issued_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 3600_000).toISOString(),
  };
}
function makeAllowResponse() {
  return {
    id: 'pi_uuid',
    object: 'payment_intent',
    status: 'authorized',
    amount: 0,
    currency: 'usd',
    action: { type: 'deploy' },
    execution_receipt: makeReceipt(),
  };
}
function jsonResp(body, status = 200) {
  return { ok: status >= 200 && status < 300, status, text: async () => JSON.stringify(body) };
}
function fakeFetch(handler) {
  const calls = [];
  const fn = async (url, options) => {
    calls.push({ url, options });
    return handler(url, options, calls.length);
  };
  fn.calls = calls;
  return fn;
}

// ─── Config validation ─────────────────────────────────────────────────────

test('createHostedRdp requires apiBaseUrl + apiKey', () => {
  assert.throws(() => createHostedRdp({}), AiyoConfigError);
  assert.throws(() => createHostedRdp({ apiBaseUrl: 'https://x' }), /apiKey/);
  assert.throws(
    () => createHostedRdp({ apiBaseUrl: 'not-a-url', apiKey: 'k' }),
    /http\(s\) URL/
  );
});

// ─── evaluate: ALLOW ──────────────────────────────────────────────────────

test('evaluate() ALLOW returns { intentId, receipt }', async () => {
  const rdp = createHostedRdp({
    apiBaseUrl: 'https://api.aiyoplane.com',
    apiKey: 'k',
    hmacKey: KEY,
    fetch: fakeFetch(() => jsonResp(makeAllowResponse(), 201)),
  });
  const result = await rdp.evaluate({ amount: 0, currency: 'usd', action: { type: 'deploy' } });
  assert.strictEqual(result.intentId, 'pi_uuid');
  assert.ok(result.receipt.token.startsWith('v1.'));
});

test('evaluate() accepts the deprecated unlock_token alias', async () => {
  const resp = makeAllowResponse();
  resp.unlock_token = resp.execution_receipt;
  delete resp.execution_receipt;

  const rdp = createHostedRdp({
    apiBaseUrl: 'https://api.aiyoplane.com',
    apiKey: 'k',
    hmacKey: KEY,
    fetch: fakeFetch(() => jsonResp(resp, 201)),
  });
  const result = await rdp.evaluate({ amount: 0, currency: 'usd', action: { type: 'deploy' } });
  assert.strictEqual(result.intentId, 'pi_uuid');
});

// ─── evaluate: DENY via 422 policy_violation ──────────────────────────────

test('evaluate() DENY throws AiyoDenied with reason and field', async () => {
  const rdp = createHostedRdp({
    apiBaseUrl: 'https://api.aiyoplane.com',
    apiKey: 'k',
    hmacKey: KEY,
    fetch: fakeFetch(() =>
      jsonResp(
        {
          error: { code: 'policy_violation', message: 'daily budget exhausted', field: 'max_daily_intent_amount_cents' },
        },
        422
      )
    ),
  });

  await assert.rejects(
    rdp.evaluate({ amount: 0, currency: 'usd', action: { type: 'deploy' } }),
    (err) => {
      assert.ok(err instanceof AiyoDenied);
      assert.strictEqual(err.reason, 'daily budget exhausted');
      assert.strictEqual(err.field, 'max_daily_intent_amount_cents');
      return true;
    }
  );
});

// ─── evaluate: network failure ────────────────────────────────────────────

test('evaluate() network error becomes AiyoUnreachable', async () => {
  const rdp = createHostedRdp({
    apiBaseUrl: 'https://api.aiyoplane.com',
    apiKey: 'k',
    hmacKey: KEY,
    fetch: fakeFetch(() => { throw new Error('ECONNREFUSED'); }),
  });
  await assert.rejects(
    rdp.evaluate({ amount: 0, currency: 'usd', action: { type: 'deploy' } }),
    AiyoUnreachable
  );
});

// ─── evaluate: missing receipt in response ────────────────────────────────

test('evaluate() ALLOW without a receipt token throws AiyoUnreachable', async () => {
  const resp = makeAllowResponse();
  delete resp.execution_receipt;
  const rdp = createHostedRdp({
    apiBaseUrl: 'https://api.aiyoplane.com',
    apiKey: 'k',
    hmacKey: KEY,
    fetch: fakeFetch(() => jsonResp(resp, 201)),
  });
  await assert.rejects(
    rdp.evaluate({ amount: 0, currency: 'usd', action: { type: 'deploy' } }),
    AiyoUnreachable
  );
});

// ─── Aiyo-Api-Key header ──────────────────────────────────────────────────

test('evaluate() sends Aiyo-Api-Key header', async () => {
  const fn = fakeFetch((_url, options) => {
    assert.strictEqual(options.headers['Aiyo-Api-Key'], 'my-api-key');
    return jsonResp(makeAllowResponse(), 201);
  });
  const rdp = createHostedRdp({
    apiBaseUrl: 'https://api.aiyoplane.com',
    apiKey: 'my-api-key',
    hmacKey: KEY,
    fetch: fn,
  });
  await rdp.evaluate({ amount: 0, currency: 'usd', action: { type: 'deploy' } });
});

// ─── close() sends Idempotency-Key ────────────────────────────────────────

test('close() posts execution-result with Idempotency-Key', async () => {
  let closeUrl = null;
  const fn = fakeFetch((url, options) => {
    closeUrl = url;
    assert.ok(options.headers['Idempotency-Key']);
    const body = JSON.parse(options.body);
    assert.strictEqual(body.ok, true);
    return jsonResp({ status: 'succeeded' });
  });
  const rdp = createHostedRdp({
    apiBaseUrl: 'https://api.aiyoplane.com',
    apiKey: 'k',
    hmacKey: KEY,
    fetch: fn,
  });
  await rdp.close('pi_uuid', { ok: true });
  assert.match(closeUrl, /\/v1\/intents\/pi_uuid\/execution-result$/);
});

// ─── verifyReceipt uses the configured verification key ───────────────────

test('verifyReceipt() validates v1 tokens against the configured hmacKey', async () => {
  const rdp = createHostedRdp({
    apiBaseUrl: 'https://api.aiyoplane.com',
    apiKey: 'k',
    hmacKey: KEY,
    fetch: fakeFetch(() => jsonResp({})),
  });
  const token = signToken(futurePayload());
  const payload = await rdp.verifyReceipt(token);
  assert.strictEqual(payload.iid, 'intent-uuid');

  const tampered = token.slice(0, -1) + '0';
  await assert.rejects(rdp.verifyReceipt(tampered), AiyoReceiptInvalid);
});
