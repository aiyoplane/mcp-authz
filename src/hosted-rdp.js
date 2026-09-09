// hosted-rdp.js — RDP provider that composes above Aiyo's production API.
//
// createHostedRdp(opts) returns an RDP provider with { evaluate, close,
// verifyReceipt } that talks to Aiyo's production Runtime Decision Point at
// the configured `apiBaseUrl` (typically https://api.aiyoplane.com).
//
// This provider is for merchants who have production Aiyo credentials.
// Access is granted through the Early Access surface at aiyoplane.com — the
// package's demo path (createLocalRdp) is what runs with zero credentials.
//
// ─── Verification model ─────────────────────────────────────────────────────
//
// Aiyo signs execution receipts with an Ed25519 private key. The public key
// is published as a standard JWKS at `${apiBaseUrl}/.well-known/aiyo-jwks.json`.
// This provider fetches the JWKS the first time verifyReceipt() is called
// and caches the resulting public keys for the process lifetime, refreshing
// on demand if verification fails against the current cache (handles key
// rotation gracefully).
//
// Merchants never hold Aiyo signing material, and key rotation propagates
// through the published key set without distributing new secrets.
//
// v1 (legacy HMAC) tokens are also accepted for backward compatibility —
// pass `hmacKey` on the config if you need to verify pre-Ed25519 receipts.
// New Aiyo deployments issue v2 exclusively; the hmacKey option exists only
// to support merchants with in-flight v1 receipts across the migration.
//
// ─── Wire contract ─────────────────────────────────────────────────────────
//   evaluate → POST to the RDP evaluate endpoint (returns intent + execution_receipt)
//   close    → POST to the RDP outcome endpoint (idempotent, records execution result)
//   verifyReceipt → local verification against JWKS-fetched public keys
//
// `/v1/payment_intents` is the historical endpoint name (Aiyo's earliest
// surface); `/v1/intents` is the neutral action-agnostic alias — both routes
// resolve to the same handler on the Aiyo backend. This SDK uses the
// neutral path.

import { verifyReceipt as verifyReceiptFn } from './verify-receipt.js';
import { AiyoDenied, AiyoUnreachable, AiyoConfigError, AiyoReceiptInvalid } from './errors.js';

const DEFAULT_TIMEOUT_MS = 5000;
const DEFAULT_CLOCK_SKEW = 30;
const USER_AGENT = '@aiyoplane/mcp-authz/0.1.0';

/**
 * @typedef {object} HostedRdpOptions
 * @property {string} apiBaseUrl - Aiyo API base URL, e.g. https://api.aiyoplane.com
 * @property {string} apiKey - Server-side merchant API key.
 * @property {string} [jwksUrl] - JWKS override; defaults to `${apiBaseUrl}/.well-known/aiyo-jwks.json`.
 * @property {string} [hmacKey] - Legacy v1 HMAC key for verifying pre-Ed25519 receipts (optional).
 * @property {typeof fetch} [fetch] - Injectable fetch (default: global fetch).
 * @property {number} [timeoutMs] - Request timeout (default: 5000).
 * @property {number} [clockSkewSeconds] - Receipt expiry leeway (default: 30).
 */

/**
 * @param {HostedRdpOptions} opts
 */
export function createHostedRdp(opts = {}) {
  const {
    apiBaseUrl,
    apiKey,
    jwksUrl: jwksUrlOverride,
    hmacKey,
    fetch: fetchImpl = globalThis.fetch,
    timeoutMs = DEFAULT_TIMEOUT_MS,
    clockSkewSeconds = DEFAULT_CLOCK_SKEW,
  } = opts;

  const missing = ['apiBaseUrl', 'apiKey'].filter((k) => !opts[k] || typeof opts[k] !== 'string');
  if (missing.length > 0) {
    throw new AiyoConfigError(
      `createHostedRdp: missing required option(s): ${missing.join(', ')}. ` +
      'Get credentials via the Early Access surface at aiyoplane.com.'
    );
  }
  if (!/^https?:\/\//.test(apiBaseUrl)) {
    throw new AiyoConfigError('createHostedRdp: apiBaseUrl must be an http(s) URL');
  }
  if (typeof fetchImpl !== 'function') {
    throw new AiyoConfigError(
      'createHostedRdp: no fetch implementation available. Provide opts.fetch or run on Node.js >= 18.'
    );
  }

  const jwksUrl = jwksUrlOverride || apiBaseUrl.replace(/\/+$/, '') + '/.well-known/aiyo-jwks.json';

  // JWKS cache: an array of JWK entries { kty, crv, x, kid, use, alg }.
  // Populated on first fetch; refreshed on demand if verification fails
  // against the current cache (rotation grace).
  let jwksCache = null;
  let jwksInflight = null;

  async function fetchJwks() {
    if (jwksInflight) return jwksInflight;
    jwksInflight = (async () => {
      try {
        const res = await fetchImpl(jwksUrl, { method: 'GET', cache: 'no-store' });
        if (!res.ok) {
          throw new Error(`JWKS fetch returned HTTP ${res.status}`);
        }
        const data = await res.json();
        if (!data || !Array.isArray(data.keys)) {
          throw new Error('JWKS response did not include a "keys" array');
        }
        jwksCache = data.keys;
        return data.keys;
      } finally {
        jwksInflight = null;
      }
    })();
    return jwksInflight;
  }

  // ─── RDP endpoint paths (neutral, action-agnostic alias) ────────────────────
  //
  // Historical name: `/v1/payment_intents` — retained on the backend for
  // backward-compatibility with existing integrators. The neutral alias
  // `/v1/intents` reflects the RDP's action-agnostic contract; both routes
  // resolve to the same handler on the Aiyo backend.
  const RDP_EVALUATE_PATH = '/v1/intents';
  const RDP_OUTCOME_PATH  = (intentId) => `/v1/intents/${intentId}/execution-result`;

  async function evaluate(intentPayload) {
    let response;
    try {
      response = await apiRequest(
        fetchImpl, apiBaseUrl, apiKey,
        'POST', RDP_EVALUATE_PATH,
        intentPayload, timeoutMs,
      );
    } catch (err) {
      throw new AiyoUnreachable('Failed to evaluate intent through the RDP', err);
    }

    if (response.status === 'denied' || (response.error && response.error.code === 'policy_violation')) {
      const err = response.error || {};
      const denial = response.denial || {};
      throw new AiyoDenied(
        err.message || denial.reason || 'Aiyo policy denied this tool call',
        err.field || denial.field,
        response.id
      );
    }
    if (response.error) {
      throw new AiyoUnreachable(
        `Aiyo API returned error: ${response.error.code} — ${response.error.message}`
      );
    }
    if (response.status === 'requires_payment') {
      throw new AiyoUnreachable(
        'Payment-gated tools that require on-rail settlement wait are not implemented in this reference. ' +
        'Use amount: 0 (non-payment) tools, or implement polling on intent.id until status transitions to "succeeded".'
      );
    }

    // Prefer execution_receipt; unlock_token is retained as a deprecated alias
    // on the production API for backward compatibility.
    const receipt = response.execution_receipt || response.unlock_token;
    if (!receipt || !receipt.token) {
      throw new AiyoUnreachable(
        `Aiyo returned status "${response.status}" but no execution_receipt.token was included`
      );
    }

    return {
      intentId: response.id,
      receipt,
    };
  }

  async function close(intentId, outcome) {
    try {
      await apiRequest(
        fetchImpl, apiBaseUrl, apiKey,
        'POST', RDP_OUTCOME_PATH(intentId),
        outcome, timeoutMs,
        { includeIdempotencyKey: true },
      );
    } catch (err) {
      throw new AiyoUnreachable('Failed to close execution lineage', err);
    }
  }

  /**
   * Verify a receipt token. Dispatches on version:
   *   v2 → verify against JWKS-fetched Ed25519 public keys (lazy fetch,
   *        auto-refresh on verification failure to handle key rotation).
   *   v1 → verify against the optional `hmacKey` config value (legacy).
   *
   * Returns a Promise<payload>. Throws AiyoReceiptInvalid on failure.
   */
  async function verifyReceipt(token) {
    if (typeof token !== 'string' || !token.length) {
      throw new AiyoReceiptInvalid('Receipt token is missing or not a string');
    }
    const version = token.split('.', 1)[0];

    if (version === 'v1') {
      if (!hmacKey) {
        throw new AiyoReceiptInvalid(
          'Received a v1 (HMAC) receipt but no hmacKey was configured on createHostedRdp. ' +
          'v1 receipts are legacy; new Aiyo deployments issue v2 exclusively. Configure hmacKey ' +
          'only if you need to accept pre-Ed25519 receipts during migration.'
        );
      }
      return verifyReceiptFn(token, hmacKey, { clockSkewSeconds });
    }

    if (version === 'v2') {
      // Ensure JWKS is loaded, then try verification.
      if (!jwksCache) {
        await fetchJwks();
      }
      try {
        return verifyReceiptFn(token, { keys: jwksCache }, { clockSkewSeconds });
      } catch (err) {
        // Verification failed. Might be a stale cache (key rotation). Refresh
        // once and retry — if it still fails, that's a real invalid receipt.
        if (err instanceof AiyoReceiptInvalid && /does not verify/i.test(err.message)) {
          await fetchJwks();
          return verifyReceiptFn(token, { keys: jwksCache }, { clockSkewSeconds });
        }
        throw err;
      }
    }

    throw new AiyoReceiptInvalid(`Unsupported receipt token version: ${version}. Expected v1 or v2.`);
  }

  // Kick off an eager JWKS warm in the background so the first verifyReceipt
  // doesn't pay the round-trip. Errors here are swallowed — the lazy fetch
  // path retries if needed.
  fetchJwks().catch(() => { /* eager warm; lazy path will retry */ });

  return { evaluate, close, verifyReceipt };
}

// ─── HTTP helper ─────────────────────────────────────────────────────────────

async function apiRequest(fetchImpl, baseUrl, apiKey, method, path, body, timeoutMs, opts = {}) {
  const url = baseUrl.replace(/\/+$/, '') + path;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  const headers = {
    'Content-Type': 'application/json',
    'Aiyo-Api-Key': apiKey,
    'User-Agent': USER_AGENT,
    'Accept': 'application/json',
  };
  if (opts.includeIdempotencyKey) {
    headers['Idempotency-Key'] = generateIdempotencyKey();
  }

  try {
    const res = await fetchImpl(url, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: controller.signal,
    });

    const text = await res.text();
    let json;
    try {
      json = text ? JSON.parse(text) : null;
    } catch {
      throw new Error(`Aiyo API returned non-JSON (status ${res.status}): ${text.slice(0, 200)}`);
    }

    if (res.status >= 500) {
      throw new Error(
        `Aiyo API server error ${res.status}: ${(json && json.error && json.error.message) || text.slice(0, 200)}`
      );
    }
    if (res.status === 401 || res.status === 403) {
      throw new Error(`Aiyo API auth error ${res.status}: check apiKey`);
    }
    return json;
  } finally {
    clearTimeout(timer);
  }
}

function generateIdempotencyKey() {
  return 'mcp-authz-' + Math.random().toString(36).slice(2) + Date.now().toString(36);
}
