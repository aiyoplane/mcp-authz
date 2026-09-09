// local-rdp.js — in-process Runtime Decision Point for the reference demo.
//
// createLocalRdp(opts) returns an RDP provider with { evaluate, close,
// verifyReceipt } that createAiyoMcpAuthz composes.
//
// Why this exists:
//   * The @aiyoplane/mcp-authz package is a public reference for how you compose
//     Aiyo above an MCP server. It should run in 60 seconds with zero
//     credentials so anyone can inspect the composition pattern.
//   * The local RDP evaluates a small policy object in-process and issues
//     execution receipts using a locally-generated signing key. Nothing
//     round-trips through the network.
//   * The receipt format (v1.<base64url(payload)>.<hex(hmac_sha256_sig)>) is
//     byte-for-byte the same format Aiyo's production server-side signer emits.
//     The middleware's verifier code path is exercised identically in both
//     local and hosted modes.
//
// Why this is not a shortcut:
//   * The composition pattern (agent → tool call → RDP evaluates → allow/deny
//     → receipt verifies → tool executes → lineage close) is the entire point
//     of the reference. It is real in both modes.
//   * The policy engine here is small and readable on purpose. See policy.js.
//
// When to switch to createHostedRdp:
//   * When you want to gate against Aiyo's production Runtime Decision Point
//     with your merchant-owned policy. See createHostedRdp in ./hosted-rdp.js
//     and the Early Access surface at aiyoplane.com.

import { createHmac, randomBytes, randomUUID } from 'node:crypto';
import { evaluatePolicy } from './policy.js';
import { verifyReceipt as verifyReceiptFn } from './verify-receipt.js';
import { AiyoDenied, AiyoConfigError } from './errors.js';

const DEFAULT_TTL_SECONDS = 300; // 5 minutes — matches production Aiyo default.
const DEFAULT_CLOCK_SKEW = 30;

/**
 * @typedef {object} LocalRdpOptions
 * @property {object} policy - Policy object (see policy.example.json).
 * @property {string} [merchantId] - Value written into the receipt's `mid` claim.
 * @property {string} [signingKey] - Hex/base64/utf8 string used as the HMAC key.
 *                                   Auto-generated if omitted (random 32 bytes).
 * @property {number} [ttlSeconds] - Receipt lifetime, default 300.
 * @property {number} [clockSkewSeconds] - Verifier leeway, default 30.
 * @property {{ info?: Function }} [logger] - Optional logger for close events.
 */

/**
 * @param {LocalRdpOptions} opts
 */
export function createLocalRdp(opts = {}) {
  const {
    policy,
    merchantId = 'demo-merchant',
    signingKey = randomBytes(32).toString('hex'),
    ttlSeconds = DEFAULT_TTL_SECONDS,
    clockSkewSeconds = DEFAULT_CLOCK_SKEW,
    logger = null,
  } = opts;

  if (!policy || typeof policy !== 'object') {
    throw new AiyoConfigError('createLocalRdp: policy object is required');
  }
  if (typeof signingKey !== 'string' || !signingKey) {
    throw new AiyoConfigError('createLocalRdp: signingKey must be a non-empty string');
  }
  if (!Number.isFinite(ttlSeconds) || ttlSeconds <= 0) {
    throw new AiyoConfigError('createLocalRdp: ttlSeconds must be a positive number');
  }

  /**
   * Evaluate an intent through the local policy engine.
   *
   * @param {object} intentPayload - Shape produced by buildIntentPayload.
   * @returns {Promise<{ intentId: string, receipt: object, decision: object }>}
   * @throws {AiyoDenied} when the policy returns deny.
   */
  async function evaluate(intentPayload) {
    const decision = evaluatePolicy(intentPayload, policy);
    const intentId = randomUUID();

    if (decision.effect === 'deny') {
      throw new AiyoDenied(
        decision.reason || 'Local RDP policy denied this intent',
        decision.rule_id,
        intentId
      );
    }

    // ALLOW → issue receipt. Format matches Aiyo production server-side signer.
    const now = Math.floor(Date.now() / 1000);
    const payload = {
      iid: intentId,
      cid: buildCid(intentPayload),
      mid: merchantId,
      exp: now + ttlSeconds,
      iat: now,
    };
    const token = signToken(payload, signingKey);

    return {
      intentId,
      receipt: {
        id: randomUUID(),
        object: 'execution_receipt',
        intent_id: intentId,
        token,
        issued_at: new Date(payload.iat * 1000).toISOString(),
        expires_at: new Date(payload.exp * 1000).toISOString(),
      },
      decision: {
        rule_id: decision.rule_id,
        effect: 'allow',
      },
    };
  }

  /**
   * Close the execution lineage. Local RDP has no lineage store; this is a
   * no-op that exists to satisfy the RDP provider interface. Production Aiyo
   * persists execution lineage server-side for the dashboard lineage panel.
   *
   * @param {string} intentId
   * @param {{ ok: boolean, error?: string }} outcome
   */
  async function close(intentId, outcome) {
    if (logger && typeof logger.info === 'function') {
      logger.info('[local-rdp] execution-result', { intentId, outcome });
    }
  }

  /**
   * Verify a receipt token against this RDP's signing key.
   *
   * @param {string} token
   * @returns {object} Verified payload.
   * @throws {AiyoReceiptInvalid} on signature mismatch, expiry, or malformed token.
   */
  function verifyReceipt(token) {
    return verifyReceiptFn(token, signingKey, { clockSkewSeconds });
  }

  return { evaluate, close, verifyReceipt };
}

// ─── helpers ─────────────────────────────────────────────────────────────────

// Compact `cid` (content/action id) derived from the intent action.
function buildCid(intentPayload) {
  const action = intentPayload && intentPayload.action;
  if (action && action.type) {
    return `${action.type}:${randomBytes(4).toString('hex')}`;
  }
  return `intent:${randomBytes(4).toString('hex')}`;
}

// v1 token format — same as Aiyo production server-side signer.
//   v1.<base64url(json_payload)>.<hex(hmac_sha256_sig)>
// The HMAC is computed over the string "v1.<base64url(payload)>".
function signToken(payload, key) {
  const payloadPart = base64urlEncode(Buffer.from(JSON.stringify(payload), 'utf8'));
  const signingInput = `v1.${payloadPart}`;
  const sig = createHmac('sha256', key).update(signingInput, 'utf8').digest('hex');
  return `${signingInput}.${sig}`;
}

function base64urlEncode(buf) {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
