// Local execution-receipt verification.
//
// The execution receipt is a cryptographically-signed authorization artifact
// issued by Aiyo when the Runtime Decision Point returns ALLOW. Local
// verification means the MCP server does not round-trip back to Aiyo to
// trust the receipt — it verifies the signature against key material the
// caller supplies.
//
// ─── Two token versions ─────────────────────────────────────────────────────
//
// The verifier dispatches on the version prefix and expects the corresponding
// key material:
//
//   v2 (current — Ed25519, public-key verification):
//     v2.<base64url(json_payload)>.<base64url(ed25519_sig)>
//     Caller passes an Ed25519 public key (Node KeyObject) or a list of
//     public keys (for JWKS-fetched key sets that may include the primary
//     key plus rotated-out-but-still-valid previous keys).
//
//   v1 (legacy — HMAC-SHA256, retained for backward compatibility):
//     v1.<base64url(json_payload)>.<hex(hmac_sha256_sig)>
//     Caller passes a shared HMAC key as a string. This is the format the
//     local RDP demo uses — signer and verifier are in the same process, so
//     the shared-secret model is safe (no cross-party trust boundary).
//
// The algorithm is fixed by the version prefix. No negotiation, no downgrade
// path, no alg=none vulnerability by construction.
//
// ─── Payload schema (same for both versions) ───────────────────────────────
//
//   { iid, cid, mid, exp, iat }
//     iid — payment_intent id (UUID)
//     cid — merchant-defined content/action id
//     mid — merchant id
//     exp — unix seconds, expiration time
//     iat — unix seconds, issued-at time

import { createHmac, timingSafeEqual, verify as cryptoVerify, createPublicKey } from 'node:crypto';
import { AiyoReceiptInvalid } from './errors.js';

/**
 * Verify an Aiyo execution receipt token.
 *
 * @param {string} token - The compact token string (v1 or v2).
 * @param {string | import('node:crypto').KeyObject | Array<import('node:crypto').KeyObject>} keyMaterial
 *        - string: v1 HMAC key.
 *        - KeyObject: v2 Ed25519 public key.
 *        - KeyObject[]: v2, try each key in order (JWKS with rotation grace).
 * @param {object} [options]
 * @param {number} [options.clockSkewSeconds=30] - Allowed leeway when checking exp/iat.
 * @returns {object} The verified payload: { iid, cid, mid, exp, iat }.
 * @throws {AiyoReceiptInvalid} on any failure.
 */
export function verifyReceipt(token, keyMaterial, options = {}) {
  if (typeof token !== 'string' || !token) {
    throw new AiyoReceiptInvalid('Receipt token is missing or not a string');
  }

  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new AiyoReceiptInvalid('Receipt token is malformed: expected 3 dot-separated parts');
  }
  const [version, payloadPart, sigPart] = parts;

  if (version !== 'v1' && version !== 'v2') {
    throw new AiyoReceiptInvalid(`Unsupported receipt token version: ${version}. Expected v1 or v2.`);
  }
  if (!payloadPart || !sigPart) {
    throw new AiyoReceiptInvalid('Receipt token has an empty part');
  }

  const signingInput = `${version}.${payloadPart}`;

  if (version === 'v1') {
    verifyV1Signature(signingInput, sigPart, keyMaterial);
  } else {
    verifyV2Signature(signingInput, sigPart, keyMaterial);
  }

  // Decode + validate payload (common to both versions).
  let payload;
  try {
    const jsonBytes = base64urlDecode(payloadPart);
    payload = JSON.parse(jsonBytes.toString('utf8'));
  } catch (err) {
    throw new AiyoReceiptInvalid(`Receipt payload could not be decoded: ${err.message}`);
  }
  if (typeof payload !== 'object' || payload === null) {
    throw new AiyoReceiptInvalid('Receipt payload is not an object');
  }

  const required = ['iid', 'cid', 'mid', 'exp', 'iat'];
  for (const k of required) {
    if (payload[k] === undefined || payload[k] === null) {
      throw new AiyoReceiptInvalid(`Receipt payload is missing required claim: ${k}`);
    }
  }
  if (typeof payload.exp !== 'number' || typeof payload.iat !== 'number') {
    throw new AiyoReceiptInvalid('Receipt payload claims exp and iat must be numeric unix seconds');
  }

  const nowSeconds = Math.floor(Date.now() / 1000);
  const skew = Number.isFinite(options.clockSkewSeconds) ? options.clockSkewSeconds : 30;

  if (payload.exp + skew < nowSeconds) {
    throw new AiyoReceiptInvalid(
      `Receipt expired at ${new Date(payload.exp * 1000).toISOString()}`
    );
  }
  if (payload.iat - skew > nowSeconds) {
    throw new AiyoReceiptInvalid(
      `Receipt issued in the future (iat ${new Date(payload.iat * 1000).toISOString()}); ` +
      `check clock sync between merchant and Aiyo.`
    );
  }

  return payload;
}

// ─── v1 HMAC verification ───────────────────────────────────────────────────

function verifyV1Signature(signingInput, sigPart, keyMaterial) {
  if (typeof keyMaterial !== 'string' || !keyMaterial) {
    throw new AiyoReceiptInvalid(
      'v1 receipt verification requires an HMAC key string; got ' + typeof keyMaterial
    );
  }
  const expectedSig = createHmac('sha256', keyMaterial)
    .update(signingInput, 'utf8').digest('hex');
  const a = Buffer.from(sigPart, 'hex');
  const b = Buffer.from(expectedSig, 'hex');
  if (a.length === 0 || a.length !== b.length) {
    throw new AiyoReceiptInvalid('Receipt signature length mismatch');
  }
  if (!timingSafeEqual(a, b)) {
    throw new AiyoReceiptInvalid('Receipt signature does not match');
  }
}

// ─── v2 Ed25519 verification ────────────────────────────────────────────────

function verifyV2Signature(signingInput, sigPart, keyMaterial) {
  const publicKeys = coerceToKeyList(keyMaterial);
  if (publicKeys.length === 0) {
    throw new AiyoReceiptInvalid(
      'v2 receipt verification requires an Ed25519 public key (or a list of keys from JWKS)'
    );
  }
  let sigBytes;
  try {
    sigBytes = base64urlDecode(sigPart);
  } catch (err) {
    throw new AiyoReceiptInvalid(`v2 signature is not valid base64url: ${err.message}`);
  }
  const inputBytes = Buffer.from(signingInput, 'utf8');

  // Try each public key in order — for a JWKS with rotation grace, this
  // accepts signatures against any currently-published public key.
  for (const publicKey of publicKeys) {
    if (cryptoVerify(null, inputBytes, publicKey, sigBytes)) {
      return; // valid
    }
  }
  throw new AiyoReceiptInvalid(
    'v2 signature does not verify against any provided public key'
  );
}

// Accept any of: KeyObject, array of KeyObjects, or a JWKS-shaped object
// { keys: [...] } where each entry is a JWK. Returns a normalized array of
// Node KeyObjects.
function coerceToKeyList(keyMaterial) {
  if (!keyMaterial) return [];
  if (Array.isArray(keyMaterial)) {
    return keyMaterial.map(coerceOneToKey);
  }
  if (keyMaterial && typeof keyMaterial === 'object' && Array.isArray(keyMaterial.keys)) {
    // JWKS-shaped
    return keyMaterial.keys.map(coerceOneToKey);
  }
  return [coerceOneToKey(keyMaterial)];
}

function coerceOneToKey(entry) {
  // Already a Node KeyObject? (duck-type on the .asymmetricKeyType property)
  if (entry && typeof entry === 'object' && entry.asymmetricKeyType === 'ed25519') {
    return entry;
  }
  // JWK shape? { kty: 'OKP', crv: 'Ed25519', x: '<base64url>' }
  if (entry && entry.kty === 'OKP' && entry.crv === 'Ed25519' && typeof entry.x === 'string') {
    // Assemble the SPKI DER: 12-byte Ed25519 SPKI prefix + 32-byte raw public key.
    const prefix = Buffer.from('302a300506032b6570032100', 'hex');
    const raw = base64urlDecode(entry.x);
    if (raw.length !== 32) {
      throw new AiyoReceiptInvalid(`JWK x is ${raw.length} bytes; Ed25519 public keys are exactly 32 bytes`);
    }
    const spki = Buffer.concat([prefix, raw]);
    return createPublicKey({ key: spki, format: 'der', type: 'spki' });
  }
  throw new AiyoReceiptInvalid(
    'Public key material must be a Node KeyObject (Ed25519), a JWK, or a JWKS-shaped object'
  );
}

// ─── base64url decode ────────────────────────────────────────────────────────

function base64urlDecode(str) {
  if (typeof str !== 'string') throw new Error('base64url input must be a string');
  const padded = str + '='.repeat((4 - (str.length % 4)) % 4);
  return Buffer.from(padded.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}
