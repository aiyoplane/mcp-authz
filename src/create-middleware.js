// createAiyoMcpAuthz — the middleware factory.
//
// Consumes a config, returns { wrap, verifyReceipt }. wrap(toolName, handler)
// takes an async MCP tool handler and returns a wrapped version that flows
// every invocation through an Aiyo Runtime Decision Point before executing.
//
// The RDP is pluggable. Pass any object implementing the RDP provider
// interface as `config.rdp`:
//
//   {
//     evaluate(intentPayload) -> Promise<{ intentId, receipt, decision }>
//       // ALLOW → resolves with the receipt; DENY → throws AiyoDenied.
//     close(intentId, outcome) -> Promise<void>
//       // Fire-and-forget lineage close.
//     verifyReceipt(token) -> object
//       // Local verification against the RDP's signing key.
//   }
//
// Two built-in providers ship in this package:
//
//   * createLocalRdp({ policy, merchantId, signingKey })
//       Zero credentials. Evaluates policy in-process. Signs receipts locally.
//       Use this for demos, tests, examples, or local development.
//
//   * createHostedRdp({ apiBaseUrl, apiKey })
//       Calls Aiyo's production RDP over HTTPS with merchant credentials.
//       Use this when you're gating against your real merchant-owned policy.
//       Contact Aiyo via the Early Access surface at aiyoplane.com.
//
// The wrap-and-execute flow is identical in both modes. That is the point of
// this reference: the composition pattern is real whether the RDP is local
// or hosted.

import { buildIntentPayload } from './intent-builder.js';
import { AiyoDenied, AiyoEscalation, AiyoUnreachable, AiyoConfigError } from './errors.js';

// Node's single-timer maximum (2^31 - 1 milliseconds, ~24.8 days). Delays
// greater than this are silently clamped to 1ms by node:timers, which would
// convert a long-timeout configuration into an immediate-fire bug. We validate
// against this ceiling in the config check below.
const TIMEOUT_MAX = 2147483647;

// Test-only hook. Set to an object with { setTimeout, clearTimeout } to
// substitute instrumented timers (for leak-cleanup assertions in the test
// suite). Production code must not touch this; it exists solely so the
// test file can verify clearTimeout is called on the resolve path.
export const _internals = {
  setTimeout: globalThis.setTimeout.bind(globalThis),
  clearTimeout: globalThis.clearTimeout.bind(globalThis),
};

/**
 * @typedef {object} RdpProvider
 * @property {(intentPayload: object) => Promise<{ intentId: string, receipt: { token: string, [k: string]: any }, decision?: object }>} evaluate
 * @property {(intentId: string, outcome: { ok: boolean, error?: string }) => Promise<void>} close
 * @property {(token: string) => object} verifyReceipt
 */

/**
 * @typedef {object} AiyoMcpAuthzConfig
 * @property {RdpProvider} rdp - The RDP provider (createLocalRdp or createHostedRdp).
 * @property {object} toolConfig - Keyed by tool name; each entry declares aiyo_gated and (if gated) action metadata.
 * @property {(toolName: string, args: object, ctx: object, toolDef: object) => object} [intentBuilder] - Custom intent-payload builder.
 * @property {object} [logger] - Logger with .info and .error (default: console).
 * @property {boolean} [verifyReceiptOnAllow] - Verify the receipt locally after ALLOW (default: true).
 * @property {number} [authorizationTimeoutMs] - If set to a positive finite number,
 *   bound rdp.evaluate() with this timeout. On fire, the wrapped handler throws
 *   AiyoUnreachable with code 'TIMEOUT' and the gated handler never runs (fail-
 *   closed per AEAP §2.2 invariant 5). Omitted or <= 0 → no timeout applied.
 */

/**
 * @param {AiyoMcpAuthzConfig} config
 */
export function createAiyoMcpAuthz(config) {
  validateConfig(config);

  const {
    rdp,
    toolConfig,
    intentBuilder = buildIntentPayload,
    logger = console,
    verifyReceiptOnAllow = true,
    authorizationTimeoutMs = 0,
  } = config;

  // Validate authorizationTimeoutMs: 0 or omitted means "no timeout applied";
  // anything else must be a positive finite integer no greater than Node's
  // supported single-timer maximum. Delays above TIMEOUT_MAX (2^31 - 1 ms,
  // ~24.8 days) are not supported by node:timers — Node clamps them to 1ms
  // and emits a warning, which would silently convert a long-timeout
  // configuration into an immediate-fire bug. Reject at construction instead.
  if (authorizationTimeoutMs !== 0) {
    if (
      !Number.isFinite(authorizationTimeoutMs) ||
      authorizationTimeoutMs < 0 ||
      authorizationTimeoutMs > TIMEOUT_MAX
    ) {
      throw new AiyoConfigError(
        `createAiyoMcpAuthz: authorizationTimeoutMs must be a non-negative finite number ` +
        `no greater than ${TIMEOUT_MAX} ms (Node's single-timer maximum). ` +
        `Omit or set 0 to disable; set a positive millisecond value to enable.`
      );
    }
  }

  /**
   * Wrap an MCP tool handler with an Aiyo authorization decision.
   *
   * @param {string} toolName - Must exist in toolConfig.
   * @param {(args: object, ctx: object) => Promise<any>} handler - The underlying tool handler.
   * @returns {(args: object, ctx?: object) => Promise<any>}
   */
  function wrap(toolName, handler) {
    if (typeof toolName !== 'string' || !toolName) {
      throw new AiyoConfigError('wrap(): toolName must be a non-empty string');
    }
    if (typeof handler !== 'function') {
      throw new AiyoConfigError('wrap(): handler must be a function');
    }
    const toolDef = toolConfig[toolName];
    if (!toolDef) {
      throw new AiyoConfigError(
        `wrap(): tool "${toolName}" not found in toolConfig. Declare it (with aiyo_gated: true|false) before wrapping.`
      );
    }

    return async function wrappedHandler(args, ctx = {}) {
      // Ungated tools bypass the RDP entirely.
      if (toolDef.aiyo_gated !== true) {
        return handler(args, ctx);
      }

      // 1. Build the intent payload.
      const intentPayload = intentBuilder(toolName, args, ctx, toolDef);

      // 2. Evaluate through the RDP.
      //    ALLOW resolves with { intentId, receipt }.
      //    DENY throws AiyoDenied (propagates directly to the caller).
      //    ESCALATE throws AiyoEscalation (propagates directly; the
      //      Composition Boundary MUST hold execution per AEAP §6.2).
      //    Timeout (if authorizationTimeoutMs is set) throws AiyoUnreachable
      //      with code 'TIMEOUT' — fail-closed per AEAP §2.2 invariant 5.
      //    Any other failure becomes AiyoUnreachable — fail closed.
      let evaluation;
      try {
        evaluation = await evaluateWithTimeout(rdp, intentPayload, authorizationTimeoutMs);
      } catch (err) {
        // Typed-error path: pass through directly.
        if (err instanceof AiyoDenied) throw err;
        if (err instanceof AiyoEscalation) throw err;

        // Wire-format translation: an RDP provider that throws a plain Error
        // carrying an AEAP verdict code is signaling a Policy decision in
        // the AEAP wire-format shape. Promote to the matching typed error
        // so downstream catches work uniformly whether the RDP returns the
        // typed class or the wire format.
        //
        // Both `code` and `verdict` are accepted (different RDP conventions
        // use one or the other). When BOTH are present on the same error
        // they MUST agree; a contradictory decision representation is an
        // ambiguous signal and we fail closed rather than silently resolving
        // it by field order.
        if (err) {
          const wireVerdict = classifyWireVerdict(err);
          if (wireVerdict === 'AMBIGUOUS') {
            // Contradictory code/verdict → fail closed. Handler never runs.
            logger.error('[aiyo-mcp-authz] RDP returned ambiguous decision shape', {
              toolName,
              code: err.code,
              verdict: err.verdict,
            });
            throw new AiyoUnreachable(
              `RDP returned a decision whose code and verdict disagree ` +
              `(code=${JSON.stringify(err.code)}, verdict=${JSON.stringify(err.verdict)}). ` +
              `Fail-closed per AEAP §2.2 invariant 5.`,
              err
            );
          }
          if (wireVerdict === 'BLOCK') {
            const reason = err.reason || err.message || 'Policy denied this intent';
            throw new AiyoDenied(reason, err.rule_id || null, err.intentId || null);
          }
          if (wireVerdict === 'ESCALATE') {
            const reason = err.reason || err.message || 'Policy escalated this intent pending resolution';
            throw new AiyoEscalation(
              reason,
              err.rule_id || null,
              err.intentId || null,
              err.escalationId || err.escalation_id || null
            );
          }
        }

        logger.error('[aiyo-mcp-authz] RDP evaluate() failed', {
          toolName,
          error: err && err.message,
          code: err && err.code,
        });
        if (err instanceof AiyoUnreachable) throw err;
        throw new AiyoUnreachable('RDP evaluate() failed', err);
      }

      const { intentId, receipt } = evaluation || {};
      if (!intentId || !receipt || !receipt.token) {
        throw new AiyoUnreachable(
          'RDP evaluate() returned an ALLOW without a valid { intentId, receipt.token } — RDP provider is misconfigured.'
        );
      }

      // 3. Verify the receipt locally (fail closed on any tamper/expiry).
      //    verifyReceiptOnAllow is on by default — verification is what makes
      //    the receipt trustworthy at the tool boundary. Awaited because the
      //    hosted RDP's verifier may fetch JWKS on first use.
      let verifiedPayload = null;
      if (verifyReceiptOnAllow) {
        try {
          verifiedPayload = await rdp.verifyReceipt(receipt.token);
        } catch (err) {
          logger.error('[aiyo-mcp-authz] receipt verification failed', {
            toolName,
            intentId,
            error: err && err.message,
          });
          throw err; // AiyoReceiptInvalid — fail closed.
        }
      }

      // 4. Invoke the underlying tool handler.
      let result;
      let outcomeOk = true;
      let outcomeError = null;
      try {
        result = await handler(args, {
          ...ctx,
          receipt,
          receiptPayload: verifiedPayload,
          intentId,
        });
      } catch (err) {
        outcomeOk = false;
        outcomeError = err;
        throw err;
      } finally {
        // 5. Close the execution lineage (fire-and-forget — a failure to close
        //    should never itself cause the tool call to fail).
        Promise.resolve()
          .then(() =>
            rdp.close(intentId, {
              ok: outcomeOk,
              error: outcomeOk ? undefined : truncate(String(outcomeError && outcomeError.message), 1024),
            })
          )
          .catch((err) => {
            logger.error('[aiyo-mcp-authz] rdp.close() failed', {
              toolName,
              intentId,
              error: err && err.message,
            });
          });
      }

      return result;
    };
  }

  return {
    wrap,
    // Async so it works uniformly with both local (sync) and hosted (async
    // with JWKS fetch) RDP providers.
    verifyReceipt: async (token) => rdp.verifyReceipt(token),
  };
}

// ─── helpers ─────────────────────────────────────────────────────────────────

/**
 * Classify an RDP-thrown error against the AEAP wire-format verdict shape.
 *
 * Returns one of:
 *   - 'BLOCK'      — err carries a BLOCK verdict (via code, verdict, or both,
 *                    and if both, they agree).
 *   - 'ESCALATE'   — err carries an ESCALATE verdict under the same rule.
 *   - 'AMBIGUOUS'  — err carries BOTH fields but they disagree. The decision
 *                    representation is malformed; fail closed.
 *   - 'NONE'       — err carries neither a BLOCK nor an ESCALATE signal.
 *
 * This classifier intentionally ignores the `ALLOW` wire-value: ALLOW is
 * not represented by a thrown error — a successful evaluate returns the
 * ALLOW shape. An error with `code: 'ALLOW'` is a programmer bug on the
 * RDP side; it falls to 'NONE' here and is wrapped as AiyoUnreachable.
 */
function classifyWireVerdict(err) {
  const code = err && err.code;
  const verdict = err && err.verdict;

  const codeIsBlock = code === 'BLOCK';
  const codeIsEscalate = code === 'ESCALATE';
  const verdictIsBlock = verdict === 'BLOCK';
  const verdictIsEscalate = verdict === 'ESCALATE';

  const hasCodeSignal = codeIsBlock || codeIsEscalate;
  const hasVerdictSignal = verdictIsBlock || verdictIsEscalate;

  // Contradiction detection: both fields present and pointing at different
  // verdicts. We require agreement when both are set.
  if (hasCodeSignal && hasVerdictSignal) {
    if (codeIsBlock !== verdictIsBlock) return 'AMBIGUOUS';
    if (codeIsEscalate !== verdictIsEscalate) return 'AMBIGUOUS';
  }

  if (codeIsBlock || verdictIsBlock) return 'BLOCK';
  if (codeIsEscalate || verdictIsEscalate) return 'ESCALATE';
  return 'NONE';
}


/**
 * Run rdp.evaluate(intent) bounded by authorizationTimeoutMs. On fire, throws
 * AiyoUnreachable with code 'TIMEOUT'. If timeoutMs is 0 or omitted, forwards
 * directly with no timeout applied.
 *
 * Scope and limitations:
 *   - This function bounds the WAIT for the authorization decision from the
 *     caller's perspective. On fire, the caller receives a rejection and the
 *     gated handler never runs.
 *   - This function does NOT cancel the underlying rdp.evaluate() work.
 *     JavaScript Promises are not cancellable. If evaluate eventually
 *     resolves, its result is discarded by Promise.race. For a metered or
 *     side-effectful RDP implementation, timeout fires do not abort the
 *     downstream work; they only bound what the caller observes.
 *   - The timer is NOT `.unref()`ed. If a caller is awaiting wrap() and the
 *     timer is the only remaining event-loop handle capable of settling the
 *     awaited Promise, we need Node to stay alive until the timer fires;
 *     otherwise the process would exit silently without delivering the
 *     rejection the caller is waiting on. The clearTimeout in the finally
 *     block ensures the timer does not outlive a resolved evaluation.
 *   - The fail-closed invariant (AEAP §2.2 invariant 5) is upheld: no path
 *     through this function returns an ALLOW shape when the timeout fires.
 */
async function evaluateWithTimeout(rdp, intentPayload, timeoutMs) {
  if (!timeoutMs || timeoutMs <= 0) {
    return rdp.evaluate(intentPayload);
  }

  let timeoutHandle;
  const timeoutPromise = new Promise((_, reject) => {
    timeoutHandle = _internals.setTimeout(() => {
      const err = new AiyoUnreachable(
        `RDP evaluate() exceeded authorizationTimeoutMs=${timeoutMs}`,
        null
      );
      err.code = 'TIMEOUT';
      reject(err);
    }, timeoutMs);
  });

  try {
    return await Promise.race([rdp.evaluate(intentPayload), timeoutPromise]);
  } finally {
    _internals.clearTimeout(timeoutHandle);
  }
}

function validateConfig(cfg) {
  if (!cfg || typeof cfg !== 'object') {
    throw new AiyoConfigError('createAiyoMcpAuthz: config object is required');
  }
  if (!cfg.rdp || typeof cfg.rdp !== 'object') {
    throw new AiyoConfigError(
      'createAiyoMcpAuthz: config.rdp is required. Pass createLocalRdp({ policy }) for a demo, ' +
      'or createHostedRdp({ apiBaseUrl, apiKey }) for production Aiyo.'
    );
  }
  const required = ['evaluate', 'close', 'verifyReceipt'];
  for (const method of required) {
    if (typeof cfg.rdp[method] !== 'function') {
      throw new AiyoConfigError(
        `createAiyoMcpAuthz: config.rdp is missing required method "${method}". ` +
        'The RDP provider must implement { evaluate, close, verifyReceipt }.'
      );
    }
  }
  if (!cfg.toolConfig || typeof cfg.toolConfig !== 'object') {
    throw new AiyoConfigError('createAiyoMcpAuthz: config.toolConfig object is required');
  }
}

function truncate(s, n) {
  if (typeof s !== 'string') return '';
  return s.length > n ? s.slice(0, n) : s;
}
