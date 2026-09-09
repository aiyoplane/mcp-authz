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
import { AiyoDenied, AiyoUnreachable, AiyoConfigError } from './errors.js';

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
  } = config;

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
      //    Any other failure becomes AiyoUnreachable — fail closed.
      let evaluation;
      try {
        evaluation = await rdp.evaluate(intentPayload);
      } catch (err) {
        if (err instanceof AiyoDenied) throw err;
        logger.error('[aiyo-mcp-authz] RDP evaluate() failed', {
          toolName,
          error: err && err.message,
        });
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
