// @aiyoplane/mcp-authz — public entry point.
//
// Reference middleware for composing Aiyo — the Economic Execution
// Authorization plane for autonomous systems — above an MCP server.
// Verify First. Execute Second.
//
// Learn more at aiyoplane.com.
//
// The public API surface:
//
//   * createAiyoMcpAuthz({ rdp, toolConfig }) → { wrap, verifyReceipt }
//       The middleware factory. Composes an RDP above your MCP tool handlers.
//
//   * createLocalRdp({ policy, merchantId?, signingKey? }) → RDP provider
//       In-process demo RDP. Zero credentials. Use for demos, tests, examples,
//       and local development. See policy.example.json.
//
//   * createHostedRdp({ apiBaseUrl, apiKey }) → RDP provider
//       Composes above Aiyo's production RDP. Verifies receipts against
//       Aiyo's Ed25519 public keys fetched from the standard JWKS endpoint
//       — no shared secret required. Get an apiKey via Early Access at
//       aiyoplane.com.
//
//   * verifyReceipt(token, keyMaterial, options?) → payload
//       Standalone receipt verifier. keyMaterial is a string (v1 HMAC key)
//       or a Node Ed25519 KeyObject / JWK / JWKS-shaped object (v2). Same
//       code path the middleware uses.
//
//   * buildIntentPayload(toolName, args, ctx, toolDef) → intent object
//       Default intent-payload builder. Pass your own via config.intentBuilder.
//
//   * AiyoDenied, AiyoUnreachable, AiyoReceiptInvalid, AiyoConfigError
//       Typed errors. Catch these in your MCP tool handler to surface useful
//       protocol errors back to the calling agent.
//
// See docs/ARCHITECTURE.md for the composition pattern.

export { createAiyoMcpAuthz } from './create-middleware.js';
export { createLocalRdp } from './local-rdp.js';
export { createHostedRdp } from './hosted-rdp.js';
export { verifyReceipt } from './verify-receipt.js';
export { buildIntentPayload } from './intent-builder.js';
export { evaluatePolicy } from './policy.js';
export {
  AiyoDenied,
  AiyoUnreachable,
  AiyoReceiptInvalid,
  AiyoConfigError,
} from './errors.js';
