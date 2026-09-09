// Basic MCP server showing @aiyoplane/mcp-authz composition.
//
// This example runs against the LOCAL RDP — zero credentials required. The
// policy is loaded from ../../policy.example.json (also at the repo root).
// Receipts are signed with a randomly-generated key that lives only in this
// process; the verifier code path is exercised identically to how it runs
// against production Aiyo.
//
// This example does not use a real MCP framework — it exposes a minimal
// tool-dispatcher so the composition is legible in isolation. In real
// integrations, register the wrapped handlers with your MCP server library
// of choice (the reference SDK, a community framework, or your own).
//
// To switch this example against production Aiyo:
//   1. Replace `createLocalRdp(...)` with `createHostedRdp({ apiBaseUrl,
//      apiKey })`. Verification is public-key-based — the middleware
//      fetches Aiyo's Ed25519 public key from the standard JWKS endpoint
//      (/.well-known/aiyo-jwks.json) and caches it. No shared secret.
//   2. Get an apiKey via the Early Access surface at aiyoplane.com.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  createAiyoMcpAuthz,
  createLocalRdp,
  AiyoDenied,
  AiyoUnreachable,
  AiyoReceiptInvalid,
} from '@aiyoplane/mcp-authz';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '..', '..');

// ─── Configuration ───────────────────────────────────────────────────────────

// Load the demo policy from the repo root.
const policy = JSON.parse(
  fs.readFileSync(path.join(repoRoot, 'policy.example.json'), 'utf8')
);

// Load the tool config for this example.
const toolConfig = JSON.parse(
  fs.readFileSync(path.join(__dirname, 'tools.json'), 'utf8')
);

// The `charge_customer` tool declares "amount": "args.amount_cents" in its
// tools.json — the intent-builder needs a function to resolve that at call
// time. We replace the string with a function for that specific tool here so
// the tools.json stays valid JSON (functions can't live in JSON).
toolConfig.charge_customer.amount = (args) => args.amount_cents;

// Build the middleware. Local RDP → no credentials, no network round-trip.
const authz = createAiyoMcpAuthz({
  rdp: createLocalRdp({
    policy,
    merchantId: 'demo-merchant',
    // signingKey omitted → randomly generated for this process.
  }),
  toolConfig,
});

// ─── Underlying tool implementations ─────────────────────────────────────────

async function deployToStagingImpl(args, ctx) {
  console.log(
    `  [deploy] receipt ${ctx.receipt.id} (iid=${ctx.receiptPayload.iid.slice(0, 8)}…) — deploying PR #${args.pr_number} to STAGING`
  );
  return { ok: true, target: 'staging', deployed_at: new Date().toISOString() };
}

async function deployToProductionImpl(args, ctx) {
  console.log(
    `  [deploy] receipt ${ctx.receipt.id} — deploying PR #${args.pr_number} to PRODUCTION`
  );
  return { ok: true, target: 'production', deployed_at: new Date().toISOString() };
}

async function chargeCustomerImpl(args, ctx) {
  console.log(
    `  [charge] receipt ${ctx.receipt.id} — charging ${args.customer_id} $${(args.amount_cents / 100).toFixed(2)}`
  );
  return { ok: true, charge_id: `ch_${Math.random().toString(36).slice(2)}`, amount_cents: args.amount_cents };
}

async function searchDocsImpl(args /* , ctx */) {
  // Ungated — no receipt, no RDP round-trip.
  console.log(`  [search] query="${args.query}" (ungated, bypassed RDP)`);
  return { results: [{ title: 'Example doc', snippet: `You searched for "${args.query}".` }] };
}

// ─── Wrap the four tools; ungated ones pass through automatically ────────────

const handlers = {
  deploy_to_staging: authz.wrap('deploy_to_staging', deployToStagingImpl),
  deploy_to_production: authz.wrap('deploy_to_production', deployToProductionImpl),
  charge_customer: authz.wrap('charge_customer', chargeCustomerImpl),
  search_docs: authz.wrap('search_docs', searchDocsImpl),
};

// ─── Dispatcher (stands in for your MCP server's tool routing) ───────────────

async function dispatch(toolName, args, ctx = {}) {
  const handler = handlers[toolName];
  if (!handler) throw new Error(`Unknown tool: ${toolName}`);
  try {
    return await handler(args, ctx);
  } catch (err) {
    if (err instanceof AiyoDenied) {
      return { error: 'denied', reason: err.reason, rule_id: err.field, intent_id: err.intentId };
    }
    if (err instanceof AiyoUnreachable) return { error: 'aiyo_unreachable', message: err.message };
    if (err instanceof AiyoReceiptInvalid) return { error: 'receipt_invalid', message: err.message };
    throw err;
  }
}

// ─── Demo run ─────────────────────────────────────────────────────────────────

const ctx = {
  attribution: {
    workflow_id: 'wf-example-continuous-delivery',
    agent_id: 'agent-deploy-bot-v1',
  },
};

function banner(label) {
  console.log(`\n── ${label} ${'─'.repeat(Math.max(1, 60 - label.length))}`);
}

console.log('\n@aiyoplane/mcp-authz — reference demo (local RDP, no credentials)\n');

banner('1. Ungated tool — RDP bypassed entirely');
console.log(await dispatch('search_docs', { query: 'runbook: production deploy' }, ctx));

banner('2. Gated non-payment tool → ALLOW (deploy to staging)');
console.log(await dispatch('deploy_to_staging', { pr_number: 2847, commit_sha: 'abc123def' }, ctx));

banner('3. Gated non-payment tool → DENY (deploy to production)');
console.log(await dispatch('deploy_to_production', { pr_number: 2847, commit_sha: 'abc123def' }, ctx));

banner('4. Gated payment tool → ALLOW ($10, under policy threshold)');
console.log(await dispatch('charge_customer', { customer_id: 'cust_9931', amount_cents: 1000 }, ctx));

banner('5. Gated payment tool → DENY ($100, above policy threshold)');
console.log(await dispatch('charge_customer', { customer_id: 'cust_9931', amount_cents: 10000 }, ctx));

console.log('\nDone. The same primitive (RDP) governs payment and non-payment actions.\n');
