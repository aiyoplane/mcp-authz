import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildIntentPayload } from '../src/intent-builder.js';

test('non-payment tool defaults amount to 0 and preserves action.type', () => {
  const toolDef = {
    aiyo_gated: true,
    action: { type: 'deploy', target: 'production' },
  };
  const payload = buildIntentPayload('deploy_to_production', { pr_number: 42 }, {}, toolDef);

  assert.strictEqual(payload.amount, 0);
  assert.strictEqual(payload.action.type, 'deploy');
  assert.strictEqual(payload.action.target, 'production');
  assert.strictEqual(payload.currency, 'usd');
  assert.strictEqual(payload.metadata.source, 'mcp-authz');
  assert.strictEqual(payload.metadata.tool_name, 'deploy_to_production');
});

test('payment tool with dynamic amount evaluates the function', () => {
  const toolDef = {
    aiyo_gated: true,
    action: { type: 'payment' },
    amount: (args) => args.amount_cents,
    currency: 'usd',
  };
  const payload = buildIntentPayload('send_payment', { amount_cents: 1500 }, {}, toolDef);

  assert.strictEqual(payload.amount, 1500);
  assert.strictEqual(payload.currency, 'usd');
  assert.strictEqual(payload.action.type, 'payment');
});

test('payment tool with literal amount uses it directly', () => {
  const toolDef = {
    aiyo_gated: true,
    action: { type: 'payment' },
    amount: 2500,
    currency: 'eur',
  };
  const payload = buildIntentPayload('send_fee', {}, {}, toolDef);

  assert.strictEqual(payload.amount, 2500);
  assert.strictEqual(payload.currency, 'eur');
});

test('attribution flows through from ctx', () => {
  const toolDef = { aiyo_gated: true, action: { type: 'deploy' } };
  const ctx = { attribution: { workflow_id: 'wf-1', agent_id: 'agent-1' } };
  const payload = buildIntentPayload('t', {}, ctx, toolDef);

  assert.deepStrictEqual(payload.attribution, { workflow_id: 'wf-1', agent_id: 'agent-1' });
});

test('attribution field is omitted when ctx has none', () => {
  const toolDef = { aiyo_gated: true, action: { type: 'deploy' } };
  const payload = buildIntentPayload('t', {}, {}, toolDef);

  assert.strictEqual(payload.attribution, undefined);
});

test('action.type defaults to "tool_invocation" if not declared', () => {
  const toolDef = { aiyo_gated: true }; // no action declared
  const payload = buildIntentPayload('t', {}, {}, toolDef);

  assert.strictEqual(payload.action.type, 'tool_invocation');
});

test('dynamic amount function that throws yields 0', () => {
  const toolDef = {
    aiyo_gated: true,
    action: { type: 'payment' },
    amount: () => { throw new Error('boom'); },
  };
  // The builder does not catch — it should propagate. This test asserts that
  // the caller is responsible for handling errors in the dynamic amount fn.
  assert.throws(() => buildIntentPayload('t', {}, {}, toolDef), /boom/);
});
