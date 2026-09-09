// Policy evaluator tests.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { evaluatePolicy } from '../src/policy.js';

test('empty policy falls through to default_effect (default: deny)', () => {
  assert.deepStrictEqual(
    evaluatePolicy({ action: { type: 'x' } }, {}),
    { effect: 'deny', rule_id: '__default__', reason: 'No policy rule matched this intent; default effect is deny (fail-closed).' }
  );
});

test('default_effect: allow works when no rule matches', () => {
  const result = evaluatePolicy({ action: { type: 'x' } }, { default_effect: 'allow', rules: [] });
  assert.strictEqual(result.effect, 'allow');
});

test('first matching rule wins', () => {
  const policy = {
    rules: [
      { id: 'first', match: { action_type: 'deploy' }, effect: 'allow' },
      { id: 'second', match: { action_type: 'deploy' }, effect: 'deny' },
    ],
  };
  const result = evaluatePolicy({ action: { type: 'deploy' } }, policy);
  assert.strictEqual(result.rule_id, 'first');
  assert.strictEqual(result.effect, 'allow');
});

test('action_type match filters correctly', () => {
  const policy = {
    rules: [{ id: 'r1', match: { action_type: 'deploy' }, effect: 'allow' }],
  };
  const allow = evaluatePolicy({ action: { type: 'deploy' } }, policy);
  assert.strictEqual(allow.effect, 'allow');

  const deny = evaluatePolicy({ action: { type: 'payment' } }, policy);
  assert.strictEqual(deny.effect, 'deny'); // falls through to default
  assert.strictEqual(deny.rule_id, '__default__');
});

test('target match filters correctly', () => {
  const policy = {
    rules: [
      { id: 'staging-only', match: { action_type: 'deploy', target: 'staging' }, effect: 'allow' },
    ],
  };
  assert.strictEqual(
    evaluatePolicy({ action: { type: 'deploy', target: 'staging' } }, policy).effect,
    'allow'
  );
  assert.strictEqual(
    evaluatePolicy({ action: { type: 'deploy', target: 'production' } }, policy).effect,
    'deny'
  );
});

test('amount_max filters correctly', () => {
  const policy = {
    rules: [
      { id: 'small-only', match: { action_type: 'payment' }, amount_max: 1000, effect: 'allow' },
    ],
  };
  assert.strictEqual(
    evaluatePolicy({ amount: 500, action: { type: 'payment' } }, policy).effect,
    'allow'
  );
  assert.strictEqual(
    evaluatePolicy({ amount: 5000, action: { type: 'payment' } }, policy).effect,
    'deny'
  );
});

test('amount_min filters correctly', () => {
  const policy = {
    rules: [
      { id: 'big-deny', match: { action_type: 'payment' }, amount_min: 5001, effect: 'deny', reason: 'too big' },
    ],
  };
  const bigDeny = evaluatePolicy({ amount: 10000, action: { type: 'payment' } }, policy);
  assert.strictEqual(bigDeny.effect, 'deny');
  assert.strictEqual(bigDeny.reason, 'too big');

  const smallPass = evaluatePolicy({ amount: 100, action: { type: 'payment' } }, policy);
  assert.strictEqual(smallPass.effect, 'deny'); // falls through to default
  assert.strictEqual(smallPass.rule_id, '__default__');
});

test('rule reason surfaces on match', () => {
  const policy = {
    rules: [{ id: 'r', match: { action_type: 'x' }, effect: 'deny', reason: 'because I said so' }],
  };
  const result = evaluatePolicy({ action: { type: 'x' } }, policy);
  assert.strictEqual(result.reason, 'because I said so');
});
