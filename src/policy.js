// policy.js — deterministic rule evaluator for the local demo RDP.
//
// This is deliberately small. It is NOT a policy engine. It is a transparent,
// readable example of what "policy evaluation" means at an RDP:
//
//   * A list of rules is walked in order.
//   * The first rule whose `match` object matches the intent, and whose
//     amount conditions (if any) are satisfied, wins.
//   * The rule's `effect` (`allow` or `deny`) becomes the decision.
//   * If no rule matches, `default_effect` applies (fail-closed default: deny).
//
// Production Aiyo policies are richer — evidence-signal composition, time
// conditions, approval workflows, budget checks against ERPs, cross-actor
// attribution rules, and more. The RDP composition pattern this middleware
// demonstrates is the same in both places; only the policy engine differs.

/**
 * Evaluate an intent against a policy.
 *
 * @param {object} intent - The intent payload (as produced by buildIntentPayload).
 * @param {object} policy - The policy object (from policy.example.json or similar).
 * @returns {{ effect: 'allow' | 'escalate' | 'deny', rule_id: string, reason?: string, escalation_id?: string }}
 */
export function evaluatePolicy(intent, policy) {
  const rules = Array.isArray(policy && policy.rules) ? policy.rules : [];
  // `default_effect` must be one of allow/escalate/deny; anything else collapses
  // to deny per the fail-closed invariant (AEAP §2.2 invariant 5).
  const defaultEffect = normalizeEffect(policy && policy.default_effect, 'deny');

  for (const rule of rules) {
    if (matchesRule(intent, rule)) {
      return {
        effect: normalizeEffect(rule.effect, 'deny'),
        rule_id: rule.id || '__unnamed_rule__',
        reason: rule.reason,
        escalation_id: rule.escalation_id,
      };
    }
  }

  return {
    effect: defaultEffect,
    rule_id: '__default__',
    reason:
      defaultEffect === 'deny'
        ? 'No policy rule matched this intent; default effect is deny (fail-closed).'
        : undefined,
  };
}

// Normalize a free-form effect string into the canonical ternary.
// Anything outside allow/escalate/deny collapses to the given fallback — the
// fail-closed default is deny.
function normalizeEffect(effect, fallback) {
  if (effect === 'allow' || effect === 'escalate' || effect === 'deny') {
    return effect;
  }
  return fallback;
}

function matchesRule(intent, rule) {
  const match = (rule && rule.match) || {};
  const action = (intent && intent.action) || {};
  const amount = Number(intent && intent.amount);

  // action_type must match if specified.
  if (match.action_type !== undefined && match.action_type !== action.type) {
    return false;
  }

  // target must match if specified (matches action.target).
  if (match.target !== undefined && match.target !== action.target) {
    return false;
  }

  // amount_max: rule matches only if intent amount is at or below this.
  if (rule.amount_max !== undefined && Number.isFinite(amount) && amount > rule.amount_max) {
    return false;
  }

  // amount_min: rule matches only if intent amount is at or above this.
  if (rule.amount_min !== undefined && Number.isFinite(amount) && amount < rule.amount_min) {
    return false;
  }

  return true;
}
