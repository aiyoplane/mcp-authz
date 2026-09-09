// Default intent-payload builder.
//
// Produces the intent shape Aiyo's RDP evaluate endpoint expects. Handles
// both payment tools (dynamic amount and currency) and non-payment tools
// (amount defaults to 0, currency defaults to 'usd' as a nominal placeholder
// that the RDP ignores when action.type is non-payment).
//
// Advanced users can pass their own `intentBuilder` in config for full
// control over the intent shape.

/**
 * @param {string} toolName - MCP tool name being invoked.
 * @param {object} args - Arguments the agent passed to the tool.
 * @param {object} ctx - Call context; may include attribution.
 * @param {object} toolDef - The toolConfig entry for this tool.
 * @returns {object} Intent payload for the RDP evaluate endpoint.
 */
export function buildIntentPayload(toolName, args, ctx, toolDef) {
  // Amount resolution: function (dynamic per-call), literal number, or default 0.
  let amount = 0;
  if (typeof toolDef.amount === 'function') {
    amount = Number(toolDef.amount(args)) || 0;
  } else if (typeof toolDef.amount === 'number') {
    amount = toolDef.amount;
  }

  const currency = toolDef.currency || 'usd';

  // Action object: always includes the tool's declared action.type. Extra
  // fields from toolDef.action pass through so the RDP can key policy on
  // (e.g.) target environment or content ID.
  const action = {
    type: (toolDef.action && toolDef.action.type) || 'tool_invocation',
    ...(toolDef.action || {}),
  };

  // Attribution: workflow_id + agent_id if the caller passed them on ctx.
  // Aiyo's Phase 3 §3.6 two-actor attribution model uses these to answer
  // "which workflow, which agent" in the execution lineage.
  const attribution = {};
  if (ctx && ctx.attribution) {
    if (ctx.attribution.workflow_id) attribution.workflow_id = ctx.attribution.workflow_id;
    if (ctx.attribution.agent_id) attribution.agent_id = ctx.attribution.agent_id;
  }

  // Metadata: tool name and args are recorded (redact-worthy args are the
  // integrator's responsibility to filter before calling wrap()).
  const metadata = {
    source: 'mcp-authz',
    tool_name: toolName,
    ...(ctx && ctx.metadata ? ctx.metadata : {}),
  };

  const payload = {
    amount,
    currency,
    action,
    metadata,
  };

  if (Object.keys(attribution).length > 0) {
    payload.attribution = attribution;
  }

  return payload;
}
