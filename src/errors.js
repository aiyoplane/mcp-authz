// Typed error classes.
//
// Each error names a specific failure the MCP server can catch and surface
// back to the calling agent (or convert into an MCP protocol error response).

export class AiyoDenied extends Error {
  /**
   * The Aiyo Runtime Decision Point returned DENY for this tool call.
   * @param {string} reason - Human-readable policy rejection message.
   * @param {string} [field] - The policy field that triggered the rejection.
   * @param {string} [intentId] - The intent ID (present when the intent was created but denied at RDP).
   */
  constructor(reason, field, intentId) {
    super(reason || 'Aiyo denied this tool call');
    this.name = 'AiyoDenied';
    this.reason = reason;
    this.field = field;
    this.intentId = intentId;
  }
}

export class AiyoEscalation extends Error {
  /**
   * The Aiyo Runtime Decision Point returned ESCALATE for this tool call
   * (AEAP §6). The intent was neither authorized nor denied; the Composition
   * Boundary MUST hold execution pending out-of-band resolution rather than
   * proceed.
   *
   * Error-shape contract for downstream Composition Boundary Adapters:
   *
   *   - `err.name === 'AiyoEscalation'` and `err instanceof AiyoEscalation`
   *     both hold. Adapters that previously detected ESCALATE by matching
   *     the error message text (`/escalat/i`) should switch to `instanceof`
   *     — the string-match path remains supported for backward compatibility
   *     (`AiyoEscalation` extends `Error` with a message beginning
   *     "ESCALATE: ..."), but it is locale-sensitive and brittle.
   *
   *   - `err.code === 'ESCALATE'` for parity with the Python
   *     `aiyoplane-mcp-authz` AiyoDenied(code="ESCALATE") convention.
   *
   *   - `err.intentId` is set when the RDP produced an intent before
   *     escalating (same contract as AiyoDenied.intentId).
   *
   *   - `err.escalationId`, if set by the RDP, correlates this escalation
   *     with an external approval workflow (e.g., a merchant-side human-
   *     approval queue). Optional; may be null.
   *
   * ESCALATE is distinct from DENY: a DENY is a Policy-authored refusal,
   * final at that moment; an ESCALATE is a Policy-authored pause pending
   * resolution. See AEAP §6.2 and §15.2 (ternary verdict semantics).
   *
   * @param {string} reason - Human-readable reason the Policy escalated.
   * @param {string} [rule_id] - The Policy rule that triggered the escalation.
   * @param {string} [intentId] - The intent ID the RDP created before escalating.
   * @param {string} [escalationId] - Optional correlation ID for external
   *                                  approval workflows.
   */
  constructor(reason, rule_id, intentId, escalationId) {
    super(reason ? `ESCALATE: ${reason}` : 'ESCALATE: Aiyo escalated this tool call pending resolution');
    this.name = 'AiyoEscalation';
    this.code = 'ESCALATE';
    this.reason = reason;
    this.rule_id = rule_id;
    this.intentId = intentId;
    this.escalationId = escalationId || null;
  }
}

export class AiyoUnreachable extends Error {
  /**
   * The Aiyo API was unreachable or returned a non-2xx response outside of a
   * policy denial. Caller can choose to fail closed (throw to the agent) or
   * fail open (proceed without authorization) based on their own risk model.
   * The default policy of this middleware is fail-closed.
   */
  constructor(message, cause) {
    super(message || 'Aiyo API unreachable');
    this.name = 'AiyoUnreachable';
    this.cause = cause;
  }
}

export class AiyoReceiptInvalid extends Error {
  /**
   * The execution receipt returned by Aiyo failed local HMAC verification.
   * This is a serious integrity signal — either the shared verification key
   * is stale, or the receipt was tampered with in transit. Fail closed.
   */
  constructor(message) {
    super(message || 'Execution receipt failed verification');
    this.name = 'AiyoReceiptInvalid';
  }
}

export class AiyoConfigError extends Error {
  /**
   * The middleware was configured incorrectly. Thrown at construction time
   * when required config fields are missing or malformed.
   */
  constructor(message) {
    super(message);
    this.name = 'AiyoConfigError';
  }
}
