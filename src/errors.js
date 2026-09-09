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
