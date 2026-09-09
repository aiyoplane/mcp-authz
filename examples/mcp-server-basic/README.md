# Example — Basic MCP server with Aiyo authorization

A minimal MCP server that exposes four tools and runs against a **local, in-process RDP** — no credentials required.

The example demonstrates:

1. **Ungated tool bypass** — a read-only `search_docs` tool with `aiyo_gated: false` skips the RDP entirely.
2. **Non-payment ALLOW** — `deploy_to_staging` (action type: `deploy`, target: `staging`) is allowed by the demo policy and executes with a verified execution receipt.
3. **Non-payment DENY** — `deploy_to_production` (action type: `deploy`, target: `production`) is denied by the demo policy and never executes.
4. **Payment ALLOW** — `charge_customer` for $10 (below the demo threshold) is allowed and executes.
5. **Payment DENY** — `charge_customer` for $100 (above the demo threshold) is denied and never executes.

The same Runtime Decision Point evaluates all four gated calls. Payment is one action type the RDP knows about; non-payment consequential actions are another. That's the action-agnostic thesis, live.

---

## Run it

```bash
cd examples/mcp-server-basic
npm install
npm start
```

You should see five labeled sections showing the five outcomes above. No environment variables to set. No credentials to obtain.

---

## What to look at in the code

- `server.js` — the MCP-server surface. Note the `createLocalRdp({ policy })` call — that's what makes this demo work without credentials.
- `tools.json` — tool config declarations passed to `createAiyoMcpAuthz`. Notice that only gated tools declare an `action`; the ungated tool declares `aiyo_gated: false`.
- `../../policy.example.json` — the demo policy the local RDP evaluates against. Deliberately small and readable.

---

## Switch this example against production Aiyo

Replace the `createLocalRdp(...)` call in `server.js` with:

```js
import { createHostedRdp } from '@aiyoplane/mcp-authz';

const authz = createAiyoMcpAuthz({
  rdp: createHostedRdp({
    apiBaseUrl: 'https://api.aiyoplane.com',
    apiKey: process.env.AIYO_API_KEY,
  }),
  toolConfig,
});
```

Only the `apiKey` is required — verification is public-key-based. The middleware fetches Aiyo's Ed25519 public key from the standard JWKS endpoint (`/.well-known/aiyo-jwks.json`) and caches it. No shared secret to configure, no signing material for the merchant to hold.

Access to production Aiyo credentials (the `apiKey`) is granted through the Early Access surface at [aiyoplane.com](https://aiyoplane.com). The wrap-and-execute flow is identical in both modes — the composition pattern is real whether the RDP is local or hosted.

---

## Try the failure modes

1. **Edit the demo policy.** Change `default_effect: "deny"` to `"allow"`, or flip individual rule effects. Re-run and watch which calls flip.
2. **Force a receipt-invalid.** Tamper with the token string returned by an ALLOW before verification (e.g., inject an interceptor between `evaluate` and `verifyReceipt`). The middleware fails closed with `AiyoReceiptInvalid`.
3. **Force a deny inside a new tool.** Add a new tool with an action type that no rule matches, then invoke it. The `default_effect: "deny"` catches it — the tool never runs.

All three failure modes fail closed by construction.
