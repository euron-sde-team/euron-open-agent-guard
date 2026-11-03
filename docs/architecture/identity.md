# Identity

Two kinds of principals use AgentGuard: **agents** (workloads that ask for decisions) and
**people** (who use the dashboard). Automation uses management API keys. None of them is
ever identified by a name or id in a request body
([ADR-0006](adr/0006-ed25519-short-lived-agent-tokens.md)).

Code: `identity/` (agents, credentials, tokens, signed requests, `keys.py`), `auth/`
(people, sessions, lockout, OIDC, role dependencies), `users/`, `integrations/` (API keys).

## Agents

An agent is a workload with its own identity inside a project:

| Field | Meaning |
| --- | --- |
| `slug` | The stable name policies refer to (`finance-agent`), unique in the organisation |
| `project_id` | Its project: the boundary for resources, and the source of `project.environment` |
| `framework` | `langgraph`, `crewai`, `mcp`, `autogen`, `python`, `node`, `agentos` or `other`; policies can scope on it |
| `labels` | Free attributes for ABAC (`team`, `tier`, `pii_cleared`), read as `agent.labels.<key>` |
| `owner_user_id` | The person responsible for it |
| roles | Agent roles bound to the agent (plus those bound to its project and organisation) |
| `network_policy_id` | Where it may connect; the organisation default otherwise |
| `require_signed_requests` | Every `authorize` and `execute` call must also be signed |
| `status` | `active`, `suspended`, `quarantined`, `revoked` |

`POST /api/v1/agents/register` creates the agent and its first credential in one call.

### Status

| Status | Set by | Effect |
| --- | --- | --- |
| `active` | registration, reactivation | Decided normally |
| `suspended` | a person, or a limit with `on_exceed: suspend` | Every action denied (`agent_suspended`); it still authenticates, so each attempt is recorded |
| `quarantined` | a person, an incident containment, a policy `quarantine` decision, or a threat response | Every action denied (`agent_quarantined`), refused by the egress proxy, no MCP tools listed; still recorded |
| `revoked` | a person | Permanent. Every credential is revoked and the token version bumped, so every token dies at once; cannot be reactivated |

Suspended and quarantined agents keep authenticating on purpose: a compromised agent that
keeps trying stays visible in the decision log. A critical threat's default response also
revokes the agent's credentials, which stops its tokens.

## Credentials and tokens

A credential is a public **client id** (`ag_` and 12 hex characters) and a **client
secret** (`ags_` and 43 URL-safe characters) shown once and stored as a peppered HMAC
(`TOKEN_PEPPER`). Each credential also has a **signing secret** (shown once, stored sealed)
for signed requests.

| Credential option | Effect |
| --- | --- |
| `expires_in_days` | The credential stops working at that time; tokens never outlive it |
| `allowed_cidrs` | The token exchange is refused from other source addresses |
| Rotation (`POST .../credentials/{id}/rotate`) | A new credential; the old one keeps working for `CREDENTIAL_ROTATION_GRACE_S` (one hour) so callers can switch |
| Revocation (`POST .../credentials/{id}/revoke`) | Immediate |

### The token exchange

```bash
curl -s http://localhost:5130/oauth/token \
  -d grant_type=client_credentials -d client_id=ag_0123456789ab -d client_secret=ags_...
# {"access_token": "eyJ...", "token_type": "Bearer", "expires_in": 900, "agent": "support-agent", ...}
```

OAuth 2.0 client credentials, form encoded, rate limited per address (`TOKEN_RPM`). Every
failure (unknown client id, wrong secret, expired, rotated out, revoked, wrong network,
revoked agent) gives the same `invalid_client`, and the secret comparison runs in constant
time even for unknown ids, so ids cannot be probed.

The access token is an Ed25519 JWT:

```
header: {"alg": "EdDSA", "typ": "ag+jwt", "kid": "<signing key id>"}
claims: iss = PUBLIC_API_URL, aud = "agentguard", sub = agent id, org, agent (slug),
        cid = credential id, tv = the agent's token_version, iat, exp, jti
```

`exp` is `AGENT_TOKEN_TTL_S` (900 s default, 60 s to a day) after issue, capped by the
credential's expiry and rotation grace.

### Authenticating a request

`Authorization: Bearer <token>` on `/api/v1/authorize`, `/api/v1/execute`,
`/api/v1/content/scan`, `/api/v1/approvals` (ask), `/api/v1/approvals/{id}/status`,
`/api/v1/runs/{key}/end`, `/api/v1/agent/me` and `/mcp`. On every request:

1. the signature, type, audience, issuer and expiry are checked against the key ring;
2. the agent and credential are re-read: the agent must exist in the token's
   organisation and not be revoked, the credential must belong to it and be usable, and
   the agent's `token_version` must equal `tv`.

A revoked credential or agent therefore stops at the next call, not when the token
expires (`test_revoked_and_rotated_credentials`,
`test_suspended_and_quarantined_agents_are_denied_and_revoked_ones_lose_tokens`). An agent
token reaches only the agent runtime routes; the management API refuses it
(`test_an_agent_token_cannot_reach_the_management_api`).

### Signed requests

For an agent with `require_signed_requests` (or any request that carries a signature),
three headers are required:

```
X-AgentGuard-Timestamp: <unix seconds>
X-AgentGuard-Nonce:     <16 to 64 URL-safe characters, never reused>
X-AgentGuard-Signature: hex(HMAC-SHA256(signing_secret, "<timestamp>.<nonce>.<hex sha256(body)>"))
```

The timestamp must be within `REQUEST_SIGNATURE_SKEW_S` (300 s) of the server's clock; the
signature is compared in constant time; the nonce is inserted into `request_nonces`
(primary key agent and nonce) and a repeat is refused as `replayed_request`. Nonces are
kept in Postgres, not a cache, because an evicted nonce would let a captured request replay
(`test_signed_requests_refuse_replays_and_stale_or_missing_signatures`). The SDKs sign when
given the signing secret.

Signed requests are checked on the HTTP agent runtime routes. The `/mcp` gateway and the
egress proxy authenticate with the token alone.

### Signing keys and JWKS

Installation-wide Ed25519 keys (`signing_keys`) sign agent tokens, decision tokens, proxy
tokens and audit checkpoints. The private key is sealed (KMS or the local key). The first
key is created on first use; `agentguard rotate-keys` creates a new one and retires the
others. The newest unretired key signs; keys retired less than a day ago stay in
`/.well-known/jwks.json` and keep verifying, so rotation never breaks tokens in flight.
Key ids sort by creation time.

## People

| Role | Can |
| --- | --- |
| `org_admin` | Everything in the organisation, including users, OIDC, settings, integrations and the kill switch |
| `security_officer` | Agents, credentials, roles and permissions, resources, tools and MCP servers, policies, secrets, network policies, limits, threats, incidents; approve, expire and revoke approvals |
| `reviewer` | Decide approvals they are eligible for; read agents, decisions, approvals (with exact parameters) |
| `auditor` | Read everything (approval previews only, never secret values), change nothing, never approve |

A user can also be `is_global_admin`, which adds the installation scope (the organisations
list). `test_dashboard_roles_can_do_exactly_their_job` checks every role against the API;
`test_people_cannot_raise_their_own_role` checks the obvious attack.

### Passwords and sessions

- Argon2id hashes; at least 10 characters with upper and lower case and a digit.
- Sessions are HS256 JWTs (audience `agentguard-dashboard`, `SESSION_TTL_HOURS`, 12) in an
  HttpOnly cookie `ag_session`, `SameSite=Lax`, `Secure` with `COOKIE_SECURE`; or the same
  token as a bearer header. Sign-out stores the session's `jti` in `revoked_sessions`
  (Postgres, never evicted); a password change bumps `session_version`, ending every other
  session.
- Cookie-authenticated mutations must send `X-AgentGuard-CSRF: 1`. A cross-site page
  cannot add a custom header without a CORS preflight, which the `CORS_ORIGINS` allowlist
  refuses (`test_csrf_header_is_required_for_cookie_mutations`).
- Lockout: five failures per account and address lock that pair for 15 minutes, so a
  stranger cannot lock the owner out from elsewhere; fifty per account in the window lock
  the account, except for addresses that signed in successfully in the last 30 days.
  Failure keys are hashes, so emails and addresses are not stored in the clear.
- Sign-in and sign-up are rate limited per address (`LOGIN_RPM`, `SIGNUP_RPM`). Sign-up can
  be switched off (`SIGNUP_ENABLED=false`); invitations (7 days, single use, stored as
  hashes) and OIDC still work.

### OIDC single sign-on

One provider per organisation (Okta, Entra ID, Google, Keycloak, any OpenID Connect
provider), configured by an org admin with the issuer, client id and secret (sealed),
allowed email domains, a role claim (`groups` by default), a map from claim values to
dashboard roles, and a default role (empty refuses unmapped users).

1. `/api/v1/auth/oidc/{org_slug}/start` reads the discovery document, keeps the PKCE
   verifier (S256), the nonce and the organisation in a signed, short-lived, HttpOnly state
   cookie, and redirects to the provider.
2. `/api/v1/auth/oidc/callback` checks the state against the cookie, exchanges the code
   (client secret sent from the server), validates the ID token (signature from the
   provider's JWKS, RS256, ES256 or EdDSA; issuer; audience; expiry; nonce), and requires an
   email that is not marked unverified, in an allowed domain.
3. A new user is created with the highest role the claims map to (or the default role).
   An existing user must belong to the organisation and not be disabled; the first SSO
   sign-in binds the account to the provider's `sub`, and a different `sub` with the same
   email is refused afterwards, so an email change at the provider cannot take over another
   account. When a role map is configured the role is synced on each sign-in, and audited.

`test_single_sign_on_with_oidc` runs the flow against the mock provider.

## Management API keys

`agk_<prefix>_<secret>`, created by an org admin and shown once, stored as a peppered
HMAC, compared in constant time, revocable. Scope `read` acts like an auditor; `write` acts
like a security officer. Keys manage AgentGuard (and redeem decision tokens for the
organisation's tools); they never authorize an agent action.
