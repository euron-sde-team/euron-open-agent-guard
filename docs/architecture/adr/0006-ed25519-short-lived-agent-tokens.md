# ADR-0006: Ed25519 short-lived agent tokens, credentials exchanged, never sent per call

- **Status:** Accepted
- **Date:** 2026-11-02

## Context

In most agent deployments the agent is whoever holds the API key, and the key is long
lived and broad. An authorization layer needs every request to name an agent that proved
who it is, and revocation must take effect immediately, not when a token happens to
expire. A name or id in the request body must never count as identity.

## Decision

- An agent has credentials: a public client id (`ag_` and 12 hex characters) and a client
  secret (`ags_...`, shown once, stored as a peppered HMAC). Credentials can expire, be
  bound to source networks (`allowed_cidrs`), be rotated with a grace period, and be
  revoked.
- The agent exchanges them at `POST /oauth/token` (OAuth 2.0 client credentials, form
  encoded, rate limited per address) for an access token: an Ed25519 JWT (`typ: ag+jwt`,
  audience `agentguard`) valid for `AGENT_TOKEN_TTL_S` (900 seconds by default, never
  beyond the credential's expiry or rotation grace) that names the agent, its organisation,
  the credential and the agent's `token_version`.
- Every request re-checks the credential and the version against the database, so revoking
  a credential, or revoking the agent (which bumps the version), stops the next call.
- Signing keys are installation wide, stored with the private half sealed (KMS or the local
  key), and published at `/.well-known/jwks.json`. The newest key signs; rotated keys stay
  published for a day.
- Agents can be made to sign each request as well (`require_signed_requests`): an HMAC
  over the timestamp, a nonce and the body hash, with nonces kept in Postgres for the
  signature window, so a captured request cannot be replayed.

## Consequences

**Good**
- The client secret crosses the network once per token lifetime, not on every call.
- Identity comes from the token, never the body (`test_identity_comes_from_the_token_never_the_body`);
  revoked and rotated-out credentials stop at once (`test_revoked_and_rotated_credentials`).
- Ed25519 keys are small and fast, and verifiers (the SDKs) need only the JWKS.

**Bad / caveats**
- Each request costs two primary-key reads (agent and credential). That is the price of
  immediate revocation.
- Suspended and quarantined agents keep authenticating on purpose, so their attempts are
  recorded as denied decisions; only revocation kills their tokens.
- Workload identity (mTLS, SPIFFE) is on the roadmap, not in 0.1.0.

## Alternatives considered

- **Static API keys per agent**: simple, but sent on every call and usually long lived.
- **Stateless JWT validation only**: no database read, but a revoked agent keeps working
  until the token expires.
- **HS256 shared-secret tokens**: verifiers would need the signing secret.
