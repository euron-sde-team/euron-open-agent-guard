# Python SDK

`euron-agentguard` connects an agent to AgentGuard (`AgentGuard`, `AsyncAgentGuard`) and lets
a tool verify that AgentGuard allowed the exact call it is about to perform
(`DecisionVerifier`). Python 3.10 or newer; the core depends only on `httpx` and `PyJWT`.

- [Install](#install)
- [Connect an agent](#connect-an-agent)
- [Decisions](#decisions)
- [Failing closed](#failing-closed)
- [Approvals](#approvals)
- [The `tool` decorator](#the-tool-decorator)
- [Execute through AgentGuard](#execute-through-agentguard)
- [Untrusted content, runs and identity](#untrusted-content-runs-and-identity)
- [Signed requests](#signed-requests)
- [Why a client-side check is not enough](#why-a-client-side-check-is-not-enough)
- [Verifying decision tokens](#verifying-decision-tokens)
- [FastAPI](#fastapi)
- [The action hash](#the-action-hash)
- [Errors](#errors)

## Install

```bash
pip install ./sdks/python                    # core (PyPI publishing is on the roadmap)
pip install "./sdks/python[fastapi,langgraph,mcp]"
pip install "./sdks/python[crewai]"          # CrewAI needs Python 3.11 or newer
```

## Connect an agent

Register the agent in the dashboard (Agents, Register) or through
`POST /api/v1/agents/register`. The response shows the client id (`ag_...`), the client
secret (`ags_...`) and the signing secret once.

```python
from euron_agentguard import AgentGuard

guard = AgentGuard(
    "http://localhost:5130",           # the API
    client_id, client_secret,
    signing_secret=None,               # set when the agent must sign its requests
    run_id="ticket-4711",              # optional default run for every call
    timeout=10.0,                      # seconds per request
    fail_mode="closed",                # the default; see Failing closed
)
```

The client exchanges the credentials at `/oauth/token` (OAuth 2.0 client credentials) on
first use, keeps the Ed25519 access token, refreshes it shortly before it expires (10% of its
lifetime, at most a minute early) and, when the API answers 401 with `invalid_token` or
`token_revoked`, exchanges again and retries the request once. One `AgentGuard` is thread
safe; one `AsyncAgentGuard` is safe to share between tasks of an event loop. Both are
context managers (`with` / `async with`) that close their HTTP client.

## Decisions

```python
decision = guard.authorize(
    "refunds", "create",
    resource=None,                     # default: built from the tool's resource template
    parameters={"amount": 700, "customer": "c-1"},
    run_id=None, on_behalf_of="maria@example.com", context={"channel": "chat"},
    want_token=False,                  # ask for a decision token (see below)
)
```

| Field | Meaning |
| --- | --- |
| `allowed` | the only field that says whether to act (`allow` or `restrict`) |
| `decision` | `allow`, `deny`, `require_approval`, `restrict` or `quarantine` |
| `would_be`, `mode` | in audit mode `decision` is `allow` and `would_be` says what enforce mode would have done |
| `reason_code`, `reason`, `reasons` | why, in a stable code and in words |
| `policy`, `policy_version` | the policy that decided, if any |
| `obligations` | what a restricted action must honour (`max_rows`, `redact_fields`, ...) |
| `risk`, `data_classes` | the risk score and the data classes found in the parameters |
| `approval` | for `require_approval`: `id`, `status`, `url`, `expires_at`, `required` |
| `decision_token`, `expires_at` | a single-use proof of this decision (function tools, or `want_token=True`) |
| `action_hash` | the hash the decision and token are bound to |

Helpers: `needs_approval`, `denied`, `restricted`, `failed_closed`, and `raise_for_decision()`,
which returns the decision when allowed and raises `ApprovalRequired` or `ActionDenied`.

## Failing closed

`authorize`, `execute` and `ask_person` never raise because AgentGuard could not decide. They
return a denial the SDK made itself: `decision="deny"`, `decision_id=None`, `failed_closed`
true, the failure in `error`, and `reason_code`:

- `guard_unavailable` for connection errors, timeouts, 5xx and the API's own 503 (the API
  answers `decision: deny, reason_code: guard_unavailable` when it cannot reach its database);
- the API's error code for anything it refused (`invalid_client`, `signature_required`,
  `validation_error`, `rate_limited`, ...).

`fail_mode="open"` exists for organisations in **audit mode** only. With it, a failure to
reach AgentGuard (never an error AgentGuard answered with) allows the action, but only when the
last decision this client received said `mode: audit`. In enforce mode, or before the client
has seen any decision, it still denies. Use it to roll AgentGuard out without blocking agents
while it only observes; switch back to closed before enforcing.

## Approvals

```python
decision = guard.authorize("refunds", "create", parameters={"amount": 700, "customer": "c-1"})
if decision.needs_approval:
    print("approve at", decision.approval.url)
    status = decision.wait_for_approval(timeout=300)   # long-polls 30 s at a time
    if status.approved:
        decision = guard.authorize("refunds", "create",
                                   parameters={"amount": 700, "customer": "c-1"})
        assert decision.allowed       # allowed once: the approval is used up by this call
```

An approval is bound to the action hash, so it covers exactly the parameters the reviewer
saw; a different amount needs its own approval. `wait_for_approval` returns the status after
the timeout even if it is still `pending` (check `status.pending`). Other final statuses are
`rejected` (with `comment`), `changes_requested`, `expired` and `revoked`; the next
`authorize` is then denied with the matching reason code.

`ask_person(...)` asks a person even where policy would allow the action, for an agent that
is unsure; a denied action stays denied. `approval_status(id, wait=0..30)` reads the status
once.

## The `tool` decorator

```python
from euron_agentguard import current_decision

@guard.tool("refunds", "create", resource=lambda p: f"customer:{p['customer']}",
            wait=True, wait_timeout=300)
def refund(amount: int, customer: str) -> str:
    decision = current_decision()          # obligations of a restricted decision
    return payments.refund(amount, customer)
```

The parameters are the call's arguments by name with defaults applied (`self` and `cls`
excluded; `**kwargs` merged; `*args` as a list). Denied raises `ActionDenied`; approval raises
`ApprovalRequired`, or with `wait=True` waits for the person, asks again with the approval id
and runs only if now allowed. It works on plain functions, `async def` functions (the sync
client runs the check in a thread) and methods. `AsyncAgentGuard.tool` decorates
`async def` functions.

## Execute through AgentGuard

```python
result = guard.execute("crm.export", parameters={"segment": "churned"})
if result.executed:
    rows = result.result                   # after obligations (redaction, truncation)
```

For http, MCP and sandbox tools AgentGuard runs the call itself, with credentials it injects
at execution time, so the agent never holds them and a denied call never reaches the tool.

## Untrusted content, runs and identity

```python
scan = guard.scan(page_text, "web", spotlight=True)
if scan.is_injection:                      # the run is now tainted: high-risk actions wait
    ...
guard.end_run()                            # free the run's concurrent-run slot
me = guard.me()                            # agent id, organisation id, roles
```

`scan` raises `GuardUnavailable` when the scan cannot run; treat the content as untrusted
then. With `spotlight=True` the result carries the content wrapped as untrusted data, with
hidden characters removed.

## Signed requests

When the agent is registered with `require_signed_requests`, pass `signing_secret`. The SDK
then signs every request: `X-AgentGuard-Timestamp` (Unix seconds), `X-AgentGuard-Nonce` (a new
32-character URL-safe nonce per attempt) and `X-AgentGuard-Signature`, the hex HMAC-SHA256
over `timestamp.nonce.sha256_hex(body)` of the exact bytes sent. The API refuses a request
outside the time window and any nonce it has seen before (a replay).

## Why a client-side check is not enough

`authorize` is advice the agent asks for. It protects against honest mistakes, but the agent
process is exactly what a prompt injection or a compromised dependency controls: such an
agent can skip the call, ignore a denial or call the tool directly with credentials it holds.
A security boundary cannot live only inside the thing it guards against. Two mechanisms put
the decision outside the agent:

1. **`execute`**: AgentGuard runs the tool, so the agent never holds the tool's credentials
   and there is nothing to call around. Use it for http, MCP and sandbox tools.
2. **Decision tokens**: for tools you run yourself (an internal service, a function behind an
   API), the tool refuses any call without a valid token. The agent asks with
   `want_token=True` (function tools always get one) and sends `decision.decision_token`
   with the call; the tool verifies it. A token is signed by AgentGuard, names one
   organisation, agent, tool, action and resource, binds the exact parameters through the
   action hash, expires after 60 seconds by default and can be redeemed once.

## Verifying decision tokens

```python
from euron_agentguard import DecisionVerifier, DecisionRejected

verifier = DecisionVerifier("http://localhost:5130", api_key="agk_...")  # read scope
try:
    ok = verifier.verify(token, tool="refunds", action="create", parameters=body)
except DecisionRejected as exc:
    refuse(exc.reason)            # e.g. params_mismatch, already_used, invalid_or_expired
```

`verify` checks, in order: the token header (`typ agd+jwt`, `alg EdDSA`, a key id); the
Ed25519 signature against `/.well-known/jwks.json` (cached for 5 minutes, refetched when a
token names an unknown key, at most every 10 seconds so forged key ids cannot flood the API);
audience `agentguard-decision`, issuer and expiry (5 seconds of leeway); the organisation
(by default the API key's, looked up once); the tool and action; the resource and agent when
you pass `resource=` or `agent_id=`; the action hash recomputed locally from `parameters`;
and finally it redeems the token at `POST /api/v1/decisions/redeem`, which marks it used
atomically. The result (`VerifiedDecision`) carries the decision id, the agent, the decided
resource and the obligations.

With `resource=None` the token's resource is accepted: AgentGuard derived it from the
parameters, which are checked. Pass `issuer=` when the verifier reaches AgentGuard on another
address than its `PUBLIC_API_URL`.

Reasons: `missing_token`, `malformed`, `invalid_or_expired`, `unknown_key`, `wrong_org`,
`wrong_agent`, `tool_mismatch`, `action_mismatch`, `resource_mismatch`, `params_mismatch`,
`already_used`, `guard_unavailable`. Online verification fails closed: if the redemption
cannot be made, `verify` raises with `guard_unavailable`.

**Offline mode** (`DecisionVerifier(url, org_id=..., offline=True)`) skips the redemption.
Every other check still holds, but the token is **not single use**: it can be presented again
until it expires. Use it only where a replay within the token lifetime is harmless (an
idempotent read) or the API is deliberately unreachable from the tool.

`AsyncDecisionVerifier` has the same interface for asyncio.

## FastAPI

```python
from euron_agentguard import AsyncDecisionVerifier
from euron_agentguard.fastapi import require_decision

verifier = AsyncDecisionVerifier(AGENTGUARD_URL, api_key=AGENTGUARD_API_KEY)

@app.post("/refunds")
async def refund(body: Refund,
                 decision=Depends(require_decision(verifier, tool="refunds", action="create"))):
    ...
```

The dependency reads the token from `X-AgentGuard-Decision` and the parameters from the JSON
body (or the query string when there is no body), and answers 401 for a missing token, 403
for any failed check and 503 when AgentGuard is unreachable; the handler never runs then.
`parameters=` overrides how parameters are read (they must equal what the agent passed to
`authorize`), `resource=` pins the resource. Both sync and async verifiers work.

## The action hash

`action_hash(org_id, agent_id, tool, action, resource, params)` is
`sha256(b"agentguard-action-v1\x00" + canonical_json({...}))`, the same function the API
uses (`apps/api/src/agentguard/core/canonical.py`). Canonical JSON sorts keys by code point,
writes no whitespace, normalises strings to NFC and writes an integral float below 2**53 as an
integer, so `{"amount": 5.0}` and `{"amount": 5}` are the same action. Cross-language vectors
generated from the API (`sdks/testdata/action-hash-vectors.json`, including 2000 random
floats) pass in both SDKs.

Float edge cases, stated plainly: NaN and infinity are refused; integers outside the 64-bit
range are refused (the API cannot hash them); an integral float of 2**53 or more keeps its
`.0` (`9007199254740994.0`), while JavaScript cannot tell it from an integer, so Python and
Node agents hashing such a value disagree. **Send amounts as integers in minor units below
2**53, or as strings.**

## Errors

| Exception | When |
| --- | --- |
| `ActionDenied` | `raise_for_decision()` or a decorated call was not allowed (`.decision`) |
| `ApprovalRequired` | a subclass of `ActionDenied`: waits for a person (`.approval`) |
| `APIError` | the API answered an error to a call with no decision to return (`status_code`, `code`) |
| `GuardUnavailable` | a subclass of `APIError`: unreachable, timeout or 5xx |
| `DecisionRejected` | resource-side verification failed (`.reason`) |

All derive from `AgentGuardError`.
