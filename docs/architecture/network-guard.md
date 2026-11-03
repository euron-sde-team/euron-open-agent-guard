# Network guard

Where an agent may connect is decided the same way on every outbound path: the egress
proxy that agents and sandboxed code use, HTTP tools that AgentGuard calls, MCP upstreams,
and AgentGuard's own webhooks, SIEM forwarding and AI classifier calls. Private ranges and
cloud metadata addresses are refused even after DNS rebinding
([ADR-0009](adr/0009-egress-proxy-and-peer-checks.md)).

Code: `apps/api/src/agentguard/network/` (`service.py` policies and evaluation, `proxy.py`
the egress proxy, `egress_auth.py` proxy credentials, `router.py` the API) and
`core/net.py` (URL and address safety).

## Network policies

A network policy is an ordered list of rules, a default action, and an optional
`is_default` flag (the organisation's default, for agents without a policy of their own).
An agent's `network_policy_id` names its policy.

```json
{
  "name": "research-browsing",
  "default_action": "deny",
  "rules": [
    {"action": "deny",  "host": "*.exfil.example"},
    {"action": "allow", "host": "*.wikipedia.org", "ports": [443]},
    {"action": "allow", "host": "news.example.com", "ports": [443], "methods": ["GET"]},
    {"action": "allow", "cidr": "10.20.0.0/16", "ports": [5432], "note": "the analytics replica"}
  ]
}
```

| Rule field | Matches when |
| --- | --- |
| `host` | The canonical host equals the pattern, or matches it as a shell glob. `*.example.com` matches `example.com` and every subdomain |
| `cidr` | Every resolved address of the host is inside the network |
| `ports` | The port is listed |
| `methods` | The HTTP method is listed (known only for plain HTTP through the proxy and for HTTP tools) |
| `action` | `allow` or `deny` |

Evaluation (`evaluate_rules`), for a host, its resolved addresses, a port and a method:

1. **Metadata first.** A metadata host name (`metadata`, `metadata.google.internal`,
   `instance-data`) or any link-local, unspecified or AWS IPv6 metadata address
   (`fd00:ec2::254`) is refused (`metadata_address`). No rule, CIDR or switch opens it.
2. **Rules in order; the first match decides.** A matching `deny` refuses (`rule_deny`).
   A matching `allow` allows (`rule_allow`), except that if any resolved address is
   private (private, loopback, link-local, multicast, reserved, unspecified, or an
   IPv4-mapped IPv6 form of one) the allow must be a **CIDR** rule: an allow by host name
   never opens a private address (`private_address`).
3. **No rule matched**: private addresses are refused (`private_address`); otherwise the
   policy's `default_action` (`default_allow` or `not_in_policy`).
4. A host that resolves to nothing is refused (`unresolvable`).

With no policy at all (no agent policy and no organisation default), only public
destinations are allowed. For a closed posture, make a default policy with
`default_action: deny`. `ALLOW_PRIVATE_URLS=true` (development and the demo only; refused
in production) skips the private address check, never the metadata check.

Hosts are canonicalised before matching and checking: lower case, no brackets or trailing
dot, and numeric IPv4 spellings (`2852039166`, `0xa9fea9fe`, `0251.0376.0251.0376`) turned
into dotted quads, so every spelling of a metadata address is recognised.

`POST /api/v1/network-policies/test` evaluates a host, port and method against a policy
without connecting.

## The egress proxy

`agentguard egress` (container `egress`, port 3128 inside, 5128 on the host locally) is an
HTTP forward proxy:

- **Credentials**: `Proxy-Authorization: Bearer <agent access token>`, or Basic with the
  client id as user and the token as password (`HTTPS_PROXY=http://ag_xxx:<token>@egress:3128`)
  for tools that only speak Basic. Sandbox runs use a proxy token instead (below). No or
  bad credentials: `407 Proxy Authentication Required`.
- **Requests**: `CONNECT host:port` for TLS (the proxy never sees inside), or absolute-form
  `http://` requests, forwarded with `Proxy-*` and `Connection` headers removed and
  `connection: close`, one request per connection. Request heads are limited to 16 KB and
  15 seconds.

For each connection:

1. The agent is authenticated; a suspended or quarantined agent, or an organisation with
   the kill switch on, is refused (403, recorded as `agent_not_active` or `kill_switch`)
   (`test_a_suspended_agent_cannot_use_the_proxy`).
2. The host is resolved **once** and every address is decided by the agent's network
   policy (`decide`).
3. An allowed destination is still refused (`data_transfer_limit`) when the agent is
   already over a `data_transfer_bytes` limit.
4. Refused: `403 Blocked by AgentGuard: <reason>`, an egress event, and a count of denied
   destinations; the fifth refusal in ten minutes raises a medium `suspicious_network`
   threat, the twenty-fifth a high one.
5. Allowed: the proxy connects to an address it evaluated (it never resolves again, so
   rebinding has no window), relays bytes both ways for at most `EGRESS_MAX_TUNNEL_S`
   (600 s default), then records the connection with bytes up and down and its duration,
   and adds the bytes to the agent's `data_transfer_bytes` limits.

`test_the_egress_proxy_enforces_network_policy` covers allowed, denied, private and
metadata destinations through the real proxy.

### Proxy tokens for the sandbox

A sandbox run with network gets a proxy token: an Ed25519 JWT (`typ: agp+jwt`, audience
`agentguard-egress`) naming the agent, its organisation, the run and the agent's token
version, valid for 15 minutes (`PROXY_TTL_S`). The sandbox service's relay adds it to the
requests it forwards; the program inside never sees it ([sandbox.md](sandbox.md#network-modes)).
Its connections are recorded with the run, so a tainted run's traffic is visible.

## Peer checks on AgentGuard's own requests

| Path | Check before connecting | Check after connecting |
| --- | --- | --- |
| HTTP tools (`decisions/execute.py`) | The agent's network policy on the resolved addresses and the method; the secret's `allowed_hosts`; redirects off | The connected peer must be one of the evaluated addresses (`dns_rebinding`) |
| MCP upstreams over HTTP | The organisation's default network policy | n/a (long-lived sessions) |
| Webhooks, SIEM forwarding | URL checked when saved and again at send time after DNS (`resolves_safely`): public addresses unless `ALLOW_PRIVATE_URLS` | The connected peer must not be private or forbidden (`peer_is_safe`) |
| AI classifier | URL checked like webhooks; private endpoints allowed with `AI_ALLOW_PRIVATE_ENDPOINTS` (for Ollama in the same network), which production refuses together with open sign-up | as above |
| Sandbox | No network, or only the egress proxy | The proxy's checks |

Every HTTP tool connection, allowed or refused, is an egress event with source
`http_tool` (`test_http_tools_follow_the_agents_network_policy`).

## Egress events

`egress_events` holds every recorded connection: agent, run, source (`proxy`,
`http_tool`), host, port, connected address, method, decision, reason, the policy that
decided, bytes up and down, duration. `GET /api/v1/egress-events` lists them for the
Network guard page. Retention deletes them after `retention.egress_days` (30 by default).
The `threats.exfiltration` task (every 60 s) raises a high `data_exfiltration` threat when
an agent sent at least 1 MB in five minutes to a host it had not used in the previous 30
days.
