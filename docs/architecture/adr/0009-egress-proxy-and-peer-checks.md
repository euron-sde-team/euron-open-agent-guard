# ADR-0009: An egress forward proxy plus connected-peer checks on every outbound path

- **Status:** Accepted
- **Date:** 2026-11-02

## Context

Exfiltration and server-side request forgery are the network side of agent abuse: an
injected agent posts the customer list to a new host, or a tool URL points at the cloud's
metadata service. AgentGuard makes outbound connections itself (HTTP tools, MCP upstreams,
webhooks, the AI classifier, SIEM forwarding) and agents and sandboxed code make their own.

A check of the hostname before connecting is not enough: DNS can answer a public address
at check time and a private one at connect time (DNS rebinding).

## Decision

- **Network policies** per organisation (`network/service.py`): an ordered rule list
  (`allow` or `deny` by host pattern, CIDR, ports, methods), first match wins, a default
  action, and a default policy for agents without their own. Private, loopback, link-local
  and reserved addresses are refused unless a rule allows them **by CIDR**; metadata
  addresses are refused by every rule and every switch.
- **The egress proxy** (`network/proxy.py`, `agentguard egress`): a forward proxy for
  `CONNECT host:port` and absolute-form HTTP. It authenticates the agent (access token, or
  the sandbox proxy token), refuses inactive agents and the kill switch, resolves the host
  once, decides every address, connects to an address it evaluated (never resolving
  again), relays bytes under a time limit, and records the connection and the bytes.
- **Peer checks** on the paths that use an HTTP client: HTTP tools compare the connected
  peer with the addresses that were evaluated (`dns_rebinding`); webhooks and SIEM
  forwarding check the peer is not private.
- In production the API refuses `ALLOW_PRIVATE_URLS=true`.

## Consequences

**Good**
- One decision function for every path, so a policy means the same thing for an agent's
  `curl`, an HTTP tool and sandboxed code (`test_the_egress_proxy_enforces_network_policy`,
  `test_http_tools_follow_the_agents_network_policy`).
- Every refusal is recorded, and repeated refusals raise a `suspicious_network` threat.

**Bad / caveats**
- The proxy never sees inside TLS: policies decide by host and port, and methods only for
  plain HTTP.
- An agent that is not configured to use the proxy and has a direct route out bypasses
  it. Deployments must make the proxy the only route (the Terraform security groups and
  the Compose `sandbox` network do).
- With no network policy at all, public destinations are allowed; write a default policy
  with `default_action: deny` for a closed posture.

## Alternatives considered

- **Hostname allowlists in each tool**: scattered and easy to forget on a new path.
- **A service mesh egress gateway**: strong, but Kubernetes-specific and invisible to
  AgentGuard's decisions and audit.
- **DNS filtering**: cheap, but blind to direct IP connections and rebinding.
