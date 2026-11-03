# ADR-0001: MIT licence

- **Status:** Accepted
- **Date:** 2026-11-02

## Context

The brief for AgentGuard proposed Apache 2.0. Every project in the Euron open-source
programme is MIT licensed, and the programme rules override a brief where they differ.
AgentGuard is infrastructure that companies will embed next to their own agents and
products, so the licence should impose as few conditions as possible.

## Decision

MIT. `LICENSE` reads `Copyright (c) 2026 ENGAGESPHERE TECHNOLOGY PRIVATE LIMITED and the
Euron Open AgentGuard contributors`. The SDKs under `sdks/` carry the same licence in their
own `LICENSE` files so they can be vendored on their own. There is no enterprise edition;
every feature in the repository is MIT.

## Consequences

**Good**
- Companies can run, modify and embed AgentGuard and its SDKs, including in closed products.
- One licence across the programme: no per-project legal review.

**Bad / caveats**
- No explicit patent grant (Apache 2.0 has one).
- Operators who modify AgentGuard need not share their changes.

## Alternatives considered

- **Apache 2.0** (the brief): the same permissions plus a patent grant, but it breaks the
  programme's single licence.
- **AGPLv3**: forces network operators to share changes, and keeps many companies from
  adopting a security component at all.
