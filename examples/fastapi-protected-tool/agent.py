"""The agent side: ask AgentGuard for a decision token, then call the protected service.

    python agent.py http://localhost:8095
"""

from __future__ import annotations

import os
import sys

import httpx

from euron_agentguard import AgentGuard


def main() -> int:
    service = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8095"
    guard = AgentGuard(
        os.environ.get("AGENTGUARD_URL", "http://localhost:5130"),
        os.environ["AGENTGUARD_CLIENT_ID"],
        os.environ["AGENTGUARD_CLIENT_SECRET"],
    )
    body = {"amount": 45, "customer": "c-3001"}
    decision = guard.authorize("refunds", "create", parameters=body, want_token=True)
    decision.raise_for_decision()
    headers = {"X-AgentGuard-Decision": decision.decision_token or ""}

    results = {
        "no token": httpx.post(f"{service}/refunds", json=body),
        "other amount": httpx.post(f"{service}/refunds", json={**body, "amount": 4500},
                                   headers=headers),
        "valid token": httpx.post(f"{service}/refunds", json=body, headers=headers),
        "replayed token": httpx.post(f"{service}/refunds", json=body, headers=headers),
    }
    for name, response in results.items():
        print(f"{name:15} -> {response.status_code} {response.text}")
    guard.close()
    expected = {"no token": 401, "other amount": 403, "valid token": 200, "replayed token": 403}
    return 0 if all(results[k].status_code == v for k, v in expected.items()) else 1


if __name__ == "__main__":
    sys.exit(main())
