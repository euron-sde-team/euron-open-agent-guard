"""The five-minute path: one agent, four actions, four different answers from AgentGuard.

    export AGENTGUARD_URL=http://localhost:5130
    export AGENTGUARD_CLIENT_ID=ag_...        # from registering the agent
    export AGENTGUARD_CLIENT_SECRET=ags_...
    python quickstart.py
"""

from __future__ import annotations

import os
import sys

from euron_agentguard import ActionDenied, AgentGuard, ApprovalRequired


def main() -> int:
    guard = AgentGuard(
        os.environ.get("AGENTGUARD_URL", "http://localhost:5130"),
        os.environ["AGENTGUARD_CLIENT_ID"],
        os.environ["AGENTGUARD_CLIENT_SECRET"],
        run_id="quickstart-run",
    )
    me = guard.me()
    print(f"Signed in as agent {me.agent} (roles: {', '.join(me.roles)})\n")

    # 1. A small refund: the agent's role grants it, no policy objects.
    small = guard.authorize("refunds", "create", parameters={"amount": 40, "customer": "c-1001"})
    print(f"refund 40      -> {small.decision:16} {small.reason}")

    # 2. A large refund: the policy wants a person to look first.
    large = guard.authorize("refunds", "create", parameters={"amount": 900, "customer": "c-1001"})
    print(f"refund 900     -> {large.decision:16} {large.reason}")
    if large.approval:
        print(f"                  approve it at {large.approval.url}")

    # 3. A shell command: denied by policy, whatever the role says.
    shell = guard.authorize("shell", parameters={"command": "cat /etc/passwd"})
    print(f"shell          -> {shell.decision:16} {shell.reason}")

    # 4. A customer export: allowed, with obligations the tool must apply.
    export = guard.authorize("customers", "export", parameters={"segment": "all"})
    print(f"export         -> {export.decision:16} obligations {export.obligations}")

    # The decorator: the function body only runs when AgentGuard allows the call.
    @guard.tool("refunds", "create")
    def refund(amount: int, customer: str) -> str:
        return f"refunded {amount} to {customer}"

    print()
    for amount in (25, 900, 20000):
        try:
            print(f"refund({amount}) -> {refund(amount, 'c-1002')}")
        except ApprovalRequired as exc:
            print(f"refund({amount}) -> waits for approval {exc.approval.id if exc.approval else ''}")
        except ActionDenied as exc:
            print(f"refund({amount}) -> denied ({exc.reason_code})")

    guard.end_run()
    guard.close()
    ok = small.allowed and large.needs_approval and shell.denied and export.restricted
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
