# Node.js quickstart

Decisions, a guarded function, and an Express route that only runs for a valid, unused
decision token, in one script.

```bash
(cd sdks/node && pnpm install && pnpm build)          # npm publishing is on the roadmap
eval "$(uv run --with httpx python examples/bootstrap.py)"
cd examples/node-quickstart && pnpm install && pnpm start
```

```text
refunds {"amount":40,...} -> allow: Granted by role example-support
refunds {"amount":900,...} -> require_approval: Refunds over 500 need a person
shell {"command":"cat /etc/passwd"} -> deny: Agents do not get a shell
refund(25) -> refunded 25 to c-4002
refund(900) -> waits for approval ...
refund(20000) -> denied (policy_deny)

other amount  -> 403 {"error":{"code":"params_mismatch",...}}
valid token   -> 200 {"refunded":45,...}
replayed      -> 403 {"error":{"code":"already_used",...}}
```
