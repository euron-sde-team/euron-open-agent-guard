# AgentGuard API, worker, egress proxy and sandbox service

One Python package (`agentguard`) for the API, the background worker, the egress proxy and
the operator CLI, plus the sandbox service (`agentguard_sandbox`) and the mock services used
in development and tests (`mockai`). See the repository README and `docs/` for how they fit
together.

```bash
uv sync
uv run pytest tests/unit -q          # no database, no network
uv run ruff check . && uv run mypy --strict src
```
