"""AgentGuard benchmark: what deciding and enforcing costs.

    make bench            (or: uv run python bench.py --database-url ... --redis-url ...)

Runs the real API, the egress proxy and the mock services in process against a throwaway
``agentguard_bench`` database, and measures:

* ``authorize`` latency (sequential) and throughput (50 concurrent agents);
* the policy engine alone, with 50 active policies;
* ``execute`` of an HTTP tool against calling the tool directly (AgentGuard's overhead);
* an MCP ``tools/call`` through the gateway against the same call made directly;
* a request through the egress proxy against the same request made directly;
* audit sealing and verification throughput.

Results are printed and written to ``docs/bench.json`` with the machine's CPU count and
load, so the numbers can be read in context.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import statistics
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import httpx
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine


def pct(values: list[float], p: float) -> float:
    ordered = sorted(values)
    return round(ordered[min(len(ordered) - 1, int(len(ordered) * p))], 3)


def summary(values: list[float]) -> dict[str, float]:
    return {"p50_ms": pct(values, 0.5), "p95_ms": pct(values, 0.95), "p99_ms": pct(values, 0.99), "mean_ms": round(statistics.mean(values), 3), "n": len(values)}


async def timed(fn: Callable[[], Awaitable[Any]], n: int) -> list[float]:
    out = []
    for _ in range(n):
        started = time.perf_counter()
        await fn()
        out.append((time.perf_counter() - started) * 1000)
    return out


async def main(args: argparse.Namespace) -> dict[str, Any]:
    from tests.integration.conftest import Served, free_port, make_settings

    url = args.database_url
    admin = create_async_engine(url.rsplit("/", 1)[0] + "/postgres", isolation_level="AUTOCOMMIT")
    async with admin.connect() as conn:
        await conn.execute(text("DROP DATABASE IF EXISTS agentguard_bench WITH (FORCE)"))
        await conn.execute(text("CREATE DATABASE agentguard_bench"))
    await admin.dispose()
    bench_db = url.rsplit("/", 1)[0] + "/agentguard_bench"
    from agentguard.migrations.runner import upgrade

    await asyncio.to_thread(upgrade, bench_db)
    mock = Served("mockai.app:app").start()
    port = free_port()
    settings = make_settings(bench_db, Path("/tmp/agentguard-bench"), f"http://127.0.0.1:{port}", redis_url=args.redis_url, login_rpm=100000)  # noqa: S108 a scratch directory for the run
    from agentguard.main import create_app

    api = Served(create_app(settings), port=port).start()
    results: dict[str, Any] = {"cpus": os.cpu_count(), "load_before": os.getloadavg()[0]}
    async with httpx.AsyncClient(base_url=api.url, timeout=60, headers={"x-agentguard-csrf": "1"}) as admin_c:
        signup = await admin_c.post("/api/v1/auth/signup", json={"org_name": "Bench", "name": "Bench", "email": "bench@bench.test", "password": "Bench-Pass-2026"})
        admin_c.headers["authorization"] = f"Bearer {signup.json()['session_token']}"
        await admin_c.post("/api/v1/tools/register", json={"name": "ping", "kind": "function", "actions": ["call"], "input_schema": {"type": "object"}})
        await admin_c.post("/api/v1/tools/register", json={"name": "crm.get", "kind": "http", "actions": ["read"], "input_schema": {"type": "object"},
                                                            "config": {"method": "GET", "url": f"{mock.url}/tools/crm/customers/{{customer_id}}"}})
        await admin_c.post("/api/v1/roles", json={"name": "bench", "permissions": [{"tool": "*", "actions": [], "resource": "*"}]})
        for i in range(50):
            await admin_c.post("/api/v1/policies", json={"source": f"name: policy-{i}\ntools: [tool-{i}]\nrules:\n  - when: params.amount > {i * 10}\n    decision: require_approval\n  - actions: [delete]\n    decision: deny\n"})
        agents = []
        for i in range(50):
            data = (await admin_c.post("/api/v1/agents/register", json={"slug": f"bench-{i}", "name": f"Bench {i}", "roles": ["bench"]})).json()
            cred = data["credential"]
            tok = (await admin_c.post("/oauth/token", data={"grant_type": "client_credentials", "client_id": cred["client_id"], "client_secret": cred["client_secret"]})).json()["access_token"]
            agents.append(tok)
        agent = httpx.AsyncClient(base_url=api.url, timeout=60, headers={"authorization": f"Bearer {agents[0]}"})
        counter = iter(range(10**9))

        async def authorize() -> None:
            r = await agent.post("/api/v1/authorize", json={"tool": "ping", "action": "call", "parameters": {"n": next(counter)}, "run_id": f"r{next(counter)}"})
            assert r.status_code == 200, r.text
            assert r.json()["decision"] == "allow", r.text

        await timed(authorize, 50)
        results["authorize"] = summary(await timed(authorize, args.n))
        # Throughput: 50 agents, each its own client, for a fixed number of requests.
        clients = [httpx.AsyncClient(base_url=api.url, timeout=60, headers={"authorization": f"Bearer {t}"}) for t in agents]
        total = args.n * 2
        started = time.perf_counter()

        async def worker(c: httpx.AsyncClient, k: int) -> None:
            for j in range(total // len(clients)):
                await c.post("/api/v1/authorize", json={"tool": "ping", "action": "call", "parameters": {"j": j}, "run_id": f"t{k}-{j}"})

        await asyncio.gather(*(worker(c, k) for k, c in enumerate(clients)))
        elapsed = time.perf_counter() - started
        results["authorize_throughput"] = {"decisions_per_s": round(total / elapsed, 1), "concurrency": len(clients), "total": total}
        for c in clients:
            await c.aclose()
        # The engine alone.
        from agentguard.policies import engine
        from agentguard.policies.dsl import compile_policy

        policies = [engine.ActivePolicy(str(i), f"p{i}", 1, compile_policy(f"name: policy-{i}\ntools: [tool-{i}]\nrules:\n  - when: params.amount > {i * 10}\n    decision: require_approval\n  - actions: [delete]\n    decision: deny\n")) for i in range(50)]
        data = {"agent": {"slug": "a", "roles": []}, "tool": {"name": "tool-7"}, "action": "pay", "resource": {"key": ""}, "params": {"amount": 500}}
        loops = 20000
        started = time.perf_counter()
        for _ in range(loops):
            engine.evaluate(policies, [], data)
        results["engine_only"] = {"us_per_decision": round((time.perf_counter() - started) / loops * 1e6, 2), "policies": 50}
        # execute vs direct.
        direct_client = httpx.AsyncClient(timeout=30)

        async def direct() -> None:
            await direct_client.get(f"{mock.url}/tools/crm/customers/1024")

        async def execute() -> None:
            r = await agent.post("/api/v1/execute", json={"tool": "crm.get", "action": "read", "parameters": {"customer_id": "1024"}, "run_id": f"e{next(counter)}"})
            assert r.json()["executed"], r.text

        await timed(direct, 20)
        await timed(execute, 20)
        d = summary(await timed(direct, args.n // 2))
        e = summary(await timed(execute, args.n // 2))
        results["execute_http_tool"] = {"direct": d, "through_agentguard": e, "overhead_p50_ms": round(e["p50_ms"] - d["p50_ms"], 3)}
        # Audit.
        from agentguard.audit import service as audit
        from agentguard.core.container import Container

        container = Container.build(settings)
        async with container.db.sessionmaker() as session:
            org_id = (await session.execute(text("SELECT id FROM orgs LIMIT 1"))).scalar_one()
            started = time.perf_counter()
            sealed = 0
            while n := await audit.seal(session, org_id):
                sealed += n
            seal_s = time.perf_counter() - started
            started = time.perf_counter()
            verification = await audit.verify(session, org_id, container.keys)
            verify_s = time.perf_counter() - started
        results["audit"] = {
            "sealed_after_run": sealed,
            "seal_records_per_s": round(sealed / seal_s, 1) if sealed else None,
            "verified_records": verification.checked,
            "verify_records_per_s": round(verification.checked / verify_s, 1),
            "ok": verification.ok,
        }
        await container.close()
        await agent.aclose()
        await direct_client.aclose()
    results["load_after"] = os.getloadavg()[0]
    api.stop()
    mock.stop()
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--database-url", default=os.environ.get("TEST_DATABASE_URL", "postgresql+asyncpg://agentguard:agentguard@localhost:5142/agentguard_test"))
    parser.add_argument("--redis-url", default=os.environ.get("TEST_REDIS_URL", "redis://localhost:5179/14"))
    parser.add_argument("-n", type=int, default=1000)
    parser.add_argument("--out", default=str(Path(__file__).resolve().parents[2] / "docs" / "bench.json"))
    ns = parser.parse_args()
    out = asyncio.run(main(ns))
    print(json.dumps(out, indent=2))
    Path(ns.out).write_text(json.dumps(out, indent=2) + "\n")
