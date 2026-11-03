"""The ``agentguard`` command: every service and admin task in one entry point."""

from __future__ import annotations

import argparse
import asyncio
import getpass
import os
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agentguard.core.config import Settings


def _settings() -> Settings:
    from agentguard.core.config import get_settings

    return get_settings()


def _uvicorn(target: str, args: argparse.Namespace) -> None:
    import uvicorn

    uvicorn.run(
        target,
        factory=True,
        host=args.host,
        port=args.port,
        workers=1,  # one process per container: metrics and in-process state stay exact
        proxy_headers=True,
        # Only trust X-Forwarded-For from the load balancer's network (the VPC CIDR on AWS).
        forwarded_allow_ips=os.environ.get("FORWARDED_ALLOW_IPS", "127.0.0.1"),
        access_log=False,
        log_config=None,
        timeout_graceful_shutdown=30,
        # Above the load balancer's idle timeout, or a reused connection can be closed by
        # the API just as the load balancer sends on it (502s). Terraform sets 310.
        timeout_keep_alive=_settings().http_keep_alive_s,
    )


def _serve(args: argparse.Namespace) -> None:
    _uvicorn("agentguard.main:create_app", args)


def _worker(_: argparse.Namespace) -> None:
    from agentguard.worker import main

    asyncio.run(main())


def _migrate(_: argparse.Namespace) -> None:
    from agentguard.core.config import get_settings
    from agentguard.migrations.runner import upgrade

    upgrade(get_settings().database_url)
    print("migrations applied")


def _revision(args: argparse.Namespace) -> None:
    from agentguard.core.config import get_settings
    from agentguard.migrations.runner import revision

    revision(get_settings().database_url, args.message)


async def _create_admin(email: str, name: str, org_name: str, password: str) -> None:
    from sqlalchemy import func, select

    from agentguard.core.config import get_settings
    from agentguard.core.db import Database, import_all_models
    from agentguard.core.security import hash_password, password_problems
    from agentguard.users.models import User

    if problems := password_problems(password):
        sys.exit("password needs " + ", ".join(problems))
    import_all_models()
    settings = get_settings()
    db = Database(settings.database_url, pool_size=1, max_overflow=0)
    try:
        async with db.sessionmaker() as session:
            existing = await session.scalar(
                select(User).where(func.lower(User.email) == email.lower())
            )
            if existing:
                existing.role = "org_admin"
                existing.password_hash = hash_password(password)
                existing.disabled = False
                existing.session_version += 1
                await session.commit()
                print(f"updated {email} (org_admin)")
                return
        async with db.sessionmaker() as session:
            from agentguard.auth.service import signup

            await signup(
                session,
                settings.model_copy(update={"signup_enabled": True}),
                org_name,
                name,
                email,
                password,
                None,
            )
            print(f"created {email} (org_admin of {org_name})")
    finally:
        await db.dispose()


def _admin(args: argparse.Namespace) -> None:
    password = os.environ.get("AGENTGUARD_ADMIN_PASSWORD") or getpass.getpass("Password: ")
    asyncio.run(_create_admin(args.email, args.name, args.org, password))


def _seed(args: argparse.Namespace) -> None:
    from agentguard.demo.seed import run

    asyncio.run(run())


def _egress(_: argparse.Namespace) -> None:
    from agentguard.core.container import Container
    from agentguard.core.db import import_all_models
    from agentguard.core.logs import configure_logging
    from agentguard.network.proxy import serve

    settings = _settings()
    import_all_models()
    configure_logging(settings.log_level)

    async def run() -> None:
        container = Container.build(settings)
        try:
            await serve(container)
        finally:
            await container.close()

    asyncio.run(run())


def _rotate_keys(_: argparse.Namespace) -> None:
    from agentguard.core.container import Container
    from agentguard.core.db import import_all_models

    import_all_models()

    async def run() -> None:
        container = Container.build(_settings())
        try:
            kid = await container.keys.rotate()
            print(f"new signing key {kid}; previous keys stay verifiable for a day")
        finally:
            await container.close()

    asyncio.run(run())


def _verify(args: argparse.Namespace) -> None:
    """Seal, then verify every organisation's audit chain; exit 1 on any problem."""
    from sqlalchemy import select

    from agentguard.audit import service as audit
    from agentguard.core.container import Container
    from agentguard.core.db import import_all_models
    from agentguard.org.models import Org

    import_all_models()

    async def run() -> int:
        container = Container.build(_settings())
        failed = 0
        try:
            async with container.db.sessionmaker() as session:
                orgs = list((await session.execute(select(Org.id, Org.slug))).all())
            for org_id, slug in orgs:
                if args.org and slug != args.org:
                    continue
                async with container.db.sessionmaker() as session:
                    await audit.seal(session, org_id)
                    result = await audit.verify(session, org_id, container.keys)
                status = "ok" if result.ok else "TAMPERED"
                print(
                    f"{slug}: {status}, {result.checked} records, head #{result.head_seq}, {result.checkpoints_checked} checkpoints"
                )
                for problem in result.problems[:10]:
                    print(f"  #{problem['seq']} {problem['problem']}: {problem['detail']}")
                failed += 0 if result.ok else 1
        finally:
            await container.close()
        return failed

    sys.exit(1 if asyncio.run(run()) else 0)


def _openapi(_: argparse.Namespace) -> None:
    from agentguard.openapi import spec, to_yaml

    sys.stdout.write(to_yaml(spec()))


def _server(
    sub: argparse._SubParsersAction[argparse.ArgumentParser], name: str, fn: object, help_: str
) -> None:
    p = sub.add_parser(name, help=help_)
    p.add_argument("--host", default="0.0.0.0")  # noqa: S104 containers listen on all interfaces
    p.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8080")))
    p.set_defaults(fn=fn)


def main(argv: list[str] | None = None) -> None:
    argv = argv if argv is not None else sys.argv[1:]
    parser = argparse.ArgumentParser(prog="agentguard", description="Euron Open AgentGuard")
    sub = parser.add_subparsers(dest="command", required=True)
    _server(sub, "serve", _serve, "the API")
    sub.add_parser(
        "worker",
        help="background jobs: approvals, notifications, webhooks, MCP discovery, detection, audit sealing",
    ).set_defaults(fn=_worker)
    sub.add_parser("egress", help="the egress proxy (EGRESS_LISTEN_PORT)").set_defaults(fn=_egress)
    sub.add_parser(
        "rotate-keys", help="create a new token signing key and retire the old ones"
    ).set_defaults(fn=_rotate_keys)
    sub.add_parser("migrate", help="apply database migrations").set_defaults(fn=_migrate)
    p = sub.add_parser("verify", help="seal and verify the audit chain of every organisation")
    p.add_argument("--org", default="", help="only this organisation slug")
    p.set_defaults(fn=_verify)
    p = sub.add_parser("revision", help="autogenerate a migration from the models")
    p.add_argument("-m", "--message", required=True)
    p.set_defaults(fn=_revision)
    p = sub.add_parser(
        "create-admin", help="create an organisation and its administrator, or reset one"
    )
    p.add_argument("--email", required=True)
    p.add_argument("--name", default="Owner")
    p.add_argument("--org", default="My Company")
    p.set_defaults(fn=_admin)
    sub.add_parser(
        "seed-demo",
        help="a demo company with agents, tools, policies, secrets and a month of history",
    ).set_defaults(fn=_seed)
    sub.add_parser("openapi", help="print the OpenAPI document as YAML").set_defaults(fn=_openapi)
    args = parser.parse_args(argv)
    args.fn(args)
