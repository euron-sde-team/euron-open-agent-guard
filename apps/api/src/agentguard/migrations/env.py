"""Alembic environment. Run through ``agentguard migrate`` (no alembic.ini needed)."""

from __future__ import annotations

import asyncio

from alembic import context
from sqlalchemy import pool, text
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import create_async_engine

from agentguard.core.db import Base, import_all_models
from agentguard.migrations.env_filters import include_object

import_all_models()
target_metadata = Base.metadata
config = context.config


# Two deploys starting at once must not both migrate: the second waits for the first.
MIGRATION_LOCK = 0x5D5D_0008


def _run(connection: Connection) -> None:
    connection.execute(text("SET lock_timeout = '10s'"))
    connection.execute(text("SELECT pg_advisory_lock(:k)"), {"k": MIGRATION_LOCK})
    connection.commit()
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        include_object=include_object,
        transaction_per_migration=True,
    )
    with context.begin_transaction():
        context.run_migrations()


async def _online() -> None:
    engine = create_async_engine(
        config.get_main_option("sqlalchemy.url") or "", poolclass=pool.NullPool
    )
    async with engine.connect() as connection:
        await connection.run_sync(_run)
    await engine.dispose()


if context.is_offline_mode():
    context.configure(url=config.get_main_option("sqlalchemy.url"), target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()
else:
    asyncio.run(_online())
