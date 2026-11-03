"""Database engine, session factory and the declarative base shared by every domain.

Tenant scoping is structural: every tenant-owned table carries ``org_id`` through
:class:`OrgScoped`, and repositories take an :class:`OrgScope` and filter with it, so a
query that forgets the organisation does not type-check against the repository API.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Select, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, declared_attr, mapped_column


def new_id() -> uuid.UUID:
    return uuid.uuid4()


class Base(DeclarativeBase):
    type_annotation_map = {dict[str, Any]: JSONB, list[str]: JSONB, list[Any]: JSONB}
    # Values the database fills in (server defaults, computed columns) come back with
    # RETURNING, so a row stays readable after commit without a lazy load.
    __mapper_args__ = {"eager_defaults": True}


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=lambda: datetime.now(UTC),
        nullable=False,
    )


class OrgScoped:
    """A row owned by one organisation. Deleting the organisation deletes its rows."""

    @declared_attr
    def org_id(cls) -> Mapped[uuid.UUID]:  # noqa: N805 SQLAlchemy declared_attr convention
        return mapped_column(
            UUID(as_uuid=True),
            ForeignKey("orgs.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        )


@dataclass(frozen=True, slots=True)
class OrgScope:
    """The organisation a request or a job acts for. Repositories filter every query by it."""

    org_id: uuid.UUID


def scoped[T: tuple[Any, ...], M: OrgScoped](
    stmt: Select[T], model: type[M], scope: OrgScope
) -> Select[T]:
    return stmt.where(model.org_id == scope.org_id)


async def get_scoped[M: OrgScoped](
    session: AsyncSession, model: type[M], scope: OrgScope, id_: uuid.UUID
) -> M | None:
    """A row by primary key, or None when it belongs to another organisation."""
    row = await session.get(model, id_)
    if row is None or row.org_id != scope.org_id:
        return None
    return row


class Database:
    """Owns the engine and session factory for one application instance."""

    def __init__(self, url: str, *, pool_size: int = 10, max_overflow: int = 20) -> None:
        self.url = url
        self.engine: AsyncEngine = create_async_engine(
            url,
            pool_size=pool_size,
            max_overflow=max_overflow,
            pool_pre_ping=True,
            pool_recycle=1800,
            # Never echo bound values (password hashes, token hashes, customer messages)
            # into an exception message, and so never into a log line.
            hide_parameters=True,
        )
        self.sessionmaker = async_sessionmaker(self.engine, expire_on_commit=False)

    async def session(self) -> AsyncIterator[AsyncSession]:
        async with self.sessionmaker() as session:
            yield session

    async def dispose(self) -> None:
        await self.engine.dispose()


def import_all_models() -> None:
    """Import every domain's models so Base.metadata is complete (Alembic, tests)."""
    from agentguard.access import models as _access  # noqa: F401
    from agentguard.approvals import models as _approvals  # noqa: F401
    from agentguard.audit import models as _audit  # noqa: F401
    from agentguard.auth import models as _auth  # noqa: F401
    from agentguard.core import jobs as _jobs  # noqa: F401
    from agentguard.decisions import models as _decisions  # noqa: F401
    from agentguard.identity import models as _identity  # noqa: F401
    from agentguard.incidents import models as _incidents  # noqa: F401
    from agentguard.integrations import models as _integrations  # noqa: F401
    from agentguard.limits import models as _limits  # noqa: F401
    from agentguard.mcp import models as _mcp  # noqa: F401
    from agentguard.network import models as _network  # noqa: F401
    from agentguard.org import models as _org  # noqa: F401
    from agentguard.policies import models as _policies  # noqa: F401
    from agentguard.risk import models as _risk  # noqa: F401
    from agentguard.sandbox import models as _sandbox  # noqa: F401
    from agentguard.secrets import models as _secrets  # noqa: F401
    from agentguard.threats import models as _threats  # noqa: F401
    from agentguard.tools import models as _tools  # noqa: F401
    from agentguard.users import models as _users  # noqa: F401
