"""Periodic background tasks, registered by the domains that own them.

Each task runs at most every ``every_s`` seconds. With several worker replicas, a Postgres
advisory lock per task makes exactly one replica run it each time; the others skip. Tasks
must still be idempotent (a run can be cut short by a restart).
"""

from __future__ import annotations

import hashlib
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agentguard.core.container import Container

# Returns how many items it handled (for logs and metrics).
TaskFn = Callable[["Container"], Awaitable[int]]


@dataclass(frozen=True)
class Task:
    name: str
    fn: TaskFn
    every_s: float

    @property
    def lock_id(self) -> int:
        digest = hashlib.blake2b(self.name.encode(), digest_size=8).digest()
        return int.from_bytes(digest, "big", signed=True)


_TASKS: dict[str, Task] = {}


def periodic(name: str, every_s: float = 30.0) -> Callable[[TaskFn], TaskFn]:
    def register(fn: TaskFn) -> TaskFn:
        _TASKS[name] = Task(name, fn, every_s)
        return fn

    return register


def tasks() -> dict[str, Task]:
    return dict(_TASKS)
