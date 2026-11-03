"""Schema objects the models do not describe (shared by env.py and the drift test)."""

from __future__ import annotations


def include_object(
    obj: object, name: str | None, type_: str, reflected: bool, compare_to: object
) -> bool:
    """Every schema object is described by the models; the append-only rules are triggers,
    which autogenerate does not compare."""
    return True
