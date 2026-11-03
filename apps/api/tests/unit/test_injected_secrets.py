"""The leak scan's memory of injected secret values stays bounded in size and age."""

from __future__ import annotations

import uuid

import pytest

from agentguard.secrets import service


def test_injected_values_are_remembered_per_org() -> None:
    org, other = uuid.uuid4(), uuid.uuid4()
    service._note_injected(org, "vault_value_1", None)
    service._note_injected(org, "vault_value_1", "previous_value")
    assert sorted(service.injected_values(org)) == ["previous_value", "vault_value_1"]
    assert service.injected_values(other) == []


def test_injected_values_are_capped_oldest_first(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(service, "INJECTED_MAX_PER_ORG", 3)
    org = uuid.uuid4()
    for i in range(5):
        service._note_injected(org, f"value_{i}")
    service._note_injected(org, "value_2")
    service._note_injected(org, "value_5")
    assert service.injected_values(org) == ["value_4", "value_2", "value_5"]


def test_injected_values_expire(monkeypatch: pytest.MonkeyPatch) -> None:
    org = uuid.uuid4()
    clock = [1000.0]
    monkeypatch.setattr("agentguard.secrets.service.time.monotonic", lambda: clock[0])
    service._note_injected(org, "old_value")
    clock[0] += service.INJECTED_TTL_S + 1
    service._note_injected(org, "new_value")
    assert service.injected_values(org) == ["new_value"]
