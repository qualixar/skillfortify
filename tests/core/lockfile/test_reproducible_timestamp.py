"""A lockfile is committed to version control, so it must be reproducible.

The document records when it was generated, which is useful provenance but
makes two runs over identical inputs differ. Builds that need byte-identical
output set ``SOURCE_DATE_EPOCH``, the reproducible-builds convention, and the
lockfile honours it.
"""

from __future__ import annotations

import json

import pytest

from skillfortify.core.lockfile.lockfile import Lockfile


@pytest.fixture
def lockfile() -> Lockfile:
    return Lockfile()


def test_generated_at_varies_between_runs_by_default(lockfile, monkeypatch):
    """Without the variable set, the timestamp reflects the moment of writing."""
    monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)

    first = json.loads(lockfile.to_json())["generated_at"]

    assert first.endswith("+00:00")


def test_source_date_epoch_pins_the_timestamp(lockfile, monkeypatch):
    """With the variable set, generation is byte-identical across runs."""
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")

    first = lockfile.to_json()
    second = lockfile.to_json()

    assert first == second
    assert json.loads(first)["generated_at"] == "2023-11-14T22:13:20+00:00"


def test_invalid_source_date_epoch_falls_back_to_now(lockfile, monkeypatch):
    """A malformed value must not fail the build; provenance degrades instead."""
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "not-a-number")

    generated_at = json.loads(lockfile.to_json())["generated_at"]

    assert generated_at.endswith("+00:00")


def test_pinned_lockfiles_are_byte_identical_for_identical_inputs(monkeypatch):
    """Two independently constructed lockfiles agree byte for byte."""
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")

    assert Lockfile().to_json() == Lockfile().to_json()
