from __future__ import annotations

import pytest

from aws_hygiene_auditor import regions


class FakeEc2:
    def call(self, operation: str, **kwargs: object) -> dict[str, object]:
        return {
            "Regions": [
                {"RegionName": "us-east-1", "OptInStatus": "opt-in-not-required"},
                {"RegionName": "eu-central-1", "OptInStatus": "opted-in"},
                {"RegionName": "ap-east-1", "OptInStatus": "not-opted-in"},
            ]
        }


def test_enabled_region_discovery(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(regions, "client", lambda *_args: FakeEc2())
    enabled, skipped = regions.discover_regions(object())  # type: ignore[arg-type]
    assert enabled == ["eu-central-1", "us-east-1"]
    assert skipped == ["ap-east-1"]


def test_explicit_region_filtering(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(regions, "client", lambda *_args: FakeEc2())
    enabled, _ = regions.discover_regions(object(), ("eu-central-1",))  # type: ignore[arg-type]
    assert enabled == ["eu-central-1"]


def test_disabled_requested_region_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(regions, "client", lambda *_args: FakeEc2())
    with pytest.raises(ValueError):
        regions.discover_regions(object(), ("ap-east-1",))  # type: ignore[arg-type]
