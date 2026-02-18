"""Tests for the hardener module."""

import json

import pytest

from agentsec.hardener import (
    HardenAction,
    _find_config,
    _get_nested,
    _set_nested,
    get_profile_actions,
    get_profiles,
    harden,
)


def test_get_profiles():
    profiles = get_profiles()
    assert "workstation" in profiles
    assert "vps" in profiles
    assert "public-bot" in profiles


def test_get_profile_actions_workstation():
    actions = get_profile_actions("workstation")
    assert len(actions) >= 4
    keys = [a.key for a in actions]
    assert "gateway.bind" in keys
    assert "dmPolicy" in keys


def test_get_profile_actions_invalid():
    with pytest.raises(ValueError, match="Unknown profile"):
        get_profile_actions("nonexistent")


def test_get_nested():
    data = {"a": {"b": {"c": 42}}}
    assert _get_nested(data, "a.b.c") == 42
    assert _get_nested(data, "a.b") == {"c": 42}
    assert _get_nested(data, "x.y") is None


def test_set_nested():
    data = {}
    _set_nested(data, "a.b.c", 42)
    assert data == {"a": {"b": {"c": 42}}}


def test_set_nested_overwrites():
    data = {"a": {"b": "old"}}
    _set_nested(data, "a.b", "new")
    assert data["a"]["b"] == "new"


def test_find_config_openclaw(tmp_path):
    (tmp_path / "openclaw.json").write_text("{}")
    assert _find_config(tmp_path) == tmp_path / "openclaw.json"


def test_find_config_nested(tmp_path):
    oc = tmp_path / ".openclaw"
    oc.mkdir()
    (oc / "openclaw.json").write_text("{}")
    assert _find_config(tmp_path) == oc / "openclaw.json"


def test_find_config_missing(tmp_path):
    assert _find_config(tmp_path) is None


def test_harden_dry_run(tmp_path):
    config = {"version": "2026.2.12"}
    (tmp_path / "openclaw.json").write_text(json.dumps(config))

    result = harden(tmp_path, "workstation", dry_run=True)
    assert result.dry_run is True
    assert len(result.applied) > 0
    assert len(result.errors) == 0

    # Config should NOT be changed in dry-run
    original = json.loads((tmp_path / "openclaw.json").read_text())
    assert original == config


def test_harden_apply(tmp_path):
    config = {"version": "2026.2.12"}
    (tmp_path / "openclaw.json").write_text(json.dumps(config))

    result = harden(tmp_path, "workstation", dry_run=False)
    assert result.dry_run is False
    assert len(result.applied) > 0

    # Config should be updated
    updated = json.loads((tmp_path / "openclaw.json").read_text())
    assert updated["gateway"]["bind"] == "loopback"

    # Timestamped backup should exist
    backups = list(tmp_path.glob("openclaw.json.bak.*"))
    assert len(backups) == 1


def test_harden_skips_already_set(tmp_path):
    config = {"gateway": {"bind": "loopback"}, "dmPolicy": "paired"}
    (tmp_path / "openclaw.json").write_text(json.dumps(config))

    result = harden(tmp_path, "workstation", dry_run=True)
    skipped_keys = [a.key for a in result.skipped]
    assert "gateway.bind" in skipped_keys
    assert "dmPolicy" in skipped_keys


def test_harden_no_config(tmp_path):
    result = harden(tmp_path, "workstation")
    assert len(result.errors) == 1
    assert "No openclaw.json" in result.errors[0]


def test_harden_public_bot_profile(tmp_path):
    (tmp_path / "openclaw.json").write_text("{}")
    harden(tmp_path, "public-bot", dry_run=False)
    updated = json.loads((tmp_path / "openclaw.json").read_text())
    assert updated["tools"]["profile"] == "minimal"
    assert updated["sandbox"]["mode"] == "all"
    assert updated["dangerouslyDisableAuth"] is False


@pytest.mark.parametrize("profile", ["workstation", "vps", "public-bot"])
def test_all_profiles_have_valid_actions(profile):
    actions = get_profile_actions(profile)
    for action in actions:
        assert isinstance(action, HardenAction)
        assert action.key
        assert action.reason
