"""Tests for the filesystem watcher."""

import json
import time
from pathlib import Path

from agentsec.watcher import (
    WatchEvent,
    WatchResult,
    _build_snapshot,
    _diff_snapshots,
    _get_watch_paths,
    watch_and_scan,
)


def test_get_watch_paths_finds_config_files(tmp_path):
    """Watch paths should include existing config files."""
    (tmp_path / "openclaw.json").write_text("{}")
    (tmp_path / ".env").write_text("KEY=val")
    (tmp_path / "SOUL.md").write_text("# Soul")

    paths = _get_watch_paths(tmp_path)
    names = {p.name for p in paths}
    assert "openclaw.json" in names
    assert ".env" in names
    assert "SOUL.md" in names


def test_get_watch_paths_finds_subdirectories(tmp_path):
    """Watch paths should include agent config dirs and skill dirs."""
    oc_dir = tmp_path / ".openclaw"
    oc_dir.mkdir()
    (oc_dir / "openclaw.json").write_text("{}")
    ext_dir = oc_dir / "extensions"
    ext_dir.mkdir()
    (ext_dir / "some-skill").mkdir()

    paths = _get_watch_paths(tmp_path)
    assert oc_dir in paths
    assert ext_dir in paths


def test_build_snapshot_tracks_mtimes(tmp_path):
    f1 = tmp_path / "test.json"
    f1.write_text("{}")

    snapshot = _build_snapshot([f1])
    assert f1 in snapshot
    assert isinstance(snapshot[f1], float)


def test_diff_snapshots_detects_new_file(tmp_path):
    f1 = tmp_path / "a.json"
    f1.write_text("{}")

    old = {}
    new = _build_snapshot([f1])

    events = _diff_snapshots(old, new)
    assert len(events) == 1
    assert events[0].event_type == "created"
    assert events[0].path == f1


def test_diff_snapshots_detects_modification(tmp_path):
    f1 = tmp_path / "a.json"
    f1.write_text("{}")
    old = _build_snapshot([f1])

    time.sleep(0.05)
    f1.write_text('{"changed": true}')
    new = _build_snapshot([f1])

    events = _diff_snapshots(old, new)
    assert len(events) == 1
    assert events[0].event_type == "modified"


def test_diff_snapshots_detects_deletion(tmp_path):
    f1 = tmp_path / "a.json"
    f1.write_text("{}")
    old = _build_snapshot([f1])

    f1.unlink()
    new = _build_snapshot([f1])

    events = _diff_snapshots(old, new)
    assert len(events) == 1
    assert events[0].event_type == "deleted"


def test_diff_snapshots_no_changes(tmp_path):
    f1 = tmp_path / "a.json"
    f1.write_text("{}")
    snapshot = _build_snapshot([f1])

    events = _diff_snapshots(snapshot, snapshot)
    assert len(events) == 0


def test_watch_and_scan_initial_scan(tmp_path):
    """Watch should perform an initial baseline scan."""
    config = {"version": "2026.2.12"}
    (tmp_path / "openclaw.json").write_text(json.dumps(config))

    results = []

    def on_result(result: WatchResult):
        results.append(result)

    watch_and_scan(tmp_path, interval=0.1, on_result=on_result, max_iterations=0)

    assert len(results) == 1
    assert results[0].event.event_type == "initial_scan"
    assert isinstance(results[0].finding_count, int)
    assert isinstance(results[0].grade, str)


def test_watch_event_creation():
    event = WatchEvent(path=Path("/tmp/test"), event_type="created")
    assert event.event_type == "created"
    assert event.timestamp > 0
