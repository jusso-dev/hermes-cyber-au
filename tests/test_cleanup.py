"""Retention touches only disposable artefacts and preserves operator choices."""

from __future__ import annotations

import importlib.util
import json
import os
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cleanup = load("cyberau_cleanup")
activation = load("cyberau_enable_maintenance")
NOW = 2_000_000_000


def put(path, age=60):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"keep or prune")
    os.utime(path, (NOW - age * cleanup.DAY,) * 2)
    return path


def test_rules_backups_and_output_are_bounded_with_dry_run(tmp_path):
    data = tmp_path / "plugin-data/cyber-au"
    for i in range(4):
        put(data / f"v{i}" / "sigma_core.zip", age=60 + i)
    for i in range(1, 10):
        put(data / "backups" / f"202601{i:02d}T000000Z-pre-migrate-intel.sqlite", age=60 + i)
        put(tmp_path / "intel/snapshots" / f"public-2026-01-{i:02d}.sqlite.zst", age=60 + i)
        put(
            tmp_path / "cron/output/cyberau-ingest-feodo" / f"2026-01-{i:02d}_00-00-00.md",
            age=60 + i,
        )
    custom = put(data / "custom" / "my-rule.yml")
    skill = put(tmp_path / "skills/custom/SKILL.md")
    brief = put(tmp_path / "cron/output/cyberau-morning-brief/2026-01-01_00-00-00.md")
    unknown = put(data / "backups/manual.sqlite")
    preview = cleanup.cleanup(tmp_path, now=NOW)
    assert preview["files"] == 8
    assert (data / "v3/sigma_core.zip").exists()
    actual = cleanup.cleanup(tmp_path, now=NOW, apply=True)
    assert actual["files"] == preview["files"]
    assert actual["file_bytes"] == preview["file_bytes"]
    assert (data / "v0/sigma_core.zip").exists()
    assert (data / "v1/sigma_core.zip").exists()
    assert not (data / "v2/sigma_core.zip").exists()
    assert all(p.exists() for p in (custom, skill, brief, unknown))
    assert cleanup.cleanup(tmp_path, now=NOW, apply=True)["files"] == 0


def test_recent_release_is_kept_even_beyond_two(tmp_path):
    for i in range(4):
        put(tmp_path / f"plugin-data/cyber-au/v{i}/sigma_core.zip", age=i)
    assert cleanup.cleanup(tmp_path, now=NOW, apply=True)["files"] == 0


def test_cache_expires_past_ttl_and_grace_and_reclaims_pages(tmp_path):
    path = tmp_path / "plugin-data/cyber-au/http_cache.sqlite"
    path.parent.mkdir(parents=True)
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE http_cache (key TEXT, fetched_at REAL, ttl INTEGER, body BLOB)")
        conn.executemany(
            "INSERT INTO http_cache VALUES (?, ?, ?, ?)",
            [
                ("old", NOW - 60 * cleanup.DAY, 3600, bytes(1000000)),
                ("stale-fallback", NOW - 2 * cleanup.DAY, 3600, b"stale"),
                ("fresh", NOW, 3600, b"fresh"),
            ],
        )
    assert cleanup.cleanup(tmp_path, now=NOW)["cache_rows"] == 1
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT count(*) FROM http_cache").fetchone()[0] == 3
    result = cleanup.cleanup(tmp_path, now=NOW, apply=True)
    assert result["cache_rows"] == 1
    assert result["cache_bytes_reclaimed"] > 900000
    with sqlite3.connect(path) as conn:
        assert {row[0] for row in conn.execute("SELECT key FROM http_cache")} == {
            "fresh",
            "stale-fallback",
        }


def test_symlinked_directories_and_files_are_not_pruned(tmp_path):
    profile = tmp_path / "profile"
    outside = put(tmp_path / "outside/sigma_core.zip")
    data = profile / "plugin-data/cyber-au"
    data.mkdir(parents=True)
    (data / "v0").symlink_to(outside.parent, target_is_directory=True)
    (data / "http_cache.sqlite").symlink_to(outside)
    with pytest.raises(ValueError, match="symlinks"):
        cleanup.cleanup(profile, now=NOW, apply=True)
    assert outside.exists()
    (data / "http_cache.sqlite").unlink()
    assert cleanup.cleanup(profile, now=NOW, apply=True)["files"] == 0
    assert outside.exists()


def test_bootstrap_enables_only_seeded_maintenance_once(tmp_path, monkeypatch):
    jobs = []
    for job_id in (*activation.JOBS, "cyberau-morning-brief"):
        jobs.append(
            {
                "id": job_id,
                "paused_reason": activation.SEEDED_REASON,
                "script": job_id.replace("-", "_") + ".sh",
                "no_agent": True,
                "deliver": "local",
            }
        )
    path = tmp_path / "cron/jobs.json"
    path.parent.mkdir()
    path.write_text(json.dumps({"jobs": jobs}))
    calls = []

    def run(command, **kwargs):
        if command[-2:] == ["config", "path"]:
            return SimpleNamespace(stdout=str(tmp_path / "config.yaml"))
        calls.append(command)

    monkeypatch.setattr(activation.subprocess, "run", run)
    activation.enable(tmp_path, "test")
    assert [call[-1] for call in calls] == list(activation.JOBS)
    activation.enable(tmp_path, "test")
    assert len(calls) == 2


def test_bootstrap_preserves_manual_pause_and_used_jobs(tmp_path, monkeypatch):
    path = tmp_path / "cron/jobs.json"
    path.parent.mkdir()
    path.write_text(
        json.dumps(
            {
                "jobs": [
                    {"id": activation.JOBS[0], "paused_reason": "Paused by operator"},
                    {
                        "id": activation.JOBS[1],
                        "paused_reason": activation.SEEDED_REASON,
                        "last_run_at": "2026-01-01",
                    },
                ]
            }
        )
    )
    monkeypatch.setattr(
        activation.subprocess, "run", lambda *a, **kw: pytest.fail("must not resume")
    )
    activation.enable(tmp_path, "test")
