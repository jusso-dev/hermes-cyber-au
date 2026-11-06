"""Offline checks for skill data regeneration. Fetches use stand-in connectors."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import types
from datetime import date
from pathlib import Path

import pytest
import yaml
from cyberau_common import regen
from cyberau_common.cli import main
from cyberau_common.regen import SOURCES, missing_message, regen_main

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "skill-data-regen.yml"
TOKEN = "ghp_supersecretvalue123456"

PINS = {
    "actions/checkout": ("3d3c42e5aac5ba805825da76410c181273ba90b1", "v7.0.1"),
    "actions/setup-python": ("5fda3b95a4ea91299a34e894583c3862153e4b97", "v7.0.0"),
    "actions/upload-artifact": ("cf430e030ddbb5b0abf93d22962f4752f3646cd9", "v7.0.2"),
}


def _catalog(directory: Path, control_id: str) -> None:
    directory.mkdir(parents=True)
    payload = {"catalog": {"groups": [{"controls": [{"id": control_id}]}]}}
    (directory / "ISM_catalog.json").write_text(json.dumps(payload), encoding="utf-8")


def _ism_tree(root: Path) -> Path:
    data = root / "mcp" / "asd-ism" / "data"
    _catalog(data / "v2026.06.18", "ism-0001")
    _catalog(data / "v2026.09.4", "ism-1173")
    _catalog(data / "v2025.01.1", "ism-0002")
    releases = {
        "releases": [
            {"tag_name": "v2026.06.18", "published_at": "2026-06-18T00:00:00Z"},
            {"tag_name": "v2026.09.4", "published_at": "2026-09-03T00:00:00Z"},
            {"tag_name": "v2025.01.1", "published_at": "2025-01-01T00:00:00Z"},
        ]
    }
    (data / "releases.json").write_text(json.dumps(releases), encoding="utf-8")
    return data


def test_cli_regen_forwards_flags(tmp_path, capsys, monkeypatch):
    _ism_tree(tmp_path)
    monkeypatch.chdir(tmp_path)
    assert main(["regen", "ism"]) == 0
    assert "Regenerated ISM data in mcp/asd-ism/data" in capsys.readouterr().out
    assert main(["regen", "ism"]) == 0
    assert "ISM data is unchanged." in capsys.readouterr().out
    assert main(["regen", "ism", "--force"]) == 0
    assert "Regenerated ISM data" in capsys.readouterr().out
    assert main(["regen", "e8"]) == 1
    assert missing_message("e8") in capsys.readouterr().err


def test_missing_data_directories_are_errors(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", TOKEN)
    monkeypatch.setenv("GH_TOKEN", TOKEN)
    for source in SOURCES:
        assert regen_main([source], root=tmp_path) == 1
        err = capsys.readouterr().err
        assert missing_message(source) in err
        assert TOKEN not in err
        assert not (tmp_path / "mcp").exists()


def test_every_source_points_at_a_real_connector_directory():
    for source, spec in SOURCES.items():
        assert (ROOT / spec.data_dir).is_dir(), source
        assert (ROOT / spec.data_dir).parent.joinpath("pyproject.toml").is_file(), source
    assert "attack" not in SOURCES
    assert "sigma" not in SOURCES


def test_shipped_checkout_keeps_its_ism_data():
    assert (ROOT / "mcp" / "asd-ism" / "data").is_dir()


def test_ism_keeps_two_local_releases_without_a_network(tmp_path, capsys):
    data = _ism_tree(tmp_path)
    assert regen_main(["ism", "--keep", "2"], root=tmp_path) == 0
    message = capsys.readouterr().out
    assert "Regenerated ISM data in mcp/asd-ism/data (kept v2026.09.4, v2026.06.18)." in message
    assert (data / "v2026.09.4" / "ISM_catalog.json").is_file()
    assert (data / "v2026.06.18" / "ISM_catalog.json").is_file()
    assert not (data / "v2025.01.1").exists()
    assert (data / "releases.json").is_file()
    manifest = json.loads((data / "regen.json").read_text(encoding="utf-8"))
    assert manifest["kept"] == ["v2026.09.4", "v2026.06.18"]
    assert manifest["catalogues"]["v2026.09.4"]["controls"] == 1
    assert "http" not in json.dumps(manifest)

    assert regen_main(["ism", "--keep", "2"], root=tmp_path) == 0
    assert "ISM data is unchanged." in capsys.readouterr().out
    assert regen_main(["ism", "--keep", "2", "--force"], root=tmp_path) == 0
    assert "Regenerated ISM data" in capsys.readouterr().out


def test_published_date_wins_over_version_name(tmp_path):
    data = tmp_path / "mcp" / "asd-ism" / "data"
    _catalog(data / "v2026.09.4", "ism-1173")
    _catalog(data / "v2020.01.1", "ism-0001")
    releases = {
        "releases": [
            {"tag_name": "v2026.09.4", "published_at": "2020-01-01T00:00:00Z"},
            {"tag_name": "v2020.01.1", "published_at": "2026-12-01T00:00:00Z"},
        ]
    }
    (data / "releases.json").write_text(json.dumps(releases), encoding="utf-8")
    assert regen_main(["ism", "--keep", "1"], root=tmp_path) == 0
    manifest = json.loads((data / "regen.json").read_text(encoding="utf-8"))
    assert manifest["kept"] == ["v2020.01.1"]
    assert not (data / "v2026.09.4").exists()


def test_e8_regen_hashes_local_files(tmp_path, capsys):
    data = tmp_path / "mcp" / "asd-essentials" / "data"
    data.mkdir(parents=True)
    (data / "baseline.txt").write_text("maturity\n", encoding="utf-8")
    assert regen_main(["e8"], root=tmp_path) == 0
    assert "Regenerated Essential Eight data in mcp/asd-essentials/data." in capsys.readouterr().out
    manifest = json.loads((data / "regen.json").read_text(encoding="utf-8"))
    assert manifest["files"][0]["path"] == "mcp/asd-essentials/data/baseline.txt"
    assert regen_main(["e8"], root=tmp_path) == 0
    assert "Essential Eight data is unchanged." in capsys.readouterr().out


def test_empty_data_directory_fails(tmp_path, capsys):
    (tmp_path / "mcp" / "au-regulatory" / "data").mkdir(parents=True)
    assert regen_main(["aureg"], root=tmp_path) == 1
    assert "has no files" in capsys.readouterr().err


def _fake_connector(monkeypatch, write):
    """Stand in for cyberau_au_regulatory.source so --fetch runs without a network."""
    module = types.ModuleType("fake_aureg")
    calls = []

    def rebuild_shipped_snapshot(destination: Path) -> dict:
        calls.append(destination)
        write(destination)
        return {}

    module.rebuild_shipped_snapshot = rebuild_shipped_snapshot
    monkeypatch.setitem(sys.modules, "fake_aureg", module)
    spec = SOURCES["aureg"]
    monkeypatch.setitem(
        SOURCES, "aureg", regen.Source(spec.label, spec.data_dir, "fake_aureg", spec.skill)
    )
    return calls


def _obligations(directory: Path, day: str, rule: str) -> None:
    for old in directory.glob("obligations-*.json"):
        old.unlink()
    payload = {"retrieved_at": day, "obligations": [{"rule": rule}]}
    (directory / f"obligations-{day}.json").write_text(json.dumps(payload), encoding="utf-8")


def test_fetch_keeps_fresh_unchanged_data(tmp_path, capsys, monkeypatch):
    data = tmp_path / "mcp" / "au-regulatory" / "data"
    data.mkdir(parents=True)
    _obligations(data, "2026-10-10", "report within 72 hours")
    calls = _fake_connector(
        monkeypatch, lambda d: _obligations(d, "2026-10-18", "report within 72 hours")
    )
    assert regen.regenerate(tmp_path, "aureg", fetch=True, today=date(2026, 10, 18)) == 0
    assert calls and calls[0] != data
    assert "upstream is unchanged" in capsys.readouterr().out
    assert [p.name for p in data.glob("obligations-*.json")] == ["obligations-2026-10-10.json"]


def test_fetch_writes_changed_data(tmp_path, capsys, monkeypatch):
    data = tmp_path / "mcp" / "au-regulatory" / "data"
    data.mkdir(parents=True)
    _obligations(data, "2026-10-10", "report within 72 hours")
    _fake_connector(monkeypatch, lambda d: _obligations(d, "2026-10-18", "report within 24 hours"))
    assert regen.regenerate(tmp_path, "aureg", fetch=True, today=date(2026, 10, 18)) == 0
    assert "upstream changed" in capsys.readouterr().out
    assert [p.name for p in data.glob("obligations-*.json")] == ["obligations-2026-10-18.json"]
    assert (data / "regen.json").is_file()


def test_fetch_restamps_unchanged_data_before_it_expires(tmp_path, capsys, monkeypatch):
    data = tmp_path / "mcp" / "au-regulatory" / "data"
    data.mkdir(parents=True)
    _obligations(data, "2026-09-01", "report within 72 hours")
    _fake_connector(monkeypatch, lambda d: _obligations(d, "2026-10-18", "report within 72 hours"))
    assert regen.regenerate(tmp_path, "aureg", fetch=True, today=date(2026, 10, 18)) == 0
    assert "Refreshed the retrieval date" in capsys.readouterr().out
    assert [p.name for p in data.glob("obligations-*.json")] == ["obligations-2026-10-18.json"]


def test_failed_fetch_leaves_the_shipped_data_alone(tmp_path, capsys, monkeypatch):
    data = tmp_path / "mcp" / "au-regulatory" / "data"
    data.mkdir(parents=True)
    _obligations(data, "2026-10-10", "report within 72 hours")
    before = (data / "obligations-2026-10-10.json").read_bytes()

    def broken(destination: Path) -> None:
        _obligations(destination, "2026-10-18", "half written")
        raise RuntimeError("upstream refused the request")

    _fake_connector(monkeypatch, broken)
    assert regen_main(["aureg", "--fetch"], root=tmp_path) == 1
    assert "upstream refused the request" in capsys.readouterr().err
    assert (data / "obligations-2026-10-10.json").read_bytes() == before
    assert not (data / "regen.json").exists()


def test_fetch_without_a_rebuild_function_fails(tmp_path, capsys, monkeypatch):
    data = tmp_path / "mcp" / "au-regulatory" / "data"
    data.mkdir(parents=True)
    _obligations(data, "2026-10-10", "rule")
    monkeypatch.setitem(sys.modules, "fake_empty", types.ModuleType("fake_empty"))
    spec = SOURCES["aureg"]
    monkeypatch.setitem(SOURCES, "aureg", regen.Source(spec.label, spec.data_dir, "fake_empty"))
    assert regen_main(["aureg", "--fetch"], root=tmp_path) == 1
    assert "has no rebuild_shipped_snapshot" in capsys.readouterr().err


def test_unknown_source_and_bad_keep(tmp_path, capsys):
    assert regen_main(["nope"], root=tmp_path) == 2
    assert "regen does not know nope." in capsys.readouterr().err
    assert regen_main(["ism", "--keep", "0"], root=tmp_path) == 2


def test_empty_ism_directory_fails(tmp_path, capsys):
    (tmp_path / "mcp" / "asd-ism" / "data").mkdir(parents=True)
    assert regen_main(["ism"], root=tmp_path) == 1
    assert "no catalogues" in capsys.readouterr().err


def test_shipped_ism_has_two_catalogues():
    data = ROOT / "mcp" / "asd-ism" / "data"
    releases = [path for path in data.iterdir() if (path / "ISM_catalog.json").is_file()]
    assert len(releases) == 2
    # Full catalogues, not excerpts.
    for path in releases:
        payload = json.loads((path / "ISM_catalog.json").read_text(encoding="utf-8"))
        assert regen.count_controls(payload) > 500
        assert len(list(path.glob("ISM_*-baseline_profile.json"))) == 8


def test_regen_module_does_not_fetch():
    text = (ROOT / "mcp" / "common" / "src" / "cyberau_common" / "regen.py").read_text(
        encoding="utf-8"
    )
    for banned in ("httpx", "urlopen", "requests", "socket", "curl", "wget"):
        assert banned not in text


def test_workflow_skips_missing_sources_and_pins_actions():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "\u2014" not in text
    assert "\u2013" not in text
    assert "Skipping regen" not in text
    assert "absent. Skipping" not in text
    for source, spec in SOURCES.items():
        command = f"cyberau-mcp regen {source}" + (" --fetch" if source != "aureg" else "")
        assert command in text
        assert spec.data_dir in text
    for gone in ("mcp/e8/", "mcp/aureg/", "mcp/attack/", "mcp/ism/"):
        assert gone not in text
    assert "parser-check" not in text
    assert "tools/build_skill_references.py --write PR_BODY.md" in text
    assert "uv run --project mcp pytest -q tests/skills tests/data --block-network" in text
    assert "${{ github.token }}" not in text
    for banned in (
        "ghp_",
        "github_pat_",
        "AKIA",
        "curl ",
        "wget ",
        "api.github.com",
        "cyber.gov.au",
    ):
        assert banned not in text
    pinned = re.findall(r"uses: (actions/[\w.-]+)@([0-9a-f]{40}) # (v\d+\.\d+\.\d+)", text)
    assert pinned
    for action, sha, version in pinned:
        expect_sha, expect_version = PINS[action]
        assert sha == expect_sha
        assert version == expect_version
    assert not re.search(r"uses: actions/[\w.-]+@v\d+", text)
    assert "./.github/workflows/data-update-pr.yml" in text
    assert "secrets: inherit" not in text
    assert "DATA_PR_TOKEN: ${{ secrets.DATA_PR_TOKEN }}" in text
    document = yaml.safe_load(text)
    assert document["permissions"] == {"contents": "read"}
    assert set(document["jobs"]) == {"regen", "fetch-failed", "pr"}


def test_actionlint_on_the_copied_layout():
    binary = shutil.which("actionlint")
    if binary is None:
        pytest.skip("actionlint is absent")
    destination = Path("/tmp") / "skill-data-regen-actionlint"
    workflow_dir = destination / ".github" / "workflows"
    if destination.exists():
        shutil.rmtree(destination)
    workflow_dir.mkdir(parents=True)
    shutil.copy(WORKFLOW, workflow_dir / "skill-data-regen.yml")
    shutil.copy(
        ROOT / ".github" / "workflows" / "data-update-pr.yml",
        workflow_dir / "data-update-pr.yml",
    )
    completed = subprocess.run(
        [binary, str(workflow_dir / "skill-data-regen.yml")],
        check=False,
        text=True,
        capture_output=True,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr


def test_obligations_workflow_does_not_claim_unsupported_live_refresh():
    workflow = (ROOT / ".github/workflows/skill-data-regen.yml").read_text()
    assert "regen aureg --fetch" not in workflow
    assert "regen aureg" in workflow
    assert "reviewed reference data" in workflow
