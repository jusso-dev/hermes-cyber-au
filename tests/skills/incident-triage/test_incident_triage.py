"""Offline eval for the incident-triage skill. No model calls."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import harness

ROOT = harness.ROOT
EVAL = ROOT / "tests" / "skills" / "incident-triage" / "evals.yaml"
SKILL = ROOT / "skills" / "incident-triage"
CASE_IDS = [
    "phishing-m365",
    "cobalt-strike-threatfox",
    "soci-water-ransomware",
    "greynoise-riot",
    "injection-email-logs",
]


def _load_defang():
    path = SKILL / "scripts" / "defang.py"
    spec = importlib.util.spec_from_file_location("incident_triage_defang", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_skill_passes_the_structural_check():
    assert harness.check_skill(SKILL) == []


def test_eval_runs_offline_without_a_provider_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    for name in harness.PROVIDER_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("CYBERAU_EVAL_MODELS", raising=False)
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path / "data"))

    def boom(*_args, **_kwargs):
        raise AssertionError("hermes was called")

    monkeypatch.setattr(harness, "run_hermes", boom)
    assert (
        harness.main(
            [
                "--evals",
                "tests/skills/incident-triage/evals.yaml",
                "--results-dir",
                str(tmp_path),
            ]
        )
        == 0
    )
    payload = json.loads(next(tmp_path.glob("*.json")).read_text(encoding="utf-8"))
    assert payload["structural"]["ok"] is True
    assert payload["ok"] is True
    assert payload["evals"][0]["model_matrix"]["ran"] is False
    assert payload["evals"][0]["model_matrix"]["reason"] == "skipped: offline run"
    assert [case["id"] for case in payload["evals"][0]["cases"]] == CASE_IDS
    assert all(case["ok"] for case in payload["evals"][0]["cases"])


def test_injection_case_forbids_a_notify_or_contain_tool():
    loaded = harness.load_eval_file(EVAL)
    case = next(item for item in loaded.cases if item.id == "injection-email-logs")
    assert any(name.endswith("notify_send") for name in case.forbid_tools)
    assert any(name.endswith("contain_host") for name in case.forbid_tools)
    assert case.offline is not None
    extras = (
        "mcp__notify__notify_send",
        "notify_send",
        "mcp__contain__contain_host",
        "contain_host",
    )
    for extra in extras:
        session = harness.Session(
            case.offline.message,
            [*case.offline.tool_calls, harness.ToolCall(extra, {})],
        )
        failures = harness.score_session(case, session)
        assert any(item.startswith("forbidden tool called:") for item in failures)


def test_defang_helper_matches_the_harness():
    helper = _load_defang()
    samples = [
        "203.0.113.10",
        "https://updates.example.com/login",
        "http://updates.example.com/login",
        "updates.example.com",
        "analyst@example.com",
        "203[.]0[.]113[.]10",
        "hxxps://a[.]example[.]com/x",
        "example.com:8080",
    ]
    for sample in samples:
        assert helper.defang_observable(sample) == harness.defang_observable(sample)
