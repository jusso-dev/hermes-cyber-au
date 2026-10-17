"""Structural checks and the offline sample eval. No model calls."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import harness  # noqa: E402

ROOT = harness.ROOT
SAMPLE_EVAL = ROOT / "tests" / "skills" / "harness-sample" / "evals.yaml"
CI = ROOT / "ci" / "workflows" / "ci.yml"


def _write_skill(directory: Path, name: str = "sample-skill", **replacements: str) -> Path:
    skill = directory / name
    (skill / "references").mkdir(parents=True)
    (skill / "references" / "note.md").write_text("A note.\n", encoding="utf-8")
    sections = replacements.get(
        "sections",
        "\n".join(
            f"## {title}\n\nText.\n"
            for title in (
                "When to Use",
                "Quick Reference",
                "Procedure",
                "Pitfalls",
                "Verification",
            )
        ),
    )
    text = f"""---
name: {replacements.get("front_name", name)}
description: "A long enough description for the structural check."
version: 0.1.0
author: Test Author
license: Apache-2.0
metadata:
  hermes:
    tags: [Testing]
---

# Title

{sections}
See [note](references/note.md).
{replacements.get("extra", "")}
"""
    (skill / "SKILL.md").write_text(text, encoding="utf-8")
    return skill


def test_shipped_sample_skill_passes_structural_check():
    assert harness.check_skill(ROOT / "skills" / "harness-sample") == []


def test_structural_check_passes_without_a_provider_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    for name in harness.PROVIDER_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("CYBERAU_EVAL_MODELS", raising=False)
    assert harness.main(["--structural", "--results-dir", str(tmp_path)]) == 0
    written = list(tmp_path.glob("*.json"))
    assert len(written) == 1
    payload = json.loads(written[0].read_text(encoding="utf-8"))
    assert payload["structural"]["ok"] is True
    assert payload["evals"] == []


def test_em_dash_missing_section_and_missing_reference_fail(tmp_path: Path):
    dashed = _write_skill(tmp_path, "dashed-skill", extra="A bad \u2014 dash.\n")
    assert any("em dash" in item for item in harness.check_skill(dashed))

    short = _write_skill(
        tmp_path,
        "short-skill",
        sections="## When to Use\n\nText.\n## Quick Reference\n\nText.\n",
    )
    assert any("level-2 sections" in item for item in harness.check_skill(short))

    missing = _write_skill(tmp_path, "missing-ref", extra="See [gone](references/missing.md).\n")
    assert any("does not exist" in item for item in harness.check_skill(missing))

    mismatched = _write_skill(tmp_path, "real-name", front_name="other-name")
    assert any("does not match" in item for item in harness.check_skill(mismatched))


def test_emoji_in_a_reference_fails(tmp_path: Path):
    skill = _write_skill(tmp_path, "emoji-skill")
    (skill / "references" / "note.md").write_text("Hello \u2705\n", encoding="utf-8")
    assert any("emoji" in item for item in harness.check_skill(skill))


def test_standard_and_workflow_do_not_use_an_em_dash():
    standard = (ROOT / "docs" / "skills" / "STANDARD.md").read_text(encoding="utf-8")
    workflow = CI.read_text(encoding="utf-8")
    assert "\u2014" not in standard
    assert "\u2014" not in workflow
    assert "harness.py --structural" in workflow
    step = workflow.split("Skill structural check", 1)[1].split("Validate skills", 1)[0]
    assert "secrets." not in step


def test_defang_observable_matches_the_standard():
    assert harness.defang_observable("203.0.113.10") == "203[.]0[.]113[.]10"
    assert (
        harness.defang_observable("https://updates.example.com/login")
        == "hxxps://updates[.]example[.]com/login"
    )
    assert (
        harness.defang_observable("http://updates.example.com/login")
        == "hxxp://updates[.]example[.]com/login"
    )
    assert harness.defang_observable("updates.example.com") == "updates[.]example[.]com"
    assert harness.defang_observable("analyst@example.com") == "analyst[@]example[.]com"


def test_sample_eval_runs_offline_and_writes_results(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    for name in harness.PROVIDER_ENV_VARS:
        monkeypatch.setenv(name, "")
    monkeypatch.setenv("CYBERAU_EVAL_MODELS", "should-not-run")

    def boom(*_args, **_kwargs):
        raise AssertionError("hermes was called")

    monkeypatch.setattr(harness, "run_hermes", boom)
    assert (
        harness.main(
            [
                "--evals",
                "tests/skills/harness-sample/evals.yaml",
                "--results-dir",
                str(tmp_path),
            ]
        )
        == 0
    )
    payload = json.loads(next(tmp_path.glob("*.json")).read_text(encoding="utf-8"))
    assert payload["ok"] is True
    assert payload["evals"][0]["model_matrix"]["ran"] is False
    assert [case["id"] for case in payload["evals"][0]["cases"]] == [
        "echo-fixture",
        "injection-not-acted-on",
        "kev-snapshot",
    ]


def test_live_flag_without_a_provider_key_stays_offline(monkeypatch: pytest.MonkeyPatch):
    for name in harness.PROVIDER_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("CYBERAU_EVAL_MODELS", "test-model")

    def boom(*_args, **_kwargs):
        raise AssertionError("hermes was called")

    monkeypatch.setattr(harness, "run_hermes", boom)
    report = harness.run_eval_file(SAMPLE_EVAL, live=True)
    assert report["model_matrix"]["reason"] == "skipped: no provider key"
    assert report["ok"] is True


def test_forbid_tools_fails_when_the_tool_is_called():
    eval_file = harness.load_eval_file(SAMPLE_EVAL)
    case = next(item for item in eval_file.cases if item.id == "injection-not-acted-on")
    assert case.offline is not None
    session = harness.Session(
        case.offline.message,
        [*case.offline.tool_calls, harness.ToolCall("mcp__stub__stub_send", {})],
    )
    failures = harness.score_session(case, session)
    assert any(item.startswith("forbidden tool called:") for item in failures)


def test_missing_fact_and_forbidden_claim_fail():
    eval_file = harness.load_eval_file(SAMPLE_EVAL)
    case = next(item for item in eval_file.cases if item.id == "echo-fixture")
    failures = harness.score_session(case, harness.Session("all clear", []))
    assert any(item.startswith("missing fact:") for item in failures)
    assert any(item.startswith("forbidden claim:") for item in failures)
    assert any(item.startswith("expected tool not called:") for item in failures)


def test_hermes_argv_is_the_non_interactive_chat_query():
    argv = harness.hermes_argv("cyber-au-eval", "test-model", "harness-sample", Path("prompt.txt"))
    assert argv[1:6] == ["-p", "cyber-au-eval", "-m", "test-model", "chat"]
    assert "--query-file" in argv
    assert "--oneshot" in argv
    assert "stream-json" in argv
    assert argv[-2:] == ["--skills", "harness-sample"]


def test_parse_stream_json_reads_tool_use_and_result():
    stdout = "\n".join(
        [
            json.dumps({"type": "tool_use", "name": "stub_ping", "input": {"echo": "x"}}),
            json.dumps({"type": "result", "text": "done x"}),
        ]
    )
    session = harness.parse_stream_json(stdout)
    assert session.message == "done x"
    assert session.tool_calls[0].name == "stub_ping"
    assert harness.same_tool("mcp__stub__stub_ping", "stub_ping")


def test_results_directory_is_gitignored():
    text = (ROOT / ".gitignore").read_text(encoding="utf-8")
    assert "tests/skills/results/" in text
