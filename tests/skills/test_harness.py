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
CI = ROOT / ".github" / "workflows" / "ci.yml"


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
    assert argv[1:5] == ["-p", "cyber-au-eval", "chat", "-m"]
    assert "--query-file" in argv
    assert "-Q" in argv
    assert "--oneshot" not in argv
    assert "--format" not in argv
    assert argv[-2:] == ["-s", "harness-sample"]


def test_live_session_cannot_pass_a_tool_assertion_unscored():
    eval_file = harness.load_eval_file(SAMPLE_EVAL)
    case = next(item for item in eval_file.cases if item.id == "echo-fixture")
    message = case.offline.message  # type: ignore[union-attr]
    failures = harness.score_session(case, harness.Session(message, [], tools_observed=False))
    assert any("not observable" in item for item in failures)


def test_forbid_tools_ignores_the_server_prefix():
    forbidden = "mcp__stub__stub_send"
    assert harness.forbidden_tool_called(forbidden, "mcp__other__stub_send")
    assert harness.forbidden_tool_called(forbidden, "mcp_stub_stub_send")
    assert harness.forbidden_tool_called(forbidden, "stub_send")
    assert not harness.forbidden_tool_called(forbidden, "mcp__stub__stub_ping")


def test_malformed_citation_fails():
    case = harness.EvalCase("c", "q", ["x"], [], [], [], [], None)
    bad = harness.Session("x\nSource: hermes-cyber-au stub, none, retrieved yesterday.")
    assert any(item.startswith("malformed citation") for item in harness.score_session(case, bad))
    good = harness.Session("x\nSource: hermes-cyber-au stub, none, retrieved 2026-10-17.")
    assert harness.score_session(case, good) == []


def test_bad_yaml_frontmatter_is_a_problem_not_a_crash(tmp_path: Path):
    skill = tmp_path / "bad-yaml"
    skill.mkdir()
    (skill / "SKILL.md").write_text("---\nname: [unclosed\n---\n# Title\n", encoding="utf-8")
    assert any("not valid YAML" in item for item in harness.check_skill(skill))


def test_links_cannot_leave_the_skill_directory(tmp_path: Path):
    (tmp_path / "outside.md").write_text("x\n", encoding="utf-8")
    skill = _write_skill(tmp_path, "escape", extra="[up](../outside.md) [abs](/etc/hosts)\n")
    problems = harness.check_skill(skill)
    assert sum("outside the skill directory" in item for item in problems) == 2


def test_emoji_ranges_cover_enclosed_and_symbol_blocks():
    for char in ("\U0001f197", "\U0001f170", "\u2b50", "\u2705"):
        assert harness.EMOJI_RE.search(char)


def test_defang_covers_hosts_with_a_port_or_path():
    assert harness.defang_observable("updates.example.com/login") == "updates[.]example[.]com/login"
    assert harness.defang_observable("example.com:8080") == "example[.]com:8080"
    assert harness.defang_observable("hxxps://a[.]example[.]com/x") == "hxxps://a[.]example[.]com/x"
    assert harness.defang_observable("203[.]0[.]113[.]10") == "203[.]0[.]113[.]10"


def test_case_with_no_assertion_is_rejected(tmp_path: Path):
    path = tmp_path / "evals.yaml"
    path.write_text('skill: x\ncases:\n  - id: empty\n    input: "q"\n', encoding="utf-8")
    with pytest.raises(ValueError, match="asserts nothing"):
        harness.load_eval_file(path)


def test_fixture_path_escape_is_a_failure_not_a_crash():
    step = harness.ReplayStep("stub", "stub_ping", {}, {"CYBERAU_FIXTURE": "/etc/passwd"}, None)
    case = harness.EvalCase("c", "q", ["x"], [], [], [], [step], None)
    failures = harness.replay_case(case, SAMPLE_EVAL)
    assert failures and "escapes the repository" in failures[0]


def test_fixture_scrub_flags_secrets_and_real_addresses(tmp_path: Path):
    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    (fixtures / "a.json").write_text(
        '{"mail": "someone@corp.com.au", "key": "AKIAABCDEFGHIJKLMNOP"}\n', encoding="utf-8"
    )
    (fixtures / "ok.json").write_text('{"mail": "a@example.com"}\n', encoding="utf-8")
    problems = harness.check_fixtures([tmp_path])
    assert any("non-reserved domain" in item for item in problems)
    assert any("AWS access key id" in item for item in problems)
    assert not any("ok.json" in item for item in problems)
    assert harness.check_fixtures() == []


def test_results_directory_is_gitignored():
    text = (ROOT / ".gitignore").read_text(encoding="utf-8")
    assert "tests/skills/results/" in text


def test_every_shipped_skill_has_an_eval_and_ci_runs_the_full_set():
    skills = {
        path.name
        for path in (ROOT / "skills").iterdir()
        if path.is_dir() and (path / "SKILL.md").is_file()
    }
    evaluated = {path.parent.name for path in harness.discover_eval_files()}
    assert evaluated == skills

    workflow = CI.read_text(encoding="utf-8")
    eval_step = workflow.split("Offline skill evals (no model key)", 1)[1].split(
        "STIX export validates", 1
    )[0]
    assert "python tests/skills/harness.py" in eval_step
    assert "--evals" not in eval_step
