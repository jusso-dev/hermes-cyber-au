"""Offline eval for the executive briefing skill. No model calls."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import harness  # noqa: E402

ROOT = harness.ROOT
EVAL = ROOT / "tests" / "skills" / "executive-briefing" / "evals.yaml"
SEND = "mcp__briefing__briefing_send"
CASE_IDS = (
    "weekly-kev-and-asd-alert",
    "board-ransomware",
    "essentials-progress",
    "exposure-counts-only",
    "injection-do-not-send",
    "monthly-report-demo",
)


def test_send_tool_is_forbidden_in_every_case():
    eval_file = harness.load_eval_file(EVAL)
    assert eval_file.skill == "executive-briefing"
    assert [case.id for case in eval_file.cases] == list(CASE_IDS)
    injection = next(case for case in eval_file.cases if case.id == "injection-do-not-send")
    assert SEND in injection.forbid_tools
    assert "mcp__stub__stub_ping" in injection.expect_tools
    for case in eval_file.cases:
        assert SEND in case.forbid_tools
        assert case.offline is not None
        assert all(call.name != SEND for call in case.offline.tool_calls)
        assert "\u2014" not in case.offline.message


def test_offline_pages_fit_one_page():
    for case in harness.load_eval_file(EVAL).cases:
        # A report template's appendices (sources, limitations, evidence) follow the page.
        page = case.offline.message.split("## Appendix A", 1)[0]
        assert len(page.split()) <= 450, case.id


def test_monthly_report_case_is_the_real_demo_report(tmp_path, monkeypatch, capsys):
    """The offline answer is exactly what the report command prints on demo data."""
    import importlib.util

    from cyberau_common.cli import main

    plugin = ROOT / "plugins" / "cyber-au"
    monkeypatch.syspath_prepend(str(plugin))
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CYBERAU_E8_SNAPSHOT", str(ROOT / "mcp" / "asd-essentials" / "data"))
    monkeypatch.setenv("CYBERAU_TODAY", "2026-11-03")
    spec = importlib.util.spec_from_file_location(
        "cyberau_demo_eval",
        plugin / "demo" / "__init__.py",
        submodule_search_locations=[str(plugin / "demo")],
    )
    demo = importlib.util.module_from_spec(spec)
    sys.modules["cyberau_demo_eval"] = demo
    spec.loader.exec_module(demo)
    summary = demo.load(tmp_path / "demo")
    case = next(c for c in harness.load_eval_file(EVAL).cases if c.id == "monthly-report-demo")
    argv = [
        "store",
        "report",
        "monthly",
        "--month",
        "2026-10",
        "--path",
        summary["path"],
        "--obligations",
        summary["obligations"],
        "--as-of",
        "2026-11-03",
    ]
    try:
        assert main(argv) == 0
    finally:
        from store.db import close_store

        close_store(summary["path"])
    assert capsys.readouterr().out.strip() == case.offline.message.strip()
