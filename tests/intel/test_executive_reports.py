"""Monthly and incident executive reports on demo data (#170). Offline."""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from datetime import date
from pathlib import Path

import pytest
from cyberau_common.cli import main
from store import documents, reports
from store.db import close_store

ROOT = Path(__file__).resolve().parents[2]
PLUGIN = ROOT / "plugins" / "cyber-au"
SNAPSHOT = ROOT / "mcp" / "asd-essentials" / "data"
CITATION = re.compile(r"Source: [^,]+, [^,]+, retrieved \d{4}-\d{2}-\d{2}\b")
KEY = re.compile(r"\bS\d+\b")


def _demo():
    name = "cyberau_demo_reports"
    spec = importlib.util.spec_from_file_location(
        name, PLUGIN / "demo" / "__init__.py", submodule_search_locations=[str(PLUGIN / "demo")]
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


demo = _demo()


@pytest.fixture
def demo_store(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path / "real"))
    monkeypatch.setenv("CYBERAU_E8_SNAPSHOT", str(SNAPSHOT))
    monkeypatch.setenv("CYBERAU_TODAY", "2026-11-03")
    summary = demo.load(tmp_path / "demo")
    yield summary
    close_store(summary["path"])


@pytest.fixture
def incident(demo_store, tmp_path):
    record = demo.triage()
    record["retrieved"] = "2026-10-17"
    path = tmp_path / "incident.json"
    path.write_text(json.dumps(record), encoding="utf-8")
    return path


def _monthly(demo_store, **extra):
    return reports.monthly_report(
        start=date(2026, 10, 1),
        end=date(2026, 10, 31),
        store=demo_store["path"],
        obligations=demo_store["obligations"],
        on=date(2026, 11, 3),
        **extra,
    )


def _assert_every_figure_cited(doc: documents.Document, ledger: reports.Ledger) -> None:
    keys = {item.key for item in ledger.sources}
    assert ledger.figures
    for figure in ledger.figures:
        assert figure.source in keys, figure
    appendix = documents.to_markdown(doc).split("## Appendix A: Sources", 1)[1]
    for item in ledger.sources:
        line = next(line for line in appendix.splitlines() if line.startswith(f"- [{item.key}]"))
        assert CITATION.search(line), line
    body = documents.to_markdown(doc).split("## Appendix A", 1)[0]
    for block in doc.blocks:
        if block.kind != "table" or "Source" not in block.rows[0]:
            continue
        column = block.rows[0].index("Source")
        for row in block.rows[1:]:
            assert row[column] in keys, row
    for line in body.splitlines():
        if re.search(r"\b\d+\b", line) and line.startswith(("In ", "Our organisation")):
            assert KEY.search(line), line


def test_demo_load_adds_report_inputs(demo_store):
    assert demo_store["vulnerabilities"] == 3
    assert demo_store["evidence"] == 7
    obligations = json.loads(Path(demo_store["obligations"]).read_text(encoding="utf-8"))
    assert obligations["demo"] is True


def test_monthly_report_is_readable_and_cited(demo_store):
    doc, ledger = _monthly(demo_store)
    text = documents.to_markdown(doc)
    assert text.startswith("# Monthly cyber summary\n\n" + reports.DEMO_BANNER)
    assert "Period: 2026-10-01 to 2026-10-31." in text
    assert "3 KEV additions and 3 advisories" in text
    assert "| of which linked to ransomware | 1 |" in text
    assert "| ASD Essentials for enterprise IT | 3 of 58 | 3 | 52 | 1 |" in text
    assert "Privacy Act 1988 (Cth) s 26WH(2)" in text
    assert "update[.]example[.]net" in text and "update.example.net" not in text
    assert reports.GUIDANCE in text and reports.NOT_SENT in text
    assert "## Appendix B: Limitations" in text
    assert "## Appendix C: Evidence references" in text
    assert "hxxps://example[.]com/demo/board-charter" in text
    assert "Proposal:" in text
    assert reports.body_words(text) <= reports.BODY_WORDS
    assert "\u2014" not in text
    _assert_every_figure_cited(doc, ledger)


def test_monthly_report_states_missing_inputs(demo_store, tmp_path):
    doc, ledger = reports.monthly_report(
        start=date(2026, 9, 1),
        end=date(2026, 9, 30),
        store=demo_store["path"],
        on=date(2026, 11, 3),
    )
    text = documents.to_markdown(doc)
    assert "0 KEV additions" in text
    assert "that is missing data, not a quiet month" in text
    assert "No obligations input was given" in text
    assert "zero matches is not an all-clear" in text
    _assert_every_figure_cited(doc, ledger)


def test_essential_eight_rows_stay_out_of_report_figures(demo_store):
    doc, ledger = _monthly(demo_store)
    text = documents.to_markdown(doc)
    assert "1 Essential Eight requirement record is in the register" in text
    labels = " ".join(item.label for item in ledger.figures)
    assert "Essential Eight" not in labels
    for phrase in ("Maturity Level", "ML1", "ML2", "ML3"):
        assert phrase not in text


def test_incident_report_is_readable_and_cited(demo_store, incident):
    doc, ledger = reports.incident_report(
        reports.load_incident(incident),
        store=demo_store["path"],
        obligations=demo_store["obligations"],
        on=date(2026, 10, 17),
    )
    text = documents.to_markdown(doc)
    assert text.startswith("# Incident summary\n\n" + reports.DEMO_BANNER)
    assert "Our organisation is handling a P1 incident" in text
    assert "3 of 5 observables match hostile records" in text
    assert "T1071.001" in text
    assert "203[.]0[.]113[.]45" in text and "203.0.113.45" not in text
    assert "Earliest due" in text and "2026-11-16" in text
    assert "Severity is the local triage rating" in text
    assert (
        "Source: cyber-au DEMO dataset (synthetic; not real intelligence), demo-2026.10, "
        "retrieved 2026-10-17" in text
    )
    assert reports.body_words(text) <= reports.BODY_WORDS
    _assert_every_figure_cited(doc, ledger)


def test_obligations_input_shapes(tmp_path):
    plain = tmp_path / "plain.json"
    plain.write_text(
        json.dumps({"obligations": [{"regime": "soci", "trigger": "significant_impact"}]}),
        encoding="utf-8",
    )
    records, meta = reports.load_obligations(plain)
    assert records[0]["regime"] == "soci"
    listed = tmp_path / "list.json"
    listed.write_text(
        json.dumps(
            [
                {
                    "source": "au-regulatory",
                    "retrieved_at": "2026-10-20T01:00:00Z",
                    "data_as_of": "2026-10-17",
                    "data": [{"regime": "ndb", "citation": "s 26WK"}],
                }
            ]
        ),
        encoding="utf-8",
    )
    records, meta = reports.load_obligations(listed)
    assert meta["version"] == "2026-10-17" and meta["retrieved"] == "2026-10-20"
    assert reports._obligation_row(records[0])[0] == "NDB"
    bad = tmp_path / "bad.json"
    bad.write_text("not json", encoding="utf-8")
    with pytest.raises(ValueError, match="not JSON"):
        reports.load_obligations(bad)


def test_cli_monthly_markdown_and_docx(demo_store, capsys):
    argv = [
        "store",
        "report",
        "monthly",
        "--month",
        "2026-10",
        "--path",
        demo_store["path"],
        "--obligations",
        demo_store["obligations"],
        "--as-of",
        "2026-11-03",
    ]
    assert main(argv) == 0
    out = capsys.readouterr().out
    assert out.startswith("# Monthly cyber summary")
    docx = pytest.importorskip("docx")
    assert main([*argv, "--format", "docx", "--output", "october.docx"]) == 0
    result = json.loads(capsys.readouterr().out)
    word = docx.Document(str(Path(demo_store["path"]).parent / result["output"]))
    text = "\n".join(paragraph.text for paragraph in word.paragraphs)
    assert reports.DEMO_BANNER in text
    assert "Appendix A: Sources" in text
    assert CITATION.search(text)
    assert len(word.tables) >= 3


def test_cli_incident_json(demo_store, incident, capsys):
    argv = ["store", "report", "incident", "--incident", str(incident)]
    argv += ["--path", demo_store["path"], "--format", "json", "--as-of", "2026-10-17"]
    assert main(argv) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["untrusted"] is True
    keys = {item["key"] for item in payload["sources"]}
    assert all(item["source"] in keys for item in payload["figures"])


def test_cli_month_and_range_are_exclusive(demo_store, capsys):
    argv = ["store", "report", "monthly", "--path", demo_store["path"], "--month", "2026-10"]
    assert main([*argv, "--start", "2026-10-01", "--end", "2026-10-31"]) == 1
    assert "not both" in capsys.readouterr().err
