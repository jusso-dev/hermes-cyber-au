"""Essentials evidence register, gap report and xlsx and docx exports (#168)."""

from __future__ import annotations

import json
import sqlite3
from datetime import date
from pathlib import Path

import pytest
from cyberau_common.cli import main
from store import documents, evidence
from store.db import open_store

ROOT = Path(__file__).resolve().parents[2]
SNAPSHOT = ROOT / "mcp" / "asd-essentials" / "data"
ON = date(2026, 11, 28)


@pytest.fixture(autouse=True)
def asd_snapshot(monkeypatch):
    monkeypatch.setenv("CYBERAU_E8_SNAPSHOT", str(SNAPSHOT))
    monkeypatch.setenv("CYBERAU_TODAY", ON.isoformat())


def _row(path, action="GOV-01.1", status="met", **extra):
    defaults = {
        "evidence": "https://intranet.example.com/board-charter",
        "owner": "Example CISO",
        "review_date": "2027-03-01",
        "source": "board minutes",
        "evidence_date": "2026-10-01",
    }
    defaults.update(extra)
    return evidence.record_evidence(
        "essentials", "enterprise-it", action, status, path=path, **defaults
    )


def _cli(capsys, *argv: str) -> tuple[int, str, str]:
    code = main(["store", "evidence", *argv])
    out, err = capsys.readouterr()
    return code, out, err


# Reference data


def test_action_ids_come_from_the_asd_snapshot():
    reference = evidence.load_reference("enterprise-it")
    ids = [item.action_id for item in reference.actions]
    assert len(ids) == len(set(ids)) == 58
    assert ids[0] == "GOV-01.1"
    first = reference.find("GOV-01.1")
    assert first.text.startswith("Formally define and establish executive")
    assert "<<untrusted" not in first.text
    assert reference.as_of == "2026-11-20"
    assert reference.citation().startswith(
        "Source: ASD Essentials for enterprise IT, 2026-11-20, retrieved "
    )
    phases = {item.phase for item in reference.actions}
    assert phases <= {None, 1, 2, 3}


def test_cloud_chapter_has_no_inferred_phases():
    reference = evidence.load_reference("cloud")
    assert {item.phase for item in reference.actions} == {None}
    assert "No phase order is inferred" in reference.phase_note


# Recording


def test_record_keeps_source_and_freshness_fields(store_path):
    row = _row(store_path)
    stored = evidence.list_evidence(path=store_path)
    assert stored == [row]
    assert row["source"] == "board minutes"
    assert row["evidence_date"] == "2026-10-01"
    assert row["reference_as_of"] == "2026-11-20"
    assert len(row["action_sha256"]) == 64


def test_record_replaces_the_same_action(store_path):
    _row(store_path, status="partial")
    _row(store_path, status="met")
    rows = evidence.list_evidence(path=store_path)
    assert [row["status"] for row in rows] == ["met"]


@pytest.mark.parametrize(
    ("framework", "chapter", "action", "status", "message"),
    [
        ("essentials", "enterprise-it", "GOV-99.1", "met", "is not an action"),
        ("essentials", "enterprise-it", "GOV-01.1", "ML2", "A maturity level is not a status"),
        ("essentials", "enterprise-it", "GOV-01.1", "2", "A maturity level is not a status"),
        ("essentials", "multi_factor_authentication", "ism-1504", "met", "enterprise-it"),
        ("essential-eight", "enterprise-it", "GOV-01.1", "met", "strategy"),
        ("essential-eight", "multi_factor_authentication", "ism-0001", "met", "not an Essential"),
        ("e8-to-essentials", "enterprise-it", "GOV-01.1", "met", "kept separate"),
    ],
)
def test_record_refuses_bad_input(store_path, framework, chapter, action, status, message):
    with pytest.raises(ValueError, match=message):
        evidence.record_evidence(framework, chapter, action, status, path=store_path)
    open_store(store_path).connection()
    assert evidence.list_evidence(path=store_path) == []


def test_schema_refuses_a_maturity_level_as_status(store_path):
    conn = open_store(store_path).connection()
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO essentials_evidence (framework, chapter, action_id, status, source, "
            "evidence_date, updated_at) VALUES ('essentials','enterprise-it','GOV-01.1',"
            "'ML2','x','2026-10-01','2026-10-01T00:00:00Z')"
        )


def test_import_is_all_or_nothing(store_path, tmp_path):
    good = tmp_path / "good.csv"
    good.write_text(
        ",".join(evidence.COLUMNS)
        + "\nessentials,enterprise-it,GOV-01.1,met,note,Owner,2027-01-01,minutes,2026-10-01\n"
        + "essential-eight,regular_backups,ism-1511,partial,,,,,2026-10-01\n",
        encoding="utf-8",
    )
    assert evidence.import_csv(good, path=store_path) == {"imported": 2}
    bad = tmp_path / "bad.csv"
    bad.write_text(
        ",".join(evidence.COLUMNS)
        + "\nessentials,ot,GOV-01.1,met,,,,,\nessentials,ot,NOPE-1.1,met,,,,,\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="line 3"):
        evidence.import_csv(bad, path=store_path)
    assert {row["chapter"] for row in evidence.list_evidence(path=store_path)} == {
        "enterprise-it",
        "regular_backups",
    }


# Separation of the two frameworks


def test_no_essential_eight_level_becomes_an_essentials_rating(store_path):
    """Essential Eight rows, at any level, never change an Essentials figure."""
    reference = evidence.load_reference("enterprise-it")
    before = evidence.summarise(evidence.essentials_view(reference, [], ON))
    e8 = evidence.load_e8_reference()
    for requirement in e8.requirements:
        evidence.record_evidence(
            "essential-eight",
            requirement.strategy,
            requirement.control_id,
            "met",
            path=store_path,
            reference=e8,
        )
    rows = evidence.list_evidence(path=store_path)
    assert rows and all(row["framework"] == "essential-eight" for row in rows)
    after = evidence.summarise(evidence.essentials_view(reference, rows, ON))
    assert after == before
    assert after["met"] == 0

    report = evidence.build_report(chapters=["enterprise-it"], path=store_path, on=ON)
    payload = report.to_json()
    assert payload["essentials"][0]["summary"]["met"] == 0
    assert len(payload["essential_eight"]["rows"]) == len(rows)
    for row in payload["essential_eight"]["rows"]:
        assert "maturity_level" not in row
        assert set(row["applies_at_e8_levels"].replace(" ", "").split(",")) <= {"1", "2", "3"}
    text = documents.to_markdown(evidence.gap_document(report))
    assert "Met | Partial" in text
    assert "| ASD Essentials for enterprise IT | 58 | 0 |" in text
    for phrase in ("Maturity Level", "maturity level 1", "ML1", "ML2", "ML3", "effectiveness: "):
        assert phrase not in text
    assert "no Essentials result is derived from them" in text


def test_every_output_says_self_assessment(store_path):
    _row(store_path)
    report = evidence.build_report(path=store_path, on=ON)
    markdown = documents.to_markdown(evidence.gap_document(report))
    assert markdown.count(evidence.NOTICE) >= 2
    assert evidence.NOTICE in json.dumps(report.to_json())
    sheet = evidence.register_sheets(report)[0]
    assert sheet.title == "About" and sheet.rows[0] == [evidence.NOTICE]


# Gap report


def test_gaps_sort_not_met_first_and_cite_asd(store_path):
    _row(store_path, action="PRO-10.3", status="not met", owner="Infra")
    _row(store_path, action="PRO-13.4", status="partial")
    _row(store_path, action="GOV-01.1", status="met")
    report = evidence.build_report(path=store_path, on=ON)
    listed = evidence.gaps(report.views["enterprise-it"])
    assert [item["action_id"] for item in listed[:2]] == ["PRO-10.3", "PRO-13.4"]
    assert "GOV-01.1" not in [item["action_id"] for item in listed]
    assert listed[0]["action"].startswith("Conduct regular testing of backup")
    assert listed[0]["next_step"].startswith("Plan the work")
    text = documents.to_markdown(evidence.gap_document(report))
    assert "Source: ASD Essentials for enterprise IT, 2026-11-20, retrieved " in text
    assert "Guidance: https://www.cyber.gov.au/publication/essentials-for-enterprise-it" in text
    assert "Unknown means no evidence was recorded. It is not a failure." in text
    assert "\u2014" not in text


def test_freshness_flags_overdue_and_stale(store_path):
    assert evidence.freshness(None, ON) == "not recorded"
    assert evidence.freshness({"review_date": "2026-11-01"}, ON) == "review overdue"
    stale = {"review_date": "2027-12-01", "evidence_date": "2025-01-01"}
    assert evidence.freshness(stale, ON) == "evidence older than 12 months"
    assert evidence.freshness({"review_date": "2026-12-10"}, ON) == "review due within 30 days"
    assert evidence.freshness({"review_date": "2027-06-01"}, ON) == "current"
    _row(store_path, action="PRO-06.2", status="met", review_date="2026-10-01")
    report = evidence.build_report(path=store_path, on=ON)
    listed = {item["action_id"]: item for item in evidence.gaps(report.views["enterprise-it"])}
    assert listed["PRO-06.2"]["next_step"].startswith("Review the evidence again")


def test_reference_change_is_shown(store_path):
    _row(store_path)
    conn = open_store(store_path).connection()
    conn.execute("UPDATE essentials_evidence SET action_sha256 = 'old'")
    report = evidence.build_report(path=store_path, on=ON)
    view = {item["action_id"]: item for item in report.views["enterprise-it"]}
    assert view["GOV-01.1"]["reference_changed"] is True
    listed = {item["action_id"]: item for item in evidence.gaps(report.views["enterprise-it"])}
    assert "changed this action's wording" in listed["GOV-01.1"]["next_step"]


def test_chapters_follow_the_org_profile_when_empty(store_path, tmp_path):
    (tmp_path / "org.yaml").write_text("environments: [it, ot]\n", encoding="utf-8")
    assert evidence.chapters_in_scope(None, store_path) == ["enterprise-it", "ot"]
    evidence.record_evidence("essentials", "cloud", "GOV-01.1", "met", path=store_path)
    assert evidence.chapters_in_scope(None, store_path) == ["cloud"]


# Exports open with the same libraries


def test_xlsx_export_opens_with_openpyxl(store_path):
    openpyxl = pytest.importorskip("openpyxl")
    _row(store_path)
    _row(store_path, action="PRO-10.3", status="not met", evidence="=HYPERLINK(\"x\")")
    evidence.record_evidence(
        "essential-eight", "regular_backups", "ism-1511", "partial", path=store_path
    )
    result = evidence.export("xlsx", path=store_path, on=ON)
    assert result["output"] == "exports/essentials-2026-11-28-register.xlsx"
    book = openpyxl.load_workbook(store_path.parent / result["output"])
    assert book.sheetnames == [
        "About",
        "Essentials register",
        "Gaps by chapter",
        "Essential Eight register",
    ]
    assert book["About"]["A2"].value == evidence.NOTICE
    register = book["Essentials register"]
    header = [cell.value for cell in register[1]]
    for name in ("action_id", "status", "evidence", "owner", "review_date", "source"):
        assert name in header
    assert "freshness" in header and "evidence_date" in header
    assert register.max_row == 59
    cells = {row[1].value: row for row in register.iter_rows(min_row=2)}
    formula = cells["PRO-10.3"][header.index("evidence")]
    assert formula.data_type == "s"
    assert formula.value.startswith("=")
    e8 = book["Essential Eight register"]
    assert [cell.value for cell in e8[2]][:2] == ["regular_backups", "ism-1511"]
    assert not (store_path.parent / "exports" / (Path(result["output"]).name + ".partial")).exists()


def test_docx_export_opens_with_python_docx(store_path):
    docx = pytest.importorskip("docx")
    _row(store_path, action="PRO-10.3", status="not met")
    result = evidence.export("docx", output="board-pack.docx", path=store_path, on=ON)
    assert result["output"] == "exports/board-pack.docx"
    word = docx.Document(str(store_path.parent / result["output"]))
    text = "\n".join(paragraph.text for paragraph in word.paragraphs)
    assert evidence.NOTICE in text
    assert evidence.SEPARATION in text
    assert "Source: ASD Essentials for enterprise IT, 2026-11-20, retrieved " in text
    assert len(word.tables) >= 2
    cells = [cell.text for table in word.tables for row in table.rows for cell in row.cells]
    assert "PRO-10.3" in cells


@pytest.mark.parametrize("output", ["../escape.docx", "/tmp/elsewhere.docx", "wrong.txt"])
def test_export_stays_under_exports(store_path, output):
    pytest.importorskip("docx")
    with pytest.raises(ValueError):
        evidence.export("docx", output=output, path=store_path, on=ON)


def test_missing_extra_gives_the_install_hint(store_path, monkeypatch, capsys):
    real = documents.importlib.import_module

    def refuse(name, *args, **kwargs):
        if name in ("openpyxl", "docx"):
            raise ImportError(name)
        return real(name, *args, **kwargs)

    monkeypatch.setattr(documents.importlib, "import_module", refuse)
    with pytest.raises(documents.DocumentsUnavailable, match="--extra documents"):
        evidence.export("xlsx", path=store_path, on=ON)
    code, out, err = _cli(capsys, "export", "--format", "docx", "--path", str(store_path))
    assert code == 2
    assert out == ""
    assert "uv sync --project mcp --extra documents" in err
    assert not (store_path.parent / "exports").exists() or not any(
        (store_path.parent / "exports").iterdir()
    )


# Command line


def test_cli_record_report_and_export(store_path, capsys):
    code, out, _ = _cli(capsys, "actions", "--chapter", "ot")
    assert code == 0
    assert json.loads(out)["actions"][0]["action_id"] == "GOV-01.1"
    code, out, err = _cli(
        capsys,
        "record",
        "--path",
        str(store_path),
        "--framework",
        "essentials",
        "--chapter",
        "ot",
        "--action",
        "GOV-01.1",
        "--status",
        "partial",
        "--owner",
        "Example OT lead",
        "--review-date",
        "2027-01-31",
    )
    assert code == 0, err
    assert json.loads(out)["notice"] == evidence.NOTICE
    code, out, _ = _cli(capsys, "report", "--path", str(store_path))
    assert code == 0
    assert out.startswith("# ASD Essentials gap report (self-assessment)")
    assert "ASD Essentials for OT" in out
    code, out, _ = _cli(capsys, "report", "--path", str(store_path), "--json")
    assert json.loads(out)["essentials"][0]["summary"]["partial"] == 1
    code, out, _ = _cli(capsys, "list", "--path", str(store_path))
    assert json.loads(out)["rows"][0]["owner"] == "Example OT lead"
    pytest.importorskip("openpyxl")
    code, out, _ = _cli(capsys, "export", "--format", "xlsx", "--path", str(store_path))
    assert code == 0
    assert json.loads(out)["output"].endswith("-register.xlsx")


def test_cli_rejects_a_maturity_level(store_path, capsys):
    code, out, err = _cli(
        capsys,
        "record",
        "--path",
        str(store_path),
        "--framework",
        "essentials",
        "--chapter",
        "enterprise-it",
        "--action",
        "GOV-01.1",
        "--status",
        "ML2",
    )
    assert code == 2
    assert "invalid choice" in err
