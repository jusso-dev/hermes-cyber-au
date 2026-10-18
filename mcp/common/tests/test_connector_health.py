"""Fixture tests for connector health. They do not contact vendor hosts."""

from __future__ import annotations

import json
import re
from datetime import date
from pathlib import Path

import pytest
from cyberau_common.cli import main
from cyberau_common.health import collect_connector_health, diff_response, fetch_live

ROOT = Path(__file__).resolve().parents[3]
SECRET = "super-secret-value"
SCHEMA_PATH = ROOT / "mcp" / "first-epss" / "schema" / "epss_scores.response.json"
SCHEMA = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def _mini_checkout(tmp_path: Path) -> Path:
    """A checkout with one schema-bearing connector and one without, so the
    result does not depend on how many connectors ship response schemas."""
    root = tmp_path / "checkout"
    for key in ("first-epss", "nvd"):
        (root / "mcp" / key).mkdir(parents=True)
        (root / "mcp" / key / "pyproject.toml").write_text("", encoding="utf-8")
    schema_dir = root / "mcp" / "first-epss" / "schema"
    schema_dir.mkdir()
    (schema_dir / SCHEMA_PATH.name).write_text(
        SCHEMA_PATH.read_text(encoding="utf-8"), encoding="utf-8"
    )
    return root


def _row(epss=0.96, percentile=0.99, extra=None, drop=()):
    row = {
        "cve": "CVE-2024-3400",
        "epss": epss,
        "percentile": percentile,
        "date": "2026-10-17",
    }
    for name in drop:
        row.pop(name, None)
    if extra:
        row.update(extra)
    return {"data": [row]}


def test_schema_diff_reports_added_removed_and_type_changed():
    changes = diff_response(
        SCHEMA,
        _row(epss="high", extra={"note": SECRET}, drop=("percentile",)),
    )
    assert changes is not None
    by_change = {item["change"]: item for item in changes}
    assert by_change["added"]["field"] == "data.0.note"
    assert by_change["removed"]["field"] == "data.0.percentile"
    assert by_change["type_changed"]["field"] == "data.0.epss"
    assert by_change["type_changed"]["from"] == "number"
    assert by_change["type_changed"]["to"] == "string"
    assert SECRET not in json.dumps(changes)


def test_numeric_strings_match_a_number_schema():
    assert diff_response(SCHEMA, _row(epss="0.96000", percentile="0.99800")) == []


def test_empty_record_list_is_not_drift():
    assert diff_response(SCHEMA, {"data": []}) is None


def test_checkout_without_a_response_schema_is_not_checked(tmp_path: Path):
    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    (fixtures / "first-epss.json").write_text(
        json.dumps(_row()),
        encoding="utf-8",
    )
    called = []

    def record(key: str) -> dict:
        called.append(key)
        return {"ok": False, "status_code": None, "error_class": "no_fixture", "body": None}

    report = collect_connector_health(
        ROOT,
        live=True,
        check_schema=True,
        fixtures=fixtures,
        fetcher=record,
        today=date(2026, 10, 17),
    )
    by_key = {row["key"]: row for row in report["connectors"]}
    with_schema = {
        key for key in by_key if any((ROOT / "mcp" / key / "schema").glob("*.response.json"))
    }
    assert set(called) == with_schema - {"first-epss"}
    assert by_key["first-epss"]["status"] == "ok"
    assert by_key["first-epss"]["detail"] == "schema ok"
    assert by_key["first-epss"]["keyed"] is False
    unchecked = [
        key
        for key, row in by_key.items()
        if not any((ROOT / "mcp" / key / "schema").glob("*.response.json"))
    ]
    assert "nvd" in unchecked
    assert len(unchecked) >= 1
    for key in unchecked:
        assert by_key[key]["status"] == "not_checked"
        assert by_key[key]["detail"] == "not checked"
        assert by_key[key]["schema_diff"] == []
    assert by_key["nvd"]["keyed"] is True
    assert SECRET not in json.dumps(report)


def test_drift_fixture_fails_and_keeps_the_last_good_date(tmp_path: Path):
    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    state = tmp_path / "state.json"
    good = fixtures / "first-epss.json"
    good.write_text(json.dumps(_row()), encoding="utf-8")
    first = collect_connector_health(
        ROOT,
        live=False,
        check_schema=True,
        fixtures=fixtures,
        state_path=state,
        today=date(2026, 10, 1),
    )
    assert next(row for row in first["connectors"] if row["key"] == "first-epss")["last_good"] == (
        "2026-10-01"
    )
    good.write_text(
        json.dumps(_row(epss="high", extra={"note": SECRET}, drop=("percentile",))),
        encoding="utf-8",
    )
    second = collect_connector_health(
        ROOT,
        live=False,
        check_schema=True,
        fixtures=fixtures,
        state_path=state,
        today=date(2026, 10, 17),
    )
    row = next(item for item in second["connectors"] if item["key"] == "first-epss")
    assert row["status"] == "fail"
    assert row["error_class"] == "schema_drift"
    assert row["status_code"] == 200
    assert row["last_good"] == "2026-10-01"
    changes = {item["change"] for item in row["schema_diff"]}
    assert changes == {"added", "removed", "type_changed"}
    assert SECRET not in json.dumps(second)


def test_http_error_fixture_does_not_schema_check_the_body(tmp_path: Path):
    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    (fixtures / "first-epss.json").write_text(
        json.dumps(
            {
                "status_code": 503,
                "error_class": "http_error",
                "body": {"leak": SECRET},
                "detail": "upstream status 503",
            }
        ),
        encoding="utf-8",
    )
    report = collect_connector_health(
        ROOT,
        live=False,
        check_schema=True,
        fixtures=fixtures,
        today=date(2026, 10, 17),
    )
    row = next(item for item in report["connectors"] if item["key"] == "first-epss")
    assert row["status"] == "fail"
    assert row["status_code"] == 503
    assert row["error_class"] == "http_error"
    assert row["schema_diff"] == []
    assert SECRET not in json.dumps(report)


def test_cli_writes_json_from_fixtures(tmp_path: Path, monkeypatch, capsys):
    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    (fixtures / "first-epss.json").write_text(json.dumps(_row()), encoding="utf-8")
    monkeypatch.setenv("CYBERAU_HEALTH_FIXTURES", str(fixtures))
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path / "data"))
    out = tmp_path / "health.json"

    def boom(*args, **kwargs):
        raise AssertionError("vendor probe")

    monkeypatch.setattr("cyberau_common.health.fetch_live", boom)
    monkeypatch.setattr("cyberau_common.health.default_root", lambda: _mini_checkout(tmp_path))
    assert main(["health", "--all", "--schema-drift", "--json", str(out)]) == 0
    captured = capsys.readouterr().out
    assert "nvd not_checked not checked" in captured
    assert "first-epss ok schema ok" in captured
    report = json.loads(out.read_text(encoding="utf-8"))
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", report["checked_at"])
    assert any(row["status"] == "not_checked" for row in report["connectors"])


def test_live_without_a_fixture_refuses_during_tests(tmp_path: Path):
    report = collect_connector_health(
        _mini_checkout(tmp_path), live=True, check_schema=True, today=date(2026, 10, 17)
    )
    row = next(item for item in report["connectors"] if item["key"] == "first-epss")
    assert row["status"] == "fail"
    assert "refusing to probe" in row["detail"]
    assert all(
        item["status"] == "not_checked"
        for item in report["connectors"]
        if item["key"] != "first-epss"
    )


def test_fetch_live_refuses_before_any_network_call():
    with pytest.raises(RuntimeError, match="refusing to probe"):
        fetch_live("first-epss")


def test_workflow_pins_actions_and_does_not_embed_a_secret():
    text = (ROOT / "ci" / "workflows" / "connector-health.yml").read_text(encoding="utf-8")
    uses = re.findall(r"uses:\s*(\S+)", text)
    assert uses
    for use in uses:
        assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", use)
    assert "cyberau-mcp health --all --live --schema-drift --json health.json" in text
    assert "open_health_issues.py --kind connector --input health.json --close-recovered" in text
    for line in text.splitlines():
        if "secrets." in line:
            assert "${{ secrets." in line
    assert "connector-health-state.json" in text
    assert "http_cache" not in text
    assert SECRET not in text
    assert "\u2014" not in text


def test_map_schema_keys_are_not_drift_and_are_not_reported():
    payload = {"CVE-2024-0001": {"epss": 0.1}, "CVE-2024-0002": {"epss": 0.2}}
    assert diff_response({"type": "object"}, payload) == []
    assert diff_response({"type": "object", "properties": {}}, payload) == []
    permissive = {
        "type": "object",
        "properties": {"a": {"type": "string"}},
        "additionalProperties": True,
    }
    assert diff_response(permissive, {"a": "x", "CVE-2024-0003": 1}) == []


def test_detail_is_redacted_before_it_reaches_the_report(tmp_path: Path):
    leak = "upstream failed https://example.invalid/x?api_key=hunter2"

    def fetcher(key: str) -> dict:
        return {"ok": False, "status_code": 500, "error_class": None, "body": None, "detail": leak}

    report = collect_connector_health(
        ROOT, live=True, check_schema=True, fetcher=fetcher, today=date(2026, 10, 17)
    )
    assert "hunter2" not in json.dumps(report)
