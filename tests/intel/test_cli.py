"""cyberau-mcp store command."""

from __future__ import annotations

import json
from pathlib import Path

from cyberau_common.cli import main


def _json(capsys):
    out = capsys.readouterr().out
    return json.loads(out)


def test_refresh_stays_unimplemented():
    assert main(["refresh"]) == 2


def test_store_help_and_missing_command(capsys):
    assert main(["store", "--help"]) == 0
    help_text = capsys.readouterr().out
    assert "add-observation" in help_text
    assert "ingest-kev" in help_text
    assert "stix21" in help_text.lower()
    assert "duckdb" not in help_text.lower()
    assert main(["store"]) == 2


def test_cli_dedupes_exports_and_loads_kev(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    path = tmp_path / "intel.sqlite"
    assert main(["store", "init", "--path", str(path)]) == 0
    assert Path(capsys.readouterr().out.strip()) == path.resolve()

    common = [
        "--path",
        str(path),
        "--type",
        "url",
        "--source",
        "feed",
        "--observed-at",
        "2026-01-01T00:00:00Z",
    ]
    assert (
        main(
            [
                "store",
                "indicator",
                *common,
                "--value",
                "hxxps://Example[.]COM/a/../b#x",
                "--raw",
                "first",
                "--tlp",
                "CLEAR",
            ]
        )
        == 0
    )
    first = _json(capsys)["id"]
    assert (
        main(
            [
                "store",
                "indicator",
                *common,
                "--value",
                "https://example.com/b",
                "--raw",
                "second",
                "--observed-at",
                "2026-02-01T00:00:00Z",
            ]
        )
        == 0
    )
    assert _json(capsys)["id"] == first

    assert main(["store", "search", "example", "--path", str(path), "--kind", "indicator"]) == 0
    found = _json(capsys)
    assert found["untrusted"] is True
    assert len(found["data"]) == 1
    assert found["data"][0]["value_norm"] == "https://example.com/b"

    assert (
        main(["store", "get", "https://example.com/b", "--type", "url", "--path", str(path)]) == 0
    )
    assert _json(capsys)["data"][0]["id"] == first

    assert (
        main(
            [
                "store",
                "add-observation",
                "--path",
                str(path),
                "--type",
                "domain",
                "--value",
                "secret.example",
                "--note",
                "seen in mail",
                "--verdict",
                "suspicious",
            ]
        )
        == 0
    )
    added = _json(capsys)
    assert added["data"][0]["tlp"] == "AMBER"
    assert added["data"][0]["observations"][0]["source_id"] == "analyst"

    assert main(["store", "export", "--path", str(path)]) == 0
    exported = _json(capsys)
    assert exported["explicit_max_tlp"] is False
    assert exported["max_tlp"] == "GREEN"
    assert all(row["tlp"] in {"CLEAR", "GREEN"} for row in exported["records"])
    assert any(row.get("value_norm") == "https://example.com/b" for row in exported["records"])
    assert all(row.get("value_norm") != "secret.example" for row in exported["records"])

    assert main(["store", "export", "--path", str(path), "--max-tlp", "AMBER"]) == 0
    asked = _json(capsys)
    assert asked["explicit_max_tlp"] is True
    assert any(row.get("value_norm") == "secret.example" for row in asked["records"])

    catalogue = tmp_path / "kev.json"
    catalogue.write_text(
        json.dumps(
            {
                "dateReleased": "2026-01-02T03:04:05Z",
                "vulnerabilities": [
                    {
                        "cveID": "CVE-2099-0001",
                        "dateAdded": "2026-01-01",
                        "dueDate": "2026-01-15",
                        "knownRansomwareCampaignUse": "Unknown",
                        "cwes": ["CWE-79"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    assert main(["store", "ingest-kev", str(catalogue), "--path", str(path)]) == 0
    assert _json(capsys)["loaded"] == 1
    assert main(["store", "counts", "--path", str(path)]) == 0
    once = _json(capsys)
    assert main(["store", "ingest-kev", str(catalogue), "--path", str(path)]) == 0
    assert _json(capsys)["loaded"] == 1
    assert main(["store", "counts", "--path", str(path)]) == 0
    assert _json(capsys) == once

    assert main(["store", "indicator", "--type", "nope", "--path", str(path)]) == 2
    assert (
        main(
            [
                "store",
                "indicator",
                "--path",
                str(path),
                "--type",
                "ipv4",
                "--value",
                "192.168.001.1",
                "--source",
                "feed",
                "--observed-at",
                "2026-01-01T00:00:00Z",
                "--raw",
                "bad",
            ]
        )
        == 1
    )


def test_unknown_export_format_is_rejected(tmp_path):
    assert main(["store", "export", "--format", "stix", "--path", str(tmp_path / "x.sqlite")]) == 2
    assert (
        main(["store", "export", "--format", "duckdb", "--path", str(tmp_path / "x.sqlite")]) == 2
    )
