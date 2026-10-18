"""Tests for the dashboard Sources page. Synthetic files only, no network."""

from __future__ import annotations

import http.client
import importlib.util
import json
import sqlite3
import sys
import threading
from datetime import UTC, datetime
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 10, 18, 9, 0, tzinfo=UTC)


def _load(name: str, filename: str):
    path = ROOT / "dashboard" / filename
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


server = _load("cyberau_dashboard_server_sources_test", "server.py")
sources = server.sources

CATALOGUE = """\
version: 1
excluded_servers:
  stub: Test stub server.
feeds:
  # Keyless
  - id: cisa-kev
    name: CISA Known Exploited Vulnerabilities
    connector: cisa-kev
    server: kev
    auth: {type: none}
    keyed: false
    enabled_by_default: true
    poll: PT6H
    refresh: kev
    licence: CC0 1.0. Do not use the CISA logo or DHS seal.

  - id: asd-acsc
    name: ASD ACSC alerts
    connector: asd-acsc
    server: asd
    urls:
      - https://www.cyber.gov.au/rss/alerts
    auth: {type: none}
    keyed: false
    enabled_by_default: true
    poll: PT15M
    refresh: asd
    licence: CC BY 4.0 with exclusions.
    notes: >-
      Rate limit is one feed poll
      per 10 minutes.

  - id: otx
    name: AlienVault OTX
    connector: otx
    server: otx
    auth: {type: header, header: X-OTX-API-KEY, env: OTX_API_KEY}
    keyed: true
    enabled_by_default: true
    poll: PT1H
    licence: OTX terms.

  - id: example-premium
    name: Example premium feed <script>
    connector: example-premium
    server: premium
    auth: {type: bearer, env: EXAMPLE_TOKEN, env_also: [EXAMPLE_URL]}
    keyed: true
    enabled_by_default: false
    poll: P1D
    licence: Commercial licence.
"""

CONFIG = """\
model: example
mcp_servers:
  kev:
    command: /opt/example/cyberau-mcp
    args:
    - serve
    - cisa-kev
  asd:
    command: /opt/example/cyberau-mcp
  otx:
    command: /opt/example/cyberau-mcp
    env:
      OTX_API_KEY: ${OTX_API_KEY}
    enabled: false
timezone: Australia/Sydney
"""


def _profile(tmp_path: Path) -> tuple[Path, Path, Path]:
    profile = tmp_path / "cyber-au"
    data = profile / "plugin-data" / "cyber-au"
    data.mkdir(parents=True)
    (profile / "feeds").mkdir()
    catalogue = profile / "feeds" / "catalogue.yaml"
    catalogue.write_text(CATALOGUE, encoding="utf-8")
    (profile / "config.yaml").write_text(CONFIG, encoding="utf-8")
    (profile / ".env").write_text("OTX_API_KEY=do-not-read-me\n", encoding="utf-8")
    (data / "bootstrap-status.json").write_text(
        json.dumps({"missing_env": [{"server": "otx", "variable": "OTX_API_KEY"}]}),
        encoding="utf-8",
    )
    (data / "feed-status.json").write_text(
        json.dumps(
            {
                "generated_at": "2026-10-18T08:00:00Z",
                "sources": {
                    "kev": {
                        "last_run": "2026-10-18T08:00:00Z",
                        "last_ok": "2026-10-18T08:00:00Z",
                        "status": "ok",
                        "item_count": 1450,
                        "last_error": None,
                    },
                    "asd": {
                        "last_run": "2026-10-18T08:30:00Z",
                        "last_ok": "2026-10-16T08:30:00Z",
                        "status": "fail",
                        "last_error": "alerts was not fetched live",
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    with sqlite3.connect(data / "asd_advisories.sqlite") as conn:
        conn.execute(
            "CREATE TABLE feed_status (feed TEXT PRIMARY KEY, last_success TEXT, "
            "method TEXT NOT NULL, item_count INTEGER NOT NULL, warning TEXT NOT NULL, "
            "data_as_of TEXT)"
        )
        conn.execute(
            "INSERT INTO feed_status VALUES ('alerts', '2026-10-16T08:30:00Z', 'stale', 12, "
            "'alerts was not fetched live', '2026-10-16T07:00:00Z')"
        )
    with sqlite3.connect(data / "intel.sqlite") as conn:
        conn.execute(
            "CREATE TABLE advisories (id TEXT, source_id TEXT, title TEXT, url TEXT, "
            "published_at TEXT, summary TEXT, content_sha256 TEXT, first_seen TEXT)"
        )
        conn.execute(
            "INSERT INTO advisories VALUES ('a1', 'asd-acsc', 't', 'https://example.com', "
            "NULL, NULL, NULL, '2026-10-16T08:30:00Z')"
        )
        conn.execute(
            "CREATE TABLE vulnerabilities (cve_id TEXT, kev_date_added TEXT, epss REAL, "
            "epss_date TEXT, updated_at TEXT)"
        )
        conn.execute(
            "INSERT INTO vulnerabilities VALUES ('CVE-2026-0001', '2026-10-17', NULL, NULL, "
            "'2026-10-18T08:00:00Z')"
        )
    return profile, data, catalogue


def test_fallback_parser_reads_the_test_catalogue() -> None:
    feeds = sources.parse_catalogue(CATALOGUE)
    assert [feed["id"] for feed in feeds] == ["cisa-kev", "asd-acsc", "otx", "example-premium"]
    assert feeds[1]["notes"] == "Rate limit is one feed poll per 10 minutes."
    assert feeds[2]["auth"] == {"type": "header", "header": "X-OTX-API-KEY", "env": "OTX_API_KEY"}
    assert feeds[3]["auth"]["env_also"] == ["EXAMPLE_URL"]
    assert feeds[3]["enabled_by_default"] is False


def test_fallback_parser_agrees_with_yaml_on_the_shipped_catalogue() -> None:
    yaml = pytest.importorskip("yaml")
    text = (ROOT / "feeds" / "catalogue.yaml").read_text(encoding="utf-8")
    expected = yaml.safe_load(text)["feeds"]
    keys = ("id", "name", "server", "connector", "keyed", "enabled_by_default", "poll")
    parsed = sources.parse_catalogue(text)
    assert [{k: f.get(k) for k in keys} for f in parsed] == [
        {k: f.get(k) for k in keys} for f in expected
    ]
    assert [f.get("auth") for f in parsed] == [f.get("auth") for f in expected]
    assert [f.get("licence") for f in parsed] == [f.get("licence") for f in expected]


def test_rows_combine_every_input(tmp_path: Path) -> None:
    profile, data, catalogue = _profile(tmp_path)
    rows, notes = sources.collect(
        profile,
        catalogue=catalogue,
        status_files=[data / "feed-status.json"],
        data_dir=data,
        now=NOW,
    )
    assert notes == []
    by_id = {row.id: row for row in rows}
    kev = by_id["cisa-kev"]
    assert (kev.enabled, kev.key, kev.state, kev.age, kev.items) == (
        "enabled",
        "not needed",
        "fresh",
        "1h",
        1450,
    )
    assert any(origin.startswith("intel store") for origin in kev.origins)
    asd = by_id["asd-acsc"]
    assert asd.state == "overdue"
    assert asd.cache == "stale"
    assert asd.last_error == "alerts was not fetched live"
    assert asd.data_as_of == "2026-10-16T07:00:00Z"
    otx = by_id["otx"]
    assert (otx.enabled, otx.key, otx.state) == (
        "disabled",
        "missing: OTX_API_KEY",
        "no run recorded",
    )
    premium = by_id["example-premium"]
    assert premium.enabled == "not in config"
    assert premium.key == "unknown (not recorded at last bootstrap)"


def test_key_presence_needs_explicit_bootstrap_evidence(tmp_path: Path) -> None:
    profile, data, catalogue = _profile(tmp_path)
    status_file = data / "bootstrap-status.json"
    for names, expected in (
        (["EXAMPLE_TOKEN"], "missing: EXAMPLE_URL"),
        (["EXAMPLE_TOKEN", "EXAMPLE_URL"], "set at last bootstrap"),
    ):
        status_file.write_text(json.dumps({"missing_env": [], "present_env": names}))
        rows, _ = sources.collect(
            profile, catalogue=catalogue, status_files=[], data_dir=data, now=NOW
        )
        assert next(row for row in rows if row.id == "example-premium").key == expected


def test_offset_timestamp_is_displayed_in_utc(tmp_path: Path) -> None:
    profile, data, catalogue = _profile(tmp_path)
    status_file = data / "feed-status.json"
    status = json.loads(status_file.read_text())
    status["sources"]["kev"]["last_ok"] = "2026-10-18T19:00:00+11:00"
    status_file.write_text(json.dumps(status))
    rows, _ = sources.collect(
        profile, catalogue=catalogue, status_files=[status_file], data_dir=data, now=NOW
    )
    kev = next(row for row in rows if row.id == "cisa-kev")
    assert kev.last_success == "2026-10-18T08:00:00Z"
    assert kev.age == "1h"


def test_recent_asd_feed_does_not_hide_an_older_member(tmp_path: Path) -> None:
    profile, data, catalogue = _profile(tmp_path)
    catalogue.write_text(
        CATALOGUE.replace(
            "      - https://www.cyber.gov.au/rss/alerts",
            "      - https://www.cyber.gov.au/rss/alerts\n"
            "      - https://www.cyber.gov.au/rss/news",
        )
    )
    with sqlite3.connect(data / "asd_advisories.sqlite") as conn:
        conn.execute(
            "INSERT INTO feed_status VALUES ('news', '2026-10-18T08:50:00Z', 'live', 2, "
            "'', '2026-10-18T08:45:00Z')"
        )
    status_file = data / "feed-status.json"
    status = json.loads(status_file.read_text())
    status["sources"]["asd"].update(last_ok="2026-10-18T08:50:00Z", last_error=None)
    status_file.write_text(json.dumps(status))
    rows, _ = sources.collect(
        profile, catalogue=catalogue, status_files=[status_file], data_dir=data, now=NOW
    )
    asd = next(row for row in rows if row.id == "asd-acsc")
    assert asd.state == "overdue"
    assert asd.last_success == "2026-10-16T08:30:00Z"
    assert asd.data_as_of == "2026-10-16T07:00:00Z"


def test_missing_asd_member_is_reported(tmp_path: Path) -> None:
    profile, data, catalogue = _profile(tmp_path)
    catalogue.write_text(
        CATALOGUE.replace(
            "      - https://www.cyber.gov.au/rss/alerts",
            "      - https://www.cyber.gov.au/rss/alerts\n"
            "      - https://www.cyber.gov.au/rss/news",
        )
    )
    with sqlite3.connect(data / "asd_advisories.sqlite") as conn:
        conn.execute(
            "UPDATE feed_status SET last_success='2026-10-18T08:55:00Z', "
            "method='live', warning='' WHERE feed='alerts'"
        )
    rows, _ = sources.collect(profile, catalogue=catalogue, status_files=[], data_dir=data, now=NOW)
    asd = next(row for row in rows if row.id == "asd-acsc")
    assert asd.state == "error after last success"
    assert asd.last_error == "no successful refresh for news"


def test_sources_page_renders_escaped_and_never_shows_env_values(tmp_path: Path) -> None:
    profile, data, catalogue = _profile(tmp_path)
    status, body = server.route(profile, "/sources")
    text = body.decode("utf-8")
    assert status == 200
    assert "<h1>Sources</h1>" in text
    assert "cisa-kev" in text and "overdue" in text and "missing: OTX_API_KEY" in text
    assert "Example premium feed &lt;script&gt;" in text
    assert "<script>" not in text
    assert "do-not-read-me" not in text
    index = server.route(profile, "/")[1].decode("utf-8")
    assert 'href="/sources"' in index


def test_sources_page_without_any_inputs(tmp_path: Path) -> None:
    profile = tmp_path / "empty"
    profile.mkdir()
    settings = server.SourceSettings(catalogue=tmp_path / "missing.yaml")
    status, body = server.route(profile, "/sources", settings)
    text = body.decode("utf-8")
    assert status == 200
    assert "No feed catalogue found" in text
    assert "No refresh status file found" in text


def test_duration_and_age_helpers() -> None:
    assert sources.parse_duration("PT6H").total_seconds() == 6 * 3600
    assert sources.parse_duration("P1D").days == 1
    assert sources.parse_duration("PT0S").total_seconds() == 0
    assert sources.parse_duration("bogus") is None
    assert sources.age_text(None, NOW) == "never"
    assert sources.age_text(datetime(2026, 10, 10, tzinfo=UTC), NOW) == "8d"


@pytest.mark.block_network(allowed_hosts=["127.0.0.1"])
def test_live_sources_page_is_host_checked(tmp_path: Path) -> None:
    profile, _data, _catalogue = _profile(tmp_path)
    httpd = server.make_server(profile, "127.0.0.1", 0)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        port = httpd.server_address[1]
        for host, expected in ((f"127.0.0.1:{port}", 200), ("attacker.example", 421)):
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            try:
                conn.putrequest("GET", "/sources", skip_host=True)
                conn.putheader("Host", host)
                conn.endheaders()
                resp = conn.getresponse()
                resp.read()
                assert resp.status == expected
            finally:
                conn.close()
    finally:
        httpd.shutdown()
        httpd.server_close()
