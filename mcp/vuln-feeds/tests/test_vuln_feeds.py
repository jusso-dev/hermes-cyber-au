"""Vulnerability feed tests. Every body is a synthetic fixture."""

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import cyberau_vuln_feeds.source as source
import httpx
import pytest
from cyberau_vuln_feeds import feeds

FIXTURES = Path(__file__).resolve().parent / "fixtures"
SINCE = datetime(2026, 10, 22, 2, 0, tzinfo=UTC)


def _text(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.delenv("CYBERAU_OFFLINE", raising=False)
    yield
    source._TRANSPORT = None


def _serve(routes: dict[str, str], seen: list | None = None, status: int = 200):
    """Answer by URL without the query string. A route value may be a (status, body) pair."""

    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(request)
        key = str(request.url).split("?", 1)[0]
        value = routes.get(key)
        if value is None:
            return httpx.Response(404, text="missing")
        if isinstance(value, tuple):
            return httpx.Response(value[0], text=value[1])
        return httpx.Response(status, text=value)

    source._TRANSPORT = httpx.MockTransport(handler)


# Parsers


def test_osv_modified_ids_keep_mal_records_in_the_window():
    ids, covered = feeds.osv_modified_ids(_text("osv_modified_id.csv"), SINCE)
    assert ids == ["MAL-2026-18205", "MAL-2026-18204", "MAL-2026-18100"]
    assert covered is True


def test_osv_modified_ids_report_a_window_the_range_did_not_reach():
    text = "\n".join(_text("osv_modified_id.csv").splitlines()[:3]) + "\n2026-10-22T0"
    ids, covered = feeds.osv_modified_ids(text, SINCE)
    assert ids == ["MAL-2026-18205", "MAL-2026-18204"]
    assert covered is False


def test_osv_row_drops_the_per_source_marker_and_names_the_package():
    item = feeds.osv_row(json.loads(_text("osv_mal_record.json")))
    assert item["id"] == "osv-mal:MAL-2026-18205"
    assert item["title"] == "MAL-2026-18205: Malicious code in example-pai (npm)"
    assert item["kind"] == "malicious-package"
    assert item["severity"] == "critical"
    assert "Per source details" not in item["summary"]
    assert "npm/example-pai" in item["summary"]
    assert item["url"] == "https://osv.dev/vulnerability/MAL-2026-18205"


def test_osv_row_skips_a_withdrawn_record():
    assert feeds.osv_row({"id": "MAL-1", "withdrawn": "2026-10-22T00:00:00Z"}) is None


@pytest.mark.parametrize(
    ("purl", "expected"),
    [
        (
            "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
            {
                "ecosystem": "Maven",
                "package": "org.apache.logging.log4j:log4j-core",
                "version": "2.14.1",
            },
        ),
        (
            "pkg:npm/%40scope/name@1.2.3?arch=x#sub",
            {"ecosystem": "npm", "package": "@scope/name", "version": "1.2.3"},
        ),
        ("pkg:pypi/requests", {"ecosystem": "PyPI", "package": "requests"}),
        ("pkg:deb/debian/curl@7.0", None),
        ("not a purl", None),
    ],
)
def test_purl_query(purl, expected):
    assert feeds.purl_query(purl) == expected


def test_ghsa_rows_skip_withdrawn_and_name_the_cve():
    rows = feeds.ghsa_rows(json.loads(_text("ghsa_reviewed.json")))
    assert [item["id"] for item in rows] == ["ghsa:GHSA-aaaa-bbbb-cccc", "ghsa:GHSA-old1-old2-old3"]
    first = rows[0]
    assert first["title"] == "GHSA-aaaa-bbbb-cccc: Path traversal in example-web (CVE-2026-1111)"
    assert first["cves"] == ["CVE-2026-1111"]
    assert first["severity"] == "high"
    assert "CVSS 8.1" in first["summary"]
    assert "EPSS 0.0123" in first["summary"]


def test_delta_log_new_reads_whole_blocks_and_drops_a_cut_one():
    found = feeds.delta_log_new(_text("cvelist_delta_log.json"), SINCE)
    # The off-site link and the updated entry are refused, the old block is out of the window.
    assert [item["cve"] for item in found] == ["CVE-2026-2222", "CVE-2026-4444"]
    cut = _text("cvelist_delta_log.json").split('"fetchTime": "2026-10-22')[0] + '"fetchTime": "20'
    assert [item["cve"] for item in feeds.delta_log_new(cut, SINCE)] == ["CVE-2026-2222"]


def test_cve_record_row_and_a_rejected_record():
    item = feeds.cve_record_row(json.loads(_text("cve_record_2222.json")))
    assert item["title"] == "CVE-2026-2222: Example Gateway auth bypass"
    assert item["severity"] == "critical"
    assert "Affects: Example Gateway." in item["summary"]
    assert feeds.cve_record_row(json.loads(_text("cve_record_4444.json"))) is None


def test_exploitdb_rows_use_the_date_added_and_name_cves():
    rows = feeds.exploitdb_rows(_text("exploitdb_files_exploits.csv"), SINCE)
    assert [item["id"] for item in rows] == ["edb:52002", "edb:52001"]
    first = rows[1]
    assert first["cves"] == ["CVE-2026-1111"]
    assert first["kind"] == "public-exploit"
    assert "Verified." in first["summary"]
    assert first["url"] == "https://www.exploit-db.com/exploits/52001"


def test_metasploit_rows_keep_exploits_and_cve_modules_changed_in_the_window():
    rows = feeds.metasploit_rows(_text("metasploit_modules.json"), SINCE)
    assert [item["id"] for item in rows] == [
        "msf:auxiliary/scanner/example_check",
        "msf:exploit/multi/http/example_rce",
    ]
    assert rows[1]["cves"] == ["CVE-2026-2222"]
    assert rows[1]["published_at"] == "2026-10-22T17:52:59Z"
    assert feeds.metasploit_rows("not json", SINCE) == []


def test_dependabot_rows_keep_open_alerts_only():
    rows = feeds.dependabot_rows(json.loads(_text("dependabot_alerts.json")), "example/app")
    assert [item["id"] for item in rows] == ["dependabot:example/app#7"]
    assert rows[0]["title"].endswith("(example/app)")
    assert "Fixed in 2.0.1." in rows[0]["summary"]


def test_rows_keep_only_valid_cve_ids_and_known_severities():
    item = feeds.row(
        "x:1",
        "x",
        "t",
        "https://x",
        kind="vulnerability",
        cves=["cve-2026-1", "bogus", "CVE-2026-1234"],
        severity="Urgent",
    )
    assert item["cves"] == ["CVE-2026-1234"]
    assert item["severity"] is None


# Fetchers


def _osv_routes() -> dict:
    return {
        f"{source.OSV_BUCKET}/npm/modified_id.csv": _text("osv_modified_id.csv"),
        f"{source.OSV_BUCKET}/PyPI/modified_id.csv": "2026-10-20T00:00:00Z,MAL-2026-1\n",
        f"{source.OSV_BUCKET}/crates.io/modified_id.csv": "2026-10-20T00:00:00Z,MAL-2026-2\n",
        f"{source.OSV_BUCKET}/RubyGems/modified_id.csv": "2026-10-20T00:00:00Z,MAL-2026-3\n",
        f"{source.OSV_API}/vulns/MAL-2026-18205": _text("osv_mal_record.json"),
        f"{source.OSV_API}/vulns/MAL-2026-18204": _text("osv_mal_record.json").replace(
            "18205", "18204"
        ),
        f"{source.OSV_API}/vulns/MAL-2026-18100": _text("osv_mal_record.json").replace(
            "18205", "18100"
        ),
    }


def test_fetch_osv_malicious_reads_the_index_with_a_range_then_each_record():
    seen: list = []
    _serve(_osv_routes(), seen)
    result = source.fetch_osv_malicious(SINCE)
    assert result.ok
    assert [item["id"] for item in result.rows] == [
        "osv-mal:MAL-2026-18205",
        "osv-mal:MAL-2026-18204",
        "osv-mal:MAL-2026-18100",
    ]
    index = [r for r in seen if r.url.path.endswith("modified_id.csv")]
    assert all(r.headers["range"].startswith("bytes=0-") for r in index)
    assert all("authorization" not in r.headers for r in seen)


def test_fetch_osv_malicious_names_an_unreachable_ecosystem():
    routes = _osv_routes()
    del routes[f"{source.OSV_BUCKET}/PyPI/modified_id.csv"]
    _serve(routes)
    result = source.fetch_osv_malicious(SINCE)
    assert len(result.rows) == 3
    assert result.problems == ["OSV PyPI index returned status 404"]
    assert not result.ok


def test_fetch_osv_scan_sends_package_coordinates_only():
    seen: list = []
    _serve(
        {
            f"{source.OSV_API}/querybatch": _text("osv_querybatch.json"),
            f"{source.OSV_API}/vulns/GHSA-jfh8-c2jp-5v3q": _text("osv_scan_record.json"),
        },
        seen,
    )
    result = source.fetch_osv_scan(
        [
            {
                "asset": "Billing API",
                "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
            },
            {"asset": "Laptop", "purl": "pkg:deb/debian/curl@7.0"},
            {"asset": "Web", "purl": "pkg:npm/left-pad@1.0.0"},
        ]
    )
    assert result.ok
    assert len(result.rows) == 1
    assert result.rows[0]["id"].startswith("osv-scan:billing-api-")
    assert result.rows[0]["id"].endswith(":GHSA-jfh8-c2jp-5v3q")
    assert not any(char.isspace() for char in result.rows[0]["id"])
    assert result.rows[0]["title"].endswith("(in Billing API)")
    body = json.loads(next(r for r in seen if r.url.path.endswith("querybatch")).content)
    assert body["queries"] == [
        {
            "package": {"name": "org.apache.logging.log4j:log4j-core", "ecosystem": "Maven"},
            "version": "2.14.1",
        },
        {"package": {"name": "left-pad", "ecosystem": "npm"}, "version": "1.0.0"},
    ]
    assert "Billing API" not in json.dumps(body)


def test_fetch_osv_scan_without_a_usable_purl_makes_no_request():
    seen: list = []
    _serve({}, seen)
    assert source.fetch_osv_scan([{"asset": "x", "purl": "pkg:deb/a/b@1"}]).rows == []
    assert seen == []


def test_fetch_ghsa_merges_reviewed_and_malware_inside_the_window():
    seen: list = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        name = (
            "ghsa_malware.json" if request.url.params["type"] == "malware" else "ghsa_reviewed.json"
        )
        return httpx.Response(200, text=_text(name))

    source._TRANSPORT = httpx.MockTransport(handler)
    result = source.fetch_ghsa(SINCE)
    assert result.ok
    assert [item["id"] for item in result.rows] == [
        "ghsa:GHSA-xvgg-qjjh-gq34",
        "ghsa:GHSA-aaaa-bbbb-cccc",
    ]
    assert {r.url.params["published"] for r in seen} == {">=2026-10-22"}
    assert all("authorization" not in r.headers for r in seen)


def test_fetch_ghsa_pages_until_a_short_page_and_stops_at_three():
    pages: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        kind, page = request.url.params["type"], request.url.params["page"]
        pages.append((kind, page))
        # Reviewed never runs out, so only the page cap stops it. Malware has one short page.
        count = 100 if kind == "reviewed" else 2
        items = [
            {
                "ghsa_id": f"GHSA-{kind[:3]}{page}-{n:04d}",
                "html_url": "https://github.com/advisories/x",
                "summary": "s",
                "type": kind,
                "severity": "high",
                "published_at": "2026-10-22T20:00:00Z",
                "vulnerabilities": [],
            }
            for n in range(count)
        ]
        return httpx.Response(200, text=json.dumps(items))

    source._TRANSPORT = httpx.MockTransport(handler)
    result = source.fetch_ghsa(SINCE)
    assert pages == [
        ("reviewed", "1"),
        ("reviewed", "2"),
        ("reviewed", "3"),
        ("malware", "1"),
    ]
    assert len(result.rows) == 302


def test_fetch_cvelist_reads_new_records_from_the_delta_log():
    raw = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026"
    _serve(
        {
            source.DELTA_LOG: _text("cvelist_delta_log.json"),
            f"{raw}/2xxx/CVE-2026-2222.json": _text("cve_record_2222.json"),
            f"{raw}/4xxx/CVE-2026-4444.json": _text("cve_record_4444.json"),
        }
    )
    result = source.fetch_cvelist(SINCE)
    assert result.ok
    assert [item["id"] for item in result.rows] == ["cvelist:CVE-2026-2222"]


def test_fetch_cvelist_reports_an_unreachable_log():
    _serve({})
    result = source.fetch_cvelist(SINCE)
    assert result.rows == []
    assert result.problems == ["cvelistV5 delta log returned status 404"]
    assert not result.ok


def test_fetch_exploitdb_and_metasploit():
    _serve(
        {
            source.EXPLOITDB_CSV: _text("exploitdb_files_exploits.csv"),
            source.METASPLOIT_JSON: _text("metasploit_modules.json"),
        }
    )
    assert len(source.fetch_exploitdb(SINCE).rows) == 2
    assert len(source.fetch_metasploit(SINCE).rows) == 2


def test_an_empty_index_is_a_problem_not_a_quiet_day():
    _serve({source.EXPLOITDB_CSV: "  "})
    result = source.fetch_exploitdb(SINCE)
    assert result.problems == ["Exploit-DB index is empty"]


def test_a_stale_cache_answer_is_not_live(tmp_path):
    _serve({source.EXPLOITDB_CSV: _text("exploitdb_files_exploits.csv")})
    assert source.fetch_exploitdb(SINCE).live is True
    # Expire the cached copy, then fail the upstream: the cache answers as stale.
    with sqlite3.connect(tmp_path / "data" / "http_cache.sqlite") as conn:
        conn.execute("UPDATE http_cache SET fetched_at = fetched_at - 999999")
    source._TRANSPORT = httpx.MockTransport(lambda _request: httpx.Response(503, text="down"))
    result = source.fetch_exploitdb(SINCE)
    assert result.live is False
    assert not result.ok


def test_dependabot_sends_the_token_and_leaves_no_cached_answer(tmp_path):
    seen: list = []
    _serve(
        {
            "https://api.github.com/repos/example/app/dependabot/alerts": _text(
                "dependabot_alerts.json"
            )
        },
        seen,
    )
    result = source.fetch_dependabot(["example/app"], "ghp_secretvalue123456789012345678901234")
    assert result.ok
    assert [item["id"] for item in result.rows] == ["dependabot:example/app#7"]
    assert seen[0].headers["authorization"].startswith("Bearer ")
    assert seen[0].url.params["severity"] == "critical,high"
    cache = tmp_path / "data" / "http_cache.sqlite"
    assert not cache.exists() or b"example-web" not in cache.read_bytes()


def test_dependabot_failure_message_holds_no_token():
    _serve({})
    token = "ghp_secretvalue123456789012345678901234"
    result = source.fetch_dependabot(["example/app"], token)
    assert result.rows == []
    assert result.problems and token not in " ".join(result.problems)


# Tools


def test_vuln_feed_list_names_every_feed():
    envelope = source.vuln_feed_list()
    assert [item["feed"] for item in envelope["data"]["feeds"]] == list(source.FEED_NAMES)


def test_vuln_feed_recent_wraps_untrusted_text_and_reports_the_count(monkeypatch):
    _serve({source.EXPLOITDB_CSV: _text("exploitdb_files_exploits.csv")})
    # The fixture dates are fixed, so pin the clock inside the connector.

    class _Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime(2026, 10, 23, 2, 0, tzinfo=tz)

    monkeypatch.setattr(source, "datetime", _Clock)
    envelope = source.vuln_feed_recent("exploit-db", days=1, limit=1)
    data = envelope["data"]
    assert data["count"] == 2
    assert len(data["items"]) == 1
    assert "untrusted" in data["items"][0]["title"]
    assert envelope["cache"] == "miss"


def test_vuln_feed_recent_offline_is_a_warning_not_data(monkeypatch):
    monkeypatch.setenv("CYBERAU_OFFLINE", "1")
    envelope = source.vuln_feed_recent("ghsa")
    assert envelope["data"] is None
    assert envelope["cache"] == "snapshot"
    assert envelope["warnings"]


def test_vuln_feed_recent_unreachable_upstream_is_a_warning():
    _serve({})
    envelope = source.vuln_feed_recent("metasploit")
    assert envelope["data"] is None
    assert envelope["warnings"]
