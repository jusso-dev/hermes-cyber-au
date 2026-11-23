"""cyberau-mcp refresh: keyless public feeds into the intel store."""

import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml
from cyberau_common.cli import main

ROOT = Path(__file__).resolve().parents[2]

KEV = {
    "catalogVersion": "2026.10.17",
    "dateReleased": "2026-10-17T15:00:00.000Z",
    "vulnerabilities": [
        {
            "cveID": "CVE-2026-0001",
            "dateAdded": "2026-10-01",
            "dueDate": "2026-10-22",
            "knownRansomwareCampaignUse": "Known",
            "cwes": ["CWE-79"],
        },
        {
            "cveID": "CVE-2026-0002",
            "dateAdded": "2026-10-02",
            "dueDate": "2026-10-23",
            "knownRansomwareCampaignUse": "Unknown",
            "cwes": [],
        },
    ],
}

ASD_ITEM = {
    "id": "asd:alerts:0123456789abcdef0123456789abcdef01234567",
    "feed": "alerts",
    "link": "https://www.cyber.gov.au/about-us/view-all-content/alerts-and-advisories/x",
    "title": "Critical vulnerability in Example product",
    "summary": "Patch now.",
    "published": "2026-10-15",
    "body": "",
    "cves": ["CVE-2026-0001"],
    "attack_ids": [],
}

AUSCERT_RECORDS = [
    {
        "bulletin_id": f"ESB-2026.900{n}",
        "kind": "ESB",
        "title": f"Bulletin {n}",
        "link": f"https://portal.auscert.org.au/bulletins/ESB-2026.900{n}",
        "stamp": datetime(2026, 10, 10 + n, tzinfo=UTC),
        "summary": "Patch now.",
        "cvss_max": None,
        "cves": [],
    }
    for n in (1, 2)
]


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("HERMES_HOME", raising=False)
    monkeypatch.delenv("CYBERAU_HOME", raising=False)


@pytest.fixture
def feeds(monkeypatch):
    """Answer every adapter from fixtures, as if each feed was fetched live."""
    from cyberau_abusech import source as abusech
    from cyberau_asd_acsc import source as asd
    from cyberau_auscert import source as auscert
    from cyberau_cisa_kev import source as kev
    from cyberau_first_epss import source as epss

    state = {"asd_live": True, "epss_calls": []}

    def poll_feed(feed):
        warning = "" if state["asd_live"] else f"{feed} served from the last stored poll"
        return ([dict(ASD_ITEM)] if feed == "alerts" else []), state["asd_live"], warning

    def score_batch(cve_ids):
        state["epss_calls"].append(list(cve_ids))
        rows = [
            {"cve": cve, "epss": 0.5, "percentile": 0.9, "date": "2026-10-17", "model": "v1"}
            for cve in cve_ids
        ]
        return rows, "miss", ""

    def feodo_blocklist(country=None):
        return {
            "cache": "miss",
            "warnings": [],
            "data": [
                {
                    "indicator": "203.0.113.7",
                    "malware": "QakBot",
                    "first_seen": "2026-10-01T00:00:00Z",
                    "last_online": "2026-10-16T00:00:00Z",
                },
                {"indicator": "not an ip", "malware": None},
            ],
        }

    monkeypatch.setattr(asd, "poll_feed", poll_feed)
    monkeypatch.setattr(kev, "catalogue", lambda: (KEV, "miss"))
    monkeypatch.setattr(epss, "score_batch", score_batch)
    monkeypatch.setattr(auscert, "poll_bulletins", lambda: ([dict(r) for r in AUSCERT_RECORDS], ""))
    monkeypatch.setattr(abusech, "feodo_blocklist", feodo_blocklist)
    return state


def test_ingest_arguments_parse_and_load_the_store(feeds, store_path, capsys):
    code = main(["refresh", "--sources", "asd,kev,epss,auscert,feodo", "--store"])
    out = capsys.readouterr().out.splitlines()
    assert code == 0, out
    assert out[0] == "refresh ok: asd 1, kev 2, epss 2, auscert 2, feodo 1"
    assert "kev ok 2 items, stored 2" in out

    from store.api import table_counts

    counts = table_counts(store_path)
    assert counts["vulnerabilities"] == 2
    assert counts["indicators"] == 1
    assert counts["advisories"] >= 2


def test_store_is_untouched_without_the_flag(feeds, store_path, capsys):
    assert main(["refresh", "--sources", "kev"]) == 0
    assert capsys.readouterr().out.splitlines()[1] == "kev ok 2 items"
    assert not store_path.exists()


def test_epss_scores_every_kev_cve_in_batches(feeds, monkeypatch, capsys):
    from store import refresh

    monkeypatch.setattr(refresh, "_EPSS_BATCH", 1)
    assert main(["refresh", "--sources", "epss"]) == 0
    assert feeds["epss_calls"] == [["CVE-2026-0001"], ["CVE-2026-0002"]]


def test_a_stale_source_fails_first_and_the_rest_still_run(feeds, capsys):
    feeds["asd_live"] = False
    code = main(["refresh", "--sources", "asd,kev"])
    out = capsys.readouterr().out.splitlines()
    assert code == 1
    assert out[0].startswith("refresh failed: asd:")
    assert "kev ok 2 items" in out


def test_optional_sources_do_not_fail(feeds, capsys):
    feeds["asd_live"] = False
    code = main(["refresh", "--sources", "kev", "--optional-sources", "asd"])
    out = capsys.readouterr().out.splitlines()
    assert code == 0
    assert any(line.startswith("asd fail") for line in out)


def test_sources_without_an_adapter_are_refused_not_skipped(capsys):
    for name in ("attack", "abusech", "otx", "radar"):
        assert main(["refresh", "--sources", "kev", "--optional-sources", name]) == 2
        assert f"unknown sources: {name}" in capsys.readouterr().err


def test_bad_arguments_fail_in_the_refresh_parser(capsys):
    assert main(["refresh", "--sources", "kev", "--snapshot-dir", "intel/snapshots"]) == 2
    capsys.readouterr()
    assert main(["refresh", "--sources", "asd", "--kev-snapshot", "intel/kev.json"]) == 2
    assert "--kev-snapshot requires kev" in capsys.readouterr().err
    assert main(["refresh"]) == 2
    assert "usage: cyberau-mcp refresh" in capsys.readouterr().err
    assert main(["refresh", "--sources", "kev,nope"]) == 2
    assert "unknown sources: nope" in capsys.readouterr().err


def test_live_kev_refresh_writes_a_private_local_snapshot(feeds, tmp_path, capsys):
    snapshot = tmp_path / "snapshots" / "kev.json"
    assert main(["refresh", "--sources", "kev", "--kev-snapshot", str(snapshot)]) == 0
    assert json.loads(snapshot.read_text(encoding="utf-8")) == KEV
    assert oct(snapshot.stat().st_mode & 0o777) == "0o600"
    assert "kev ok 2 items" in capsys.readouterr().out


def test_failed_kev_refresh_does_not_replace_the_last_snapshot(feeds, tmp_path, monkeypatch):
    from cyberau_cisa_kev import source as kev

    snapshot = tmp_path / "kev.json"
    snapshot.write_text('{"last":"known-good"}\n', encoding="utf-8")
    monkeypatch.setattr(kev, "catalogue", lambda: (KEV, "snapshot"))
    assert main(["refresh", "--sources", "kev", "--kev-snapshot", str(snapshot)]) == 1
    assert json.loads(snapshot.read_text(encoding="utf-8")) == {"last": "known-good"}


def test_nightly_outputs_status_and_summary_but_no_feed_rows(feeds, tmp_path, capsys):
    feeds_dir = tmp_path / "feeds"
    summary = tmp_path / "PR_BODY.md"
    args = [
        "refresh",
        "--sources",
        "asd,kev",
        "--catalogue",
        str(feeds_dir / "catalogue.yaml"),
        "--summary",
        str(summary),
    ]
    assert main(args) == 0
    status = json.loads((feeds_dir / "status.json").read_text(encoding="utf-8"))
    assert status["sources"]["kev"]["item_count"] == 2
    assert status["sources"]["kev"]["last_error"] is None
    assert not (feeds_dir / "catalogue.yaml").exists()
    assert sorted(path.name for path in tmp_path.rglob("*") if path.is_file()) == [
        "PR_BODY.md",
        "status.json",
    ]
    assert "| kev | ok | 2 |" in summary.read_text(encoding="utf-8")

    feeds["asd_live"] = False
    assert main(args) == 1
    status = json.loads((feeds_dir / "status.json").read_text(encoding="utf-8"))
    assert status["sources"]["asd"]["status"] == "fail"
    assert status["sources"]["asd"]["last_ok"]
    assert status["sources"]["asd"]["last_error"]


def test_refresh_runs_from_the_checkout_plugin(capsys):
    assert main(["refresh", "--sources", "nope"]) == 2
    capsys.readouterr()
    assert (
        Path(sys.modules["store.refresh"].__file__).parent.parent == ROOT / "plugins" / "cyber-au"
    )


def test_refresh_keys_match_the_feed_catalogue():
    from store import refresh

    feeds = yaml.safe_load((ROOT / "feeds" / "catalogue.yaml").read_text(encoding="utf-8"))["feeds"]
    keyed = {feed["refresh"]: feed for feed in feeds if "refresh" in feed}
    assert len(keyed) == len([feed for feed in feeds if "refresh" in feed])
    assert sorted(key for key, feed in keyed.items() if feed["refresh_supported"]) == sorted(
        refresh.SUPPORTED
    )
    for key, feed in keyed.items():
        assert feed["refresh_supported"] is (key in refresh.SUPPORTED), key
    for feed in feeds:
        if "refresh" not in feed:
            assert "refresh_supported" not in feed, feed["id"]


def test_a_second_refresh_expires_what_the_feeds_withdrew(feeds, store_path, monkeypatch, capsys):
    from cyberau_abusech import source as abusech
    from cyberau_cisa_kev import source as kev

    assert main(["refresh", "--sources", "kev,feodo", "--store"]) == 0
    capsys.readouterr()

    shrunk = {**KEV, "vulnerabilities": KEV["vulnerabilities"][:1]}
    monkeypatch.setattr(kev, "catalogue", lambda: (shrunk, "miss"))
    monkeypatch.setattr(
        abusech,
        "feodo_blocklist",
        lambda country=None: {"cache": "miss", "warnings": [], "data": []},
    )
    assert main(["refresh", "--sources", "kev,feodo", "--store"]) == 0
    out = capsys.readouterr().out.splitlines()
    assert "kev ok 1 items, stored 1, expired 1" in out
    assert "feodo ok 0 items, stored 0, expired 1" in out

    from store.api import table_counts

    counts = table_counts(store_path)
    assert counts["indicators"] == 0
    assert counts["vulnerabilities"] == 1  # 0002 was only in the store for KEV


def test_a_degraded_feodo_list_expires_nothing(feeds, store_path, monkeypatch, capsys):
    from cyberau_abusech import source as abusech

    assert main(["refresh", "--sources", "feodo", "--store"]) == 0
    monkeypatch.setattr(
        abusech,
        "feodo_blocklist",
        lambda country=None: {"cache": "miss", "warnings": ["partial"], "data": []},
    )
    assert main(["refresh", "--sources", "feodo", "--store"]) == 0

    from store.api import table_counts

    assert table_counts(store_path)["indicators"] == 1


def test_epss_alone_scores_the_stored_kev_list(feeds, store_path, monkeypatch, capsys):
    from cyberau_cisa_kev import source as kev

    assert main(["refresh", "--sources", "kev", "--store"]) == 0

    def no_fetch():
        raise AssertionError("EPSS must not fetch KEV when the store has it")

    monkeypatch.setattr(kev, "catalogue", no_fetch)
    feeds["epss_calls"].clear()
    assert main(["refresh", "--sources", "epss", "--store"]) == 0
    assert feeds["epss_calls"] == [["CVE-2026-0001", "CVE-2026-0002"]]


def test_custom_feeds_load_items_and_one_failure_does_not_fail_the_rest(
    store_path, tmp_path, monkeypatch, capsys
):
    from cyberau_custom_feeds import source

    data = store_path.parent
    data.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(data))
    (data / "watchlists.yaml").write_text(
        "feeds:\n"
        "  - id: good\n    url: https://good.example/rss\n"
        "  - id: broken\n    url: https://broken.example/rss\n",
        encoding="utf-8",
    )
    item = {
        "id": "0123456789abcdef",
        "title": "Defender for Cloud adds scanning",
        "url": "https://good.example/a",
        "guid": "a",
        "published": "2026-10-19T08:00:00Z",
        "categories": ["Security"],
        "summary": "Agentless.",
    }

    def fetch_items(feed, **_kwargs):
        if feed.id == "broken":
            return [], "snapshot", "Broken feed is unavailable"
        return [item], "miss", ""

    monkeypatch.setattr(source, "fetch_items", fetch_items)
    code = main(["refresh", "--sources", "custom", "--store"])
    out = capsys.readouterr().out.splitlines()
    assert code == 0, out
    assert any("custom ok 1 items, stored 1" in line for line in out), out

    from store.db import open_store

    row = (
        open_store(store_path)
        .connection()
        .execute("SELECT id, source_id, summary FROM advisories")
        .fetchone()
    )
    assert row["id"] == "feed-good:0123456789abcdef"
    assert row["source_id"] == "feed-good"
    assert "Categories: Security" in row["summary"]

    monkeypatch.setattr(source, "fetch_items", lambda feed, **_k: ([], "snapshot", "down"))
    assert main(["refresh", "--sources", "custom"]) == 1


def test_custom_feeds_without_config_do_nothing(store_path, monkeypatch, capsys):
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(store_path.parent))
    assert main(["refresh", "--sources", "custom"]) == 0
    assert "custom ok 0 items" in capsys.readouterr().out


# Daily vulnerability feeds


def _vuln_row(source_id: str, ident: str, title: str, **extra) -> dict:
    return {
        "id": f"{source_id}:{ident}",
        "source": source_id,
        "title": title,
        "url": f"https://example.com/{ident}",
        "published_at": "2026-10-22T20:00:00Z",
        "summary": extra.pop("summary", "Severity: high. A synthetic row."),
        "cves": [],
        "severity": "high",
        "kind": "vulnerability",
        **extra,
    }


def _stored(store_path):
    from store.db import open_store

    rows = open_store(store_path).connection().execute("SELECT id, source_id FROM advisories")
    return sorted((row["source_id"], row["id"]) for row in rows)


@pytest.mark.parametrize(
    ("key", "function", "source_id"),
    [
        ("ghsa", "fetch_ghsa", "ghsa"),
        ("cvelist", "fetch_cvelist", "cvelist"),
        ("exploitdb", "fetch_exploitdb", "exploit-db"),
        ("metasploit", "fetch_metasploit", "metasploit"),
    ],
)
def test_vulnerability_feeds_load_advisories(
    key, function, source_id, store_path, monkeypatch, capsys
):
    from cyberau_vuln_feeds import source

    seen = []

    def fetch(since, **_kwargs):
        seen.append(since)
        return source.Fetched(rows=[_vuln_row(source_id, "1", "CVE-2026-1111: thing")])

    monkeypatch.setattr(source, function, fetch)
    assert main(["refresh", "--sources", key, "--store"]) == 0
    assert f"{key} ok 1 items, stored 1" in capsys.readouterr().out
    assert _stored(store_path) == [(source_id, f"{source_id}:1")]
    assert seen and seen[0].tzinfo is not None


def test_the_lookback_window_is_set_by_the_environment(monkeypatch):
    from datetime import UTC, datetime, timedelta

    from store import refresh

    monkeypatch.setenv("CYBERAU_FEED_LOOKBACK_HOURS", "6")
    gap = datetime.now(UTC) - refresh._lookback()
    assert timedelta(hours=5, minutes=59) < gap < timedelta(hours=6, minutes=1)
    monkeypatch.setenv("CYBERAU_FEED_LOOKBACK_HOURS", "nonsense")
    assert datetime.now(UTC) - refresh._lookback() > timedelta(hours=47)


def test_a_vulnerability_feed_that_is_not_live_or_has_a_problem_fails(monkeypatch, capsys):
    from cyberau_vuln_feeds import source

    monkeypatch.setattr(
        source, "fetch_ghsa", lambda since, **_k: source.Fetched(rows=[], live=False)
    )
    assert main(["refresh", "--sources", "ghsa"]) == 1
    assert "stale cache" in capsys.readouterr().out

    monkeypatch.setattr(
        source,
        "fetch_exploitdb",
        lambda since, **_k: source.Fetched(rows=[], problems=["Exploit-DB index is empty"]),
    )
    assert main(["refresh", "--sources", "exploitdb"]) == 1
    assert "Exploit-DB index is empty" in capsys.readouterr().out


def test_a_partial_vulnerability_feed_keeps_its_rows_and_names_the_gap(
    store_path, monkeypatch, capsys
):
    from cyberau_vuln_feeds import source

    monkeypatch.setattr(
        source,
        "fetch_ghsa",
        lambda since, **_k: source.Fetched(
            rows=[_vuln_row("ghsa", "1", "GHSA-1: x")],
            problems=["GitHub advisories (malware) down"],
        ),
    )
    assert main(["refresh", "--sources", "ghsa", "--store"]) == 0
    out = capsys.readouterr().out
    assert "ghsa ok 1 items, stored 1 (partial: GitHub advisories (malware) down)" in out


def test_osv_adds_the_inventory_scan_to_the_malicious_package_feed(
    store_path, tmp_path, monkeypatch, capsys
):
    from cyberau_vuln_feeds import source

    data = store_path.parent
    data.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(data))
    (data / "assets.yaml").write_text(
        "assets:\n"
        "  - name: Billing API\n    vendor: example\n    product: billing\n"
        "    purl: pkg:npm/left-pad@1.0.0\n",
        encoding="utf-8",
    )
    scanned = []

    def scan(packages, **_kwargs):
        scanned.extend(packages)
        return source.Fetched(
            rows=[
                _vuln_row("osv-scan", "billing-api-abc123:GHSA-1", "GHSA-1: bad (in Billing API)")
            ]
        )

    monkeypatch.setattr(
        source,
        "fetch_osv_malicious",
        lambda since, **_k: source.Fetched(rows=[_vuln_row("osv-mal", "MAL-1", "MAL-1: bad")]),
    )
    monkeypatch.setattr(source, "fetch_osv_scan", scan)
    assert main(["refresh", "--sources", "osv", "--store"]) == 0
    assert "osv ok 2 items, stored 2" in capsys.readouterr().out
    assert scanned == [{"asset": "Billing API", "purl": "pkg:npm/left-pad@1.0.0"}]
    assert [source_id for source_id, _ in _stored(store_path)] == ["osv-mal", "osv-scan"]


def test_osv_without_an_inventory_skips_the_scan(store_path, monkeypatch, capsys):
    from cyberau_vuln_feeds import source

    monkeypatch.setenv("CYBERAU_DATA_DIR", str(store_path.parent))
    monkeypatch.setattr(source, "fetch_osv_malicious", lambda since, **_k: source.Fetched(rows=[]))
    monkeypatch.setattr(
        source,
        "fetch_osv_scan",
        lambda *_a, **_k: pytest.fail("no inventory, so no scan and no request"),
    )
    assert main(["refresh", "--sources", "osv"]) == 0


def test_nvd_stores_the_score_and_one_advisory_per_cve(store_path, monkeypatch, capsys):
    from cyberau_nvd import source

    def search(published_from=None, cvss_v3_severity=None, limit=20, **_k):
        row = {
            "cve_id": "CVE-2026-1111" if cvss_v3_severity == "CRITICAL" else "CVE-2026-2222",
            "description": "<<untrusted source=nvd>> Remote code execution. <<end untrusted>>",
            "cvss": {
                "version": "cvssMetricV31",
                "score": 9.8 if cvss_v3_severity == "CRITICAL" else 7.5,
                "severity": cvss_v3_severity,
            },
            "cwes": ["CWE-94"],
            "references": [],
        }
        return {"cache": "miss", "data": [row], "warnings": []}

    monkeypatch.setattr(source, "nvd_search", search)
    assert main(["refresh", "--sources", "nvd", "--store"]) == 0
    assert "nvd ok 2 items, stored 2" in capsys.readouterr().out

    from store.db import open_store

    conn = open_store(store_path).connection()
    scores = {
        row["cve_id"]: (row["cvss_v3"], row["cwe"])
        for row in conn.execute("SELECT cve_id, cvss_v3, cwe FROM vulnerabilities")
    }
    assert scores == {"CVE-2026-1111": (9.8, "CWE-94"), "CVE-2026-2222": (7.5, "CWE-94")}
    row = conn.execute("SELECT title, summary FROM advisories WHERE id = 'nvd:CVE-2026-1111'")
    row = row.fetchone()
    assert row["title"] == "CVE-2026-1111: Remote code execution."
    assert "Severity: critical. CVSS 9.8." in row["summary"]


def test_nvd_that_answers_from_a_snapshot_fails(monkeypatch, capsys):
    from cyberau_nvd import source

    monkeypatch.setattr(
        source,
        "nvd_search",
        lambda **_k: {"cache": "snapshot", "data": [], "warnings": ["NVD is unavailable"]},
    )
    assert main(["refresh", "--sources", "nvd"]) == 1
    assert "NVD is unavailable" in capsys.readouterr().out


def test_nvd_empty_answer_with_a_warning_is_a_failure_not_a_quiet_day(monkeypatch, capsys):
    from cyberau_nvd import source

    seen = []

    def search(**kwargs):
        seen.append(kwargs)
        return {"cache": "miss", "data": [], "warnings": ["NVD search payload was not usable"]}

    monkeypatch.setattr(source, "nvd_search", search)
    assert main(["refresh", "--sources", "nvd"]) == 1
    assert "not usable" in capsys.readouterr().out
    # NVD refuses a start date without an end date.
    assert all(call["published_from"] and call["published_to"] for call in seen)


def test_vulnfeeds_reads_the_shipped_pack_without_any_watchlist(store_path, monkeypatch, capsys):
    from cyberau_custom_feeds import source

    monkeypatch.setenv("CYBERAU_DATA_DIR", str(store_path.parent))
    fetched = []

    def fetch_items(feed, **_kwargs):
        fetched.append(feed.id)
        item = {
            "id": "0123456789abcdef",
            "title": f"{feed.id} item",
            "url": "https://example.com/a",
            "guid": "a",
            "published": "2026-10-22T08:00:00Z",
            "categories": ["critical"],
            "summary": "Text.",
        }
        return [item], "miss", ""

    monkeypatch.setattr(source, "fetch_items", fetch_items)
    assert main(["refresh", "--sources", "vulnfeeds", "--store"]) == 0
    assert fetched == ["cve-now-critical", "pwn-watch"]
    assert "vulnfeeds ok 2 items, stored 2" in capsys.readouterr().out
    assert _stored(store_path) == [
        ("feed-cve-now-critical", "feed-cve-now-critical:0123456789abcdef"),
        ("feed-pwn-watch", "feed-pwn-watch:0123456789abcdef"),
    ]


def test_dependabot_is_opt_in_and_needs_a_private_token_file(
    store_path, tmp_path, monkeypatch, capsys
):
    from cyberau_vuln_feeds import source

    data = store_path.parent
    data.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(data))
    monkeypatch.delenv("GITHUB_DEPENDABOT_TOKEN", raising=False)
    assert main(["refresh", "--sources", "dependabot"]) == 0
    assert "no dependabot.yaml" in capsys.readouterr().out

    token = tmp_path / "token"
    token.write_text("ghp_" + "a" * 36 + "\n", encoding="utf-8")
    token.chmod(0o644)
    (data / "dependabot.yaml").write_text(
        f"repos:\n  - example/app\n  - not a repo\ntoken_file: {token}\n", encoding="utf-8"
    )
    assert main(["refresh", "--sources", "dependabot"]) == 1
    assert "chmod 600" in capsys.readouterr().out

    token.chmod(0o600)
    calls = []

    def fetch(repos, secret):
        calls.append((repos, secret))
        return source.Fetched(rows=[_vuln_row("dependabot", "example/app#7", "GHSA-1: x")])

    monkeypatch.setattr(source, "fetch_dependabot", fetch)
    assert main(["refresh", "--sources", "dependabot", "--store"]) == 0
    out = capsys.readouterr().out
    assert calls == [(["example/app"], "ghp_" + "a" * 36)]
    assert "dependabot ok 1 items, stored 1" in out
    assert "ghp_" not in out
