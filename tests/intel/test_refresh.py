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
    for name in ("attack", "nvd", "abusech", "otx", "radar"):
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
