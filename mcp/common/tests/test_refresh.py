import json
import sys
from pathlib import Path

import pytest
from cyberau_common.cli import main

ROOT = Path(__file__).resolve().parents[3]
AUSCERT_XML = ROOT / "mcp" / "auscert" / "tests" / "fixtures" / "bulletins.xml"

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


@pytest.fixture
def feeds(monkeypatch):
    """Answer every adapter from fixtures, as if each feed was fetched live."""
    from cyberau_abusech import source as abusech
    from cyberau_asd_acsc import source as asd
    from cyberau_auscert import source as auscert
    from cyberau_cisa_kev import source as kev
    from cyberau_first_epss import source as epss

    state = {"asd_method": "direct", "epss_calls": []}

    def items_for_feed(feed):
        if feed != "alerts":
            return [], "miss", "", state["asd_method"]
        return [dict(ASD_ITEM)], "miss", "", state["asd_method"]

    def epss_fetch(params, *, force_live=False):
        state["epss_calls"].append(params)
        data = [
            {"cve": cve, "epss": "0.5", "percentile": "0.9", "date": "2026-10-17"}
            for cve in params["cve"].split(",")
        ]
        return {"version": "v2025.03.14", "data": data}, "miss", ""

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

    monkeypatch.setattr(asd, "_items_for_feed", items_for_feed)
    monkeypatch.setattr(kev, "_catalog", lambda: (KEV, "miss"))
    monkeypatch.setattr(epss, "_fetch", epss_fetch)

    def auscert_fetch(*, force_live=False):
        assert not force_live, "refresh must not bypass the AusCERT cache and rate limit"
        return auscert._Feed(AUSCERT_XML.read_text(encoding="utf-8"), "miss")

    monkeypatch.setattr(auscert, "_fetch", auscert_fetch)
    monkeypatch.setattr(abusech, "feodo_blocklist", feodo_blocklist)
    return state


@pytest.fixture
def store_path(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "plugins" / "cyber-au"))
    yield tmp_path / "intel.sqlite"
    from store.db import close_store

    close_store(tmp_path / "intel.sqlite")


def test_ingest_arguments_parse_and_load_the_store(feeds, store_path, capsys):
    code = main(["refresh", "--sources", "asd,kev,epss,auscert,feodo", "--store"])
    out = capsys.readouterr().out.splitlines()
    assert code == 0, out
    assert out[0].startswith("refresh ok: asd 1, kev 2, epss 2, auscert ")
    assert "feodo 1" in out[0]
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
    from cyberau_common import refresh

    monkeypatch.setattr(refresh, "_EPSS_BATCH", 1)
    assert main(["refresh", "--sources", "epss"]) == 0
    assert [call["cve"] for call in feeds["epss_calls"]] == ["CVE-2026-0001", "CVE-2026-0002"]


def test_a_stale_source_fails_first_and_the_rest_still_run(feeds, capsys):
    feeds["asd_method"] = "snapshot"
    code = main(["refresh", "--sources", "asd,kev"])
    out = capsys.readouterr().out.splitlines()
    assert code == 1
    assert out[0].startswith("refresh failed: asd:")
    assert "kev ok 2 items" in out


def test_optional_and_not_yet_supported_sources_do_not_fail(feeds, capsys):
    feeds["asd_method"] = "stale"
    code = main(["refresh", "--sources", "kev,attack", "--optional-sources", "asd"])
    out = capsys.readouterr().out.splitlines()
    assert code == 0
    assert "attack skipped 0 items (no refresh adapter yet)" in out
    assert any(line.startswith("asd fail") for line in out)


def test_bad_arguments_fail_in_the_refresh_parser(capsys):
    assert main(["refresh"]) == 2
    assert "usage: cyberau-mcp refresh" in capsys.readouterr().err
    assert main(["refresh", "--sources", "kev,nope"]) == 2
    assert "unknown sources: nope" in capsys.readouterr().err


def test_nightly_outputs_status_snapshots_and_summary(feeds, tmp_path, capsys):
    feeds_dir = tmp_path / "feeds"
    snapshots = tmp_path / "intel" / "snapshots"
    summary = tmp_path / "PR_BODY.md"
    args = [
        "refresh",
        "--sources",
        "asd,kev",
        "--snapshot-dir",
        str(snapshots),
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
    assert len(json.loads((snapshots / "kev.json").read_text(encoding="utf-8"))) == 2
    assert "| kev | ok | 2 |" in summary.read_text(encoding="utf-8")

    feeds["asd_method"] = "snapshot"
    assert main(args) == 1
    status = json.loads((feeds_dir / "status.json").read_text(encoding="utf-8"))
    assert status["sources"]["asd"]["status"] == "fail"
    assert status["sources"]["asd"]["last_ok"]
    assert status["sources"]["asd"]["last_error"]


def test_store_modules_come_from_the_checkout():
    from cyberau_common.refresh import _store_modules

    api, db = _store_modules()
    assert Path(api.__file__).parent.parent == ROOT / "plugins" / "cyber-au"
    assert "store" in sys.modules


def test_a_second_refresh_expires_what_the_feeds_withdrew(feeds, store_path, monkeypatch, capsys):
    from cyberau_abusech import source as abusech
    from cyberau_cisa_kev import source as kev

    assert main(["refresh", "--sources", "kev,feodo", "--store"]) == 0
    capsys.readouterr()

    shrunk = {**KEV, "vulnerabilities": KEV["vulnerabilities"][:1]}
    monkeypatch.setattr(kev, "_catalog", lambda: (shrunk, "miss"))
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

    monkeypatch.setattr(kev, "_catalog", no_fetch)
    feeds["epss_calls"].clear()
    assert main(["refresh", "--sources", "epss", "--store"]) == 0
    assert feeds["epss_calls"] == [{"cve": "CVE-2026-0001,CVE-2026-0002"}]
