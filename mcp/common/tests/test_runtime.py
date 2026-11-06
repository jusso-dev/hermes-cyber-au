import ipaddress
from datetime import UTC, date, datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
from cyberau_common import runtime

MCP = Path(__file__).resolve().parents[2]


def test_data_dir_prefers_the_profile_and_creates_it(tmp_path, monkeypatch):
    target = tmp_path / "profile" / "plugin-data"
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(target))
    assert runtime.data_dir("anything") == target
    assert target.is_dir()


def test_data_dir_falls_back_to_the_connector_tmp_dir(monkeypatch):
    monkeypatch.setenv("CYBERAU_DATA_DIR", "  ")
    assert runtime.data_dir("kev") == Path("/tmp/cyberau-kev")


def test_configured_data_dir_is_none_when_unset_and_not_created(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERAU_DATA_DIR", " ")
    assert runtime.configured_data_dir() is None
    target = tmp_path / "later"
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(target))
    assert runtime.configured_data_dir() == target
    assert not target.exists()


def test_data_dir_mode_applies_to_a_new_directory(tmp_path, monkeypatch):
    target = tmp_path / "private"
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(target))
    runtime.data_dir("taxii", mode=0o700)
    assert target.stat().st_mode & 0o077 == 0


def test_allowlist_path_override_and_default(tmp_path, monkeypatch):
    monkeypatch.delenv("CYBERAU_EGRESS_ALLOWLIST", raising=False)
    assert runtime.allowlist_path() == MCP / "egress-allowlist.yaml"
    assert runtime.allowlist_path().is_file()
    monkeypatch.setenv("CYBERAU_EGRESS_ALLOWLIST", str(tmp_path / "allow.yaml"))
    assert runtime.allowlist_path() == tmp_path / "allow.yaml"


@pytest.mark.parametrize(("value", "expected"), [("1", True), ("0", False), ("true", False)])
def test_offline_is_exactly_one(monkeypatch, value, expected):
    monkeypatch.setenv("CYBERAU_OFFLINE", value)
    assert runtime.offline() is expected


def test_today_reads_the_pinned_day(monkeypatch):
    monkeypatch.setenv("CYBERAU_TODAY", "2026-10-17")
    assert runtime.today() == date(2026, 10, 17)
    assert runtime.pinned_day() == date(2026, 10, 17)
    monkeypatch.setenv("CYBERAU_TODAY", "not a day")
    assert runtime.pinned_day() is None
    monkeypatch.delenv("CYBERAU_TODAY")
    sydney = timezone(timedelta(hours=10))
    assert runtime.today(sydney) == datetime.now(sydney).date()


def test_load_json_and_object():
    assert runtime.load_json("[1, 2]") == [1, 2]
    assert runtime.load_json("") is None
    assert runtime.load_json(None) is None
    assert runtime.load_json("{nope") is None
    assert runtime.load_json_object('{"a": 1}') == {"a": 1}
    assert runtime.load_json_object("[1]") is None


def test_iso_and_parse_iso_round_trip():
    moment = datetime(2026, 10, 17, 1, 2, 3, 999, tzinfo=UTC)
    assert runtime.iso(moment) == "2026-10-17T01:02:03Z"
    assert runtime.iso(datetime(2026, 10, 17, 1, 2, 3)) == "2026-10-17T01:02:03Z"
    plus_ten = datetime(2026, 10, 17, 11, 2, 3, tzinfo=timezone(timedelta(hours=10)))
    assert runtime.iso(plus_ten) == "2026-10-17T01:02:03Z"
    assert runtime.parse_iso("2026-10-17T01:02:03Z") == moment.replace(microsecond=0)
    assert runtime.parse_iso("2026-10-17") == datetime(2026, 10, 17, tzinfo=UTC)
    kept = runtime.parse_iso("2026-10-17T11:02:03+10:00")
    assert kept.utcoffset() == timedelta(hours=10)
    assert runtime.parse_iso("2026-10-17T11:02:03+10:00", to_utc=True).tzinfo == UTC
    for bad in ("", "  ", "yesterday", None, 7):
        assert runtime.parse_iso(bad) is None
    assert len(runtime.utc_now_iso()) == len("2026-10-17T01:02:03Z")


@pytest.mark.parametrize(
    ("states", "expected"),
    [
        ([], "snapshot"),
        (["snapshot"], "snapshot"),
        (["hit", "snapshot"], "hit"),
        (["hit", "miss"], "miss"),
        (["miss", "stale", "hit"], "stale"),
    ],
)
def test_merge_cache_states_keeps_the_least_fresh(states, expected):
    assert runtime.merge_cache_states(states) == expected


def test_http_client_wires_policy_cache_and_limiter(tmp_path, monkeypatch):
    allowlist = tmp_path / "allow.yaml"
    allowlist.write_text(
        "version: 1\nconnectors:\n  demo:\n    hosts: [example.com]\n", encoding="utf-8"
    )
    monkeypatch.setenv("CYBERAU_EGRESS_ALLOWLIST", str(allowlist))
    client = runtime.http_client(
        "demo",
        directory=tmp_path,
        user_agent="test",
        rate=1,
        burst=1,
        transport=httpx.MockTransport(lambda _request: httpx.Response(200, text="ok")),
        resolver=lambda _host: [ipaddress.ip_address("93.184.216.34")],
    )
    try:
        assert client.policy.hosts == {"example.com"}
        assert client.cache.path == tmp_path / "http_cache.sqlite"
        assert client.limiter.path == tmp_path / "rate_limit.sqlite"
        assert client.get("https://example.com/", ttl=60).body == b"ok"
    finally:
        client.close()


def test_http_client_needs_a_directory_for_default_storage():
    with pytest.raises(ValueError, match="directory"):
        runtime.http_client("demo", user_agent="test", rate=1, burst=1)


def test_configured_data_dir_expands_the_user_home(monkeypatch):
    monkeypatch.setenv("CYBERAU_DATA_DIR", "~/cyberau-data")
    assert runtime.configured_data_dir() == Path.home() / "cyberau-data"


def test_profile_data_dir_order(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "home"))
    assert runtime.profile_data_dir() == tmp_path / "data"
    monkeypatch.delenv("CYBERAU_DATA_DIR")
    assert runtime.profile_data_dir() == tmp_path / "home" / "plugin-data" / "cyber-au"
    monkeypatch.delenv("HERMES_HOME")
    assert runtime.profile_data_dir() == Path.home() / ".hermes" / "plugin-data" / "cyber-au"
    assert not (tmp_path / "data").exists()


def _clear_org_watchlist_env(monkeypatch):
    for name in ("CYBERAU_ORG_WATCHLIST", "CYBERAU_WATCHLIST", "CYBERAU_DATA_DIR", "HERMES_HOME"):
        monkeypatch.delenv(name, raising=False)


def test_org_watchlist_override_prefers_the_documented_name(tmp_path, monkeypatch):
    _clear_org_watchlist_env(monkeypatch)
    monkeypatch.setenv("CYBERAU_WATCHLIST", str(tmp_path / "old.yaml"))
    assert runtime.org_watchlist_path() == tmp_path / "old.yaml"
    monkeypatch.setenv("CYBERAU_ORG_WATCHLIST", str(tmp_path / "new.yaml"))
    assert runtime.org_watchlist_path() == tmp_path / "new.yaml"
    assert runtime.org_watchlist_override() == tmp_path / "new.yaml"


def test_org_watchlist_follows_hermes_home_then_the_profile_above_the_data_dir(
    tmp_path, monkeypatch
):
    _clear_org_watchlist_env(monkeypatch)
    profile = tmp_path / "profile"
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(profile / "plugin-data" / "cyber-au"))
    assert runtime.org_watchlist_path() == profile / "watchlists" / "org-exposure.yaml"
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "home"))
    assert runtime.org_watchlist_path() == tmp_path / "home" / "watchlists" / "org-exposure.yaml"
    _clear_org_watchlist_env(monkeypatch)
    assert runtime.org_watchlist_override() is None
    assert runtime.org_watchlist_path() == Path.home() / ".hermes" / "watchlists" / (
        "org-exposure.yaml"
    )
