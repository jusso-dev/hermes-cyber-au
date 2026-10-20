import asyncio
import json
import os
from pathlib import Path

import cyberau_ransomware_live.source as source
import httpx
import jsonschema
import pytest
import yaml
from cyberau_common.cache import HttpCache
from cyberau_common.server import build_server
from cyberau_ransomware_live.source import (
    DOCTOR_NOTE,
    TERMS,
    V2_RECENT,
    connector,
    enabled_for_profile,
    ransom_au_victims,
    ransom_watchlist_match,
    schema_drift,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures"
ROOT = Path(__file__).resolve().parents[3]
ENVELOPE = {
    "type": "object",
    "required": ["source", "retrieved_at", "cache", "data", "untrusted", "attribution"],
    "properties": {
        "source": {"type": "string"},
        "retrieved_at": {"type": "string"},
        "cache": {"enum": ["hit", "miss", "stale", "snapshot"]},
        "attribution": {"type": "string"},
        "untrusted": {"const": True},
        "warnings": {"type": "array", "items": {"type": "string"}},
        "data": {},
    },
}
MARKER = "<<untrusted source=ransomlive>>"


def setup_function():
    os.environ["CYBERAU_OFFLINE"] = "1"
    os.environ["CYBERAU_RANSOMLIVE_SNAPSHOT"] = str(FIXTURES / "victims_country_AU_synthetic.json")
    os.environ["CYBERAU_RANSOMLIVE_TODAY"] = "2026-10-17"
    os.environ.pop("RANSOMWARE_LIVE_API_KEY", None)
    os.environ.pop("CYBERAU_ORG_WATCHLIST", None)


def teardown_function():
    for name in (
        "CYBERAU_OFFLINE",
        "CYBERAU_RANSOMLIVE_SNAPSHOT",
        "CYBERAU_RANSOMLIVE_TODAY",
        "CYBERAU_ORG_WATCHLIST",
        "RANSOMWARE_LIVE_API_KEY",
    ):
        os.environ.pop(name, None)


def test_au_victims_happy_path_and_filters():
    found = ransom_au_victims()
    jsonschema.validate(found, ENVELOPE)
    record_schema = json.loads(
        (ROOT / "mcp/ransomware-live/schema/ransom_au_victims.response.json").read_text()
    )
    input_schema = json.loads(
        (ROOT / "mcp/ransomware-live/schema/ransom_au_victims.input.json").read_text()
    )
    jsonschema.Draft202012Validator.check_schema(input_schema)
    jsonschema.validate({"since": "2026-10-01", "sector": "Education", "limit": 10}, input_schema)
    assert found["attribution"].startswith("ransomware.live")
    assert found["cache"] == "snapshot"
    assert [row["discovered"] for row in found["data"]] == ["2026-10-15", "2026-09-01"]
    for row in found["data"]:
        jsonschema.validate(row, record_schema)
        assert row["claim"] == "unverified"
        assert MARKER in row["victim"]
        assert MARKER in row["note"]
        assert MARKER in row["description"]
        assert MARKER in row["website"]
    narrowed = ransom_au_victims(since="2026-10-01", sector="Education", group="samplegroup")
    assert len(narrowed["data"]) == 1
    assert "Wattle Sample Pty Ltd" in narrowed["data"][0]["victim"]
    assert ransom_au_victims(limit=1)["data"][0]["discovered"] == "2026-10-15"
    assert ransom_au_victims(group="missing")["data"] == []
    assert ransom_au_victims(since="16-10-2026")["warnings"]
    assert ransom_au_victims(limit=0)["warnings"]


def test_v2_shape_and_watchlist_match(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    os.environ["CYBERAU_RANSOMLIVE_SNAPSHOT"] = str(FIXTURES / "recentvictims_v2_synthetic.json")
    os.environ["CYBERAU_ORG_WATCHLIST"] = str(FIXTURES / "org-exposure.yaml")
    match_schema = json.loads(
        (ROOT / "mcp/ransomware-live/schema/ransom_watchlist_match.response.json").read_text()
    )
    input_schema = json.loads(
        (ROOT / "mcp/ransomware-live/schema/ransom_watchlist_match.input.json").read_text()
    )
    jsonschema.validate({"days": 7}, input_schema)
    recent = ransom_watchlist_match(days=7)
    jsonschema.validate(recent, ENVELOPE)
    assert len(recent["data"]) == 1
    jsonschema.validate(recent["data"][0], match_schema)
    assert recent["data"][0]["matched_on"] == "domain"
    assert "wattlesample.example" in recent["data"][0]["watchlist_entry"]
    assert MARKER in recent["data"][0]["watchlist_entry"]
    both = ransom_watchlist_match(days=90)
    assert [row["discovered"] for row in both["data"]] == ["2026-10-15", "2026-09-01"]
    assert both["cache"] == "snapshot"
    assert "operator-supplied" in both["warnings"][0]
    assert not (tmp_path / "ransomlive-metadata.jsonl").exists()
    missing = tmp_path / "missing.yaml"
    monkeypatch.setenv("CYBERAU_ORG_WATCHLIST", str(missing))
    assert ransom_watchlist_match()["warnings"]
    empty = tmp_path / "empty.yaml"
    empty.write_text("{}\n", encoding="utf-8")
    monkeypatch.setenv("CYBERAU_ORG_WATCHLIST", str(empty))
    assert "no names" in ransom_watchlist_match()["warnings"][0]
    brand_only = tmp_path / "brand.yaml"
    brand_only.write_text("brands:\n  - Harbour Sample\nexclude:\n  - Sample\n", encoding="utf-8")
    monkeypatch.setenv("CYBERAU_ORG_WATCHLIST", str(brand_only))
    branded = ransom_watchlist_match(days=90)
    assert len(branded["data"]) == 1
    assert branded["data"][0]["matched_on"] == "brand"
    assert ransom_watchlist_match(days=0)["warnings"]


def test_bad_payloads_warn_and_schema_drift():
    os.environ["CYBERAU_RANSOMLIVE_SNAPSHOT"] = str(FIXTURES / "ransomlive_empty.json")
    empty = ransom_au_victims()
    assert empty["data"] == []
    assert empty["warnings"]
    os.environ["CYBERAU_RANSOMLIVE_SNAPSHOT"] = str(FIXTURES / "ransomlive_malformed.json")
    malformed = ransom_au_victims()
    assert malformed["warnings"]
    assert malformed["data"] == []
    os.environ["CYBERAU_RANSOMLIVE_SNAPSHOT"] = str(FIXTURES / "ransomlive_429.json")
    limited = ransom_au_victims()
    assert limited["warnings"]
    drift = json.loads((FIXTURES / "ransomlive_drift.json").read_text(encoding="utf-8"))
    assert schema_drift(drift)
    os.environ["CYBERAU_RANSOMLIVE_SNAPSHOT"] = str(FIXTURES / "victims_country_AU_synthetic.json")
    assert connector().health(live=False, check_schema=True).ok is True
    os.environ["CYBERAU_RANSOMLIVE_SNAPSHOT"] = str(FIXTURES / "ransomlive_drift.json")
    failed = connector().health(live=False, check_schema=True)
    assert failed.ok is False
    assert "schema drift" in failed.detail


def test_advertised_schema_and_terms():
    tools = {tool.name: tool for tool in asyncio.run(build_server(connector()).list_tools())}
    victims = tools["ransom_au_victims"]
    match = tools["ransom_watchlist_match"]
    assert victims.annotations.read_only_hint is True
    assert victims.annotations.open_world_hint is True
    assert match.annotations.read_only_hint is True
    encoded = json.dumps(victims.input_schema)
    assert "since" in encoded
    assert "500" in encoded
    assert "90" in json.dumps(match.input_schema)
    docs = (ROOT / "docs/connectors/ransomware-live.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert DOCTOR_NOTE in docs
    assert "not confirmed incidents" in docs
    assert TERMS.split(".")[0] in docs
    assert "docs/connectors/ransomware-live.md" in readme
    assert "State the terms" in match.description


def test_ships_disabled_even_when_the_key_is_present(monkeypatch):
    catalog = yaml.safe_load((ROOT / "mcp/servers.yaml").read_text(encoding="utf-8"))
    entry = catalog["servers"]["ransomlive"]
    assert entry["connector"] == "ransomware-live"
    assert entry["enabled_by_default"] is False
    assert entry["env"] == ["RANSOMWARE_LIVE_API_KEY=${RANSOMWARE_LIVE_API_KEY}"]
    assert entry["required_env"] == []
    allow = yaml.safe_load((ROOT / "mcp/egress-allowlist.yaml").read_text(encoding="utf-8"))
    hosts = allow["connectors"]["ransomware-live"]["hosts"]
    assert hosts == ["api-pro.ransomware.live", "api.ransomware.live"]
    monkeypatch.setenv("RANSOMWARE_LIVE_API_KEY", "not-a-real-key")
    assert enabled_for_profile(entry, user_enabled=None) is False
    assert enabled_for_profile(entry, user_enabled=True) is True
    assert enabled_for_profile(entry, user_enabled=False) is False


def test_profile_watchlist_path(tmp_path, monkeypatch):
    data = tmp_path / "plugin-data" / "cyber-au"
    data.mkdir(parents=True)
    watch = tmp_path / "watchlists"
    watch.mkdir()
    (watch / "org-exposure.yaml").write_text(
        "domains:\n  - wattlesample.example\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(data))
    monkeypatch.delenv("CYBERAU_ORG_WATCHLIST", raising=False)
    found = ransom_watchlist_match(days=7)
    assert len(found["data"]) == 1


@pytest.mark.parametrize("status", [401, 403])
def test_auth_errors_name_the_env_var(status, tmp_path, monkeypatch):
    monkeypatch.delenv("CYBERAU_OFFLINE", raising=False)
    monkeypatch.delenv("CYBERAU_RANSOMLIVE_SNAPSHOT", raising=False)
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("RANSOMWARE_LIVE_API_KEY", "not-a-real-key")

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "api-pro.ransomware.live"
        assert request.headers["x-api-key"] == "not-a-real-key"
        return httpx.Response(status, json={"message": "nope"})

    source._TRANSPORT = httpx.MockTransport(handler)
    try:
        warned = ransom_au_victims()
    finally:
        source._TRANSPORT = None
    assert warned["data"] == []
    assert "RANSOMWARE_LIVE_API_KEY" in warned["warnings"][0]
    assert "not-a-real-key" not in json.dumps(warned)


def test_retry_after_redirect_and_timeout(tmp_path, monkeypatch):
    monkeypatch.delenv("CYBERAU_OFFLINE", raising=False)
    monkeypatch.delenv("CYBERAU_RANSOMLIVE_SNAPSHOT", raising=False)
    monkeypatch.delenv("RANSOMWARE_LIVE_API_KEY", raising=False)
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path / "retry"))
    slept: list[float] = []
    monkeypatch.setattr("time.sleep", lambda seconds: slept.append(seconds))
    calls = {"n": 0}
    body = (FIXTURES / "recentvictims_v2_synthetic.json").read_bytes()

    def retry(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        assert request.url.host == "api.ransomware.live"
        if calls["n"] == 1:
            return httpx.Response(429, headers={"retry-after": "0"}, json={"message": "slow"})
        return httpx.Response(200, content=body)

    source._TRANSPORT = httpx.MockTransport(retry)
    try:
        found = ransom_au_victims()
    finally:
        source._TRANSPORT = None
    assert calls["n"] == 2
    assert slept == [0.0]
    assert found["data"][0]["discovered"] == "2026-10-15"
    assert "not-a-real-key" not in json.dumps(found)

    def redirect(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://evil.test/stolen"})

    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path / "redirect"))
    source._TRANSPORT = httpx.MockTransport(redirect)
    try:
        refused = ransom_au_victims()
    finally:
        source._TRANSPORT = None
    assert refused["data"] == []
    assert refused["warnings"]
    assert "evil.test" in refused["warnings"][0]

    cache_dir = tmp_path / "timeout"
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(cache_dir))
    cache = HttpCache(cache_dir / "http_cache.sqlite")
    key = cache.key("GET", V2_RECENT, {}, b"", "anonymous")
    cache.put(key, status=200, headers={}, body=body, ttl=0)

    def time_out(request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("timed out")

    source._TRANSPORT = httpx.MockTransport(time_out)
    try:
        stale = ransom_au_victims()
    finally:
        source._TRANSPORT = None
    assert stale["cache"] == "stale"
    assert stale["data"][0]["discovered"] == "2026-10-15"
    assert "stale cached copy" in stale["warnings"][0]


def test_live_health_and_cassettes():
    import vcr
    from vcr.serialize import deserialize
    from vcr.serializers import yamlserializer

    os.environ.pop("CYBERAU_OFFLINE", None)
    os.environ.pop("CYBERAU_RANSOMLIVE_SNAPSHOT", None)
    body = (FIXTURES / "recentvictims_v2_synthetic.json").read_bytes()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=body)

    source._TRANSPORT = httpx.MockTransport(handler)
    try:
        probe = connector().health(live=True)
    finally:
        source._TRANSPORT = None
    assert probe.ok is True

    player = vcr.VCR(record_mode="none")
    uris = {
        "ransom_au_victims": "https://api-pro.ransomware.live/victims/?country=AU",
        "ransom_watchlist_match": "https://api.ransomware.live/v2/recentvictims",
    }
    for name, uri in uris.items():
        path = FIXTURES / f"{name}.yaml"
        text = path.read_text(encoding="utf-8")
        assert "X-API-KEY" not in text
        assert "not-a-real-key" not in text
        requests, responses = deserialize(text, yamlserializer)
        assert requests and responses[0]["status"]["code"] == 200
        with player.use_cassette(str(path)):
            played = httpx.get(uri)
        assert played.status_code == 200
        assert played.json()[0]["victim"] == "Wattle Sample Pty Ltd"


V2_BODY = (FIXTURES / "recentvictims_v2_synthetic.json").read_bytes()


def _live(monkeypatch, tmp_path, handler, key=None):
    monkeypatch.delenv("CYBERAU_OFFLINE", raising=False)
    monkeypatch.delenv("CYBERAU_RANSOMLIVE_SNAPSHOT", raising=False)
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    if key:
        monkeypatch.setenv("RANSOMWARE_LIVE_API_KEY", key)
    else:
        monkeypatch.delenv("RANSOMWARE_LIVE_API_KEY", raising=False)
    monkeypatch.setattr(source, "_TRANSPORT", httpx.MockTransport(handler))


def _seen_everywhere(directory: Path, needle: str) -> bool:
    return any(
        needle.encode() in path.read_bytes() for path in directory.rglob("*") if path.is_file()
    )


def test_keyed_call_uses_pro_for_au_and_the_key_stays_out_of_every_file(tmp_path, monkeypatch):
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, content=V2_BODY)

    _live(monkeypatch, tmp_path, handler, key="not-a-real-key")
    found = ransom_au_victims()
    assert [(r.url.host, r.url.path, r.url.params["country"]) for r in requests] == [
        ("api-pro.ransomware.live", "/victims/", "AU")
    ]
    assert requests[0].headers["x-api-key"] == "not-a-real-key"
    assert found["cache"] == "miss"
    assert found["warnings"] == []
    assert not _seen_everywhere(tmp_path, "not-a-real-key")
    assert "not-a-real-key" not in json.dumps(found)
    stored = (tmp_path / "ransomlive-metadata.jsonl").read_text(encoding="utf-8")
    assert "Wattle Sample" not in stored
    assert "wattlesample.example" not in stored


def test_keyless_call_uses_v2_and_keeps_only_au(tmp_path, monkeypatch):
    requests: list[httpx.Request] = []
    rows = json.loads(V2_BODY) + [
        {"victim": "Foreign Sample LLC", "group": "g", "country": "US", "discovered": "2026-10-16"}
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json=rows)

    _live(monkeypatch, tmp_path, handler)
    found = ransom_au_victims()
    assert [(r.url.host, r.url.path) for r in requests] == [
        ("api.ransomware.live", "/v2/recentvictims")
    ]
    assert "x-api-key" not in requests[0].headers
    assert found["data"]
    assert all(row["country"] == "AU" for row in found["data"])
    assert not any("Foreign Sample" in row["victim"] for row in found["data"])


def test_keyed_redirect_off_the_allowlist_is_refused_and_the_key_is_dropped(tmp_path, monkeypatch):
    seen: list[tuple[str, str | None]] = []

    def off_list(request: httpx.Request) -> httpx.Response:
        seen.append((request.url.host, request.headers.get("x-api-key")))
        return httpx.Response(302, headers={"location": "https://evil.test/steal"})

    _live(monkeypatch, tmp_path / "off", off_list, key="not-a-real-key")
    refused = ransom_au_victims()
    assert seen == [("api-pro.ransomware.live", "not-a-real-key")]
    assert refused["data"] == []
    assert "evil.test" in refused["warnings"][0]
    assert "not-a-real-key" not in json.dumps(refused)

    seen.clear()

    def on_list(request: httpx.Request) -> httpx.Response:
        seen.append((request.url.host, request.headers.get("x-api-key")))
        if request.url.host == "api-pro.ransomware.live":
            return httpx.Response(302, headers={"location": "https://api.ransomware.live/x"})
        return httpx.Response(200, content=V2_BODY)

    _live(monkeypatch, tmp_path / "on", on_list, key="not-a-real-key")
    ransom_au_victims()
    assert seen == [("api-pro.ransomware.live", "not-a-real-key"), ("api.ransomware.live", None)]


@pytest.mark.parametrize("failure", ["timeout", "http500"])
def test_live_failure_without_a_cache_is_unavailable_not_a_snapshot(failure, tmp_path, monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        if failure == "timeout":
            raise httpx.TimeoutException("timed out")
        return httpx.Response(500)

    _live(monkeypatch, tmp_path, handler, key="not-a-real-key")
    found = ransom_au_victims()
    assert found["data"] == []
    assert found["cache"] == "snapshot"
    assert "is unavailable" in found["warnings"][0]
    assert not (tmp_path / "ransomlive-metadata.jsonl").exists()


def test_no_package_data_ships_with_the_connector():
    assert not (ROOT / "mcp" / "ransomware-live" / "data").exists()


@pytest.mark.parametrize("mode", ["offline", "timeout", "http500", "http429"])
def test_every_tool_is_unavailable_without_live_or_cached_data(mode, tmp_path, monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        if mode == "timeout":
            raise httpx.TimeoutException("timed out")
        return httpx.Response(429 if mode == "http429" else 500)

    _live(monkeypatch, tmp_path, handler)
    if mode == "offline":
        monkeypatch.setenv("CYBERAU_OFFLINE", "1")
    monkeypatch.setenv("CYBERAU_ORG_WATCHLIST", str(FIXTURES / "org-exposure.yaml"))
    results = [
        ransom_au_victims(),
        ransom_au_victims(sector="Education"),
        ransom_watchlist_match(90),
    ]
    for result in results:
        jsonschema.validate(result, ENVELOPE)
        assert result["data"] == []
        assert result["cache"] == "snapshot"
        assert any("is unavailable" in item for item in result["warnings"])
        text = json.dumps(result)
        for marker in (
            "Wattle Sample",
            "Harbour Sample",
            "samplegroup",
            "wattlesample",
            "2026-10-15",
        ):
            assert marker not in text, marker
    assert not (tmp_path / "ransomlive-metadata.jsonl").exists()


def test_offline_without_a_cache_is_unavailable_and_stale_copies_carry_a_warning(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path / "snap"))
    monkeypatch.delenv("CYBERAU_RANSOMLIVE_SNAPSHOT", raising=False)
    monkeypatch.setenv("CYBERAU_RANSOMLIVE_TODAY", "2026-10-17")
    found = ransom_au_victims()
    assert found["cache"] == "snapshot"
    assert found["data"] == []
    assert "is unavailable" in found["warnings"][0]
    assert ransom_watchlist_match()["warnings"]
    cache = HttpCache(tmp_path / "stale" / "http_cache.sqlite")
    cache.put(
        cache.key("GET", V2_RECENT, {}, b"", "anonymous"),
        status=200,
        headers={},
        body=V2_BODY,
        ttl=0,
    )
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path / "stale"))
    stale = ransom_au_victims()
    assert stale["cache"] == "stale"
    assert "stale cached copy" in stale["warnings"][0]


def test_metadata_store_is_not_duplicated_on_repeat_calls(tmp_path, monkeypatch):
    _live(monkeypatch, tmp_path, lambda request: httpx.Response(200, content=V2_BODY))
    ransom_au_victims()
    first = (tmp_path / "ransomlive-metadata.jsonl").read_text(encoding="utf-8").splitlines()
    ransom_au_victims()
    again = (tmp_path / "ransomlive-metadata.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(first) == 2
    assert again == first


@pytest.mark.parametrize("failure", ["timeout", "http500", "http429", "garbage"])
def test_live_health_fails_on_a_failed_fetch_even_with_a_cached_copy(
    failure, tmp_path, monkeypatch
):
    def handler(request: httpx.Request) -> httpx.Response:
        if failure == "timeout":
            raise httpx.TimeoutException("timed out")
        if failure == "garbage":
            return httpx.Response(200, content=b"<html>")
        return httpx.Response(500 if failure == "http500" else 429)

    _live(monkeypatch, tmp_path, handler)
    cache = HttpCache(tmp_path / "http_cache.sqlite")
    cache.put(
        cache.key("GET", V2_RECENT, {}, b"", "anonymous"),
        status=200,
        headers={},
        body=V2_BODY,
        ttl=3600,
    )
    probe = connector().health(live=True)
    assert probe.ok is False
    monkeypatch.setenv(
        "CYBERAU_RANSOMLIVE_SNAPSHOT", str(FIXTURES / "recentvictims_v2_synthetic.json")
    )
    assert connector().health(live=True).ok is False
