import asyncio
import json
import sqlite3
from ipaddress import ip_address
from pathlib import Path

import cyberau_spamhaus_drop.source as source
import httpx
import jsonschema
import pytest
from cyberau_common.cache import HttpCache
from cyberau_common.server import build_server
from cyberau_spamhaus_drop.source import (
    ASN_DROP,
    ATTRIBUTION,
    DROP_V4,
    DROP_V6,
    LISTS,
    connector,
    drop_check_asn,
    drop_check_ip,
    drop_list_status,
    schema_drift,
)

DATA = Path(__file__).resolve().parents[1] / "data"
FIXTURES = Path(__file__).resolve().parent / "fixtures"
_BODIES = {
    DROP_V4: (FIXTURES / "drop_v4_head.json").read_bytes(),
    DROP_V6: (FIXTURES / "drop_v6_head.json").read_bytes(),
    ASN_DROP: (FIXTURES / "asndrop_head.json").read_bytes(),
}


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CYBERAU_OFFLINE", "1")
    monkeypatch.setenv("CYBERAU_DROP_SNAPSHOT", str(DATA))
    source._TRANSPORT = None
    source._SLEEP = lambda _seconds: None
    source._RESOLVER = lambda _host: [ip_address("1.1.1.1")]
    yield
    source._TRANSPORT = None
    source._SLEEP = source.time.sleep
    source._RESOLVER = None


def _online(monkeypatch):
    monkeypatch.delenv("CYBERAU_OFFLINE")
    monkeypatch.delenv("CYBERAU_DROP_SNAPSHOT")


def _serve(payloads: dict[str, bytes] | None = None, status: int = 200, headers=None):
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        url = str(request.url).split("?", 1)[0]
        if status != 200:
            return httpx.Response(status, headers=headers or {}, content=b"")
        body = (payloads or _BODIES).get(url, b"")
        return httpx.Response(200, content=body)

    source._TRANSPORT = httpx.MockTransport(handler)
    return calls


def test_offline_hits_misses_and_attribution():
    listed = drop_check_ip("203.0.113.10")
    assert listed["cache"] == "snapshot"
    assert listed["attribution"] == ATTRIBUTION
    assert listed["data"][0]["sbl_id"] == "SBL100002"
    assert listed["data"][0]["cidr"] == "203.0.113.0/28"
    assert "<<untrusted source=spamhaus-drop>>" in listed["data"][0]["rir"]
    broader = drop_check_ip("203.0.113.20")
    assert broader["data"][0]["sbl_id"] == "SBL100001"
    v6 = drop_check_ip("2001:db8::10")
    assert v6["data"][0]["sbl_id"] == "SBL100003"
    assert drop_check_ip("192.0.2.1")["data"] == []
    asn = drop_check_asn(64496)
    assert asn["data"][0]["asn"] == 64496
    assert "DOCUMENTATION-AS" in asn["data"][0]["asname"]
    assert "<<untrusted source=spamhaus-drop>>" in asn["data"][0]["domain"]
    assert drop_check_asn(64497)["data"] == []
    status = drop_list_status()
    assert [row["entries"] for row in status["data"]] == [2, 1, 1]
    assert status["data"][0]["fetched_at"] is None
    assert status["attribution"].startswith("Spamhaus")
    assert drop_check_ip("not-an-ip")["warnings"]
    assert drop_check_asn(0)["warnings"]
    assert drop_check_asn(True)["warnings"]


def test_head_fixtures_match_the_snapshot():
    assert (FIXTURES / "drop_v4_head.json").read_bytes() == (DATA / "drop_v4.json").read_bytes()
    assert (FIXTURES / "drop_v6_head.json").read_bytes() == (DATA / "drop_v6.json").read_bytes()
    assert (FIXTURES / "asndrop_head.json").read_bytes() == (DATA / "asndrop.json").read_bytes()


def test_empty_and_malformed_payloads_warn(monkeypatch, tmp_path):
    _online(monkeypatch)
    _serve({url: b"\n" for _name, url in LISTS})
    empty = drop_list_status()
    assert empty["warnings"] == []
    assert [row["entries"] for row in empty["data"]] == [0, 0, 0]
    malformed = tmp_path / "malformed"
    malformed.mkdir()
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(malformed))
    _serve({url: b"{" for _name, url in LISTS})
    broken = drop_check_ip("203.0.113.10")
    assert broken["data"] == []
    assert broken["warnings"]
    assert "JSON" in broken["warnings"][0]


def test_schema_drift_fails_health(tmp_path, monkeypatch):
    assert schema_drift((FIXTURES / "drop_v4_drift.json").read_text(encoding="utf-8"))
    assert schema_drift((DATA / "drop_v4.json").read_text(encoding="utf-8")) is None
    ok = connector().health(live=False, check_schema=True)
    drift = tmp_path / "drift"
    drift.mkdir()
    (drift / "drop_v4.json").write_text(
        (FIXTURES / "drop_v4_drift.json").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    (drift / "drop_v6.json").write_bytes((DATA / "drop_v6.json").read_bytes())
    (drift / "asndrop.json").write_bytes((DATA / "asndrop.json").read_bytes())
    monkeypatch.setenv("CYBERAU_DROP_SNAPSHOT", str(drift))
    failed = connector().health(live=False, check_schema=True)
    assert ok.ok is True
    assert failed.ok is False
    assert "schema drift" in failed.detail


@pytest.mark.parametrize("status", [401, 403])
def test_auth_refusal_names_the_missing_env_var(status, monkeypatch):
    _online(monkeypatch)
    _serve(status=status)
    refused = drop_check_ip("203.0.113.10")
    assert refused["data"] == []
    assert str(status) in refused["warnings"][0]
    assert "env var" in refused["warnings"][0]


def test_retry_after_timeout_and_redirect(monkeypatch, tmp_path):
    _online(monkeypatch)
    calls = {"n": 0}
    slept = []

    def retry(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(429, headers={"Retry-After": "0"})
        url = str(request.url).split("?", 1)[0]
        return httpx.Response(200, content=_BODIES[url])

    source._SLEEP = slept.append
    source._TRANSPORT = httpx.MockTransport(retry)
    found = drop_check_ip("203.0.113.10")
    assert found["data"][0]["sbl_id"] == "SBL100002"
    assert 0.0 in slept

    stale_dir = tmp_path / "stale"
    stale_dir.mkdir()
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(stale_dir))
    cache = HttpCache(stale_dir / "http_cache.sqlite")
    for _name, url in LISTS:
        cache.put(
            cache.key("GET", url, None, b"", "anonymous"),
            status=200,
            headers={},
            body=_BODIES[url],
            ttl=0,
        )

    def time_out(_request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("timed out")

    source._SLEEP = lambda _seconds: None
    source._TRANSPORT = httpx.MockTransport(time_out)
    stale = drop_check_ip("203.0.113.20")
    assert stale["cache"] == "stale"
    assert stale["data"][0]["sbl_id"] == "SBL100001"

    def redirect(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://evil.test/x"})

    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path / "redirect"))
    source._TRANSPORT = httpx.MockTransport(redirect)
    refused = drop_check_asn(64496)
    assert refused["warnings"]
    assert "evil.test" in refused["warnings"][0] or "allow" in refused["warnings"][0].lower()


def test_second_fetch_inside_an_hour_is_refused(monkeypatch, tmp_path):
    _online(monkeypatch)
    calls = _serve()
    first = drop_check_ip("203.0.113.10")
    assert first["data"][0]["sbl_id"] == "SBL100002"
    assert calls["n"] == 3
    for suffix in ("", "-wal", "-shm"):
        path = tmp_path / f"http_cache.sqlite{suffix}"
        if path.exists():
            path.unlink()
    second = drop_check_ip("203.0.113.10")
    assert calls["n"] == 3
    assert any("limiter" in warning for warning in second["warnings"])
    assert any("hour" in warning for warning in second["warnings"])


def test_fresh_cache_does_not_fetch_again(monkeypatch):
    _online(monkeypatch)
    calls = _serve()
    assert drop_check_ip("203.0.113.10")["cache"] == "miss"
    assert calls["n"] == 3

    def boom(_request: httpx.Request) -> httpx.Response:
        raise AssertionError("fetched twice")

    source._TRANSPORT = httpx.MockTransport(boom)
    again = drop_check_ip("203.0.113.10")
    assert again["cache"] == "hit"
    assert again["warnings"] == []
    assert again["data"][0]["sbl_id"] == "SBL100002"


def test_live_health_and_response_schemas(monkeypatch):
    listed = drop_check_ip("203.0.113.10")
    asn = drop_check_asn(64496)
    status = drop_list_status()
    ip_schema = json.loads((DATA.parent / "schema" / "drop_check_ip.response.json").read_text())
    asn_schema = json.loads((DATA.parent / "schema" / "drop_check_asn.response.json").read_text())
    status_schema = json.loads(
        (DATA.parent / "schema" / "drop_list_status.response.json").read_text()
    )
    jsonschema.validate(listed["data"][0], ip_schema)
    jsonschema.validate(asn["data"][0], asn_schema)
    jsonschema.validate(status["data"][0], status_schema)
    tools = {tool.name: tool for tool in asyncio.run(build_server(connector()).list_tools())}
    assert tools["drop_check_ip"].annotations.readOnlyHint is True
    assert tools["drop_check_ip"].annotations.openWorldHint is True
    assert set(tools) == {"drop_check_ip", "drop_check_asn", "drop_list_status"}
    _online(monkeypatch)
    _serve()
    probe = connector().health(live=True)
    assert probe.ok is True
    assert probe.detail == "live ok"


def test_history_keeps_entries(tmp_path):
    drop_check_ip("203.0.113.10")
    with sqlite3.connect(tmp_path / "drop_history.sqlite") as conn:
        rows = {
            identity
            for (identity,) in conn.execute(
                "SELECT identity FROM drop_entries WHERE list_name = 'drop_v4'"
            )
        }
    assert rows == {"203.0.113.0/24", "203.0.113.0/28"}


def test_cassettes_replay():
    import vcr
    from vcr.serialize import deserialize
    from vcr.serializers import yamlserializer

    uris = {
        "drop_check_ip": DROP_V4,
        "drop_check_asn": ASN_DROP,
        "drop_list_status": DROP_V6,
    }
    player = vcr.VCR(record_mode="none")
    for name, uri in uris.items():
        path = FIXTURES / f"{name}.yaml"
        requests, responses = deserialize(path.read_text(encoding="utf-8"), yamlserializer)
        assert requests and responses[0]["status"]["code"] == 200
        with player.use_cassette(str(path)):
            played = httpx.get(uri)
        assert played.status_code == 200
        assert played.content.startswith(b"{")
