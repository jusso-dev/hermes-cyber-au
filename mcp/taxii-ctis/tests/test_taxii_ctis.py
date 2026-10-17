import asyncio
import base64
import ipaddress
import json
import os
import re
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import cyberau_taxii_ctis.source as source
import httpx
import jsonschema
import yaml
from cyberau_common.cache import HttpCache
from cyberau_common.server import build_server
from cyberau_taxii_ctis.source import (
    DOCTOR_NOTE,
    TERMS,
    WINDOW_WARNING,
    briefing_records,
    connector,
    export_stix,
    profile_enabled,
    schema_drift,
    taxii_get_objects,
    taxii_list_collections,
    taxii_lookup_indicator,
    taxii_sync_status,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures"
DATA = Path(__file__).resolve().parents[1] / "data"
ROOT = Path(__file__).resolve().parents[3]
HASH = "0123456789abcdef" * 4
PASSWORD = "synthetic-pass-not-real"
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def setup_function():
    os.environ["CYBERAU_DATA_DIR"] = tempfile.mkdtemp(prefix="cyberau-taxii-")
    os.environ["CYBERAU_OFFLINE"] = "1"
    os.environ["CYBERAU_TAXII_SNAPSHOT"] = str(FIXTURES)
    os.environ["TAXII_COLLECTION_ID"] = "synthetic-collection-alpha"
    os.environ.pop("TAXII_API_ROOT", None)
    os.environ.pop("TAXII_USERNAME", None)
    os.environ.pop("TAXII_PASSWORD", None)
    source._TRANSPORT = None
    source._RESOLVER = None
    source._SLEEP = lambda _seconds: None


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _arm(monkeypatch, tmp_path: Path, root: str = "https://example.com/taxii2/root/"):
    monkeypatch.delenv("CYBERAU_OFFLINE", raising=False)
    monkeypatch.delenv("CYBERAU_TAXII_SNAPSHOT", raising=False)
    monkeypatch.setenv("TAXII_API_ROOT", root)
    monkeypatch.setenv("TAXII_COLLECTION_ID", "synthetic-collection-alpha")
    monkeypatch.setenv("TAXII_USERNAME", "synthetic-user")
    monkeypatch.setenv("TAXII_PASSWORD", PASSWORD)
    allow = tmp_path / "allow.yaml"
    allow.write_text(
        "connectors:\n"
        "  taxii-ctis:\n"
        "    hosts:\n"
        "    - example.com\n"
        "    allow_ip_literals: false\n"
        "    allow_http_loopback: false\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("CYBERAU_EGRESS_ALLOWLIST", str(allow))
    source._RESOLVER = lambda _host: [ipaddress.ip_address("203.0.113.50")]
    source._SLEEP = lambda _seconds: None


def _ids(rows: list[dict]) -> set[str]:
    return {row["id"] for row in rows}


def _fresh(monkeypatch):
    monkeypatch.setenv("CYBERAU_DATA_DIR", tempfile.mkdtemp(prefix="cyberau-taxii-"))


def _request_is_authenticated(request: httpx.Request) -> bool:
    accept = request.headers.get("accept", "")
    header = request.headers.get("authorization", "")
    raw = base64.b64decode(header.split(" ", 1)[1])
    return (
        "application/taxii+json" in accept
        and "2.1" in accept
        and header.startswith("Basic ")
        and raw == b"synthetic-user:" + PASSWORD.encode()
    )


def test_happy_path_tools_and_untrusted_text():
    listed = taxii_list_collections()
    assert listed["cache"] == "snapshot"
    assert TERMS in listed["attribution"]
    assert _ids(listed["data"]) == {"synthetic-collection-alpha"}
    assert "<<untrusted source=taxii>>" in listed["data"][0]["title"]
    assert "Synthetic demonstration collection" in listed["data"][0]["title"]

    objects = taxii_get_objects()
    assert "indicator--synthetic-ip" in _ids(objects["data"])
    assert "indicator--synthetic-amber" in _ids(objects["data"])
    ip = next(row for row in objects["data"] if row["id"] == "indicator--synthetic-ip")
    assert "<<untrusted source=taxii>>" in ip["pattern"]
    assert {item["kind"] for item in ip["values"]} == {"ip", "domain"}

    found = taxii_lookup_indicator("203.0.113.10")
    assert found["data"][0]["id"] == "indicator--synthetic-ip"
    domain = taxii_lookup_indicator("synthetic.example")
    assert domain["data"][0]["id"] == "indicator--synthetic-ip"
    hashed = taxii_lookup_indicator(HASH)
    assert hashed["data"][0]["id"] == "indicator--synthetic-hash"
    amber = taxii_lookup_indicator("amber.example")
    assert amber["data"][0]["tlp"] == "AMBER"

    status = taxii_sync_status()
    assert status["data"][0]["collection_id"] == "synthetic-collection-alpha"
    assert status["data"][0]["object_count"] >= 8
    assert status["data"][0]["error"] == ""
    assert status["data"][0]["last_sync"]
    assert TERMS in status["attribution"]


def test_expired_indicator_is_stored_but_not_looked_up():
    expired = _load("indicator_expired.json")["objects"][0]
    assert expired["valid_until"].startswith("2020-")
    taxii_get_objects()
    assert "indicator--synthetic-expired" in _ids(taxii_get_objects()["data"])
    missed = taxii_lookup_indicator("https://example.com/synthetic-expired")
    assert missed["data"] == []
    assert any("expired" in warning.lower() for warning in missed["warnings"])


def test_tlp_export_and_briefing_stay_inside_the_profile():
    taxii_get_objects()
    exported = {item["id"] for item in export_stix()["objects"]}
    briefing = briefing_records()
    briefed = {item["id"] for item in briefing["records"]}
    hidden = {
        "indicator--synthetic-amber",
        "indicator--synthetic-strict",
        "indicator--synthetic-red",
    }
    visible = {"indicator--synthetic-ip", "malware--synthetic-demo", "indicator--synthetic-hash"}
    assert hidden.isdisjoint(exported)
    assert hidden.isdisjoint(briefed)
    assert visible <= exported
    assert visible <= briefed
    assert briefing["warnings"] == []
    shared = next(item for item in briefing["records"] if item["id"] == "indicator--synthetic-ip")
    assert "<<untrusted source=taxii>>" in shared["name"]

    overridden = {item["id"] for item in export_stix(override=True)["objects"]}
    again = briefing_records(override=True)
    assert hidden <= overridden
    assert hidden <= {item["id"] for item in again["records"]}
    assert any("override" in warning.lower() for warning in again["warnings"])


def test_marking_refs_and_extension_tlp(tmp_path, monkeypatch):
    snap = tmp_path / "snap"
    snap.mkdir()
    (snap / "collections.json").write_text(
        (FIXTURES / "collections.json").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    (snap / "objects.json").write_text(
        json.dumps(
            {
                "more": False,
                "objects": [
                    {
                        "type": "indicator",
                        "id": "indicator--synthetic-legacy-white",
                        "pattern": "[ipv4-addr:value = '203.0.113.20']",
                        "valid_from": "2026-10-01T00:00:00.000Z",
                        "object_marking_refs": [
                            "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
                        ],
                    },
                    {
                        "type": "indicator",
                        "id": "indicator--synthetic-legacy-amber",
                        "pattern": "[domain-name:value = 'legacy-amber.example']",
                        "valid_from": "2026-10-01T00:00:00.000Z",
                        "object_marking_refs": [
                            "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"
                        ],
                    },
                    {
                        "type": "indicator",
                        "id": "indicator--synthetic-extension-red",
                        "pattern": "[domain-name:value = 'extension-red.example']",
                        "valid_from": "2026-10-01T00:00:00.000Z",
                        "extensions": {
                            "extension-definition--60a3c5c5-0d10-413e-aab3-9e08dde9e88d": {
                                "extension_type": "property-extension",
                                "tlp_2_0": "red",
                            }
                        },
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("CYBERAU_TAXII_SNAPSHOT", str(snap))
    monkeypatch.setenv("CYBERAU_OFFLINE", "1")
    taxii_get_objects()
    exported = {item["id"] for item in export_stix()["objects"]}
    assert "indicator--synthetic-legacy-white" in exported
    assert "indicator--synthetic-legacy-amber" not in exported
    assert "indicator--synthetic-extension-red" not in exported


def test_filters_empty_malformed_and_drift(tmp_path, monkeypatch):
    assert taxii_get_objects(limit=0)["warnings"]
    assert taxii_get_objects(added_after="yesterday")["warnings"]
    assert taxii_lookup_indicator("x")["warnings"]
    future = taxii_get_objects(added_after="2099-01-01T00:00:00Z")
    assert future["data"] == []
    assert WINDOW_WARNING not in future["warnings"]
    old = taxii_get_objects(added_after="2020-01-01T00:00:00Z")
    assert old["data"]
    assert WINDOW_WARNING in old["warnings"]
    recent = (datetime.now(UTC) - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    assert WINDOW_WARNING not in taxii_get_objects(added_after=recent)["warnings"]
    malware = taxii_get_objects(types=["malware"], limit=10)
    assert _ids(malware["data"]) == {"malware--synthetic-demo"}
    assert len(taxii_get_objects(limit=1)["data"]) == 1

    snap = tmp_path / "snap"
    snap.mkdir()
    (snap / "collections.json").write_text('{"collections": []}', encoding="utf-8")
    (snap / "objects.json").write_text('{"more": false, "objects": []}', encoding="utf-8")
    monkeypatch.setenv("CYBERAU_TAXII_SNAPSHOT", str(snap))
    assert taxii_list_collections()["data"] == []
    assert taxii_get_objects()["data"] == []

    (snap / "collections.json").write_text(
        (FIXTURES / "malformed.json").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    broken = taxii_list_collections()
    assert broken["data"] == []
    assert broken["warnings"]
    (snap / "collections.json").write_text("not-json", encoding="utf-8")
    assert taxii_list_collections()["warnings"]

    assert schema_drift(_load("schema_drift.json"), kind="collections")
    drift = tmp_path / "drift"
    drift.mkdir()
    (drift / "collections.json").write_text(
        (FIXTURES / "schema_drift.json").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    monkeypatch.setenv("CYBERAU_TAXII_SNAPSHOT", str(drift))
    probe = connector().health(live=False, check_schema=True)
    assert probe.ok is False
    assert "collections" in probe.detail


def test_bundle_fixture_and_schema_probe(tmp_path, monkeypatch):
    snap = tmp_path / "snap"
    snap.mkdir()
    (snap / "collections.json").write_text(
        (FIXTURES / "collections.json").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    (snap / "objects.json").write_text(
        (FIXTURES / "bundle_indicator_malware_relationship.json").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    monkeypatch.setenv("CYBERAU_TAXII_SNAPSHOT", str(snap))
    found = _ids(taxii_get_objects()["data"])
    assert {
        "indicator--synthetic-ip",
        "malware--synthetic-demo",
        "relationship--synthetic-link",
    } <= found
    monkeypatch.setenv("CYBERAU_TAXII_SNAPSHOT", str(FIXTURES))
    assert connector().health(live=False, check_schema=True).ok is True
    schema = json.loads(
        (FIXTURES.parents[1] / "schema" / "taxii_get_objects.response.json").read_text()
    )
    for row in taxii_get_objects()["data"]:
        jsonschema.validate(row, schema)


def test_default_off_and_terms_are_published():
    servers = yaml.safe_load((ROOT / "mcp" / "servers.yaml").read_text(encoding="utf-8"))
    spec = servers["servers"]["taxii"]
    assert spec["enabled_by_default"] is False
    assert spec["connector"] == "taxii-ctis"
    assert spec["required_env"] == [
        "TAXII_API_ROOT",
        "TAXII_COLLECTION_ID",
        "TAXII_USERNAME",
        "TAXII_PASSWORD",
    ]
    rendered = " ".join(spec["env"])
    for name in spec["required_env"]:
        assert f"{name}=${{{name}}}" in rendered
    assert profile_enabled(default_enabled=spec["enabled_by_default"], user_enabled=None) is False
    assert profile_enabled(default_enabled=False, user_enabled=True) is True
    assert profile_enabled(default_enabled=False, user_enabled=False) is False
    allow = yaml.safe_load((ROOT / "mcp" / "egress-allowlist.yaml").read_text(encoding="utf-8"))
    assert allow["connectors"]["taxii-ctis"]["hosts"] == []
    docs = (ROOT / "docs" / "connectors" / "taxii-ctis.md").read_text(encoding="utf-8")
    skill = (ROOT / "skills" / "taxii-ctis" / "SKILL.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert TERMS in docs and TERMS in skill
    assert DOCTOR_NOTE in docs and DOCTOR_NOTE in skill
    assert "enabled: false" in docs
    assert "docs/connectors/taxii-ctis.md" in readme
    for path in (
        ROOT / "docs" / "connectors" / "taxii-ctis.md",
        ROOT / "skills" / "taxii-ctis" / "SKILL.md",
        ROOT / "mcp" / "taxii-ctis" / "SOURCE.md",
        Path(source.__file__),
    ):
        text = path.read_text(encoding="utf-8")
        assert "\u2014" not in text
        assert "\u2013" not in text


def test_fixtures_are_synthetic_and_have_no_secrets():
    secret = re.compile(r"(?i)(authorization|password)\s*[:=]\s*\S+")
    for folder in (FIXTURES, DATA):
        for path in folder.iterdir():
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8")
            assert PASSWORD not in text
            assert secret.search(text) is None, path.name
            for match in re.finditer(r'"(?:id|collection_id)"\s*:\s*"([^"]+)"', text):
                assert _UUID.fullmatch(match.group(1)) is None, path.name
    source_text = Path(source.__file__).read_text(encoding="utf-8")
    for token in ("post_json", "httpx.post", "httpx.put", "httpx.delete", "httpx.patch"):
        assert token not in source_text
    assert "POST" not in source_text


def test_advertised_schema_is_read_only():
    tools = {tool.name: tool for tool in asyncio.run(build_server(connector()).list_tools())}
    encoded = json.dumps(tools["taxii_get_objects"].inputSchema)
    assert "1000" in encoded
    assert tools["taxii_lookup_indicator"].inputSchema["required"] == ["value"]
    lookup = json.dumps(tools["taxii_lookup_indicator"].inputSchema)
    assert "minLength" in lookup or "min_length" in lookup
    for tool in tools.values():
        assert tool.annotations.readOnlyHint is True
        assert tool.annotations.openWorldHint is True


def test_live_paging_discovery_auth_and_limits(tmp_path, monkeypatch):
    _arm(monkeypatch, tmp_path)
    calls = []

    def page(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if request.url.params.get("next"):
            assert "added_after" not in request.url.params
            assert "match[type]" not in request.url.params
            return httpx.Response(200, content=(FIXTURES / "envelope_page2.json").read_bytes())
        assert request.url.params.get("added_after") == "2026-01-01T00:00:00Z"
        assert request.url.params.get("match[type]") == "indicator,malware"
        assert _request_is_authenticated(request)
        return httpx.Response(200, content=(FIXTURES / "envelope_page1_more.json").read_bytes())

    source._TRANSPORT = httpx.MockTransport(page)
    try:
        found = taxii_get_objects(
            added_after="2026-01-01T00:00:00Z",
            types=["indicator", "malware"],
            limit=10,
        )
    finally:
        source._TRANSPORT = None
    assert len(calls) == 2
    assert _ids(found["data"]) == {
        "indicator--synthetic-ip",
        "malware--synthetic-demo",
        "indicator--synthetic-hash",
    }
    assert PASSWORD not in json.dumps(found)

    _fresh(monkeypatch)
    monkeypatch.setenv("TAXII_API_ROOT", "https://example.com/taxii2/")
    seen = []

    def discover(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        if request.url.path.rstrip("/").endswith("/collections"):
            return httpx.Response(200, content=(FIXTURES / "collections.json").read_bytes())
        return httpx.Response(200, content=(FIXTURES / "discovery.json").read_bytes())

    source._TRANSPORT = httpx.MockTransport(discover)
    try:
        listed = taxii_list_collections()
    finally:
        source._TRANSPORT = None
    assert listed["data"][0]["id"] == "synthetic-collection-alpha"
    assert all("evil.test" not in url for url in seen)
    chosen = source._choose_root(
        {"default": "https://evil.test/api/", "api_roots": ["https://example.com/taxii2/root/"]}
    )
    assert chosen == "https://example.com/taxii2/root/"


def test_auth_errors_retry_redirect_and_timeout(tmp_path, monkeypatch):
    _arm(monkeypatch, tmp_path)

    def denied(status: int):
        def handler(request: httpx.Request) -> httpx.Response:
            assert _request_is_authenticated(request)
            body = (FIXTURES / "taxii_401.json").read_bytes()
            return httpx.Response(status, content=body)

        return handler

    for status in (401, 403):
        _fresh(monkeypatch)
        source._TRANSPORT = httpx.MockTransport(denied(status))
        try:
            failed = taxii_list_collections()
        finally:
            source._TRANSPORT = None
        assert failed["data"] == []
        warning = " ".join(failed["warnings"])
        assert "TAXII_USERNAME" in warning
        assert "TAXII_PASSWORD" in warning
        assert str(status) in warning
        assert PASSWORD not in warning

    _fresh(monkeypatch)
    calls = {"n": 0}
    slept = []
    source._SLEEP = lambda seconds: slept.append(seconds)

    def retry(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(429, headers={"retry-after": "0"})
        return httpx.Response(200, content=(FIXTURES / "collections.json").read_bytes())

    source._TRANSPORT = httpx.MockTransport(retry)
    try:
        retried = taxii_list_collections()
    finally:
        source._TRANSPORT = None
        source._SLEEP = lambda _seconds: None
    assert retried["data"][0]["id"] == "synthetic-collection-alpha"
    assert 0 in slept or 0.0 in slept

    _fresh(monkeypatch)

    def redirect(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://evil.test/x"})

    source._TRANSPORT = httpx.MockTransport(redirect)
    try:
        refused = taxii_list_collections()
    finally:
        source._TRANSPORT = None
    warning = " ".join(refused["warnings"])
    assert "evil.test" in warning
    assert "allowlisted" in warning
    assert PASSWORD not in warning

    _fresh(monkeypatch)

    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("timed out")

    source._TRANSPORT = httpx.MockTransport(boom)
    try:
        timed = taxii_list_collections()
    finally:
        source._TRANSPORT = None
    assert any("unavailable" in item.lower() for item in timed["warnings"])


def test_timeout_uses_stale_cache_and_offline_prefers_fresh_cache(tmp_path, monkeypatch):
    _arm(monkeypatch, tmp_path)
    url = source._collections_url("https://example.com/taxii2/root/")
    cache = HttpCache(Path(os.environ["CYBERAU_DATA_DIR"]) / "http_cache.sqlite")
    key = cache.key("GET", url, {}, b"", source._auth_scope())
    cache.put(
        key,
        status=200,
        headers={},
        body=(FIXTURES / "collections.json").read_bytes(),
        ttl=0,
    )

    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("timed out")

    source._TRANSPORT = httpx.MockTransport(boom)
    try:
        stale = taxii_list_collections()
    finally:
        source._TRANSPORT = None
    assert stale["cache"] == "stale"
    assert stale["data"][0]["id"] == "synthetic-collection-alpha"

    monkeypatch.setenv("CYBERAU_OFFLINE", "1")
    monkeypatch.delenv("CYBERAU_TAXII_SNAPSHOT", raising=False)
    fresh = HttpCache(Path(os.environ["CYBERAU_DATA_DIR"]) / "http_cache.sqlite")
    fresh.put(
        key,
        status=200,
        headers={},
        body=(FIXTURES / "collections.json").read_bytes(),
        ttl=86400,
    )
    source._TRANSPORT = httpx.MockTransport(boom)
    try:
        hit = taxii_list_collections()
    finally:
        source._TRANSPORT = None
    assert hit["cache"] in {"hit", "stale"}
    assert hit["data"][0]["id"] == "synthetic-collection-alpha"


def test_poll_limit_and_live_health(tmp_path, monkeypatch):
    _arm(monkeypatch, tmp_path)
    calls = {"n": 0}

    def ok(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, content=(FIXTURES / "collections.json").read_bytes())

    source._TRANSPORT = httpx.MockTransport(ok)
    try:
        first = taxii_list_collections()
        second = taxii_list_collections()
    finally:
        source._TRANSPORT = None
    assert first["data"]
    assert calls["n"] == 1
    assert any("poll limit" in warning.lower() for warning in second["warnings"])

    monkeypatch.setenv("CYBERAU_DATA_DIR", tempfile.mkdtemp(prefix="cyberau-taxii-health-"))
    source._TRANSPORT = httpx.MockTransport(ok)
    try:
        probe = connector().health(live=True)
    finally:
        source._TRANSPORT = None
    assert probe.ok is True
    assert probe.detail == "live ok"

    def drift(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=(FIXTURES / "schema_drift.json").read_bytes())

    monkeypatch.setenv("CYBERAU_DATA_DIR", tempfile.mkdtemp(prefix="cyberau-taxii-drift-"))
    source._TRANSPORT = httpx.MockTransport(drift)
    try:
        failed = connector().health(live=True)
    finally:
        source._TRANSPORT = None
    assert failed.ok is False

    for name in ("TAXII_API_ROOT", "TAXII_COLLECTION_ID", "TAXII_USERNAME", "TAXII_PASSWORD"):
        monkeypatch.delenv(name, raising=False)

    def explode(request: httpx.Request) -> httpx.Response:
        raise AssertionError("live health must not call the network without credentials")

    source._TRANSPORT = httpx.MockTransport(explode)
    try:
        missing = connector().health(live=True)
    finally:
        source._TRANSPORT = None
    assert missing.ok is False
    assert "TAXII_API_ROOT" in missing.detail


def test_shipped_snapshot_and_cassettes(vcr_config):
    os.environ.pop("CYBERAU_TAXII_SNAPSHOT", None)
    os.environ["CYBERAU_OFFLINE"] = "1"
    os.environ.pop("TAXII_API_ROOT", None)
    listed = taxii_list_collections()
    assert listed["cache"] == "snapshot"
    assert listed["data"][0]["id"] == "synthetic-collection-alpha"
    assert "authorization" in vcr_config["filter_headers"]
    import vcr
    from vcr.serialize import deserialize
    from vcr.serializers import yamlserializer

    player = vcr.VCR(record_mode="none")
    path = FIXTURES / "taxii_list_collections.yaml"
    requests, responses = deserialize(path.read_text(encoding="utf-8"), yamlserializer)
    assert requests and responses[0]["status"]["code"] == 200
    with player.use_cassette(str(path)):
        played = httpx.get("https://example.com/taxii2/root/collections/")
    assert played.status_code == 200
    assert played.json()["collections"][0]["id"] == "synthetic-collection-alpha"
