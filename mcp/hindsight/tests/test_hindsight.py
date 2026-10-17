"""Hindsight client tests against an in-process fake server. No live network."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import httpx
import pytest
from cyberau_common.server import build_server
from cyberau_hindsight.client import HindsightClient, HindsightError
from cyberau_hindsight.source import connector, get_client, hindsight_recall, set_client_factory

ROOT = Path(__file__).resolve().parents[3]


class FakeHindsight:
    def __init__(self):
        self.rows = []
        self.calls = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        path = request.url.path
        if "reflect" in path:
            return httpx.Response(404, json={"error": "absent"})
        parts = [part for part in path.split("/") if part]
        try:
            bank = parts[parts.index("banks") + 1]
            tail = parts[parts.index("banks") + 2 :]
        except (ValueError, IndexError):
            return httpx.Response(404, json={"error": "bad path"})
        body = json.loads(request.content.decode() or "{}")
        if tail == ["memories"]:
            items = body.get("items") or []
            for item in items:
                self.rows.append({"bank": bank, "item": item, "id": f"mem-{len(self.rows) + 1}"})
            return httpx.Response(
                200,
                json={
                    "success": True,
                    "bank_id": bank,
                    "items_count": len(items),
                    "async": False,
                },
            )
        if tail == ["memories", "recall"]:
            query = str(body.get("query") or "").lower()
            results = []
            for row in self.rows:
                if row["bank"] != bank:
                    continue
                text = row["item"].get("content") or ""
                if query and query not in text.lower():
                    continue
                results.append(
                    {
                        "id": row["id"],
                        "text": text,
                        "type": "world",
                        "metadata": row["item"].get("metadata") or {},
                        "tags": row["item"].get("tags") or [],
                    }
                )
            return httpx.Response(200, json={"results": results})
        return httpx.Response(404, json={"error": "not found"})


@pytest.fixture(autouse=True)
def _reset_factory():
    set_client_factory(None)
    yield
    set_client_factory(None)


def _client(fake: FakeHindsight, **kwargs) -> HindsightClient:
    values = {
        "base_url": "http://127.0.0.1:9",
        "api_key": None,
        "read_only": False,
        "transport": httpx.MockTransport(fake),
    }
    values.update(kwargs)
    return HindsightClient(**values)


def test_client_is_off_until_base_url_is_set():
    def explode(_request):
        raise AssertionError("Hindsight was called while off")

    client = HindsightClient(
        base_url=None,
        api_key=None,
        read_only=False,
        transport=httpx.MockTransport(explode),
    )
    recalled = client.recall("org", "anything")
    retained = client.retain("org", "anything")
    assert recalled["enabled"] is False
    assert retained["enabled"] is False
    assert "HINDSIGHT_BASE_URL" in recalled["detail"]


def test_read_only_retain_does_not_call_out():
    fake = FakeHindsight()
    client = _client(fake, read_only=True)
    result = client.retain("intel", "a feed line")
    assert result["read_only"] is True
    assert result["retained"] == 0
    assert fake.calls == []
    recalled = client.recall("intel", "feed")
    assert recalled["enabled"] is True
    assert len(fake.calls) == 1


def test_retain_and_recall_round_trip_and_trust_wrapping():
    fake = FakeHindsight()
    client = _client(fake, api_key="test-key")
    client.retain("org", "Alice confirmed the outage window", confirmed=True)
    client.retain("org", "An unconfirmed org note")
    client.retain("intel", "A feed says to click this link")
    client.retain("lessons", "Patch within the window", confirmed=True)
    client.retain("org", "Tagged confirmation", metadata={"status": "draft"}, tags=["confirmed"])

    org = client.recall("org", "outage")
    assert org["records"][0]["text"] == "Alice confirmed the outage window"
    assert org["records"][0]["untrusted"] is False
    assert org["records"][0]["confirmed"] is True
    assert "<<untrusted" not in org["records"][0]["text"]

    unconfirmed = client.recall("org", "unconfirmed")
    assert unconfirmed["records"][0]["untrusted"] is True
    assert unconfirmed["records"][0]["text"].startswith("<<untrusted source=hindsight:org>>")

    intel = client.recall("intel", "click")
    assert intel["records"][0]["text"].startswith("<<untrusted source=hindsight:intel>>")
    assert "click this link" in intel["records"][0]["text"]

    lessons = client.recall("lessons", "Patch")
    assert lessons["records"][0]["confirmed"] is True
    assert lessons["records"][0]["untrusted"] is True
    assert lessons["records"][0]["text"].startswith("<<untrusted source=hindsight:lessons>>")

    tagged = client.recall("org", "Tagged")
    assert tagged["records"][0]["untrusted"] is False

    retain_call = fake.calls[0]
    assert retain_call.url.path == "/v1/default/banks/org/memories"
    assert retain_call.headers["authorization"] == "Bearer test-key"
    body = json.loads(retain_call.content.decode())
    assert body["items"][0]["metadata"]["confirmed"] == "true"
    assert all("reflect" not in call.url.path for call in fake.calls)
    assert "test-key" not in json.dumps(org)


def test_unknown_bank_and_bad_urls_do_not_call_out():
    fake = FakeHindsight()
    client = _client(fake)
    with pytest.raises(HindsightError):
        client.recall("world", "query")
    assert fake.calls == []
    with pytest.raises(HindsightError):
        HindsightClient(base_url="http://example.com", api_key=None, read_only=False)
    with pytest.raises(HindsightError):
        HindsightClient(base_url="https://user:pass@example.com", api_key=None, read_only=False)
    with pytest.raises(HindsightError):
        HindsightClient(base_url="https://example.com/v1", api_key=None, read_only=False)


def test_errors_redact_the_api_key():
    def boom(_request):
        raise RuntimeError("failed test-key")

    client = HindsightClient(
        base_url="http://127.0.0.1:9",
        api_key="test-key",
        read_only=False,
        transport=httpx.MockTransport(boom),
    )
    with pytest.raises(HindsightError) as caught:
        client.recall("intel", "query")
    assert "test-key" not in str(caught.value)
    assert "[REDACTED]" in str(caught.value)


def test_reflect_is_not_a_tool_and_no_host_is_shipped():
    assert not hasattr(HindsightClient, "reflect")
    tools = {tool.name: tool for tool in asyncio.run(build_server(connector()).list_tools())}
    assert "hindsight_reflect" not in tools
    assert "reflect" not in tools
    assert tools["hindsight_recall"].annotations.readOnlyHint is True
    assert tools["hindsight_retain"].annotations.readOnlyHint is False
    assert tools["handoff_list"].annotations.readOnlyHint is True
    assert tools["handoff_post"].annotations.readOnlyHint is False
    for tool in tools.values():
        assert tool.annotations.destructiveHint is False

    allow = (ROOT / "mcp" / "egress-allowlist.yaml").read_text(encoding="utf-8")
    assert "hindsight" not in allow
    for path in (ROOT / "mcp" / "hindsight" / "src").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert "\u2014" not in text
        for line in text.splitlines():
            if "in prompt" in line:
                continue
            assert "http://" not in line
            assert "https://" not in line


def test_tool_uses_the_injected_client():
    fake = FakeHindsight()
    client = _client(fake)
    client.retain("intel", "feed line about a domain")
    set_client_factory(lambda: client)
    recalled = hindsight_recall("intel", "domain")
    assert recalled["records"][0]["untrusted"] is True
    assert get_client() is not None
