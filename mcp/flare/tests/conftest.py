"""Keep Flare tests off the network and off any other worktree's cache."""

from __future__ import annotations

import ipaddress

import cyberau_flare.client as flare_client
import pytest


@pytest.fixture(autouse=True)
def _isolate_flare(monkeypatch, tmp_path):
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("FLARE_API_KEY", "unit-test-flare-key")
    monkeypatch.delenv("FLARE_TENANT_ID", raising=False)
    monkeypatch.delenv("CYBERAU_OFFLINE", raising=False)
    monkeypatch.delenv("CYBERAU_FLARE_FIXTURES", raising=False)
    monkeypatch.delenv("CYBERAU_FLARE_HTTP", raising=False)
    monkeypatch.delenv("CYBERAU_FLARE_SCHEMA_FIXTURE", raising=False)
    flare_client.TRANSPORT = None
    flare_client.SLEEPER = None
    flare_client.CLOCK = None
    flare_client.RESOLVER = lambda _host: [ipaddress.ip_address("1.1.1.1")]
    flare_client.reset_token()
    yield
    flare_client.TRANSPORT = None
    flare_client.SLEEPER = None
    flare_client.CLOCK = None
    flare_client.RESOLVER = None
    flare_client.reset_token()
