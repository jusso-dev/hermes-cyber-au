"""The org-exposure watchlist that `cyberau watchlist init --org` writes is the file every
premium connector reads. No network."""

from __future__ import annotations

import pytest
import yaml
from cyberau_crowdstrike_recon import source as crowdstrike
from cyberau_flare import source as flare
from cyberau_google_ti_dtm import source as gti
from cyberau_hudson_rock import source as hudson
from cyberau_intel471 import source as intel471
from cyberau_org_exposure.cli import main
from cyberau_org_exposure.watchlist import default_watchlist_path, load_profile
from cyberau_ransomware_live import source as ransomware
from cyberau_recorded_future import source as recorded_future
from cyberau_spycloud import source as spycloud

DOMAIN = "wattle-sample.example"
CONTENT = {"organisation": "Wattle Sample Pty Ltd", "domains": [DOMAIN]}


def _domains_seen_by_readers() -> dict[str, list[str]]:
    hudson_watch, _ = hudson._load_watchlist()
    intel_watch, _ = intel471._load_watchlist()
    ransom_watch, _ = ransomware._load_watchlist()
    readers = {
        "crowdstrike-recon": crowdstrike._load_watchlist(),
        "flare": flare.load_watchlist(),
        "google-ti-dtm": gti._load_watchlist(),
        "hudson-rock": hudson_watch,
        "intel471": intel_watch,
        "recorded-future": recorded_future._loaded_watchlist(),
        "spycloud": spycloud.local_watchlist(),
    }
    seen = {name: list(watch.domains) if watch else [] for name, watch in readers.items()}
    seen["ransomware-live"] = list((ransom_watch or {}).get("domains") or [])
    seen["org-exposure"] = list(load_profile(default_watchlist_path(), routine_path=None).domains)
    return seen


@pytest.fixture
def profile(tmp_path, monkeypatch):
    for name in ("CYBERAU_ORG_WATCHLIST", "CYBERAU_WATCHLIST", "HERMES_HOME"):
        monkeypatch.delenv(name, raising=False)
    home = tmp_path / "profile"
    (home / "plugin-data" / "cyber-au").mkdir(parents=True)
    return home


def _init_and_fill() -> None:
    assert main(["watchlist", "init", "--org"]) == 0
    written = default_watchlist_path()
    written.write_text(yaml.safe_dump(CONTENT), encoding="utf-8")


@pytest.mark.parametrize("env", ["CYBERAU_DATA_DIR", "HERMES_HOME", "both"])
def test_writer_and_every_reader_use_the_same_file(profile, monkeypatch, env):
    """The MCP servers get CYBERAU_DATA_DIR only; a shell may have HERMES_HOME only."""
    if env in ("CYBERAU_DATA_DIR", "both"):
        monkeypatch.setenv("CYBERAU_DATA_DIR", str(profile / "plugin-data" / "cyber-au"))
    else:
        monkeypatch.delenv("CYBERAU_DATA_DIR", raising=False)
    if env in ("HERMES_HOME", "both"):
        monkeypatch.setenv("HERMES_HOME", str(profile))
    _init_and_fill()
    assert default_watchlist_path() == profile / "watchlists" / "org-exposure.yaml"
    seen = _domains_seen_by_readers()
    assert seen == {name: [DOMAIN] for name in seen}


@pytest.mark.parametrize("name", ["CYBERAU_ORG_WATCHLIST", "CYBERAU_WATCHLIST"])
def test_either_override_name_moves_writer_and_readers_together(
    profile, tmp_path, monkeypatch, name
):
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(profile / "plugin-data" / "cyber-au"))
    target = tmp_path / "elsewhere" / "org.yaml"
    monkeypatch.setenv(name, str(target))
    _init_and_fill()
    assert target.is_file()
    assert not (profile / "watchlists").exists()
    seen = _domains_seen_by_readers()
    assert seen == {reader: [DOMAIN] for reader in seen}
