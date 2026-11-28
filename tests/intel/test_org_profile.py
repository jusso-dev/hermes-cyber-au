"""org.yaml contract: parse, defaults, secret refusal, round trip. No network."""

from __future__ import annotations

import stat

import pytest
from store.org import OrgFileError, OrgProfile, load_org, parse_org, write_org


def test_missing_file_gives_neutral_default(tmp_path):
    profile = load_org(tmp_path / "org.yaml")
    assert profile.sector == "general"
    assert profile.packs == ()
    assert profile.warnings


def test_parse_normalises_and_warns():
    profile = parse_org(
        {
            "sector": "Health",
            "size": "huge",
            "regulators": ["OAIC", "nope", "none"],
            "environments": ["it", "ot"],
            "domains": ["Example.COM.au"],
        }
    )
    assert profile.sector == "health"
    assert profile.size == "medium"
    assert profile.regulators == ("oaic",)
    assert profile.environments == ("it", "ot")
    assert profile.domains == ("example.com.au",)
    assert profile.packs == ("health",)
    assert any("size" in w for w in profile.warnings)


@pytest.mark.parametrize(
    "data",
    [
        {"nvd_api_key": "abc123"},
        {"connectors": [{"token": "abc"}]},
        {"keys_present": ["not a var name"]},
    ],
)
def test_refuses_credentials(data):
    with pytest.raises(OrgFileError):
        parse_org(data)


def test_keys_present_lists_names_only():
    assert parse_org({"keys_present": ["NVD_API_KEY"]}).keys_present == ("NVD_API_KEY",)


def test_write_round_trip_and_mode(tmp_path):
    target = tmp_path / "org.yaml"
    original = OrgProfile(name="Example Pty Ltd", sector="energy-water", regulators=("soci",))
    write_org(original, target)
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert load_org(target) == original
    with pytest.raises(OrgFileError):
        write_org(original, target)
    write_org(original, target, force=True)


def test_sector_packs_accept_local_names_and_none():
    local = parse_org({"sector": "retail", "sector_packs": ["Example-Pack", "bad name!"]})
    assert local.sector_packs == ("example-pack",)
    assert local.packs == ("example-pack",)
    assert any("bad name!" in w for w in local.warnings)
    off = parse_org({"sector": "health", "sector_packs": ["none"]})
    assert off.packs == ()
