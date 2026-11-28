"""hermes cyber-au setup in non-interactive mode, and the tailoring it produces.

No network, no Hermes, no real keys. Every value is synthetic (example.com names, a marker
string standing in for a key value that must never be copied).
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import stat
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
PLUGIN = ROOT / "plugins" / "cyber-au"
MODULE = "cyber_au_setup_plugin"
MARKER = "setup-test-not-a-real-key-value"
SERVERS = yaml.safe_load((ROOT / "mcp" / "servers.yaml").read_text(encoding="utf-8"))["servers"]


def _load():
    loaded = sys.modules.get(MODULE)
    if loaded is not None:
        return loaded
    spec = importlib.util.spec_from_file_location(
        MODULE, PLUGIN / "__init__.py", submodule_search_locations=[str(PLUGIN)]
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[MODULE] = module
    spec.loader.exec_module(module)
    return module


_load()
import importlib  # noqa: E402

cli = importlib.import_module(f"{MODULE}.cli")
wizard = importlib.import_module(f"{MODULE}.setup_wizard")
org_setup = importlib.import_module(f"{MODULE}.store.org_setup")
org_context = importlib.import_module(f"{MODULE}.store.org_context")
org = importlib.import_module(f"{MODULE}.store.org")


def _answers(tmp_path: Path, **values) -> Path:
    data = {
        "name": "Example Water Pty Ltd",
        "sector": "energy-water",
        "size": "large",
        "turnover": "3m-or-more",
        "regulators": ["soci", "oaic"],
        "environments": ["it", "ot"],
        "critical_infrastructure": True,
        "domains": ["Example.com.au", "example.com"],
        "brands": ["Example Water"],
        "keys_present": ["NVD_API_KEY"],
    }
    data.update(values)
    path = tmp_path / "answers.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


def _home(tmp_path: Path, env: str = "") -> Path:
    home = tmp_path / "profile"
    home.mkdir()
    (home / ".env").write_text(env, encoding="utf-8")
    return home


def _run(home: Path, answers: Path, *extra: str, capsys=None) -> int:
    parser = argparse.ArgumentParser()
    cli.setup_parser(parser)
    argv = ["setup", "--profile-home", str(home), "--from-file", str(answers), *extra]
    args = parser.parse_args(argv)
    return cli.handle(args)


def test_setup_writes_org_yaml_watchlist_and_config(tmp_path: Path, capsys):
    home = _home(tmp_path, f"OTX_API_KEY={MARKER}\n# ABUSECH_AUTH_KEY=\n")
    code = _run(home, _answers(tmp_path), "--no-doctor")
    out = capsys.readouterr().out
    assert code == 0, out
    data_dir = home / "plugin-data" / "cyber-au"

    org_file = data_dir / "org.yaml"
    assert stat.S_IMODE(org_file.stat().st_mode) == 0o600
    profile = org.load_org(org_file)
    assert profile.sector == "energy-water"
    assert profile.packs == ("energy-water",)
    assert profile.domains == ("example.com.au", "example.com")
    # Names only: one from the answers, one found set in .env. The blank one is ignored.
    assert profile.keys_present == ("NVD_API_KEY", "OTX_API_KEY")
    assert "otx" in profile.connectors and "kev" in profile.connectors
    assert "abusech" not in profile.connectors
    assert "e8" not in profile.connectors  # licence terms keep it off
    assert "hudsonrock" not in profile.connectors  # paid feed stays off

    watch = yaml.safe_load((data_dir / "watchlists.yaml").read_text(encoding="utf-8"))
    assert watch == {"domains": ["example.com.au", "example.com"], "brands": ["Example Water"]}

    config = yaml.safe_load((home / "config.yaml").read_text(encoding="utf-8"))
    servers = config["mcp_servers"]
    assert servers["otx"]["enabled"] is True
    assert servers["abusech"]["enabled"] is False
    assert servers["otx"]["env"]["OTX_API_KEY"] == "${OTX_API_KEY}"

    for path in (org_file, data_dir / "watchlists.yaml", home / "config.yaml"):
        assert MARKER not in path.read_text(encoding="utf-8")
    assert MARKER not in out
    assert "Sector packs: energy-water." in out


def test_setup_refuses_to_overwrite_without_force(tmp_path: Path, capsys):
    home = _home(tmp_path)
    answers = _answers(tmp_path)
    assert _run(home, answers, "--no-doctor", "--no-render") == 0
    assert _run(home, answers, "--no-doctor", "--no-render") == 1
    assert "--force" in capsys.readouterr().err
    changed = _answers(tmp_path, sector="health", critical_infrastructure=False)
    assert _run(home, changed, "--no-doctor", "--no-render", "--force") == 0
    profile = org.load_org(home / "plugin-data" / "cyber-au" / "org.yaml")
    assert profile.sector == "health"


def test_existing_watchlist_is_never_touched(tmp_path: Path):
    home = _home(tmp_path)
    data_dir = home / "plugin-data" / "cyber-au"
    data_dir.mkdir(parents=True)
    (data_dir / "watchlists.yaml").write_text("domains: [kept.example.org]\n", encoding="utf-8")
    assert _run(home, _answers(tmp_path), "--no-doctor", "--no-render") == 0
    assert (data_dir / "watchlists.yaml").read_text() == "domains: [kept.example.org]\n"


@pytest.mark.parametrize(
    "bad",
    [
        {"nvd_api_key": MARKER},
        {"keys_present": [f"NVD_API_KEY={MARKER}"]},
        {"domains": [{"token": MARKER}]},
    ],
)
def test_answers_holding_a_key_value_are_refused(tmp_path: Path, capsys, bad: dict):
    home = _home(tmp_path)
    code = _run(home, _answers(tmp_path, **bad), "--no-doctor", "--no-render")
    captured = capsys.readouterr()
    assert code == 1
    assert not (home / "plugin-data" / "cyber-au" / "org.yaml").exists()
    assert MARKER not in captured.out + captured.err


def test_bad_answers_warn_and_fall_back(tmp_path: Path, capsys):
    home = _home(tmp_path)
    answers = _answers(
        tmp_path,
        sector="mining",
        domains=["192.0.2.10", "example.com"],
        keys_present=["NOT_A_CONNECTOR_KEY"],
        favourite_colour="blue",
    )
    assert _run(home, answers, "--no-doctor", "--no-render") == 0
    out = capsys.readouterr().out
    profile = org.load_org(home / "plugin-data" / "cyber-au" / "org.yaml")
    assert profile.sector == "general"
    assert profile.domains == ("example.com",)
    assert "sector: 'mining'" in out
    assert "192.0.2.10" in out and "not a domain name" in out
    assert "NOT_A_CONNECTOR_KEY is not read by any shipped connector" in out
    assert "'favourite_colour' is not a setup question" in out


def test_no_terminal_and_no_file_asks_for_from_file(tmp_path: Path, capsys, monkeypatch):
    monkeypatch.setattr(sys, "stdin", None)
    parser = argparse.ArgumentParser()
    cli.setup_parser(parser)
    args = parser.parse_args(["setup", "--profile-home", str(_home(tmp_path))])
    assert cli.handle(args) == 2
    assert "--from-file" in capsys.readouterr().err


def test_connector_selection_rules():
    selection = org_setup.select_connectors(SERVERS, {"OTX_API_KEY"})
    assert "otx" in selection.enabled
    assert "kev" in selection.enabled
    none = org_setup.select_connectors(SERVERS, set())
    assert none.needs_key["otx"] == ["OTX_API_KEY"]
    for name, spec in SERVERS.items():
        if spec.get("enabled_by_default", spec.get("default_enabled", True)) is False:
            assert name in none.off
            assert name not in org_setup.select_connectors(SERVERS, set(KEYS)).enabled


KEYS = org_setup.key_names(SERVERS)


def test_key_names_are_names_not_settings():
    assert "OTX_API_KEY" in KEYS
    assert "GITHUB_ADVISORY_TOKEN" in KEYS  # placeholder target, not the upstream name
    assert "CYBERAU_DATA_DIR" not in KEYS


def test_env_names_keep_names_and_drop_values(tmp_path: Path):
    env = tmp_path / ".env"
    env.write_text(
        f'export OTX_API_KEY="{MARKER}"\nNVD_API_KEY=  # todo\nGREYNOISE_API_KEY=\n',
        encoding="utf-8",
    )
    assert org_setup.env_names(env) == {"OTX_API_KEY"}


def test_interactive_prompts_feed_the_same_contract(capsys):
    replies = iter(
        [
            "Example Clinic",  # name
            "health",  # sector
            "small",
            "under-3m",
            "oaic",
            "it, cloud",
            "",  # critical infrastructure: default no
            "y",
            "clinic.example.com",
            "",  # brands
            "nvd_api_key",
            "",  # sector packs: default
        ]
    )
    answers = org_setup.ask_answers(lambda _prompt: next(replies), SERVERS, set())
    profile, warnings = org_setup.profile_from_answers(answers, servers=SERVERS)
    assert warnings == []
    assert profile.sector == "health"
    assert profile.environments == ("it", "cloud")
    assert profile.critical_infrastructure is False
    assert profile.keys_present == ("NVD_API_KEY",)
    assert profile.packs == ("health",)


def test_org_context_cli_reads_the_written_profile(tmp_path: Path, capsys, monkeypatch):
    home = _home(tmp_path)
    assert _run(home, _answers(tmp_path), "--no-doctor", "--no-render") == 0
    capsys.readouterr()
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(home / "plugin-data" / "cyber-au"))
    assert org_context.main(["context", "--skill", "essentials-assessment", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["profile_found"] is True
    assert [pack["name"] for pack in payload["active_packs"]] == ["energy-water"]
    ids = {rule["id"] for rule in payload["rules"]}
    assert {"essentials-ot-chapter", "cyber-framework-enhanced"} <= ids
    assert "soci-annual-report" not in ids  # soci-reporting only

    assert org_context.main(["packs"]) == 0
    listed = {pack["name"]: pack["active"] for pack in json.loads(capsys.readouterr().out)["packs"]}
    assert listed == {"energy-water": True, "health": False}


def test_org_context_without_a_profile_says_so(tmp_path: Path, capsys, monkeypatch):
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    assert org_context.main(["context", "--skill", "soci-reporting"]) == 0
    out = capsys.readouterr().out
    assert "Organisation profile: not set" in out
    assert "Active sector packs: none (sector general)." in out
