"""Cross-checks for feeds/catalogue.yaml against the rest of the repository."""

from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urlsplit

import pytest
import yaml
from cyberau_common import refresh
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
CATALOGUE = ROOT / "feeds" / "catalogue.yaml"
SCHEMA = ROOT / "feeds" / "catalogue.schema.json"
PLACEHOLDER = re.compile(r"^\$\{([A-Z][A-Z0-9_]*)\}")
ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]*$")
VAR_REF = re.compile(r"\$\{([A-Z][A-Z0-9_]*)\}")
# servers.yaml connector names that share another connector's egress entry.
EGRESS_ALIAS = {"flare-mcp": "flare"}


def _yaml(path: Path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def catalogue() -> dict:
    return _yaml(CATALOGUE)


@pytest.fixture(scope="module")
def feeds(catalogue) -> list[dict]:
    return catalogue["feeds"]


@pytest.fixture(scope="module")
def servers() -> dict:
    return _yaml(ROOT / "mcp" / "servers.yaml")["servers"]


@pytest.fixture(scope="module")
def allowlist() -> dict:
    return _yaml(ROOT / "mcp" / "egress-allowlist.yaml")["connectors"]


def _env_names(auth: dict) -> list[str]:
    names = [auth["env"]] if auth.get("env") else []
    return names + list(auth.get("env_also") or [])


def _urls(feed: dict) -> list[str]:
    return [feed["url"], *(feed.get("urls") or [])]


def _known_env_names(servers: dict) -> set[str]:
    names: set[str] = set()
    template = (ROOT / ".env.template").read_text(encoding="utf-8")
    names.update(re.findall(r"^#?\s*([A-Z][A-Z0-9_]*)=", template, re.MULTILINE))
    distribution = _yaml(ROOT / "distribution.yaml")
    names.update(item["name"] for item in distribution.get("env_requires") or [])
    names.update(VAR_REF.findall((ROOT / "mcp" / "servers.yaml").read_text(encoding="utf-8")))
    for spec in servers.values():
        names.update(spec.get("required_env") or [])
        if spec.get("token_env"):
            names.add(spec["token_env"])
    return names


def test_catalogue_matches_its_schema(catalogue):
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    errors = [
        f"{'/'.join(map(str, error.path))}: {error.message}"
        for error in Draft202012Validator(schema).iter_errors(catalogue)
    ]
    assert errors == []


def test_repository_validator_accepts_the_catalogue():
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "validate_repo", ROOT / "tools" / "ci" / "validate_repo.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.check_catalogue(ROOT) == []


def test_ids_are_unique(feeds):
    ids = [feed["id"] for feed in feeds]
    assert len(ids) == len(set(ids))


def test_every_server_has_an_entry_or_an_exclusion(catalogue, feeds, servers):
    covered = {feed["server"] for feed in feeds if feed["server"]}
    excluded = set(catalogue.get("excluded_servers") or {})
    assert covered.isdisjoint(excluded)
    assert sorted(set(servers) - covered - excluded) == []
    assert sorted((covered | excluded) - set(servers)) == []


def test_entry_matches_its_server(feeds, servers):
    for feed in feeds:
        spec = servers.get(feed["server"]) if feed["server"] else None
        if spec is None:
            assert feed["enabled_by_default"] is False, feed["id"]
            continue
        assert spec.get("connector", feed["connector"]) == feed["connector"], feed["id"]
        assert feed["enabled_by_default"] is bool(spec.get("enabled_by_default")), feed["id"]


def test_server_required_env_is_named_in_the_catalogue(feeds, servers):
    named: dict[str, set[str]] = {}
    for feed in feeds:
        if feed["server"]:
            named.setdefault(feed["server"], set()).update(_env_names(feed["auth"]))
    for server, names in named.items():
        missing = set(servers[server].get("required_env") or []) - names
        assert not missing, f"{server}: {sorted(missing)}"


def test_keyed_follows_auth(feeds):
    for feed in feeds:
        auth = feed["auth"]
        needs_key = auth["type"] != "none" and not auth.get("optional", False)
        assert feed["keyed"] is needs_key, feed["id"]


def test_auth_names_environment_variables_only(feeds, servers):
    # Declared means .env.template, distribution.yaml, servers.yaml or the
    # connector's own SOURCE.md.
    known = _known_env_names(servers)
    for feed in feeds:
        auth = feed["auth"]
        names = _env_names(auth)
        if auth["type"] == "none":
            assert names == [], feed["id"]
            continue
        assert names, feed["id"]
        source_md = ROOT / "mcp" / feed["connector"] / "SOURCE.md"
        documented = source_md.read_text(encoding="utf-8") if source_md.is_file() else ""
        for name in names:
            assert ENV_NAME.fullmatch(name), f"{feed['id']}: {name!r}"
            declared = name in known or re.search(rf"\b{name}\b", documented)
            assert declared, f"{feed['id']}: {name} is not declared anywhere"


def test_url_hosts_are_allowlisted_for_the_connector(feeds, allowlist):
    for feed in feeds:
        connector = EGRESS_ALIAS.get(feed["connector"], feed["connector"])
        hosts = set((allowlist.get(connector) or {}).get("hosts") or [])
        for url in _urls(feed):
            placeholder = PLACEHOLDER.match(url)
            if placeholder:
                assert placeholder.group(1) in _env_names(feed["auth"]), feed["id"]
                continue
            parts = urlsplit(url)
            assert parts.scheme == "https", f"{feed['id']}: {url}"
            assert parts.hostname in hosts, f"{feed['id']}: {parts.hostname} not in {connector}"


def test_refresh_keys_match_cyberau_mcp_refresh(feeds):
    keyed = {feed["refresh"]: feed for feed in feeds if "refresh" in feed}
    assert len(keyed) == len([feed for feed in feeds if "refresh" in feed])
    assert sorted(keyed) == sorted(refresh.SUPPORTED + refresh.NOT_YET)
    for key, feed in keyed.items():
        assert feed["refresh_supported"] is (key in refresh.SUPPORTED), key
    for feed in feeds:
        if "refresh" not in feed:
            assert "refresh_supported" not in feed, feed["id"]


def test_supported_refresh_sources_are_keyless(feeds):
    for feed in feeds:
        if feed.get("refresh_supported"):
            assert feed["auth"]["type"] == "none", feed["id"]


def test_catalogue_holds_no_secret_values():
    text = CATALOGUE.read_text(encoding="utf-8")
    assert not re.search(
        r"(?i)(?:key|token|secret|password)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{20,}", text
    )
