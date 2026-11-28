"""Guided setup: turn answers about the organisation into org.yaml and a connector selection.

``hermes cyber-au setup`` asks the questions (or reads ``--from-file answers.yaml``), then
uses these helpers. Nothing here touches the network, and no credential value is read or
written: the profile ``.env`` is scanned for variable names with a value, and the values are
discarded on the spot. ``org.yaml`` records only names (``keys_present``).

The connector rule is conservative and matches ``install/render_config.py``:

- a connector that ``mcp/servers.yaml`` ships off (licence terms, paid, local setup) stays off;
- a connector that needs a key is on only when every required variable is named;
- every other default-on connector is on.
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from pathlib import Path

from .org import (
    ENVIRONMENTS,
    NO_PACKS,
    REGULATORS,
    SECTOR_PACKS,
    SECTORS,
    SIZES,
    TURNOVER,
    OrgFileError,
    OrgProfile,
    parse_org,
)

WATCHLIST_FILE = "watchlists.yaml"
ANSWER_KEYS = {
    "version",
    "name",
    "sector",
    "size",
    "turnover",
    "regulators",
    "environments",
    "critical_infrastructure",
    "holds_personal_information",
    "domains",
    "brands",
    "keys_present",
    "sector_packs",
}
_ASSIGNMENT = re.compile(r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$")
_PLACEHOLDER_ENV = re.compile(r"^\$\{(?:env:)?([A-Za-z_][A-Za-z0-9_]*)\}$")
_DOMAIN = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
# Runtime and connection settings, not keys a person "has".
_NOT_KEYS = {"CYBERAU_DATA_DIR", "HERMES_HOME", "CYBERAU_PROFILE_ROLE", "HINDSIGHT_READ_ONLY"}


@dataclass
class Selection:
    """Which shipped connectors setup switches on, and why the rest stay off."""

    enabled: list[str] = field(default_factory=list)
    needs_key: dict[str, list[str]] = field(default_factory=dict)
    off: dict[str, str] = field(default_factory=dict)


def env_names(env_file: Path) -> set[str]:
    """Names assigned a non-empty value in the profile .env. Values are never kept."""
    if not env_file.is_file():
        return set()
    names: set[str] = set()
    for raw in env_file.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        matched = _ASSIGNMENT.match(line)
        if matched is None:
            continue
        value = matched.group(2).strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        else:
            value = re.split(r"\s#", " " + value, maxsplit=1)[0]
        if value.strip():
            names.add(matched.group(1))
    return names


def _default_on(spec: dict) -> bool:
    return spec.get("enabled_by_default", spec.get("default_enabled", True)) is not False


def key_names(servers: dict) -> list[str]:
    """Every credential or endpoint variable a shipped connector reads, sorted."""
    names: set[str] = set()
    for spec in servers.values():
        if not isinstance(spec, dict):
            continue
        for item in spec.get("required_env") or []:
            names.add(str(item))
        for item in spec.get("env") or []:
            if isinstance(item, str) and "=" in item:
                name, _, value = item.partition("=")
                found = _PLACEHOLDER_ENV.match(value.strip())
                names.add(found.group(1) if found else name)
        token = spec.get("token_env")
        if isinstance(token, str):
            names.add(token)
    return sorted(names - _NOT_KEYS)


def select_connectors(servers: dict, keys: set[str]) -> Selection:
    selection = Selection()
    for name, spec in servers.items():
        if not isinstance(spec, dict):
            continue
        if not _default_on(spec):
            reason = spec.get("off_reason") or ("paid feed" if spec.get("paid") else "")
            selection.off[str(name)] = str(reason or "off by default")
            continue
        required = [str(item) for item in spec.get("required_env") or []]
        missing = [item for item in required if item not in keys]
        if missing:
            selection.needs_key[str(name)] = missing
            continue
        selection.enabled.append(str(name))
    return selection


def profile_from_answers(
    answers: object, *, servers: dict | None = None
) -> tuple[OrgProfile, list[str]]:
    """Validate answers with the org.yaml contract. Refuses anything that looks like a key."""
    if not isinstance(answers, dict):
        raise OrgFileError("answers must be a mapping")
    warnings = [
        f"answers: {key!r} is not a setup question; ignored"
        for key in answers
        if key not in ANSWER_KEYS
    ]
    # parse_org sees every key, so a key value under any name is refused before anything
    # is written. Unknown keys are otherwise ignored; setup sets connectors itself.
    profile = parse_org(answers)
    warnings.extend(profile.warnings)
    bad_domains = [d for d in profile.domains if not _DOMAIN.match(d) or _IPV4.match(d)]
    if bad_domains:
        warnings.append(f"domains: skipped {', '.join(bad_domains)} (not a domain name)")
        profile = replace(
            profile, domains=tuple(d for d in profile.domains if d not in bad_domains)
        )
    if servers is not None:
        known = set(key_names(servers))
        unknown = [name for name in profile.keys_present if name not in known]
        if unknown:
            warnings.append(
                f"keys_present: {', '.join(unknown)} is not read by any shipped connector"
            )
    return replace(profile, warnings=()), warnings


def finish_profile(profile: OrgProfile, servers: dict, env_set: set[str]) -> OrgProfile:
    """Merge key names found in .env and record the connector selection."""
    keys = sorted(set(profile.keys_present) | (env_set & set(key_names(servers))))
    selection = select_connectors(servers, set(keys))
    return replace(profile, keys_present=tuple(keys), connectors=tuple(selection.enabled))


# Interactive questions.

Ask = Callable[[str], str]


def _ask_choice(ask: Ask, label: str, choices: tuple[str, ...], default: str) -> str:
    while True:
        raw = ask(f"{label} [{'/'.join(choices)}] (default {default}): ").strip().lower()
        if not raw:
            return default
        if raw in choices:
            return raw
        print(f"  Choose one of: {', '.join(choices)}")


def _ask_many(ask: Ask, label: str, choices: tuple[str, ...] | None, default: str = "") -> list:
    hint = f" [{', '.join(choices)}]" if choices else ""
    shown = f" (default {default})" if default else ""
    while True:
        raw = ask(f"{label}{hint}, comma separated{shown}: ").strip() or default
        items = [item.strip() for item in raw.split(",") if item.strip()]
        if choices is None:
            return items
        lowered = [item.lower() for item in items]
        bad = [item for item in lowered if item not in choices]
        if not bad:
            return lowered
        print(f"  Not recognised: {', '.join(bad)}")


def _ask_bool(ask: Ask, label: str, default: bool) -> bool:
    shown = "Y/n" if default else "y/N"
    while True:
        raw = ask(f"{label} [{shown}]: ").strip().lower()
        if not raw:
            return default
        if raw in {"y", "yes"}:
            return True
        if raw in {"n", "no"}:
            return False
        print("  Answer y or n")


def ask_answers(ask: Ask, servers: dict, env_set: set[str]) -> dict:
    """Ask the setup questions. Key questions take variable names, never values."""
    print("cyber-au setup. Answers go to org.yaml on this profile. No key values are asked for.")
    answers: dict = {}
    answers["name"] = ask("Organisation name (optional, stays on this machine): ").strip()
    sector = _ask_choice(ask, "Sector", SECTORS, "general")
    answers["sector"] = sector
    answers["size"] = _ask_choice(ask, "Size", SIZES, "medium")
    answers["turnover"] = _ask_choice(ask, "Annual turnover band", TURNOVER, "unknown")
    answers["regulators"] = _ask_many(ask, "Regulators", REGULATORS, "none")
    answers["environments"] = _ask_many(ask, "Environments", ENVIRONMENTS, "it")
    answers["critical_infrastructure"] = _ask_bool(
        ask,
        "Responsible entity for a SOCI critical infrastructure asset?",
        "soci" in answers["regulators"] or sector == "energy-water",
    )
    answers["holds_personal_information"] = _ask_bool(ask, "Holds personal information?", True)
    answers["domains"] = _ask_many(ask, "Domains to watch", None)
    answers["brands"] = _ask_many(ask, "Brand names to watch", None)
    known = key_names(servers)
    found = sorted(env_set & set(known))
    if found:
        print(f"  Already set in the profile .env: {', '.join(found)}")
    print(f"  Key names connectors read: {', '.join(known)}")
    answers["keys_present"] = [
        name.upper() for name in _ask_many(ask, "Other key names you have (names only)", None)
    ]
    default_pack = SECTOR_PACKS.get(sector)
    hint = f"blank for {default_pack}" if default_pack else "blank for the sector default"
    answers["sector_packs"] = _ask_many(ask, f"Sector packs ({hint}, {NO_PACKS} to turn off)", None)
    return answers


# Watchlist seed.


def seed_watchlist(data_dir: Path, profile: OrgProfile) -> dict:
    """Write domains and brands to watchlists.yaml, only when no watchlist exists yet."""
    target = data_dir / WATCHLIST_FILE
    if target.exists() or target.is_symlink():
        return {"path": str(target), "created": False, "detail": "watchlist already exists"}
    if not profile.domains and not profile.brands:
        return {"path": str(target), "created": False, "detail": "no domains or brands given"}
    import yaml

    body = {}
    if profile.domains:
        body["domains"] = list(profile.domains)
    if profile.brands:
        body["brands"] = list(profile.brands)
    text = (
        "# Watchlist seeded by cyber-au setup. Yours to edit. See docs/intel/watchlists.md.\n"
        "# Watched values stay on this machine.\n" + yaml.safe_dump(body, sort_keys=False)
    )
    data_dir.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(target, flags, 0o600)
    except FileExistsError:
        return {"path": str(target), "created": False, "detail": "watchlist already exists"}
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)
    return {"path": str(target), "created": True, "detail": "seeded from setup answers"}


def summary_lines(profile: OrgProfile, selection: Selection, env_set: set[str]) -> list[str]:
    lines = [
        f"Sector {profile.sector}, size {profile.size}, turnover {profile.turnover}.",
        "Sector packs: " + (", ".join(profile.packs) or "none") + ".",
        f"Connectors on: {', '.join(selection.enabled) or 'none'}.",
    ]
    for name, missing in sorted(selection.needs_key.items()):
        lines.append(f"Off until a key is named: {name} needs {', '.join(missing)}.")
    unset = [name for name in profile.keys_present if name not in env_set]
    if unset:
        lines.append(
            f"Named but not set in the profile .env: {', '.join(unset)}. Add the values there; "
            "their connectors stay disabled until you do."
        )
    lines.append(
        f"{len(selection.off)} connectors stay off (licence terms, paid or local setup). "
        "Turn one on yourself after reading its docs page."
    )
    return lines
