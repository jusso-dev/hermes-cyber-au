"""The organisation profile, ``plugin-data/cyber-au/org.yaml``.

One small, validated contract that setup writes and skills read: sector, size, regulators,
environments, the sector packs to switch on, and which connectors to enable. It holds no
secrets. Keys always go to the profile ``.env``, never here, and ``load_org`` refuses a
file that looks like it contains one.

The file lives on the profile and is never shipped. Every value in tests and examples uses
reserved names (example.com, RFC 5737 addresses).
"""

from __future__ import annotations

import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .paths import configured_data_dir

FILE_NAME = "org.yaml"
SCHEMA_VERSION = 1

SECTORS = (
    "general",
    "health",
    "education",
    "local-government",
    "state-government",
    "federal-government",
    "energy-water",
    "financial-services",
    "telecommunications",
    "transport",
    "retail",
    "other",
)
SIZES = ("small", "medium", "large")
# Turnover band matters for the ransomware payment reporting threshold (AUD 3 million).
TURNOVER = ("under-3m", "3m-or-more", "unknown")
REGULATORS = ("oaic", "apra", "soci", "asic", "aemo", "ombudsman", "none")
ENVIRONMENTS = ("it", "ot", "cloud")
SECTOR_PACKS = {
    "health": "health",
    "energy-water": "energy-water",
    "financial-services": "financial-services",
}

_SECRET_KEY = re.compile(r"(?i)(api[_-]?key|token|secret|password|passwd|auth)")
_ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]{1,63}$")


class OrgFileError(ValueError):
    """The org file cannot be used."""


@dataclass(frozen=True)
class OrgProfile:
    name: str = ""
    sector: str = "general"
    size: str = "medium"
    turnover: str = "unknown"
    regulators: tuple[str, ...] = ()
    environments: tuple[str, ...] = ("it",)
    critical_infrastructure: bool = False
    holds_personal_information: bool = True
    domains: tuple[str, ...] = ()
    brands: tuple[str, ...] = ()
    connectors: tuple[str, ...] = ()
    sector_packs: tuple[str, ...] = ()
    keys_present: tuple[str, ...] = ()
    warnings: tuple[str, ...] = field(default=(), compare=False)

    def to_dict(self) -> dict:
        data = asdict(self)
        data.pop("warnings")
        data = {k: list(v) if isinstance(v, tuple) else v for k, v in data.items()}
        return {"version": SCHEMA_VERSION, **data}

    @property
    def packs(self) -> tuple[str, ...]:
        """Sector packs to load: explicit list, else the one matching the sector."""
        if self.sector_packs:
            return self.sector_packs
        pack = SECTOR_PACKS.get(self.sector)
        return (pack,) if pack else ()


def org_path(path: str | Path | None = None) -> Path:
    if path is not None and str(path).strip():
        return Path(path).expanduser()
    base = configured_data_dir()
    if base is None:
        raise OrgFileError("set CYBERAU_DATA_DIR or HERMES_HOME, or pass --org")
    return base / FILE_NAME


def _choice(data: dict, key: str, allowed: tuple[str, ...], default: str, warnings: list) -> str:
    value = data.get(key, default)
    if value is None:
        return default
    value = str(value).strip().lower()
    if value not in allowed:
        warnings.append(f"{key}: {value!r} is not one of {', '.join(allowed)}; using {default}")
        return default
    return value


def _choices(data: dict, key: str, allowed: tuple[str, ...] | None, warnings: list) -> tuple:
    raw = data.get(key) or []
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, list):
        warnings.append(f"{key}: must be a list")
        return ()
    out: list[str] = []
    for item in raw:
        value = str(item).strip()
        if allowed is not None:
            value = value.lower()
            if value not in allowed:
                warnings.append(f"{key}: {value!r} is not one of {', '.join(allowed)}; skipped")
                continue
        if value and value not in out:
            out.append(value)
    return tuple(out)


def _check_no_secrets(data: object, where: str = "") -> None:
    if isinstance(data, dict):
        for key, value in data.items():
            if key == "keys_present":
                continue
            if _SECRET_KEY.search(str(key)) and value not in (None, "", [], False, True):
                raise OrgFileError(
                    f"org.yaml must not hold credentials ({where}{key}). Put keys in the "
                    "profile .env and list only the variable names under keys_present."
                )
            _check_no_secrets(value, f"{where}{key}.")
    elif isinstance(data, list):
        for item in data:
            _check_no_secrets(item, where)


def parse_org(data: object) -> OrgProfile:
    if data is None:
        return OrgProfile()
    if not isinstance(data, dict):
        raise OrgFileError("org.yaml must be a mapping")
    _check_no_secrets(data)
    warnings: list[str] = []
    version = data.get("version", SCHEMA_VERSION)
    if version != SCHEMA_VERSION:
        warnings.append(f"version {version!r} is not {SCHEMA_VERSION}; reading what is known")
    keys = _choices(data, "keys_present", None, warnings)
    bad_keys = [k for k in keys if not _ENV_NAME.match(k)]
    if bad_keys:
        raise OrgFileError("keys_present lists variable names only, such as NVD_API_KEY")
    return OrgProfile(
        name=str(data.get("name") or "").strip(),
        sector=_choice(data, "sector", SECTORS, "general", warnings),
        size=_choice(data, "size", SIZES, "medium", warnings),
        turnover=_choice(data, "turnover", TURNOVER, "unknown", warnings),
        regulators=tuple(
            r for r in _choices(data, "regulators", REGULATORS, warnings) if r != "none"
        ),
        environments=_choices(data, "environments", ENVIRONMENTS, warnings) or ("it",),
        critical_infrastructure=bool(data.get("critical_infrastructure", False)),
        holds_personal_information=bool(data.get("holds_personal_information", True)),
        domains=tuple(d.lower() for d in _choices(data, "domains", None, warnings)),
        brands=_choices(data, "brands", None, warnings),
        connectors=_choices(data, "connectors", None, warnings),
        sector_packs=_choices(data, "sector_packs", tuple(set(SECTOR_PACKS.values())), warnings),
        keys_present=keys,
        warnings=tuple(warnings),
    )


def load_org(path: str | Path | None = None) -> OrgProfile:
    """Read org.yaml. A missing file gives the neutral default profile."""
    import yaml

    target = org_path(path)
    if not target.exists():
        return OrgProfile(warnings=("org.yaml not found; using a sector-neutral default",))
    try:
        data = yaml.safe_load(target.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise OrgFileError("org.yaml is not valid YAML") from exc
    return parse_org(data)


def write_org(profile: OrgProfile, path: str | Path | None = None, *, force: bool = False) -> Path:
    """Write org.yaml with mode 600. Refuses to overwrite unless ``force``."""
    import yaml

    target = org_path(path)
    if (target.exists() or target.is_symlink()) and not force:
        raise OrgFileError(f"{target} already exists; pass --force to replace it")
    target.parent.mkdir(parents=True, exist_ok=True)
    text = (
        "# Organisation profile for cyber-au. Written by setup; safe to edit.\n"
        "# No credentials here. Keys belong in the profile .env.\n"
        + yaml.safe_dump(profile.to_dict(), sort_keys=False, allow_unicode=True)
    )
    temporary = target.with_name(f".{target.name}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(temporary, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)
    temporary.replace(target)
    return target
