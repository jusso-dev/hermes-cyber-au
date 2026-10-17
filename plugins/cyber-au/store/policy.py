"""Retention settings from the profile ``config.yaml``."""

from __future__ import annotations

import os
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import yaml

DEFAULT_RETENTION_DAYS = 365
_MAX_RETENTION_DAYS = 36500


def config_file() -> Path | None:
    """Profile config, else the distribution ``config.yaml`` when this is a checkout."""
    explicit = os.environ.get("CYBERAU_CONFIG")
    if explicit:
        path = Path(explicit).expanduser()
        if not path.is_file():
            raise ValueError("CYBERAU_CONFIG does not point at a file")
        return path
    home = os.environ.get("HERMES_HOME")
    if home:
        candidate = Path(home).expanduser() / "config.yaml"
        if candidate.is_file():
            return candidate
    root = distribution_root()
    if root is not None:
        candidate = root / "config.yaml"
        if candidate.is_file():
            return candidate
    return None


def distribution_root() -> Path | None:
    """Checkout root, from ``CYBERAU_HOME`` or the nearest ``distribution.yaml``."""
    env = os.environ.get("CYBERAU_HOME")
    if env:
        return Path(env).expanduser().resolve()
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "distribution.yaml").is_file():
            return parent
    return None


def load_config(path: Path | None = None) -> dict:
    found = path if path is not None else config_file()
    if found is None:
        return {}
    data = yaml.safe_load(found.read_text(encoding="utf-8"))
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError("config must be a mapping")
    return data


def retention_days(path: Path | None = None) -> int:
    """Days to keep an observation before vacuum folds it into a counter."""
    config = load_config(path)
    cyber = config.get("cyber_au") or {}
    if not isinstance(cyber, dict):
        raise ValueError("cyber_au must be a mapping")
    store = cyber.get("store") or {}
    if not isinstance(store, dict):
        raise ValueError("cyber_au.store must be a mapping")
    if "retention_days" not in store:
        return DEFAULT_RETENTION_DAYS
    return require_retention_days(store["retention_days"])


def require_retention_days(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("retention_days must be an integer from 0 to 36500")
    if value < 0 or value > _MAX_RETENTION_DAYS:
        raise ValueError("retention_days must be an integer from 0 to 36500")
    return value


def configured_zone(path: Path | None = None) -> ZoneInfo:
    """Zone used to name a daily backup. Defaults to UTC when config has none."""
    name = load_config(path).get("timezone") or "UTC"
    if not isinstance(name, str) or not name.strip():
        return ZoneInfo("UTC")
    try:
        return ZoneInfo(name.strip())
    except ZoneInfoNotFoundError as exc:
        raise ValueError("unknown timezone") from exc
