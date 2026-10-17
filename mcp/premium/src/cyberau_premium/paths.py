"""Locations for the premium interface. No secret values are read here."""

from __future__ import annotations

import os
from pathlib import Path


def package_root() -> Path:
    return Path(__file__).resolve().parents[2]


def repo_root() -> Path:
    return Path(__file__).resolve().parents[4]


def data_dir() -> Path:
    """Profile data directory. `CYBERAU_DATA_DIR` overrides the default."""
    raw = os.environ.get("CYBERAU_DATA_DIR")
    path = Path(raw) if raw else Path("plugin-data") / "cyber-au"
    path.mkdir(parents=True, exist_ok=True)
    return path
