"""Locations for the premium interface. No secret values are read here."""

from __future__ import annotations

import json
import os
from pathlib import Path


def package_root() -> Path:
    return Path(__file__).resolve().parents[2]


def finding_schema() -> dict:
    """The bundled JSON Schema for an exposure finding."""
    path = package_root() / "schema" / "exposure_finding.json"
    return json.loads(path.read_text(encoding="utf-8"))


def repo_root() -> Path:
    return Path(__file__).resolve().parents[4]


def data_dir() -> Path:
    """Profile data directory. `CYBERAU_DATA_DIR` overrides the default."""
    raw = os.environ.get("CYBERAU_DATA_DIR")
    path = Path(raw) if raw else Path("plugin-data") / "cyber-au"
    path.mkdir(parents=True, exist_ok=True)
    return path
