"""Locations for the premium interface. No secret values are read here."""

from __future__ import annotations

import json
from pathlib import Path

from cyberau_common import runtime


def package_root() -> Path:
    return Path(__file__).resolve().parents[2]


def finding_schema() -> dict:
    """The bundled JSON Schema for an exposure finding."""
    path = package_root() / "schema" / "exposure_finding.json"
    return json.loads(path.read_text(encoding="utf-8"))


def repo_root() -> Path:
    return Path(__file__).resolve().parents[4]


def data_dir() -> Path:
    """State for the premium connectors: budget ledger, terms audit, caches and stores.
    The profile sets CYBERAU_DATA_DIR; without it this is /tmp/cyberau-premium, like every
    other connector's fallback, never a directory relative to the working directory."""
    return runtime.data_dir("premium")
