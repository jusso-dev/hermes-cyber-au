"""Put the intel store on the import path for pytest and spawned writers."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

PLUGIN = Path(__file__).resolve().parents[2] / "plugins" / "cyber-au"
plugin = str(PLUGIN)
if plugin not in sys.path:
    sys.path.insert(0, plugin)

current = os.environ.get("PYTHONPATH", "")
parts = [part for part in current.split(os.pathsep) if part]
if plugin not in parts:
    os.environ["PYTHONPATH"] = os.pathsep.join([plugin, *parts])


@pytest.fixture
def store_path(tmp_path, monkeypatch):
    path = tmp_path / "intel.sqlite"
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path))
    yield path
    from store.db import close_store

    close_store(path)
    close_store()
