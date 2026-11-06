"""The plugin's stdlib-only store/paths.py resolves the data directory exactly as
cyberau_common.runtime does. It cannot import runtime: the plugin, update and doctor load
before the connector virtualenv exists. No network."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest
from cyberau_common import runtime

ROOT = Path(__file__).resolve().parents[2]


def _paths():
    path = ROOT / "plugins" / "cyber-au" / "store" / "paths.py"
    spec = importlib.util.spec_from_file_location("cyberau_store_paths_parity", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


PATHS = _paths()


@pytest.mark.parametrize(
    ("data_dir", "hermes_home"),
    [
        (None, None),
        (None, "{tmp}/home"),
        ("{tmp}/data", None),
        ("{tmp}/data", "{tmp}/home"),
        ("~/cyberau-data", None),
        (None, "~/hermes-home"),
        ("  ", "{tmp}/home"),
    ],
)
def test_store_paths_and_runtime_agree(tmp_path, monkeypatch, data_dir, hermes_home):
    for name, value in (("CYBERAU_DATA_DIR", data_dir), ("HERMES_HOME", hermes_home)):
        if value is None:
            monkeypatch.delenv(name, raising=False)
        else:
            monkeypatch.setenv(name, value.format(tmp=tmp_path))
    assert PATHS.data_dir() == runtime.profile_data_dir()
    configured = runtime.configured_data_dir()
    if configured is not None:
        assert PATHS.configured_data_dir() == configured


def test_store_paths_imports_only_the_standard_library():
    source = (ROOT / "plugins" / "cyber-au" / "store" / "paths.py").read_text(encoding="utf-8")
    imports = [
        line.split()[1]
        for line in source.splitlines()
        if line.startswith(("import ", "from ")) and not line.startswith("from __future__")
    ]
    assert set(imports) <= {"os", "pathlib"}


def test_profile_data_dir_keeps_cyberau_data_dir_inside_the_named_profile(tmp_path, monkeypatch):
    profile = tmp_path / "profile"
    profile.mkdir()
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(profile / "state"))
    assert PATHS.profile_data_dir(profile) == profile / "state"
    assert PATHS.foreign_data_dir(profile) is None
    monkeypatch.setenv("CYBERAU_DATA_DIR", str(tmp_path / "other" / "plugin-data" / "cyber-au"))
    assert PATHS.profile_data_dir(profile) == profile / "plugin-data" / "cyber-au"
    assert PATHS.foreign_data_dir(profile) == tmp_path / "other" / "plugin-data" / "cyber-au"
