"""Run cyber-au doctor from this directory."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _load():
    name = "cyber_au_plugin"
    loaded = sys.modules.get(name)
    if loaded is not None and hasattr(loaded, "main"):
        return loaded
    directory = Path(__file__).resolve().parent
    spec = importlib.util.spec_from_file_location(
        name,
        directory / "__init__.py",
        submodule_search_locations=[str(directory)],
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cyber-au plugin could not be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


if __name__ == "__main__":
    raise SystemExit(_load().main(sys.argv[1:]))
