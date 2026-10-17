"""cyber-au plugin entrypoint."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _middleware():
    name = "cyberau_untrusted_middleware"
    cached = sys.modules.get(name)
    if cached is not None:
        return cached
    path = Path(__file__).resolve().parent / "middleware" / "untrusted.py"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def register(ctx) -> None:
    """Register the untrusted-feed middleware, the write guard, and org exposure."""
    _middleware().register(ctx)
    from cyberau_org_exposure.tool import SCHEMA, handle

    ctx.register_tool(
        name="cyber_au_org_exposure",
        toolset="cyber-au",
        schema=SCHEMA,
        handler=handle,
    )
