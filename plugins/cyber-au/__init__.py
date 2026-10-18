"""cyber-au plugin entrypoint.

``register(ctx)`` wires the intel store tools, evidence import, audit hooks,
the untrusted-content middleware, org exposure, and the doctor command.
"""

from __future__ import annotations

import os
import site
from pathlib import Path

from .cli import main

__all__ = ["data_dir", "main", "org_exposure", "register"]


def data_dir() -> Path:
    """Return the directory for cyber-au plugin state.

    ``CYBERAU_DATA_DIR`` overrides the path. Otherwise state lives under
    ``$HERMES_HOME/plugin-data/cyber-au``, or ``~/.hermes/plugin-data/cyber-au``
    when ``HERMES_HOME`` is unset. This function does not create the directory.
    """
    override = os.environ.get("CYBERAU_DATA_DIR", "").strip()
    if override:
        return Path(override).expanduser()
    home = os.environ.get("HERMES_HOME", "").strip()
    root = Path(home).expanduser() if home else Path.home() / ".hermes"
    return root / "plugin-data" / "cyber-au"


def _connector_packages() -> None:
    """Connector libraries are installed in the profile virtualenv."""
    profile = Path(__file__).resolve().parents[2]
    for packages in sorted(profile.glob("mcp/.venv/lib/python*/site-packages")):
        site.addsitedir(str(packages))


def org_exposure(args: dict | None = None, **_host) -> str:
    """Hermes passes tool arguments as one dict. The org exposure tool takes keywords."""
    from cyberau_org_exposure.tool import handle

    return handle(**(args or {}))


def register(ctx) -> None:
    """Register tools, hooks, middleware, and commands."""
    _connector_packages()
    from cyberau_org_exposure.tool import SCHEMA

    from .cli import register as register_doctor
    from .hooks.audit import register as register_audit
    from .middleware.untrusted import register as register_middleware
    from .tools.evidence import register_evidence
    from .tools.store import register_store

    register_store(ctx)
    register_evidence(ctx)
    register_audit(ctx)
    register_middleware(ctx)
    ctx.register_tool(
        name="cyber_au_org_exposure",
        toolset="cyber-au",
        schema=SCHEMA,
        handler=org_exposure,
    )
    register_doctor(ctx)
