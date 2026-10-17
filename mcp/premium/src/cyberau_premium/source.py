"""Status tool for the shared premium interface. It does not call a vendor."""

from __future__ import annotations

from cyberau_common.secrets import lookup
from cyberau_common.server import Connector, ToolSpec, register_connector

from cyberau_premium.catalog import load_vendors


def premium_status() -> dict:
    rows = []
    for spec in load_vendors():
        if not spec.licence_env:
            key_state = "not required"
        elif any(lookup(name) is None for name in spec.licence_env):
            key_state = "missing"
        else:
            key_state = "present"
        rows.append(
            {
                "server": spec.server,
                "paid": spec.paid,
                "default_enabled": False,
                "key": key_state,
            }
        )
    return {"vendors": rows}


def connector() -> Connector:
    return Connector(
        key="premium",
        server_name="premium",
        attribution=(
            "Premium feeds stay off until you enable a licence you already hold. "
            "No vendor is called from this status tool."
        ),
        tools=[
            ToolSpec(
                name="premium_status",
                description="List premium feeds and whether each one is still off by default.",
                fn=premium_status,
                open_world=False,
            )
        ],
    )


register_connector("premium", connector)
