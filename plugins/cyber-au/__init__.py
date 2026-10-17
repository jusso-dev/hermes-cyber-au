"""Register the AU org exposure tool with Hermes."""

from __future__ import annotations

from cyberau_org_exposure.tool import SCHEMA, handle


def register(ctx) -> None:
    ctx.register_tool(
        name="cyber_au_org_exposure",
        toolset="cyber-au",
        schema=SCHEMA,
        handler=handle,
    )
