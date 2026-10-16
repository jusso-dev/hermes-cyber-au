"""In-library connector used to prove server startup. It does not call the network."""

from __future__ import annotations

from cyberau_common.server import Connector, ToolSpec, register_connector


def stub_ping(echo: str = "ok") -> dict:
    return {"echo": echo}


def connector() -> Connector:
    return Connector(
        key="stub",
        server_name="stub",
        attribution="hermes-cyber-au stub. No upstream data.",
        tools=[
            ToolSpec(
                name="stub_ping",
                description="Return the echo text. This tool does not use the network.",
                fn=stub_ping,
                open_world=False,
            )
        ],
    )


register_connector("stub", connector)
