"""GitHub Advisory Database through the pinned GitHub MCP server."""

from dataclasses import dataclass

from cyberau_common.server import Connector, Probe, register_connector

from . import wrap


@dataclass
class WrapConnector(Connector):
    """A wrap serves no tools of its own. It exists for the shared health command."""

    def health(self, *, live: bool, check_schema: bool = False) -> Probe:
        return wrap.health(live=live, check_schema=check_schema)


def connector() -> Connector:
    return WrapConnector(key=wrap.KEY, server_name=wrap.SERVER, attribution=wrap.ATTRIBUTION)


register_connector(wrap.KEY, connector)

__all__ = ["connector", "wrap"]
