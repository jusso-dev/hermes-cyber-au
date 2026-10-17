"""Connector health probes."""

from __future__ import annotations

from cyberau_common.server import Probe, get_connector
from cyberau_common.wrap import find_wrap, run_wrap_health


def run_health(name: str, *, live: bool, check_schema: bool = False) -> Probe:
    try:
        find_wrap(name)
    except KeyError:
        pass
    else:
        return run_wrap_health(name, live=live, check_schema=check_schema)
    try:
        connector = get_connector(name)
    except KeyError:
        return Probe(name, False, "unknown connector")
    return connector.health(live=live, check_schema=check_schema)
