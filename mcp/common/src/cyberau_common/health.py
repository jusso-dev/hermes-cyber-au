"""Connector health probes."""

from __future__ import annotations

from cyberau_common.server import Probe, get_connector


def run_health(name: str, *, live: bool) -> Probe:
    try:
        connector = get_connector(name)
    except KeyError:
        return Probe(name, False, "unknown connector")
    return connector.health(live=live)
