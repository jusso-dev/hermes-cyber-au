"""Egress allowlist. Connectors can only reach hosts listed for them.

The policy resolves a hostname and refuses private or scoped addresses
before the HTTP request is sent. The HTTP client resolves that hostname
again when it opens the connection. Those two lookups are independent.
The private and scoped checks still run before every request, including
each redirect, and they are not relaxed because of that gap.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from pathlib import Path
from urllib.parse import unquote, urlsplit

import idna
import yaml

# Floor that code always applies. A shorter list in the allowlist file does
# not remove any of these. CI also rejects a file that drops one.
FLOOR_CIDRS: tuple[str, ...] = (
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "255.255.255.255/32",
    "::/128",
    "::1/128",
    "::ffff:0:0/96",
    "64:ff9b::/96",
    "64:ff9b:1::/48",
    "2001:db8::/32",
    "2002::/16",
    "fc00::/7",
    "fe80::/10",
    "fec0::/10",
    "ff00::/8",
)

FLOOR_NETWORKS = tuple(ipaddress.ip_network(item) for item in FLOOR_CIDRS)

_LOG = logging.getLogger("cyberau.egress")


class EgressDenied(Exception):
    """Raised when a URL is outside the connector allowlist."""


class EgressUnresolved(EgressDenied):
    """Raised when a listed host has no usable DNS answer. The request fails closed."""


class EgressPolicy:
    def __init__(
        self,
        allowlist_path: Path,
        connector: str,
        *,
        resolver=None,
    ):
        self.connector = connector
        self._resolver = resolver or _resolve
        spec, extra_networks = _load(allowlist_path, connector)
        hosts = spec.get("hosts") or []
        if not isinstance(hosts, list):
            raise EgressDenied("connector hosts must be a list")
        self.hosts = {normalise_host(str(host)) for host in hosts}
        self.allow_ip_literals = bool(spec.get("allow_ip_literals", False))
        self.allow_http_loopback = bool(spec.get("allow_http_loopback", False))
        self._networks = _merge_networks(extra_networks)

    def check(self, url: str, *, resolve: bool = True) -> None:
        """Refuse a URL. ``resolve=False`` skips DNS, for a call that sends nothing."""
        try:
            self._check(url, resolve)
        except EgressDenied as exc:
            _LOG.warning("egress refused for %s: %s", self.connector, exc)
            raise

    def _check(self, url: str, resolve: bool) -> None:
        parts = urlsplit(url)
        if parts.username or parts.password:
            raise EgressDenied("URLs must not contain userinfo")
        scheme = parts.scheme.lower()
        host = _hostname(parts)
        if not host:
            raise EgressDenied("URL has no host")
        literal = _ip_literal(host)
        loopback = _is_loopback_name(host, literal)
        if scheme == "http":
            if not (self.allow_http_loopback and loopback):
                raise EgressDenied("only https is allowed")
        elif scheme != "https":
            raise EgressDenied("only https is allowed")
        if literal is not None and not self.allow_ip_literals:
            raise EgressDenied("IP literals are not allowed for this connector")
        normalised = literal.compressed if literal is not None else normalise_host(host)
        if normalised not in self.hosts and not (
            loopback and self.allow_http_loopback and scheme == "http"
        ):
            raise EgressDenied(f"host {normalised} is not allowlisted for {self.connector}")
        if not resolve:
            return
        # This lookup is only the pre-request check. The HTTP client resolves
        # the name again when it connects.
        addresses = [literal] if literal is not None else self._resolver(host)
        if not addresses:
            raise EgressUnresolved(f"host {host} did not resolve")
        for address in addresses:
            if address.is_loopback and loopback and scheme == "http" and self.allow_http_loopback:
                continue
            if _is_blocked_ip(address, self._networks):
                raise EgressDenied(f"host {host} resolves to a blocked address")


def normalise_host(host: str) -> str:
    text = host.strip().rstrip(".").lower()
    if not text:
        raise EgressDenied("host is empty")
    literal = _ip_literal(text)
    if literal is not None:
        return literal.compressed
    try:
        return idna.encode(text).decode("ascii")
    except idna.IDNAError as exc:
        raise EgressDenied(f"host {host!r} is not valid") from exc


def _load(path: Path, connector: str) -> tuple[dict, tuple]:
    if not path.is_file():
        return {}, ()
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise EgressDenied("egress allowlist must be a mapping")
    version = data.get("version", 1)
    if version != 1:
        raise EgressDenied("egress allowlist version must be 1")
    connectors = data.get("connectors", {})
    if connectors is None:
        connectors = {}
    if not isinstance(connectors, dict):
        raise EgressDenied("egress allowlist connectors must be a mapping")
    spec = _connector_spec(connectors.get(connector) or {})
    return spec, _extra_networks(data.get("global_deny_cidrs") or [])


def _connector_spec(value) -> dict:
    if isinstance(value, list):
        return {"hosts": value}
    if isinstance(value, dict):
        return value
    raise EgressDenied("egress allowlist connector entry must be a mapping or a host list")


def _extra_networks(raw) -> tuple:
    if not isinstance(raw, list):
        raise EgressDenied("global_deny_cidrs must be a list")
    found = []
    for item in raw:
        try:
            found.append(ipaddress.ip_network(str(item), strict=False))
        except ValueError as exc:
            raise EgressDenied(f"invalid deny network {item!r}") from exc
    return tuple(found)


def _merge_networks(extra: tuple) -> tuple:
    merged = []
    seen = set()
    for network in (*FLOOR_NETWORKS, *extra):
        if network not in seen:
            seen.add(network)
            merged.append(network)
    return tuple(merged)


def _hostname(parts) -> str | None:
    host = parts.hostname
    if not host:
        return None
    return unquote(host)


def _ip_literal(host: str):
    try:
        return ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return None


def _is_loopback_name(host: str, literal) -> bool:
    if host.lower().rstrip(".") == "localhost":
        return True
    return literal is not None and literal.is_loopback


def _is_blocked_ip(address: ipaddress.IPv4Address | ipaddress.IPv6Address, networks) -> bool:
    # IPv4-mapped addresses are refused outright. An IPv4 network test does
    # not apply to the IPv6 form, so the mapped address is not given a pass.
    if getattr(address, "ipv4_mapped", None) is not None:
        return True
    embedded = getattr(address, "sixtofour", None)
    if embedded is not None:
        return _is_blocked_ip(embedded, networks)
    if any(address in network for network in networks):
        return True
    if (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
        or getattr(address, "is_site_local", False)
    ):
        return True
    return False


def _resolve(host: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    found: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    try:
        answers = socket.getaddrinfo(host, None)
    except OSError as exc:
        raise EgressUnresolved(f"host {host} did not resolve") from exc
    for family, _, _, _, sockaddr in answers:
        if family not in (socket.AF_INET, socket.AF_INET6):
            continue
        found.append(ipaddress.ip_address(sockaddr[0]))
    return found
