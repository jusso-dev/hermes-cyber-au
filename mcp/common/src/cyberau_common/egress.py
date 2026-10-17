"""Egress allowlist. Connectors can only reach hosts listed for them."""

from __future__ import annotations

import ipaddress
import socket
from pathlib import Path
from urllib.parse import urlsplit

import idna
import yaml

_PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(item)
    for item in (
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
        "::/128",
        "::1/128",
        "64:ff9b::/96",
        "2001:db8::/32",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    )
)


class EgressDenied(Exception):
    """Raised when a URL is outside the connector allowlist."""


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
        spec = _load(allowlist_path).get(connector) or {}
        self.hosts = {_normalise_host(host) for host in spec.get("hosts", [])}
        self.allow_ip_literals = bool(spec.get("allow_ip_literals", False))
        self.allow_http_loopback = bool(spec.get("allow_http_loopback", False))

    def check(self, url: str) -> None:
        parts = urlsplit(url)
        if parts.username or parts.password:
            raise EgressDenied("URLs must not contain userinfo")
        scheme = parts.scheme.lower()
        host = parts.hostname
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
        normalised = literal.compressed if literal is not None else _normalise_host(host)
        if normalised not in self.hosts and not (
            loopback and self.allow_http_loopback and scheme == "http"
        ):
            raise EgressDenied(f"host {normalised} is not allowlisted for {self.connector}")
        addresses = [literal] if literal is not None else self._resolver(host)
        if not addresses:
            raise EgressDenied(f"host {host} did not resolve")
        for address in addresses:
            if address.is_loopback and self.allow_http_loopback:
                continue
            if _is_blocked_ip(address):
                raise EgressDenied(f"host {host} resolves to a blocked address")


def _load(path: Path) -> dict:
    if not path.is_file():
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    connectors = data.get("connectors", {})
    if connectors is None:
        connectors = {}
    if not isinstance(connectors, dict):
        raise EgressDenied("egress allowlist connectors must be a mapping")
    return connectors


def _normalise_host(host: str) -> str:
    text = host.strip().rstrip(".").lower()
    try:
        return idna.encode(text).decode("ascii")
    except idna.IDNAError as exc:
        raise EgressDenied(f"host {host!r} is not valid") from exc


def _ip_literal(host: str):
    try:
        return ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return None


def _is_loopback_name(host: str, literal) -> bool:
    if host.lower().rstrip(".") == "localhost":
        return True
    return literal is not None and literal.is_loopback


def _is_blocked_ip(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(address, ipaddress.IPv6Address):
        embedded = address.ipv4_mapped or address.sixtofour
        if embedded is not None:
            return _is_blocked_ip(embedded)
    return any(address in network for network in _PRIVATE_NETWORKS)


def _resolve(host: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    found: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for family, _, _, _, sockaddr in socket.getaddrinfo(host, None):
        if family not in (socket.AF_INET, socket.AF_INET6):
            continue
        found.append(ipaddress.ip_address(sockaddr[0]))
    return found
