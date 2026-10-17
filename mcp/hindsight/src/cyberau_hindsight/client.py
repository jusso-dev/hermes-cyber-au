"""Hindsight retain and recall. Reflect is not part of this slice.

The client stays off until HINDSIGHT_BASE_URL is set. The API key, when there
is one, is HINDSIGHT_API_KEY from the environment. No host and no key are
built into this package.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

import httpx
from cyberau_common import USER_AGENT
from cyberau_common.secrets import lookup, redact

from cyberau_hindsight.constants import BANKS
from cyberau_hindsight.role import may_retain, untrusted

_TRUE = {"1", "true", "yes", "on"}
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_BIDI = re.compile("[\u202a-\u202e\u2066-\u2069\u200b-\u200f]")
_TOKEN = re.compile(r"[A-Za-z0-9_.:-]{1,100}")

# Homelab LAN (RFC 1918) and Tailscale. Loopback and link-local stay refused.
_HOMELAB = tuple(
    ipaddress.ip_network(item)
    for item in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",
        "fd7a:115c:a1e0::/48",
    )
)

# Ranges Python does not already report as non-global, plus the ones the
# request-time check refuses by name: 6to4, Teredo, NAT64 and IPv4-compatible.
_EXTRA_BLOCKED = tuple(
    ipaddress.ip_network(item)
    for item in (
        "192.88.99.0/24",
        "::/96",
        "64:ff9b::/96",
        "64:ff9b:1::/48",
        "100::/64",
        "2001::/32",
        "2001:db8::/32",
        "2002::/16",
    )
)

Resolver = Callable[[str], list]


class HindsightError(Exception):
    """The Hindsight call did not complete."""


@dataclass
class HindsightClient:
    base_url: str | None
    api_key: str | None
    read_only: bool
    transport: httpx.BaseTransport | None = None
    timeout: float = 30.0
    resolver: Resolver | None = None

    def __post_init__(self) -> None:
        if self.base_url:
            self.base_url = _check_base(self.base_url)

    @classmethod
    def from_env(
        cls,
        transport: httpx.BaseTransport | None = None,
        resolver: Resolver | None = None,
    ) -> HindsightClient:
        raw = lookup("HINDSIGHT_BASE_URL")
        base = _check_base(raw) if raw else None
        flag = (lookup("HINDSIGHT_READ_ONLY") or "").lower()
        # The flag is a hint. Retain is allowed only for a role that may retain, so a
        # missing flag or a wrong role cannot turn a read-only profile into a writer.
        return cls(
            base_url=base,
            api_key=lookup("HINDSIGHT_API_KEY"),
            read_only=flag in _TRUE or not may_retain(),
            transport=transport,
            resolver=resolver,
        )

    @property
    def enabled(self) -> bool:
        return self.base_url is not None

    def retain(
        self,
        bank: str,
        content: str,
        *,
        context: str | None = None,
        document_id: str | None = None,
        metadata: dict | None = None,
        tags: list[str] | None = None,
        confirmed: bool | None = None,
    ) -> dict:
        _bank(bank)
        if not self.enabled:
            return _off()
        if self.read_only:
            return {
                "enabled": True,
                "read_only": True,
                "bank": bank,
                "retained": 0,
                "detail": "Hindsight retain is off because this profile is read-only.",
            }
        text = self._scrub(_plain(content, "content", 100_000))
        item: dict = {"content": text}
        if context:
            item["context"] = self._scrub(_plain(context, "context", 2_000))
        if document_id:
            item["document_id"] = _plain(document_id, "document_id", 200)
        meta = _metadata(metadata, confirmed)
        if meta:
            item["metadata"] = meta
        if tags:
            item["tags"] = [_plain(tag, "tag", 80) for tag in tags]
        payload = self._post(f"/v1/default/banks/{bank}/memories", {"items": [item]})
        count = payload.get("items_count")
        if (
            payload.get("success") is not True
            or isinstance(count, bool)
            or not isinstance(count, int)
            or count < 1
        ):
            raise HindsightError("Hindsight did not confirm the retain")
        return {
            "enabled": True,
            "read_only": False,
            "bank": bank,
            "retained": count,
            "detail": "retained",
        }

    def recall(self, bank: str, query: str, *, limit: int = 10) -> dict:
        _bank(bank)
        bounded = _limit(limit)
        if not self.enabled:
            return _off()
        text = self._scrub(_plain(query, "query", 1_000))
        payload = self._post(
            f"/v1/default/banks/{bank}/memories/recall",
            {"query": text, "budget": "mid", "max_tokens": 2048},
        )
        rows = payload.get("results")
        if not isinstance(rows, list):
            rows = []
        records = [self._present(bank, row) for row in rows if isinstance(row, dict)]
        return {
            "enabled": True,
            "read_only": self.read_only,
            "bank": bank,
            "records": records[:bounded],
        }

    def _post(self, path: str, body: dict) -> dict:
        if path.endswith("/reflect") or "/reflect/" in path:
            raise HindsightError("reflect is not implemented")
        if not self.base_url:
            raise HindsightError("Hindsight is off until HINDSIGHT_BASE_URL is set")
        parts = urlsplit(self.base_url)
        host = parts.hostname or ""
        # Resolve and check right before the request, then connect to the address that
        # was checked. A second lookup at connect time could answer differently.
        pinned = self._checked_address(host)
        literal = _literal(host) is not None
        netloc = f"[{pinned}]" if pinned.version == 6 else str(pinned)
        if parts.port:
            netloc = f"{netloc}:{parts.port}"
        url = urlunsplit((parts.scheme, netloc, path, "", ""))
        headers = {
            "accept": "application/json",
            "content-type": "application/json",
            "user-agent": USER_AGENT,
            "host": parts.netloc,
        }
        if self.api_key:
            headers["authorization"] = f"Bearer {self.api_key}"
        extensions = {} if literal else {"sni_hostname": host}
        try:
            with httpx.Client(
                transport=self.transport,
                follow_redirects=False,
                timeout=self.timeout,
            ) as http:
                response = http.post(url, json=body, headers=headers, extensions=extensions)
        except Exception as exc:
            raise HindsightError(self._safe(exc)) from None
        if 300 <= response.status_code < 400:
            raise HindsightError("Hindsight redirect was refused")
        if response.status_code >= 400:
            raise HindsightError(f"Hindsight returned HTTP {response.status_code}")
        try:
            payload = response.json()
        except ValueError as exc:
            raise HindsightError(self._safe(exc)) from None
        if not isinstance(payload, dict):
            raise HindsightError("Hindsight returned an unexpected payload")
        return payload

    def _present(self, bank: str, row: dict) -> dict:
        confirmed = _confirmed(row)
        trusted = bank == "org" and confirmed
        raw = row.get("text")
        if not isinstance(raw, str):
            raw = row.get("content") if isinstance(row.get("content"), str) else ""
        raw = self._scrub(raw)
        if trusted:
            text = " ".join(_BIDI.sub("", _CONTROL.sub("", raw)).split())
        else:
            text = untrusted(raw, f"hindsight:{bank}")
        return {
            "id": _token(row.get("id")),
            "text": text,
            "untrusted": not trusted,
            "confirmed": confirmed,
            "type": _token(row.get("type")),
        }

    def _checked_address(self, host: str):
        literal = _literal(host)
        try:
            found = [literal] if literal is not None else (self.resolver or _resolve)(host)
        except HindsightError:
            raise
        except Exception:
            raise HindsightError("Hindsight host did not resolve") from None
        if not found:
            raise HindsightError("Hindsight host did not resolve")
        for address in found:
            if _blocked(address):
                raise HindsightError("Hindsight host resolves to an address that is not allowed")
        return found[0]

    def _safe(self, exc: Exception) -> str:
        return self._scrub(str(exc)) or "Hindsight request failed"

    def _scrub(self, text: str) -> str:
        text = redact(text)
        if self.api_key:
            text = text.replace(self.api_key, "[REDACTED]")
        return text


def _off() -> dict:
    return {
        "enabled": False,
        "read_only": False,
        "bank": None,
        "records": [],
        "retained": 0,
        "detail": "Hindsight is off until HINDSIGHT_BASE_URL is set.",
    }


def _bank(bank: str) -> None:
    if bank not in BANKS:
        raise HindsightError("bank must be org, intel, or lessons")


def _limit(limit: int) -> int:
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise HindsightError("limit must be an integer from 1 to 50")
    if limit < 1 or limit > 50:
        raise HindsightError("limit must be an integer from 1 to 50")
    return limit


def _plain(value: str, label: str, limit: int) -> str:
    if not isinstance(value, str):
        raise HindsightError(f"{label} must be text")
    cleaned = " ".join(value.split()).strip()
    if not cleaned:
        raise HindsightError(f"{label} is empty")
    if len(cleaned) > limit:
        raise HindsightError(f"{label} is too long")
    return cleaned


def _metadata(metadata: dict | None, confirmed: bool | None) -> dict | None:
    clean: dict[str, str] = {}
    for key, value in (metadata or {}).items():
        if not isinstance(key, str) or not key.strip():
            raise HindsightError("metadata keys must be text")
        if isinstance(value, (dict, list)):
            raise HindsightError("metadata values must be plain text")
        clean[key.strip()[:40]] = str(value)[:200]
    if confirmed is True:
        clean["confirmed"] = "true"
    elif confirmed is False:
        clean["confirmed"] = "false"
    return clean or None


def _confirmed(row: dict) -> bool:
    meta = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
    flag = meta.get("confirmed")
    if flag is True or str(flag or "").strip().lower() in _TRUE:
        return True
    if str(meta.get("status") or "").strip().lower() == "confirmed":
        return True
    tags = row.get("tags") if isinstance(row.get("tags"), list) else []
    return any(str(tag).strip().lower() == "confirmed" for tag in tags)


def _token(value: object) -> str | None:
    """Ids and types come from the server. Keep them to a short plain token."""
    if isinstance(value, str) and _TOKEN.fullmatch(value):
        return value
    return None


def _literal(host: str):
    try:
        return ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return None


def _homelab(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return any(address in network for network in _HOMELAB)


def _blocked(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Refuse anything outside the public internet and the homelab ranges."""
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return True
    if _homelab(address):
        return False
    return (
        not address.is_global
        or address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
        or any(address in network for network in _EXTRA_BLOCKED)
    )


def _resolve(host: str) -> list:
    found = []
    for family, _, _, _, sockaddr in socket.getaddrinfo(host, None):
        if family in (socket.AF_INET, socket.AF_INET6):
            found.append(ipaddress.ip_address(sockaddr[0].split("%", 1)[0]))
    return found


def _check_base(url: str) -> str:
    """The server origin over https. The address is checked again on every request."""
    url = url.strip()
    parts = urlsplit(url)
    if parts.username or parts.password:
        raise HindsightError("Hindsight URL must not contain userinfo")
    if parts.query or parts.fragment or parts.path not in {"", "/"}:
        raise HindsightError("HINDSIGHT_BASE_URL must be the server origin, without a path")
    host = parts.hostname
    if not host:
        raise HindsightError("Hindsight URL has no host")
    if parts.scheme.lower() != "https":
        raise HindsightError("Hindsight URL must be https")
    literal = _literal(host)
    if literal is not None and _blocked(literal):
        raise HindsightError("Hindsight URL names an address that is not allowed")
    try:
        parts.port
    except ValueError:
        raise HindsightError("Hindsight URL has a bad port") from None
    return url.rstrip("/")
