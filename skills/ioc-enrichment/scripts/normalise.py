"""Normalise one indicator. Pure helper: no network."""

from __future__ import annotations

import ipaddress
import posixpath
import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

STORE_FRESH_HOURS = 6

# Same display rules as tests/skills/harness.py defang_observable.
_HOST_RE = re.compile(r"(?i)^((?:[a-z0-9-]+\.)+[a-z]{2,})((?::\d+)?(?:[/?#].*)?)$")
_URL_RE = re.compile(r"\b(https?)://([^\s/]+)(\S*)", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
_HASH_LENGTHS = {"md5": 32, "sha1": 40, "sha256": 64}
_TIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2}Z)?$")
_TOKEN_RE = re.compile(r"^[a-z0-9]{3,}$")

_RFC1918 = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)
_DOCUMENTATION = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
)
_SHARED = ipaddress.ip_network("100.64.0.0/10")


@dataclass(frozen=True)
class Prepared:
    original: str
    normalised: str
    kind: str
    external_lookup: bool
    documentation: bool
    refusal: str | None

    def display(self) -> str:
        """Defanged form for a person. Hashes stay lowercase hex."""
        if self.kind in _HASH_LENGTHS or not self.normalised:
            return self.normalised
        return defang(self.normalised)


@dataclass(frozen=True)
class Brand:
    token: str
    domain: str


def defang(value: str) -> str:
    """Defang one observable. A second pass leaves an already defanged value unchanged."""
    text = value.strip()
    bare = _HOST_RE.fullmatch(text)
    if bare:
        return bare.group(1).replace(".", "[.]") + bare.group(2)

    def url_sub(match: re.Match[str]) -> str:
        scheme = "hxxps" if match.group(1).lower() == "https" else "hxxp"
        host = match.group(2).replace(".", "[.]")
        return f"{scheme}://{host}{match.group(3)}"

    text = _URL_RE.sub(url_sub, text)

    def email_sub(match: re.Match[str]) -> str:
        return f"{match.group(1)}[@]{match.group(2).replace('.', '[.]')}"

    text = _EMAIL_RE.sub(email_sub, text)
    return _IPV4_RE.sub(lambda match: match.group(0).replace(".", "[.]"), text)


def refang(value: str) -> str:
    """Undo hxxp, [.] / (.), [:] and [@] / [at] so a connector receives the original."""
    text = value.strip()
    text = re.sub(r"(?i)hxxps", "https", text)
    text = re.sub(r"(?i)hxxp", "http", text)
    text = re.sub(r"\[\.\]|\(\.\)", ".", text)
    text = text.replace("[:]", ":")
    text = re.sub(r"(?i)\[@\]|\[at\]|\(at\)", "@", text)
    return text


def prepare(value: str) -> Prepared:
    """Classify one indicator and decide whether an external connector may see it."""
    if not isinstance(value, str):
        raise TypeError("indicator must be a string")
    original = value.strip()
    text = refang(original)
    if not text:
        return Prepared(original, "", "unknown", False, False, "empty indicator")
    kind = _hash_kind(text)
    if kind:
        return Prepared(original, text.lower(), kind, True, False, None)
    if "://" in text:
        return _with_original(_from_url(text), original)
    if text.count("@") == 1 and not text.startswith("@"):
        return _with_original(_from_email(text), original)
    if _looks_like_ip(text):
        return _with_original(_from_ip(text), original)
    return _with_original(_from_domain(text), original)


def load_brands(path: Path | None = None) -> tuple[Brand, ...]:
    """Load the heuristic bank-domain list. Domains in the file are defanged."""
    file = path or _brands_path()
    brands: list[Brand] = []
    for number, line in enumerate(
        file.read_text(encoding="utf-8").splitlines(), start=1
    ):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        if len(parts) != 2:
            raise ValueError(f"{file}:{number}: expected a token and a domain")
        token = parts[0].lower()
        if not _TOKEN_RE.fullmatch(token):
            raise ValueError(
                f"{file}:{number}: token must be at least 3 letters or digits"
            )
        prepared = prepare(parts[1])
        if prepared.kind != "domain":
            raise ValueError(f"{file}:{number}: {parts[1]} is not a domain")
        brands.append(Brand(token, prepared.normalised))
    if not brands:
        raise ValueError(f"{file}: no brands")
    return tuple(brands)


def lookalike_tokens(
    domain: str, brands: Sequence[Brand] | None = None
) -> tuple[str, ...]:
    """Brand tokens in a domain that is not one of the owned names or their subdomains."""
    prepared = prepare(domain)
    if prepared.kind != "domain":
        return ()
    chosen = tuple(brands) if brands is not None else load_brands()
    name = prepared.normalised
    if any(
        name == brand.domain or name.endswith("." + brand.domain) for brand in chosen
    ):
        return ()
    parts: set[str] = set()
    for label in name.split("."):
        parts.update(piece for piece in label.split("-") if piece)
    return tuple(sorted({brand.token for brand in chosen if brand.token in parts}))


def skip_external(last_seen: str | None, now: str, *, refresh: bool) -> bool:
    """True when a store row is fresh and the analyst did not ask to refresh."""
    if refresh or not last_seen:
        return False
    return within_hours(last_seen, now)


def within_hours(last_seen: str, now: str, hours: int = STORE_FRESH_HOURS) -> bool:
    """True when last_seen is at or before now and no more than `hours` earlier, in UTC."""
    if hours < 0:
        raise ValueError("hours must be >= 0")
    seen = _parse_time(last_seen)
    current = _parse_time(now)
    if seen > current:
        return False
    return current - seen <= timedelta(hours=hours)


def _brands_path() -> Path:
    return Path(__file__).resolve().parent.parent / "references" / "au-bank-domains.txt"


def _with_original(prepared: Prepared, original: str) -> Prepared:
    return Prepared(
        original,
        prepared.normalised,
        prepared.kind,
        prepared.external_lookup,
        prepared.documentation,
        prepared.refusal,
    )


def _hash_kind(text: str) -> str | None:
    lowered = text.lower()
    if not re.fullmatch(r"[0-9a-f]+", lowered):
        return None
    for kind, length in _HASH_LENGTHS.items():
        if len(lowered) == length:
            return kind
    return None


def _looks_like_ip(text: str) -> bool:
    candidate = text[1:-1] if text.startswith("[") and text.endswith("]") else text
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        if re.fullmatch(r"[0-9.]+", candidate) and candidate.count(".") == 3:
            return True
        return (
            ":" in candidate and re.fullmatch(r"[0-9A-Fa-f:.%]+", candidate) is not None
        )
    return True


def _from_ip(text: str) -> Prepared:
    candidate = text[1:-1] if text.startswith("[") and text.endswith("]") else text
    try:
        ip = ipaddress.ip_address(candidate)
    except ValueError:
        kind = "ipv6" if ":" in candidate else "ipv4"
        return Prepared(text, text, kind, False, False, "invalid address")
    mapped = ip.ipv4_mapped if isinstance(ip, ipaddress.IPv6Address) else None
    if mapped is not None:
        return Prepared(
            text, ip.compressed, "ipv6", False, False, "IPv4-mapped address"
        )
    allowed, documentation, refusal = _policy(ip)
    normalised = str(ip) if ip.version == 4 else ip.compressed
    kind = "ipv4" if ip.version == 4 else "ipv6"
    return Prepared(text, normalised, kind, allowed, documentation, refusal)


def _policy(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> tuple[bool, bool, str | None]:
    """Return external_lookup, documentation, refusal.

    Documentation prefixes are flagged private by Python's ipaddress module.
    Check them before the private fallback so a fixture address can be labelled
    and looked up. Every other non-global address is refused.
    """
    if ip.is_unspecified:
        return False, False, "unspecified address"
    if ip.is_loopback:
        return False, False, "loopback"
    if ip.is_link_local:
        return False, False, "link-local address"
    if ip.is_multicast:
        return False, False, "multicast address"
    if _in_networks(ip, _DOCUMENTATION):
        return True, True, None
    if _in_networks(ip, _RFC1918) or (ip.version == 6 and ip.is_private):
        return False, False, "private address"
    if ip.version == 4 and ip in _SHARED:
        return False, False, "shared address"
    if ip.is_reserved or ip.is_private or not ip.is_global:
        return False, False, "reserved address"
    return True, False, None


def _in_networks(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...],
) -> bool:
    return any(network.version == ip.version and ip in network for network in networks)


def _from_email(text: str) -> Prepared:
    local, _, domain = text.rpartition("@")
    if not local or not domain or " " in local:
        return Prepared(text, text, "unknown", False, False, "invalid address")
    try:
        normalised_domain = domain.rstrip(".").lower().encode("idna").decode("ascii")
    except UnicodeError:
        return Prepared(text, text, "unknown", False, False, "invalid domain")
    return Prepared(
        text,
        f"{local}@{normalised_domain}",
        "email",
        False,
        False,
        "email addresses are out of scope for these connectors",
    )


def _from_url(text: str) -> Prepared:
    try:
        parts = urlsplit(text)
        host = parts.hostname
        port = parts.port
    except ValueError:
        return Prepared(text, text, "unknown", False, False, "invalid URL")
    if parts.scheme.lower() not in {"http", "https"} or not host:
        return Prepared(text, text, "unknown", False, False, "invalid URL")
    allowed = True
    documentation = False
    refusal = None
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return Prepared(text, text, "url", False, False, "IPv4-mapped address")
    if ip is not None:
        allowed, documentation, refusal = _policy(ip)
        host_text = f"[{ip.compressed}]" if ip.version == 6 else str(ip)
    else:
        try:
            host_text = host.rstrip(".").encode("idna").decode("ascii")
        except UnicodeError:
            return Prepared(text, text, "unknown", False, False, "invalid domain")
    scheme = parts.scheme.lower()
    default_port = (scheme == "https" and port == 443) or (
        scheme == "http" and port == 80
    )
    netloc = host_text if port is None or default_port else f"{host_text}:{port}"
    path = _normalise_path(parts.path)
    normalised = urlunsplit((scheme, netloc, path, parts.query, ""))
    return Prepared(text, normalised, "url", allowed, documentation, refusal)


def _normalise_path(path: str) -> str:
    if not path:
        return ""
    keep_slash = path.endswith("/") and path != "/"
    normalised = posixpath.normpath(path)
    if not normalised.startswith("/"):
        normalised = "/" + normalised
    if keep_slash and not normalised.endswith("/"):
        normalised += "/"
    return "" if normalised == "/." else normalised


def _from_domain(text: str) -> Prepared:
    candidate = text.rstrip(".").lower()
    if not candidate or any(mark in candidate for mark in ("*", " ", "/")):
        return Prepared(text, text, "unknown", False, False, "invalid domain")
    try:
        normalised = candidate.encode("idna").decode("ascii")
    except UnicodeError:
        return Prepared(text, text, "unknown", False, False, "invalid domain")
    if len(normalised) > 253 or not _DOMAIN_RE.fullmatch(normalised):
        return Prepared(text, text, "unknown", False, False, "invalid domain")
    return Prepared(text, normalised, "domain", True, False, None)


def _parse_time(value: str) -> datetime:
    if not _TIME_RE.fullmatch(value):
        raise ValueError(f"time must be YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ: {value}")
    if "T" not in value:
        value = f"{value}T00:00:00Z"
    return datetime.fromisoformat(value)
