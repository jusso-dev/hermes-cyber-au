"""Canonical indicator values and STIX SCO identifiers.

Dedupe key is ``(type, value_norm)``. Refang replaces ``hxxp``, ``[.]``,
``(.)``, ``[:]`` and ``[at]``. Domain names use IDNA 2008 via the ``idna``
package. URLs follow RFC 3986: lowercase scheme and host, drop the default
port, remove dot segments, keep query order, drop the fragment.

Indicator ids are STIX 2.1 SCO ids. The UUID is UUIDv5 over the ID
contributing properties, serialised as JSON with sorted keys and no
insignificant whitespace (RFC 8785 for the ASCII values this store emits).
The namespace is ``00abedb4-aa42-466c-9c01-fed23315a9b7`` except for ``cidr``,
which is not a STIX SCO and uses a namespace derived from that value.
"""

from __future__ import annotations

import ipaddress
import json
import re
import uuid
from datetime import UTC, datetime
from urllib.parse import quote, urlsplit, urlunsplit

import idna

INDICATOR_TYPES = (
    "ipv4",
    "ipv6",
    "domain",
    "url",
    "email",
    "md5",
    "sha1",
    "sha256",
    "asn",
    "cidr",
)
HASH_LENGTHS = {"md5": 32, "sha1": 40, "sha256": 64}
HASH_NAMES = {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256"}
SCO_TYPES = {
    "ipv4": "ipv4-addr",
    "ipv6": "ipv6-addr",
    "domain": "domain-name",
    "url": "url",
    "email": "email-addr",
    "asn": "autonomous-system",
    "cidr": "x-cyberau-cidr",
}
STIX_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")
CIDR_NAMESPACE = uuid.uuid5(STIX_NAMESPACE, "x-cyberau-cidr")
TLP_RANK = {
    "CLEAR": 0,
    "GREEN": 1,
    "AMBER": 2,
    "AMBER+STRICT": 3,
    "RED": 4,
}
EXPORT_DEFAULT_TLP = "GREEN"
_SOURCE_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_HEX = re.compile(r"^[0-9a-f]+$")
_IPV4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_CVE = re.compile(r"^CVE-\d{4}-\d{4,16}$")
_HXXP = re.compile(r"hxxp", re.IGNORECASE)
_AT = re.compile(r"\[at\]", re.IGNORECASE)
_ASCII_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


def refang(value: str) -> str:
    """Undo the defang spellings listed on the store ticket."""
    text = _HXXP.sub("http", value)
    text = text.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")
    return _AT.sub("@", text)


def canonical_value(indicator_type: str, value: str) -> str:
    """Return the dedupe form of one indicator value."""
    if indicator_type not in INDICATOR_TYPES:
        raise ValueError("unknown indicator type")
    if not isinstance(value, str) or not value.strip():
        raise ValueError("indicator value is empty")
    return _CANONICAL[indicator_type](value)


def canonical_timestamp(value: str) -> str:
    """Normalise an ISO 8601 timestamp to UTC ``YYYY-MM-DDTHH:MM:SSZ``."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("timestamp is empty")
    text = value.strip()
    if _DATE.fullmatch(text):
        return f"{text}T00:00:00Z"
    parsed = text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text
    try:
        moment = datetime.fromisoformat(parsed)
    except ValueError as exc:
        raise ValueError("invalid timestamp") from exc
    if moment.tzinfo is None:
        raise ValueError("timestamp needs a timezone")
    moment = moment.astimezone(UTC).replace(microsecond=0)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def canonical_date(value: str | None) -> str | None:
    """Validate a calendar date. ``None`` stays ``None``."""
    if value is None:
        return None
    if not isinstance(value, str) or not _DATE.fullmatch(value):
        raise ValueError("invalid date")
    try:
        datetime.strptime(value, "%Y-%m-%d")
    except ValueError as exc:
        raise ValueError("invalid date") from exc
    return value


def canonical_cve(value: str) -> str:
    text = value.strip().upper()
    if not _CVE.fullmatch(text):
        raise ValueError(f"invalid CVE id: {value.strip()[:32]}")
    return text


def require_tlp(value: str) -> str:
    if value not in TLP_RANK:
        raise ValueError("tlp must be CLEAR, GREEN, AMBER, AMBER+STRICT or RED")
    return value


def more_restrictive(left: str, right: str) -> str:
    """Return the more restrictive of two TLP 2.0 markings."""
    require_tlp(left)
    require_tlp(right)
    return left if TLP_RANK[left] >= TLP_RANK[right] else right


def tlp_allows(marking: str, ceiling: str) -> bool:
    """True when ``marking`` is at or below ``ceiling``."""
    return TLP_RANK[require_tlp(marking)] <= TLP_RANK[require_tlp(ceiling)]


def require_source_id(value: str) -> str:
    if not isinstance(value, str) or not _SOURCE_ID.fullmatch(value):
        raise ValueError("invalid source id")
    return value


def indicator_id(indicator_type: str, value_norm: str) -> str:
    """Deterministic STIX SCO id for a canonical indicator value."""
    if indicator_type in HASH_NAMES:
        sco_type = "file"
        properties: dict = {"hashes": {HASH_NAMES[indicator_type]: value_norm}}
        namespace = STIX_NAMESPACE
    elif indicator_type == "asn":
        sco_type = "autonomous-system"
        properties = {"number": int(value_norm.removeprefix("AS"))}
        namespace = STIX_NAMESPACE
    elif indicator_type == "cidr":
        sco_type = "x-cyberau-cidr"
        properties = {"value": value_norm}
        namespace = CIDR_NAMESPACE
    else:
        sco_type = SCO_TYPES[indicator_type]
        properties = {"value": value_norm}
        namespace = STIX_NAMESPACE
    name = json.dumps(properties, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return f"{sco_type}--{uuid.uuid5(namespace, name)}"


def utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def remove_dot_segments(path: str) -> str:
    """RFC 3986 section 5.2.4."""
    output: list[str] = []
    remaining = path
    while remaining:
        if remaining.startswith("../"):
            remaining = remaining[3:]
        elif remaining.startswith("./"):
            remaining = remaining[2:]
        elif remaining.startswith("/./"):
            remaining = "/" + remaining[3:]
        elif remaining == "/.":
            remaining = "/"
        elif remaining.startswith("/../"):
            remaining = "/" + remaining[4:]
            if output:
                output.pop()
        elif remaining == "/..":
            remaining = "/"
            if output:
                output.pop()
        elif remaining in {".", ".."}:
            remaining = ""
        else:
            start = 1 if remaining.startswith("/") else 0
            slash = remaining.find("/", start)
            if slash == -1:
                output.append(remaining)
                remaining = ""
            else:
                output.append(remaining[:slash])
                remaining = remaining[slash:]
    return "".join(output)


def _canonical_ipv4(value: str) -> str:
    text = refang(value).strip()
    if not _IPV4.fullmatch(text):
        raise ValueError("invalid ipv4")
    _reject_leading_zeros(text)
    try:
        address = ipaddress.IPv4Address(text)
    except ipaddress.AddressValueError as exc:
        raise ValueError("invalid ipv4") from exc
    return str(address)


def _canonical_ipv6(value: str) -> str:
    text = refang(value).strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    try:
        address = ipaddress.IPv6Address(text)
    except ipaddress.AddressValueError as exc:
        raise ValueError("invalid ipv6") from exc
    return address.compressed


def _canonical_domain(value: str) -> str:
    text = refang(value).strip().lower()
    if text.endswith("."):
        text = text[:-1]
    if not text or any(char in text for char in "/?#@: "):
        raise ValueError("invalid domain")
    if _simple_ascii_domain(text):
        return text
    try:
        encoded = idna.encode(text, uts46=False).decode("ascii")
    except idna.IDNAError as exc:
        raise ValueError("invalid domain") from exc
    if len(encoded) > 253 or not encoded:
        raise ValueError("invalid domain")
    return encoded


def _simple_ascii_domain(text: str) -> bool:
    """True when IDNA 2008 leaves an ASCII domain unchanged.

    Labels with ``--`` stay on the idna path so punycode is still checked.
    """
    if len(text) > 253 or not text.isascii() or "--" in text:
        return False
    return all(_ASCII_LABEL.fullmatch(label) for label in text.split("."))


def _canonical_url(value: str) -> str:
    text = refang(value).strip()
    if not text or any(char.isspace() for char in text) or "\\" in text:
        raise ValueError("invalid url")
    try:
        parts = urlsplit(text)
        host = parts.hostname
        port = parts.port
    except ValueError as exc:
        raise ValueError("invalid url") from exc
    scheme = parts.scheme.lower()
    if scheme not in {"http", "https"} or not host:
        raise ValueError("invalid url")
    try:
        normalised_host = _canonical_host(host)
    except ValueError as exc:
        raise ValueError("invalid url") from exc
    netloc = _netloc(normalised_host, port, parts.username, parts.password, scheme)
    path = remove_dot_segments(parts.path)
    return urlunsplit((scheme, netloc, path, parts.query, ""))


def _canonical_email(value: str) -> str:
    text = refang(value).strip()
    if text.count("@") != 1:
        raise ValueError("invalid email")
    local, domain = text.split("@", 1)
    if not local or any(char.isspace() for char in local):
        raise ValueError("invalid email")
    try:
        normalised = _canonical_domain(domain)
    except ValueError as exc:
        raise ValueError("invalid email") from exc
    return f"{local}@{normalised}"


def _canonical_hash(kind: str, value: str) -> str:
    text = value.strip().lower()
    if not _HEX.fullmatch(text) or len(text) != HASH_LENGTHS[kind]:
        raise ValueError(f"invalid {kind}")
    return text


def _canonical_asn(value: str) -> str:
    text = refang(value).strip().upper()
    if text.startswith("AS"):
        text = text[2:]
    if not text.isdigit() or (len(text) > 1 and text.startswith("0")):
        raise ValueError("invalid asn")
    number = int(text)
    if number > 4_294_967_295:
        raise ValueError("invalid asn")
    return f"AS{number}"


def _canonical_cidr(value: str) -> str:
    text = refang(value).strip()
    if "/" not in text:
        raise ValueError("invalid cidr")
    address, _prefix = text.split("/", 1)
    if _IPV4.fullmatch(address):
        _reject_leading_zeros(address)
    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError as exc:
        raise ValueError("invalid cidr") from exc
    return str(network)


def _canonical_host(host: str) -> str:
    if _IPV4.fullmatch(host):
        return _canonical_ipv4(host)
    if ":" in host:
        return _canonical_ipv6(host)
    return _canonical_domain(host)


def _netloc(
    host: str,
    port: int | None,
    username: str | None,
    password: str | None,
    scheme: str,
) -> str:
    default = 80 if scheme == "http" else 443
    host_part = f"[{host}]" if ":" in host else host
    auth = ""
    if username is not None:
        user = quote(username, safe="")
        auth = f"{user}:{quote(password, safe='')}" if password is not None else user
        auth += "@"
    if port is None or port == default:
        return auth + host_part
    return f"{auth}{host_part}:{port}"


def _reject_leading_zeros(dotted: str) -> None:
    for octet in dotted.split("."):
        if len(octet) > 1 and octet.startswith("0"):
            raise ValueError("invalid ipv4")


_CANONICAL = {
    "ipv4": _canonical_ipv4,
    "ipv6": _canonical_ipv6,
    "domain": _canonical_domain,
    "url": _canonical_url,
    "email": _canonical_email,
    "md5": lambda value: _canonical_hash("md5", value),
    "sha1": lambda value: _canonical_hash("sha1", value),
    "sha256": lambda value: _canonical_hash("sha256", value),
    "asn": _canonical_asn,
    "cidr": _canonical_cidr,
}
