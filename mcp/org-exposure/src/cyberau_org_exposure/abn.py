"""ABN checksum and ABN Lookup name expansion.

Vendors are searched by name and domain. An ABN is turned into the entity's
registered name and business names, and only those names are sent.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

import httpx
from cyberau_common import USER_AGENT
from cyberau_common.cache import HttpCache
from cyberau_common.egress import EgressPolicy
from cyberau_common.http import HttpClient, HttpError
from cyberau_common.ratelimit import RateLimiter
from cyberau_common.secrets import lookup, redact

# ATO modulus 89. Subtract 1 from the first digit, then apply these weights.
# The weighted sum is divisible by 89.
WEIGHTS = (10, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19)

ABN_LOOKUP_URL = "https://abr.business.gov.au/json/AbnDetails.aspx"
_DIGITS = re.compile(r"[0-9]{11}")
_GUID_QUERY = re.compile(r"(?i)(guid=)[^&\s]+")


class LookupNotConfigured(Exception):
    """ABR_GUID is unset, so no names can be expanded and nothing is sent."""


class LookupFailed(Exception):
    """The lookup did not return usable names. The message never includes the GUID."""


def normalise_abn(value: str) -> str:
    """Return 11 digits, or an empty string when the value is not an ABN shape."""
    digits = re.sub(r"\s+", "", value or "")
    if not _DIGITS.fullmatch(digits):
        return ""
    return digits


def checksum_ok(value: str) -> bool:
    """Return True when the value passes the ATO ABN checksum."""
    digits = normalise_abn(value)
    if not digits:
        return False
    numbers = [int(char) for char in digits]
    numbers[0] -= 1
    total = sum(number * weight for number, weight in zip(numbers, WEIGHTS, strict=True))
    return total % 89 == 0


def expand_abns(
    abns: tuple[str, ...] | list[str], *, lookup_fn=None
) -> tuple[list[str], list[str]]:
    """Return names that may be sent, plus warnings. Digits are never included."""
    if not abns:
        return [], []
    if lookup_fn is None and not lookup("ABR_GUID"):
        return [], ["ABN Lookup is not configured (ABR_GUID). Registered names were not sent."]
    resolve = lookup_fn or lookup_names
    names: list[str] = []
    warnings: list[str] = []
    for abn in abns:
        try:
            found = resolve(abn)
        except LookupNotConfigured:
            return [], ["ABN Lookup is not configured (ABR_GUID). Registered names were not sent."]
        except LookupFailed as exc:
            warnings.append(str(exc))
            continue
        if not found:
            warnings.append("ABN Lookup returned no names. Nothing from that ABN was sent.")
            continue
        names.extend(found)
    return _unique(names), warnings


def lookup_names(abn: str, *, transport=None, resolver=None) -> list[str]:
    """Call AbnDetails and return the entity name and business names."""
    guid = lookup("ABR_GUID")
    if not guid:
        raise LookupNotConfigured(
            "ABN Lookup is not configured (ABR_GUID). Registered names were not sent."
        )
    digits = normalise_abn(abn)
    if not checksum_ok(digits):
        raise LookupFailed("ABN checksum failed. Nothing from that ABN was sent.")
    client = _client(transport=transport, resolver=resolver)
    try:
        try:
            response = client.get(
                ABN_LOOKUP_URL,
                params={"abn": digits, "callback": "callback", "guid": guid},
                ttl=0,
                skip_cache=True,
            )
        except (HttpError, httpx.HTTPError) as exc:
            raise LookupFailed(_strip_guid(str(exc), guid)) from None
    finally:
        client.close()
    try:
        payload = _parse_body(response.body)
    except ValueError as exc:
        raise LookupFailed(_strip_guid(str(exc), guid)) from None
    message = str(payload.get("Message") or "").strip()
    if message:
        raise LookupFailed("ABN Lookup returned no names. Nothing from that ABN was sent.")
    return _names_from_payload(payload, digits)


def _client(*, transport, resolver) -> HttpClient:
    directory = data_dir()
    allowlist = Path(os.environ.get("CYBERAU_EGRESS_ALLOWLIST", str(_default_allowlist())))
    policy = EgressPolicy(allowlist, "org-exposure", resolver=resolver)
    return HttpClient(
        "org-exposure",
        policy=policy,
        cache=HttpCache(directory / "http_cache.sqlite"),
        limiter=RateLimiter(directory / "rate_limit.sqlite"),
        user_agent=USER_AGENT,
        rate=1.0,
        burst=1,
        retries=0,
        transport=transport,
        sleeper=lambda _seconds: None,
        rng=lambda: 0,
    )


def _parse_body(body: bytes) -> dict:
    text = body.decode("utf-8-sig").strip()
    if not text:
        raise ValueError("ABN Lookup returned an empty body")
    if text[0] not in "{[":
        start = text.find("{")
        end = text.rfind("}")
        if start < 0 or end < start:
            raise ValueError("ABN Lookup returned no record")
        text = text[start : end + 1]
    payload = json.loads(text)
    if not isinstance(payload, dict):
        raise ValueError("ABN Lookup returned no record")
    return payload


def _names_from_payload(payload: dict, digits: str) -> list[str]:
    found: list[str] = []
    entity = payload.get("EntityName")
    if isinstance(entity, str):
        found.append(entity)
    business = payload.get("BusinessName") or []
    if isinstance(business, str):
        business = [business]
    if isinstance(business, list):
        found.extend(item for item in business if isinstance(item, str))
    names = []
    for item in found:
        cleaned = redact(re.sub(r"\s+", " ", item).strip())
        if not cleaned or len(cleaned) > 200:
            continue
        if normalise_abn(cleaned) == digits:
            continue
        names.append(cleaned)
    return _unique(names)


def _unique(names: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for name in names:
        key = name.casefold()
        if key in seen:
            continue
        seen.add(key)
        ordered.append(name)
    return ordered


def _strip_guid(text: str, guid: str) -> str:
    cleaned = _GUID_QUERY.sub(r"\1[REDACTED]", redact(text))
    if guid:
        cleaned = cleaned.replace(guid, "[REDACTED]")
    return cleaned


def data_dir() -> Path:
    """Profile data directory. Routine state, the ledger and the audit log live here, so it
    must be the same on every run. Tests point CYBERAU_DATA_DIR at a temporary directory."""
    raw = os.environ.get("CYBERAU_DATA_DIR")
    if raw:
        return Path(raw)
    return profile_home() / "plugin-data" / "cyber-au"


def profile_home() -> Path:
    """Hermes profile directory: HERMES_HOME, otherwise ~/.hermes."""
    raw = os.environ.get("HERMES_HOME")
    if raw:
        return Path(raw)
    return Path.home() / ".hermes"


def _default_allowlist() -> Path:
    return Path(__file__).resolve().parents[3] / "egress-allowlist.yaml"
