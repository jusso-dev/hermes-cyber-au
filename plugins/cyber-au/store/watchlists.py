"""Watchlists: match the user's own domains, brands, ranges, ASNs and vendors.

The watchlist lives at ``plugin-data/cyber-au/watchlists.yaml`` on the profile and is never
shipped. Each run recomputes ``watchlist_matches`` from what is in the store now: current
matches are kept (with their first match time) and every other row is deleted, so a match
never refers to an indicator or advisory that has expired or been removed.

Watched values stay local. The only outbound call is the optional crt.sh query
(``run_watchlist(crtsh=True)``), which sends each watched domain to crt.sh and is recorded
in the audit log.
"""

from __future__ import annotations

import hashlib
import ipaddress
import os
import re
import time
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

import idna

from .canonical import utc_now
from .db import fts_rowid, open_store, resolve_db_path
from .text import indexable_text, unwrap_untrusted

FILE_NAME = "watchlists.yaml"
ROUTINE = "watchlist"
TEMPLATE_PATH = Path(__file__).resolve().parent / "watchlists.example.yaml"
LISTS = ("domains", "brands", "ip_ranges", "asns", "vendors")
STORE_REFS = ("indicator", "advisory")
CRTSH_REF = "crtsh"
# A crt.sh match is replaced only by a successful query for its domain. When queries keep
# failing, or the nightly run stops passing --crtsh, the match ages out after this long.
CRTSH_KEEP_SECONDS = 7 * 24 * 3600

# Built-in vendor aliases. Keys and aliases are matched with the token rule below.
VENDOR_ALIASES: dict[str, tuple[str, ...]] = {
    "Microsoft": ("MSFT",),
    "Fortinet": ("FortiGate", "FortiOS"),
    "Palo Alto Networks": ("PAN-OS",),
    "Cisco": (),
    "Citrix": ("NetScaler",),
    "Ivanti": ("Pulse Secure",),
    "VMware": ("Broadcom VMware",),
    "Atlassian": ("Confluence", "Jira"),
}

_MULTI_SUFFIXES = frozenset(
    {
        "com.au",
        "net.au",
        "org.au",
        "gov.au",
        "edu.au",
        "asn.au",
        "id.au",
        "co.nz",
        "net.nz",
        "org.nz",
        "govt.nz",
        "co.uk",
        "org.uk",
    }
)

# Working subset of confusables, copied from the phishing-analysis skill. Not the Unicode
# confusables catalogue.
_CONFUSABLES = {
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "у": "y",
    "х": "x",
    "і": "i",
    "ї": "i",
    "ј": "j",
    "ѕ": "s",
    "һ": "h",
    "ԁ": "d",
    "ɡ": "g",
    "ο": "o",
    "α": "a",
    "ε": "e",
    "ι": "i",
    "ν": "v",
    "ρ": "p",
    "τ": "t",
    "υ": "u",
    "0": "o",
    "1": "l",
    "5": "s",
}
# Letter pairs that read as one letter in most fonts.
_PAIRS = (("rn", "m"), ("vv", "w"))
_HOST = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$")
_NON_WORD = re.compile(r"[^\w]+|_+")
_ORG_SUFFIXES = frozenset(
    {
        "ag",
        "co",
        "company",
        "corp",
        "corporation",
        "gmbh",
        "inc",
        "incorporated",
        "limited",
        "llc",
        "ltd",
        "plc",
        "pty",
    }
)


class WatchlistFileError(ValueError):
    """The watchlist file exists but cannot be used."""


@dataclass(frozen=True)
class Vendor:
    name: str
    aliases: tuple[str, ...] = ()


@dataclass(frozen=True)
class Watchlist:
    domains: tuple[str, ...] = ()
    brands: tuple[str, ...] = ()
    ip_ranges: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = ()
    asns: tuple[int, ...] = ()
    vendors: tuple[Vendor, ...] = ()
    warnings: tuple[str, ...] = ()

    def counts(self) -> dict[str, int]:
        return {name: len(getattr(self, name)) for name in LISTS}

    def empty(self) -> bool:
        return not any(self.counts().values())


@dataclass(frozen=True)
class Match:
    list: str
    kind: str
    value: str
    ref_kind: str
    ref: str
    matched: str
    detail: str

    @property
    def key(self) -> tuple[str, str, str, str]:
        return (self.list, self.value, self.ref_kind, self.ref)


@dataclass
class CrtshResult:
    enabled: bool = False
    queried: int = 0
    failed: list[str] = field(default_factory=list)
    skipped: str | None = None
    matches: list[Match] = field(default_factory=list)
    # Watched domains whose query succeeded, so their old crt.sh rows can be replaced.
    refreshed: set[str] = field(default_factory=set)


# Paths and the template.


def data_dir() -> Path:
    """Profile data directory, the same one the store and org-exposure use."""
    raw = os.environ.get("CYBERAU_DATA_DIR")
    if raw:
        return Path(raw).expanduser()
    hermes = os.environ.get("HERMES_HOME")
    if hermes:
        return Path(hermes).expanduser() / "plugin-data" / "cyber-au"
    raise ValueError("set CYBERAU_DATA_DIR or HERMES_HOME, or pass --watchlist")


def watchlist_path(path: str | Path | None = None) -> Path:
    if path is not None and str(path).strip():
        return Path(path).expanduser()
    return data_dir() / FILE_NAME


def init_watchlist(path: str | Path | None = None) -> dict:
    """Write the example template when no watchlist exists. Never overwrites."""
    target = watchlist_path(path)
    if target.exists() or target.is_symlink():
        return {"path": str(target), "created": False, "detail": "watchlist already exists"}
    target.parent.mkdir(parents=True, exist_ok=True)
    text = TEMPLATE_PATH.read_text(encoding="utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(target, flags, 0o600)
    except FileExistsError:
        return {"path": str(target), "created": False, "detail": "watchlist already exists"}
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)
    return {"path": str(target), "created": True, "detail": "template written"}


# Parsing.


def load_watchlist(path: str | Path) -> Watchlist:
    """Parse the watchlist. A bad entry is skipped with a warning; a bad file raises."""
    import yaml

    try:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise WatchlistFileError("watchlist is not valid YAML") from exc
    if data is None:
        return Watchlist()
    if not isinstance(data, dict):
        raise WatchlistFileError("watchlist must be a mapping")
    warnings: list[str] = []
    domains = _parse_list(data, "domains", _parse_domain, warnings)
    brands = _parse_list(data, "brands", _parse_name, warnings)
    ranges = _parse_list(data, "ip_ranges", _parse_range, warnings)
    asns = _parse_list(data, "asns", _parse_asn, warnings)
    vendors = _parse_list(data, "vendors", _parse_vendor, warnings)
    return Watchlist(
        domains=tuple(_unique(domains)),
        brands=tuple(_unique(brands)),
        ip_ranges=tuple(_unique(ranges)),
        asns=tuple(_unique(asns)),
        vendors=tuple(_merge_vendors(vendors)),
        warnings=tuple(warnings),
    )


def _parse_list(data: dict, name: str, parse, warnings: list[str]) -> list:
    raw = data.get(name)
    if raw is None:
        return []
    if not isinstance(raw, list):
        warnings.append(f"{name} must be a list and was skipped")
        return []
    parsed = []
    for index, item in enumerate(raw):
        value = parse(item)
        if value is None:
            # The entry itself is not echoed: it may be private.
            warnings.append(f"{name} entry {index + 1} was not usable and was skipped")
            continue
        parsed.append(value)
    return parsed


def _parse_domain(item) -> str | None:
    if not isinstance(item, str):
        return None
    text = item.strip().lower().rstrip(".")
    if "://" in text:
        text = text.split("://", 1)[1].split("/", 1)[0]
    if text.startswith("*."):
        text = text[2:]
    if not text:
        return None
    if not text.isascii():
        try:
            text = idna.encode(text, uts46=True).decode("ascii")
        except idna.IDNAError:
            return None
    return text if _HOST.fullmatch(text) else None


def _parse_name(item) -> str | None:
    if not isinstance(item, str) or not item.strip():
        return None
    name = " ".join(item.split())
    return name if tokens(name) else None


def _parse_range(item):
    if not isinstance(item, str) or not item.strip():
        return None
    try:
        return ipaddress.ip_network(item.strip(), strict=False)
    except ValueError:
        return None


def _parse_asn(item) -> int | None:
    if isinstance(item, bool):
        return None
    if isinstance(item, int):
        number = item
    elif isinstance(item, str):
        text = item.strip().upper()
        if text.startswith("AS"):
            text = text[2:]
        if not text.isdigit():
            return None
        number = int(text)
    else:
        return None
    return number if 0 < number <= 4_294_967_295 else None


def _parse_vendor(item) -> Vendor | None:
    if isinstance(item, str):
        name = _parse_name(item)
        return None if name is None else Vendor(name)
    if not isinstance(item, dict):
        return None
    name = _parse_name(item.get("name"))
    if name is None:
        return None
    raw_aliases = item.get("aliases") or []
    if not isinstance(raw_aliases, list):
        return None
    aliases = [alias for alias in (_parse_name(entry) for entry in raw_aliases) if alias]
    return Vendor(name, tuple(aliases))


def _merge_vendors(vendors: list[Vendor]) -> list[Vendor]:
    """Merge user vendors with the built-in alias table. Same vendor named twice is merged."""
    builtin = {}
    for name, aliases in VENDOR_ALIASES.items():
        for spelling in (name, *aliases):
            builtin[_phrase(spelling)] = name
    merged: dict[str, list[str]] = {}
    display: dict[str, str] = {}
    for vendor in vendors:
        canonical = builtin.get(_phrase(vendor.name))
        key = _phrase(canonical or vendor.name)
        display.setdefault(key, canonical or vendor.name)
        names = merged.setdefault(key, [])
        extra = VENDOR_ALIASES[canonical] if canonical else ()
        for spelling in (canonical or vendor.name, vendor.name, *extra, *vendor.aliases):
            if _phrase(spelling) not in {_phrase(item) for item in names}:
                names.append(spelling)
    return [Vendor(display[key], tuple(names)) for key, names in merged.items()]


def _unique(items: Iterable) -> list:
    seen = set()
    kept = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        kept.append(item)
    return kept


# Token rule (skills/daily-briefing/references/matching.md), applied as a phrase.


def tokens(text: str) -> tuple[str, ...]:
    folded = unicodedata.normalize("NFKC", text).casefold().replace("&", " and ")
    parts = _NON_WORD.split(folded)
    return tuple(part for part in parts if len(part) >= 2 and part not in _ORG_SUFFIXES)


def _phrase(text: str) -> tuple[str, ...]:
    return tokens(text)


def phrase_in(needle: tuple[str, ...], haystack: tuple[str, ...]) -> bool:
    """True when ``needle`` appears as consecutive tokens in ``haystack``."""
    if not needle or len(needle) > len(haystack):
        return False
    width = len(needle)
    first = needle[0]
    for index, token in enumerate(haystack[: len(haystack) - width + 1]):
        if token == first and haystack[index : index + width] == needle:
            return True
    return False


# Domain helpers, copied from skills/phishing-analysis/scripts/analyse_email.py.


def registrable_domain(host: str) -> str:
    labels = [part for part in host.lower().rstrip(".").split(".") if part]
    if len(labels) < 2:
        return ".".join(labels)
    if len(labels) >= 3 and ".".join(labels[-2:]) in _MULTI_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def is_under(host: str, domain: str) -> bool:
    host = host.lower().rstrip(".")
    domain = domain.lower().rstrip(".")
    return bool(host) and (host == domain or host.endswith("." + domain))


def _fold_label(label: str) -> str:
    folded = label.lower()
    if folded.startswith("xn--"):
        try:
            folded = idna.decode(folded).lower()
        except (idna.IDNAError, UnicodeError):
            try:
                folded = folded.encode("ascii").decode("idna").lower()
            except UnicodeError:
                pass
    folded = "".join(_CONFUSABLES.get(char, char) for char in folded)
    for pair, single in _PAIRS:
        folded = folded.replace(pair, single)
    return folded


def fold_host(host: str) -> str:
    return ".".join(_fold_label(part) for part in host.lower().rstrip(".").split(".") if part)


def _edit_limit(length: int) -> int | None:
    if length < 5:
        return None
    if length < 8:
        return 1
    return 2


def _levenshtein(left: str, right: str) -> int:
    if left == right:
        return 0
    if not left:
        return len(right)
    if not right:
        return len(left)
    previous = list(range(len(right) + 1))
    for index, left_char in enumerate(left, start=1):
        current = [index]
        for right_index, right_char in enumerate(right, start=1):
            insert = current[right_index - 1] + 1
            delete = previous[right_index] + 1
            substitute = previous[right_index - 1] + (left_char != right_char)
            current.append(min(insert, delete, substitute))
        previous = current
    return previous[-1]


def _label(registrable: str) -> str:
    return registrable.split(".", 1)[0]


def lookalike(host: str, watched: str) -> str | None:
    """Return the rule when ``host`` looks like ``watched`` without being under it."""
    host = host.lower().rstrip(".")
    if not host or is_under(host, watched):
        return None
    candidate = registrable_domain(host)
    target = registrable_domain(watched)
    if candidate == target:
        return None
    folded_candidate = fold_host(candidate)
    folded_target = fold_host(target)
    if folded_candidate == folded_target:
        return "homoglyph"
    left = _label(folded_candidate)
    right = _label(folded_target)
    if left == right:
        return "suffix-swap"
    if len(right) >= 5 and right in left.split("-"):
        return "token"
    limit = _edit_limit(len(right))
    if limit is None or abs(len(left) - len(right)) > limit:
        return None
    distance = _levenshtein(left, right)
    if 0 < distance <= limit:
        return f"edit-distance-{distance}"
    return None


def _host_of(kind: str, value: str) -> str | None:
    if kind == "domain":
        return value
    if kind == "email":
        return value.rsplit("@", 1)[-1]
    if kind == "url":
        from urllib.parse import urlsplit

        try:
            return urlsplit(value).hostname
        except ValueError:
            return None
    return None


def _address(value: str):
    try:
        return ipaddress.ip_address(value.strip("[]"))
    except ValueError:
        return None


# Matching against the store.


def match_indicator(watch: Watchlist, indicator_id: str, kind: str, value: str) -> list[Match]:
    """Matches for one stored indicator (``value`` is its canonical form)."""
    found: list[Match] = []
    if kind in ("ipv4", "ipv6") or (kind == "url" and watch.ip_ranges):
        host = value if kind in ("ipv4", "ipv6") else _host_of(kind, value)
        address = _address(host) if host else None
        if address is not None:
            for network in watch.ip_ranges:
                if address.version == network.version and address in network:
                    found.append(
                        Match(
                            "ip_ranges",
                            "ip_range",
                            str(network),
                            "indicator",
                            indicator_id,
                            value,
                            f"{kind} inside {network}",
                        )
                    )
    if kind == "cidr":
        try:
            stored = ipaddress.ip_network(value, strict=False)
        except ValueError:
            stored = None
        for network in watch.ip_ranges if stored is not None else ():
            if stored.version != network.version or not stored.overlaps(network):
                continue
            relation = "inside" if stored.subnet_of(network) else "covers"
            found.append(
                Match(
                    "ip_ranges",
                    "ip_range",
                    str(network),
                    "indicator",
                    indicator_id,
                    value,
                    f"cidr {relation} {network}",
                )
            )
    if kind == "asn":
        number = _parse_asn(value)
        if number is not None and number in watch.asns:
            found.append(
                Match("asns", "asn", f"AS{number}", "indicator", indicator_id, value, "asn equal")
            )
    if kind in ("domain", "url", "email") and watch.domains:
        host = _host_of(kind, value)
        if host and _address(host) is None:
            found.extend(_domain_matches(watch, host, "indicator", indicator_id, value, kind))
    return found


def _domain_matches(
    watch: Watchlist, host: str, ref_kind: str, ref: str, matched: str, kind: str
) -> list[Match]:
    found: list[Match] = []
    for domain in watch.domains:
        if is_under(host, domain):
            relation = "equal" if host.rstrip(".").lower() == domain else "subdomain"
            found.append(
                Match("domains", "domain", domain, ref_kind, ref, matched, f"{kind} {relation}")
            )
            continue
        rule = lookalike(host, domain)
        if rule is not None:
            found.append(
                Match("domains", "lookalike", domain, ref_kind, ref, matched, f"{kind} {rule}")
            )
    return found


def match_text(watch: Watchlist, advisory_id: str, title: str, text: str) -> list[Match]:
    """Brand and vendor matches in one advisory's title, summary and indexed body."""
    found: list[Match] = []
    haystack = tokens(text)
    shown = title[:200]
    for brand in watch.brands:
        if phrase_in(tokens(brand), haystack):
            found.append(
                Match("brands", "brand", brand, "advisory", advisory_id, shown, "token match")
            )
    for vendor in watch.vendors:
        for spelling in vendor.aliases or (vendor.name,):
            if phrase_in(tokens(spelling), haystack):
                detail = "name" if _phrase(spelling) == _phrase(vendor.name) else "alias"
                found.append(
                    Match(
                        "vendors",
                        "vendor",
                        vendor.name,
                        "advisory",
                        advisory_id,
                        shown,
                        f"{detail} {spelling}",
                    )
                )
                break
    return found


def compute_matches(conn, watch: Watchlist) -> list[Match]:
    """Every current match against the rows in the store now."""
    matches: list[Match] = []
    types: list[str] = []
    if watch.ip_ranges:
        types += ["ipv4", "ipv6", "cidr", "url"]
    if watch.asns:
        types.append("asn")
    if watch.domains:
        types += ["domain", "url", "email"]
    types = _unique(types)
    if types:
        marks = ",".join("?" for _ in types)
        rows = conn.execute(
            f"SELECT id, type, value_norm FROM indicators WHERE type IN ({marks})", types
        )
        for row in rows:
            matches.extend(match_indicator(watch, row["id"], row["type"], row["value_norm"]))
    if watch.brands or watch.vendors:
        rows = conn.execute("SELECT id, title, summary FROM advisories").fetchall()
        for row in rows:
            body = conn.execute(
                "SELECT body FROM fts WHERE rowid = ?", (fts_rowid("advisory", row["id"]),)
            ).fetchone()
            summary = indexable_text(row["summary"] or "")
            text = " ".join((row["title"] or "", summary, body["body"] if body else ""))
            matches.extend(match_text(watch, row["id"], row["title"] or "", text))
    unique: dict[tuple[str, str, str, str], Match] = {}
    for item in matches:
        unique.setdefault(item.key, item)
    return list(unique.values())


# crt.sh lookalike discovery.


def crtsh_lookalikes(watch: Watchlist, *, audit=None) -> CrtshResult:
    """Query crt.sh for each watched domain and keep certificate names that look alike.

    Only watched domains are sent, only to crt.sh, and each query is written to the audit
    log first. Any failure is a warning, never an error.
    """
    result = CrtshResult(enabled=True)
    if not watch.domains:
        result.skipped = "no watched domains"
        return result
    try:
        from cyberau_crtsh import source as crtsh
    except ImportError:
        result.skipped = "crt.sh connector is not installed"
        return result
    try:
        if audit is None:
            from cyberau_common.audit import AuditLog

            audit = AuditLog()
        audit.probe()
    except Exception:
        result.skipped = "audit log is not writable, crt.sh was not queried"
        return result
    for domain in watch.domains:
        args = {"domain": domain, "include_subdomains": True}
        started = time.monotonic()
        try:
            envelope = crtsh.crtsh_certs(domain, include_subdomains=True)
        except Exception:
            envelope = None
        elapsed = int((time.monotonic() - started) * 1000)
        result.queried += 1
        ok = isinstance(envelope, dict) and (
            bool(envelope.get("data")) or not envelope.get("warnings")
        )
        flags = ["watchlist", "crtsh"]
        if isinstance(envelope, dict) and envelope.get("cache"):
            flags.append(f"cache:{envelope['cache']}")
        if not ok:
            flags.append("failed")
        try:
            audit.record(
                "tool_call",
                tool="crtsh_certs",
                args=args,
                result=envelope,
                duration_ms=elapsed,
                flags=flags,
            )
        except Exception:
            result.skipped = "audit log write failed, crt.sh queries stopped"
            return result
        if not ok:
            result.failed.append(domain)
            continue
        result.refreshed.add(domain)
        for name in _certificate_names(envelope.get("data") or []):
            rule = lookalike(name, domain)
            if rule is None:
                continue
            result.matches.append(
                Match("domains", "lookalike", domain, CRTSH_REF, name, name, f"crt.sh {rule}")
            )
    return result


def _certificate_names(rows: list) -> list[str]:
    names: list[str] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        for raw in [row.get("common_name"), *(row.get("names") or [])]:
            if not isinstance(raw, str):
                continue
            inner = unwrap_untrusted(raw)
            text = (inner if inner is not None else raw).strip().lower().rstrip(".")
            if text.startswith("*."):
                text = text[2:]
            if _HOST.fullmatch(text) and text not in names:
                names.append(text)
    return names


# One run.


def run_watchlist(
    *,
    store: str | Path | None = None,
    watchlist: str | Path | None = None,
    crtsh: bool = False,
    audit=None,
    now: str | None = None,
) -> dict:
    """Recompute watchlist matches. Returns a JSON-ready summary without watched values."""
    file = watchlist_path(watchlist)
    run_at = now or utc_now()
    summary: dict = {
        "status": "ok",
        "routine": ROUTINE,
        "run_at": run_at,
        "watchlist": str(file),
        "entries": dict.fromkeys(LISTS, 0),
        "matches": 0,
        "new": 0,
        "removed": 0,
        "by_kind": {},
        "crtsh": {"enabled": crtsh},
        "warnings": [],
    }
    store_file = resolve_db_path(store)
    summary["store"] = str(store_file)
    if not file.is_file():
        summary["status"] = "skipped"
        summary["detail"] = "no watchlist configured"
        if store_file.is_file():
            # Nothing is watched now, so no earlier match may stay.
            summary["removed"] = _clear(store_file, run_at)
        return summary
    watch = load_watchlist(file)
    summary["entries"] = watch.counts()
    summary["warnings"].extend(watch.warnings)

    found_crtsh = CrtshResult()
    if crtsh:
        found_crtsh = crtsh_lookalikes(watch, audit=audit)
        summary["crtsh"] = {
            "enabled": True,
            "queried": found_crtsh.queried,
            "failed": len(found_crtsh.failed),
            "matches": len(found_crtsh.matches),
        }
        if found_crtsh.skipped:
            summary["crtsh"]["skipped"] = found_crtsh.skipped
            summary["warnings"].append(f"crt.sh skipped: {found_crtsh.skipped}")
        if found_crtsh.failed:
            summary["warnings"].append(
                f"crt.sh query failed for {len(found_crtsh.failed)} watched domain(s)"
            )

    handle = open_store(store_file)
    with handle.transaction() as conn:
        current = compute_matches(conn, watch)
        current.extend(found_crtsh.matches)
        new, removed = _store_matches(conn, watch, current, found_crtsh, run_at)
        _touch_routine(conn, run_at)
    by_kind: dict[str, int] = {}
    for item in current:
        by_kind[item.kind] = by_kind.get(item.kind, 0) + 1
    summary.update(
        matches=len(current), new=new, removed=removed, by_kind=dict(sorted(by_kind.items()))
    )
    return summary


def _store_matches(conn, watch, current, crtsh: CrtshResult, run_at: str) -> tuple[int, int]:
    existing = {
        (row["list"], row["value"], row["ref_kind"], row["ref"]): row["last_matched"]
        for row in conn.execute(
            "SELECT list, value, ref_kind, ref, last_matched FROM watchlist_matches"
        )
    }
    keys = {item.key for item in current}
    new = 0
    for item in current:
        if item.key not in existing:
            new += 1
        conn.execute(
            """
            INSERT INTO watchlist_matches (
                list, kind, value, ref_kind, ref, matched, detail, first_matched, last_matched
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (list, value, ref_kind, ref) DO UPDATE SET
                kind = excluded.kind,
                matched = excluded.matched,
                detail = excluded.detail,
                last_matched = excluded.last_matched
            """,
            (
                item.list,
                item.kind,
                item.value,
                item.ref_kind,
                item.ref,
                item.matched,
                item.detail,
                run_at,
                run_at,
            ),
        )
    watched_domains = set(watch.domains)
    cutoff = _shift(run_at, -CRTSH_KEEP_SECONDS)
    removed = 0
    for key, last in existing.items():
        if key in keys:
            continue
        _list, value, ref_kind, _ref = key
        if ref_kind == CRTSH_REF:
            # Kept only while the domain is watched, its query did not succeed this run,
            # and the match is recent.
            keep = value in watched_domains and value not in crtsh.refreshed and last >= cutoff
            if keep:
                continue
        conn.execute(
            "DELETE FROM watchlist_matches"
            " WHERE list = ? AND value = ? AND ref_kind = ? AND ref = ?",
            key,
        )
        removed += 1
    return new, removed


def _touch_routine(conn, run_at: str) -> None:
    conn.execute(
        """
        INSERT INTO routine_state (routine, watermark, updated_at) VALUES (?, ?, ?)
        ON CONFLICT (routine) DO UPDATE SET
            watermark = excluded.watermark, updated_at = excluded.updated_at
        """,
        (ROUTINE, run_at, run_at),
    )


def _clear(store_file: Path, run_at: str) -> int:
    handle = open_store(store_file)
    with handle.transaction() as conn:
        removed = conn.execute("DELETE FROM watchlist_matches").rowcount
        _touch_routine(conn, run_at)
    return int(removed)


def _shift(stamp: str, seconds: int) -> str:
    from datetime import datetime, timedelta

    moment = datetime.fromisoformat(stamp.replace("Z", "+00:00")) + timedelta(seconds=seconds)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


# Reading.

_LIVE = """
    (m.ref_kind = 'indicator' AND EXISTS (SELECT 1 FROM indicators i WHERE i.id = m.ref))
    OR (m.ref_kind = 'advisory' AND EXISTS (SELECT 1 FROM advisories a WHERE a.id = m.ref))
    OR m.ref_kind = 'crtsh'
"""


def list_matches(
    *,
    store: str | Path | None = None,
    since: str | None = None,
    lists: Iterable[str] = (),
) -> list[dict]:
    """Current matches, newest first. ``since`` filters on the first match time."""
    from .canonical import canonical_timestamp

    chosen = [name for name in lists if name]
    for name in chosen:
        if name not in LISTS:
            raise ValueError(f"unknown watchlist list: {name}")
    clauses = [f"({_LIVE})"]
    params: list = []
    if since:
        clauses.append("m.first_matched >= ?")
        params.append(canonical_timestamp(since))
    if chosen:
        clauses.append(f"m.list IN ({','.join('?' for _ in chosen)})")
        params.extend(chosen)
    store_file = resolve_db_path(store)
    if not store_file.is_file():
        return []
    conn = open_store(store_file).connection()
    rows = conn.execute(
        "SELECT m.* FROM watchlist_matches m WHERE "
        + " AND ".join(clauses)
        + " ORDER BY m.first_matched DESC, m.list, m.value, m.ref",
        params,
    ).fetchall()
    return [dict(row) for row in rows]


def hits(*, store: str | Path | None = None, since: str) -> dict:
    """Matches since ``since`` in the daily-briefing intel-store ``hits`` shape."""
    rows = list_matches(store=store, since=since)
    out = []
    for row in rows:
        digest = hashlib.sha256(
            "\0".join((row["list"], row["value"], row["ref_kind"], row["ref"])).encode()
        ).hexdigest()[:12]
        kind = row["kind"] if row["ref_kind"] != "advisory" else f"advisory {row['kind']}"
        out.append(
            {
                "id": f"watch-{digest}",
                "kind": kind,
                "value": row["matched"],
                "seen": row["first_matched"],
                "asset": row["value"],
            }
        )
    out.sort(key=lambda item: (item["seen"], item["id"]))
    return {
        "source": "intel-store",
        "retrieved_at": utc_now(),
        "untrusted": True,
        "data": {"hits": out},
    }
