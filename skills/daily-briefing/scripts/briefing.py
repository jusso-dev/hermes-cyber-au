"""Render the daily Australian cyber briefing from local inputs.

Feed text is data. This module does not fetch, post, or follow text that
arrives inside a connector envelope. The asset inventory is read from a path
the caller supplies. A missing inventory is reported; it is not created.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

SYDNEY = ZoneInfo("Australia/Sydney")
EPSS_TIER1 = 0.7
EPSS_MOVER = 0.1
TREND_MIN = 2
BRIEF_WORDS = 600
BRIEF_ASSETS = 3
BRIEF_OUTAGES = 2
FULL_TEXT = 8000
# (act, this week, watchlist, text length). A busy window steps down these tiers
# until the brief is under BRIEF_WORDS. The first tier is the normal case.
BRIEF_TIERS = (
    (8, 8, 5, 160),
    (5, 5, 3, 100),
    (3, 3, 2, 60),
    (2, 2, 1, 40),
    (1, 1, 1, 24),
)

WEEKDAYS = (
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
    "Sunday",
)
MONTHS = (
    "",
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
)
SUFFIXES = frozenset(
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
SOURCES = (
    ("asd-acsc", "ASD ACSC"),
    ("cisa-kev", "CISA KEV"),
    ("nvd", "NVD"),
    ("first-epss", "FIRST EPSS"),
    ("auscert", "AusCERT"),
    ("attack", "MITRE ATT&CK"),
    ("cloudflare-radar", "Cloudflare Radar"),
    ("intel-store", "Intel store"),
)
_SECRET = re.compile(
    r"(?i)\b([a-z0-9_-]*(?:token|api[_-]?key|access[_-]?key|private[_-]?key|secret|passwd|password))"
    r"\s*=\s*\S+"
)
_BEARER = re.compile(r"(?i)\bbearer\s+\S+")
_CONTROL = re.compile(r"[\x00-\x1f\x7f\u202a-\u202e\u2066-\u2069\u200b-\u200f]")
_WORDS = re.compile(r"[A-Za-z0-9]+(?:'[A-Za-z0-9]+)?")


@dataclass(frozen=True)
class Asset:
    name: str
    vendor: str
    product: str
    exposure: str
    owner: str


@dataclass(frozen=True)
class Bullet:
    label: str
    text: str


def word_count(text: str) -> int:
    return len(_WORDS.findall(text))


def window_for(as_of: datetime) -> tuple[datetime, datetime, int]:
    """Monday covers 72 hours. Every other day covers 24."""
    moment = _aware(as_of).astimezone(SYDNEY)
    hours = 72 if moment.weekday() == 0 else 24
    return moment - timedelta(hours=hours), moment, hours


def tokens(value: str) -> frozenset[str]:
    text = unicodedata.normalize("NFKC", value).casefold().replace("&", " and ")
    parts = re.sub(r"[^a-z0-9]+", " ", text).split()
    return frozenset(part for part in parts if len(part) >= 2 and part not in SUFFIXES)


def field_match(left: str, right: str) -> bool:
    """True when the token sets are equal or one is a subset of the other."""
    a, b = tokens(left), tokens(right)
    if not a or not b:
        return False
    return a == b or a < b or b < a


def cpe_match(asset: Asset, cpe: str) -> bool:
    parsed = _cpe_target(cpe)
    if parsed is None:
        return False
    vendor, product = parsed
    return field_match(asset.vendor, vendor) and field_match(asset.product, product)


def load_assets(text: str) -> list[Asset]:
    """Load the plain asset list. Anchors and nested blocks are rejected."""
    assets: list[Asset] = []
    current: dict[str, str] | None = None
    seen_key = False
    for raw in text.splitlines():
        if "\t" in raw:
            raise ValueError("assets.yaml must use spaces, not tabs")
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        body = line.strip()
        if indent == 0 and body == "assets:":
            seen_key = True
            continue
        if not seen_key:
            raise ValueError("assets.yaml must start with an assets list")
        if body.startswith("- "):
            if current:
                assets.append(_asset(current))
            current = {}
            rest = body[2:].strip()
            if rest:
                key, value = _pair(rest)
                current[key] = value
            continue
        if current is None or ":" not in body:
            raise ValueError(f"unreadable assets.yaml line: {body}")
        key, value = _pair(body)
        current[key] = value
    if current:
        assets.append(_asset(current))
    return assets


def render(
    pack: dict,
    assets: list[Asset],
    as_of: datetime,
    detail: str = "brief",
    channel: str = "owner",
    *,
    inventory_configured: bool = True,
) -> str:
    if detail not in {"brief", "full"}:
        raise ValueError("detail must be brief or full")
    if channel not in {"owner", "external"}:
        raise ValueError("channel must be owner or external")
    if detail == "full":
        return _compose(pack, assets, as_of, detail, channel, inventory_configured, None)
    text = ""
    for tier in BRIEF_TIERS:
        text = _compose(pack, assets, as_of, detail, channel, inventory_configured, tier)
        if word_count(text) < BRIEF_WORDS:
            break
    return text


def _compose(
    pack: dict,
    assets: list[Asset],
    as_of: datetime,
    detail: str,
    channel: str,
    inventory_configured: bool,
    tier: tuple[int, int, int, int] | None,
) -> str:
    act_cap, week_cap, watch_cap, limit = tier if tier else (None, None, None, None)
    start, end, hours = window_for(as_of)
    connectors = _connectors(pack)
    alerts, advisories = _acsc(connectors, start, end, limit)
    records = _records(connectors)
    act_vulns, movers = _vulnerabilities(
        records, assets, alerts, start, end, detail, channel, inventory_configured
    )
    act = _alert_bullets(alerts, detail) + act_vulns
    week = (
        _advisory_bullets(advisories, detail)
        + _auscert(connectors, start, end, limit)
        + movers
        + _techniques(connectors, start, end, limit)
    )
    watch = _watchlist(
        connectors,
        start,
        end,
        channel,
        limit,
        assets if inventory_configured else [],
    )
    internet = _internet(connectors, start, end, limit)
    sources, missing = _sources(connectors)

    act_lines = _cap(act, act_cap)
    if not inventory_configured:
        note = "Asset inventory is not configured, so asset matches were skipped."
        act_lines = [note, *act_lines]
    elif not assets:
        note = "Asset inventory is empty, so asset matches were skipped."
        act_lines = [note, *act_lines]

    headline = _headline(end, act)
    parts = [
        "# Daily Australian cyber briefing",
        "",
        f"Window: {hours} hours ending {end.isoformat(timespec='seconds')}.",
        f"Detail: {detail}.",
        f"Channel: {channel}.",
        "",
        "## Headline",
        "",
        headline,
        "",
        "## Act today",
        "",
        _body(act_lines),
        "",
        "## This week",
        "",
        _body(_cap(week, week_cap)),
        "",
        "## Australian internet picture",
        "",
        _body(internet),
        "",
        "## Watchlist hits",
        "",
        _body(_cap(watch, watch_cap)),
        "",
        "## Sources",
        "",
        _body(sources),
        "",
        f"Missing connectors: {', '.join(missing) if missing else 'none'}.",
        "",
    ]
    return "\n".join(parts)


def default_assets_path() -> Path:
    home = os.environ.get("HERMES_HOME")
    base = Path(home) if home else Path()
    return base / "plugin-data" / "cyber-au" / "assets.yaml"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Render the daily Australian cyber briefing.")
    parser.add_argument("--input", required=True, help="Pack JSON path, or - for stdin.")
    parser.add_argument("--assets", help="Path to the user-owned assets.yaml.")
    parser.add_argument("--as-of", required=True, help="Briefing time, with a timezone.")
    parser.add_argument("--detail", choices=("brief", "full"), default="brief")
    parser.add_argument("--channel", choices=("owner", "external"), default="owner")
    args = parser.parse_args(argv)
    try:
        raw = (
            sys.stdin.read() if args.input == "-" else Path(args.input).read_text(encoding="utf-8")
        )
        pack = json.loads(raw)
        assets_path = Path(args.assets) if args.assets else default_assets_path()
        configured = assets_path.is_file()
        assets = load_assets(assets_path.read_text(encoding="utf-8")) if configured else []
        text = render(
            pack,
            assets,
            _parse(args.as_of),
            args.detail,
            args.channel,
            inventory_configured=configured,
        )
    except (OSError, ValueError, json.JSONDecodeError, KeyError, TypeError) as exc:
        print(f"briefing failed: {exc}", file=sys.stderr)
        return 2
    sys.stdout.write(text)
    return 0


def _aware(moment: datetime) -> datetime:
    if moment.tzinfo is None:
        raise ValueError("timestamps need a timezone")
    return moment


def _parse(value: str) -> datetime:
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    if "T" not in text:
        year, month, day = (int(part) for part in text.split("-"))
        return datetime(year, month, day, tzinfo=SYDNEY)
    parsed = datetime.fromisoformat(text)
    return _aware(parsed)


def _in_window(value: str, start: datetime, end: datetime) -> bool:
    """A timestamp is in the half-open window. A date-only value is the whole Sydney day.

    KEV dateAdded and EPSS dates carry no time and are stamped in US time. Midnight
    would drop an entry dated yesterday from this morning's window, and no later
    window would pick it up.
    """
    moment = _parse(value).astimezone(SYDNEY)
    if "T" not in str(value):
        return moment < end and moment + timedelta(days=1) > start
    return start <= moment < end


def _display(value: str) -> str:
    return _parse(value).astimezone(SYDNEY).isoformat(timespec="seconds")


def _flatten(value: object, limit: int | None) -> str:
    text = unicodedata.normalize("NFKC", "" if value is None else str(value))
    text = _CONTROL.sub(" ", text)
    text = re.sub(r"\s+", " ", text).strip()
    text = _SECRET.sub(r"\1=[redacted]", text)
    text = _BEARER.sub("bearer [redacted]", text)
    if limit is not None and len(text) > limit:
        text = text[: limit - 3].rstrip() + "..."
    return text


def _pair(body: str) -> tuple[str, str]:
    key, value = body.split(":", 1)
    key = key.strip()
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        value = value[1:-1]
    if not key or not value:
        raise ValueError(f"assets.yaml entry needs a value: {body}")
    return key, value


def _asset(fields: dict[str, str]) -> Asset:
    missing = [
        key for key in ("name", "vendor", "product", "exposure", "owner") if key not in fields
    ]
    if missing:
        raise ValueError("asset is missing " + ", ".join(missing))
    exposure = fields["exposure"]
    if exposure not in {"internet", "internal"}:
        raise ValueError("exposure must be internet or internal")
    return Asset(
        fields["name"],
        fields["vendor"],
        fields["product"],
        exposure,
        fields["owner"],
    )


def _cpe_target(cpe: str) -> tuple[str, str] | None:
    text = str(cpe).strip()
    if not text.startswith("cpe:2.3:"):
        return None
    parts = text.split(":")
    if len(parts) < 5 or parts[2] not in {"a", "o", "h"}:
        return None
    if parts[3] in {"", "*"} or parts[4] in {"", "*"}:
        return None
    return parts[3].replace("\\", ""), parts[4].replace("\\", "")


def _connectors(pack: dict) -> dict[str, dict]:
    raw = pack.get("connectors")
    if not isinstance(raw, dict):
        raise ValueError("connectors must be an object")
    found: dict[str, dict] = {}
    for key, _label in SOURCES:
        item = raw.get(key, {"status": "missing"})
        if not isinstance(item, dict) or item.get("status") not in {"ok", "missing"}:
            raise ValueError(f"bad status for {key}")
        found[key] = item
    return found


def _data(item: dict) -> dict:
    if item.get("status") != "ok":
        return {}
    envelope = item.get("envelope") or {}
    data = envelope.get("data") or {}
    if not isinstance(data, dict):
        raise ValueError("envelope data must be an object")
    return data


def _rows(item: dict, key: str) -> list[dict]:
    rows = _data(item).get(key) or []
    if not isinstance(rows, list):
        raise ValueError(f"{key} must be a list")
    return [row for row in rows if isinstance(row, dict)]


def _retrieved(item: dict) -> str:
    envelope = item.get("envelope") or {}
    when = envelope.get("retrieved_at")
    if not when:
        raise ValueError("an ok connector needs retrieved_at")
    return _display(str(when))


def _acsc(
    connectors: dict[str, dict], start: datetime, end: datetime, limit: int | None
) -> tuple[list[dict], list[dict]]:
    alerts: list[dict] = []
    advisories: list[dict] = []
    for row in _rows(connectors["asd-acsc"], "items"):
        published = str(row.get("published") or "")
        if not published or not _in_window(published, start, end):
            continue
        kind = str(row.get("kind") or "")
        item = {
            "id": _flatten(row.get("id"), limit),
            "title": _flatten(row.get("title"), limit),
            "published": _display(published),
            "summary": _flatten(row.get("summary"), FULL_TEXT if limit is None else None),
            "cves": [str(cve) for cve in row.get("cves") or [] if isinstance(cve, str)],
        }
        if kind == "alert":
            alerts.append(item)
        elif kind == "advisory":
            advisories.append(item)
    alerts.sort(key=lambda item: (item["published"], item["id"]))
    advisories.sort(key=lambda item: (item["published"], item["id"]))
    return alerts, advisories


def _records(connectors: dict[str, dict]) -> dict[str, dict]:
    kev: dict[str, dict] = {}
    for row in _rows(connectors["cisa-kev"], "entries"):
        cve = str(row.get("cve_id") or "")
        if cve:
            kev[cve] = row
    nvd: dict[str, dict] = {}
    for row in _rows(connectors["nvd"], "records"):
        cve = str(row.get("cve_id") or "")
        if cve:
            nvd[cve] = row
    epss: dict[str, dict] = {}
    for row in _rows(connectors["first-epss"], "scores"):
        cve = str(row.get("cve_id") or "")
        if cve:
            epss[cve] = row
    return {"kev": kev, "nvd": nvd, "epss": epss}


def _matched(cve: str, records: dict[str, dict], assets: list[Asset]) -> tuple[str, list[Asset]]:
    kev = records["kev"].get(cve)
    cpes = []
    nvd = records["nvd"].get(cve) or {}
    raw_cpes = nvd.get("cpes") or []
    if isinstance(raw_cpes, list):
        cpes = [str(item) for item in raw_cpes]
    found: list[Asset] = []
    rule = ""
    for asset in assets:
        kev_hit = bool(
            kev
            and field_match(asset.vendor, str(kev.get("vendor_project") or ""))
            and field_match(asset.product, str(kev.get("product") or ""))
        )
        cpe_hit = any(cpe_match(asset, cpe) for cpe in cpes)
        if not kev_hit and not cpe_hit:
            continue
        found.append(asset)
        if kev_hit and not rule:
            rule = "kev-vendor-product"
        elif cpe_hit and not rule:
            rule = "nvd-cpe"
    if any(
        kev
        and field_match(asset.vendor, str(kev.get("vendor_project") or ""))
        and field_match(asset.product, str(kev.get("product") or ""))
        for asset in found
    ):
        rule = "kev-vendor-product"
    return rule, found


def _vulnerabilities(
    records: dict[str, dict],
    assets: list[Asset],
    alerts: list[dict],
    start: datetime,
    end: datetime,
    detail: str,
    channel: str,
    inventory_configured: bool,
) -> tuple[list[Bullet], list[Bullet]]:
    if not inventory_configured or not assets:
        act: list[Bullet] = []
        return act, _movers(records, set(), start, end)
    alert_cves = {cve for alert in alerts for cve in alert["cves"]}
    candidates = set(records["kev"]) | set(records["nvd"]) | set(records["epss"]) | alert_cves
    act_rows: list[tuple[str, Bullet]] = []
    acted: set[str] = set()
    for cve in sorted(candidates):
        rule, matched = _matched(cve, records, assets)
        if not matched:
            continue
        kev = records["kev"].get(cve)
        epss = records["epss"].get(cve)
        kev_new = bool(
            kev and kev.get("date_added") and _in_window(str(kev["date_added"]), start, end)
        )
        alert_new = cve in alert_cves
        epss_new = _epss_tier_new(epss, start, end)
        if not (kev_new or alert_new or epss_new):
            continue
        if kev_new:
            label = "KEV"
        elif alert_new:
            label = "ACSC alert"
        else:
            label = "EPSS"
        acted.add(cve)
        act_rows.append(
            (cve, _vuln_bullet(cve, label, rule, matched, kev, epss, records, detail, channel))
        )
    act_rows.sort(key=lambda item: item[0])
    return [bullet for _cve, bullet in act_rows], _movers(records, acted, start, end)


def _epss_tier_new(epss: dict | None, start: datetime, end: datetime) -> bool:
    if not epss:
        return False
    score = float(epss.get("score") or 0)
    previous = epss.get("previous")
    scored = str(epss.get("date") or "")
    if score < EPSS_TIER1 or not scored or not _in_window(scored, start, end):
        return False
    return previous is None or float(previous) < EPSS_TIER1


def _vuln_bullet(
    cve: str,
    label: str,
    rule: str,
    matched: list[Asset],
    kev: dict | None,
    epss: dict | None,
    records: dict[str, dict],
    detail: str,
    channel: str,
) -> Bullet:
    when = ""
    if kev and kev.get("date_added"):
        when = f", added {kev['date_added']}"
    elif epss and epss.get("date"):
        when = f", scored {epss['date']}"
    if channel == "owner":
        shown = matched if detail == "full" else matched[:BRIEF_ASSETS]
        names = "; ".join(
            f"{asset.name} ({asset.vendor} {asset.product}, {asset.exposure}, owner {asset.owner})"
            for asset in shown
        )
        if len(shown) < len(matched):
            names += f"; and {len(matched) - len(shown)} more"
        text = f"{cve} ({label}{when}), rule {rule}, matches {names}."
    else:
        text = f"{cve} ({label}{when}), rule {rule}, matches {_count(matched)}."
    if detail == "full":
        extra = _full_extra(kev, epss, records["nvd"].get(cve))
        if extra:
            text = text[:-1] + ". " + extra
    return Bullet(cve, text)


def _full_extra(kev: dict | None, epss: dict | None, nvd: dict | None) -> str:
    bits: list[str] = []
    if epss and epss.get("score") is not None:
        bits.append(f"EPSS {epss['score']}")
    if nvd and nvd.get("cvss") is not None:
        bits.append(f"CVSS {nvd['cvss']}")
    if kev and kev.get("required_action"):
        bits.append("Action: " + _flatten(kev.get("required_action"), FULL_TEXT))
    cleaned = [bit.rstrip(".") for bit in bits]
    return ". ".join(cleaned) + ("." if cleaned else "")


def _movers(
    records: dict[str, dict], acted: set[str], start: datetime, end: datetime
) -> list[Bullet]:
    bullets: list[Bullet] = []
    for cve, epss in sorted(records["epss"].items()):
        scored = str(epss.get("date") or "")
        if cve in acted or not scored or not _in_window(scored, start, end):
            continue
        previous = epss.get("previous")
        if previous is None:
            continue
        score = float(epss.get("score") or 0)
        if score - float(previous) < EPSS_MOVER:
            continue
        text = f"EPSS mover {cve} from {previous} to {score} on {epss['date']}."
        bullets.append(Bullet(cve, text))
    return bullets


def _alert_bullets(alerts: list[dict], detail: str) -> list[Bullet]:
    bullets: list[Bullet] = []
    for alert in alerts:
        text = f"ASD ACSC alert {alert['id']}, published {alert['published']}: {alert['title']}."
        if detail == "full" and alert["summary"]:
            text = text[:-1] + ". " + alert["summary"]
        bullets.append(Bullet(alert["id"], text))
    return bullets


def _advisory_bullets(advisories: list[dict], detail: str) -> list[Bullet]:
    bullets: list[Bullet] = []
    for advisory in advisories:
        text = (
            f"ASD ACSC advisory {advisory['id']}, published {advisory['published']}: "
            f"{advisory['title']}."
        )
        if detail == "full" and advisory["summary"]:
            text = text[:-1] + ". " + advisory["summary"]
        bullets.append(Bullet(advisory["id"], text))
    return bullets


def _auscert(
    connectors: dict[str, dict], start: datetime, end: datetime, limit: int | None
) -> list[Bullet]:
    bullets: list[Bullet] = []
    for row in _rows(connectors["auscert"], "bulletins"):
        published = str(row.get("published") or "")
        if not published or not _in_window(published, start, end):
            continue
        ident = _flatten(row.get("id"), limit)
        title = _flatten(row.get("title"), limit)
        text = f"AusCERT bulletin {ident}, published {_display(published)}: {title}."
        bullets.append(Bullet(ident, text))
    bullets.sort(key=lambda bullet: bullet.text)
    return bullets


def _techniques(
    connectors: dict[str, dict], start: datetime, end: datetime, limit: int | None
) -> list[Bullet]:
    ranked: list[tuple[int, str, Bullet]] = []
    for row in _rows(connectors["attack"], "techniques"):
        seen = [str(item) for item in row.get("seen") or [] if _in_window(str(item), start, end)]
        if len(seen) < TREND_MIN:
            continue
        ident = _flatten(row.get("id"), limit)
        name = _flatten(row.get("name"), limit)
        text = f"ATT&CK {ident} {name}, {len(seen)} mentions in this window."
        ranked.append((len(seen), ident, Bullet(ident, text)))
    ranked.sort(key=lambda item: (-item[0], item[1]))
    return [item[2] for item in ranked]


def _watchlist(
    connectors: dict[str, dict],
    start: datetime,
    end: datetime,
    channel: str,
    limit: int | None,
    assets: list[Asset],
) -> list[Bullet]:
    by_name = {asset.name.casefold(): asset for asset in assets}
    public: list[Bullet] = []
    owned: list[tuple[dict, Asset]] = []
    for row in _rows(connectors["intel-store"], "hits"):
        seen = str(row.get("seen") or "")
        if not seen or not _in_window(seen, start, end):
            continue
        claimed = _flatten(row.get("asset"), None)
        asset = by_name.get(claimed.casefold()) if claimed else None
        if asset is not None:
            owned.append((row, asset))
            continue
        ident = _flatten(row.get("id"), limit)
        kind = _flatten(row.get("kind"), limit)
        value = _flatten(row.get("value"), limit)
        text = f"{ident}, {kind} {value}, seen {_display(seen)}."
        public.append(Bullet(ident, text))
    public.sort(key=lambda bullet: bullet.text)
    if not owned:
        return public
    if channel == "owner":
        owned_bullets = []
        for row, asset in sorted(owned, key=lambda item: str(item[0].get("id"))):
            ident = _flatten(row.get("id"), limit)
            kind = _flatten(row.get("kind"), limit)
            value = _flatten(row.get("value"), limit)
            text = (
                f"{ident}, {kind} {value}, asset {asset.name} ({asset.exposure}), "
                f"seen {_display(str(row.get('seen')))}."
            )
            owned_bullets.append(Bullet(ident, text))
        return owned_bullets + public
    internet = sum(1 for _row, asset in owned if asset.exposure == "internet")
    internal = sum(1 for _row, asset in owned if asset.exposure == "internal")
    noun = "hit" if len(owned) == 1 else "hits"
    text = f"{len(owned)} watchlist {noun} on inventoried assets"
    bits = _exposure_bits(internet, internal)
    if bits:
        text += f" ({bits})"
    return [Bullet("watchlist-assets", text + "."), *public]


def _internet(
    connectors: dict[str, dict], start: datetime, end: datetime, limit: int | None
) -> list[str]:
    brief = limit is not None
    item = connectors["cloudflare-radar"]
    if item.get("status") != "ok":
        return ["Not available in this run."]
    outages = []
    for row in _rows(item, "outages"):
        # get_radar_annotations_outages returns start, locations and cause. Older packs
        # carry started, location and name.
        started = str(row.get("started") or row.get("start") or "")
        if not started or not _in_window(started, start, end):
            continue
        places = row.get("locations") if isinstance(row.get("locations"), list) else []
        if not any(_is_au(str(place or "")) for place in [row.get("location"), *places]):
            continue
        outages.append(
            {**row, "started": started, "name": row.get("name") or row.get("cause") or "outage"}
        )
    attacks = []
    for row in _rows(item, "attacks"):
        seen = str(row.get("seen") or "")
        if not seen or not _in_window(seen, start, end):
            continue
        if not _is_au(str(row.get("location") or "")):
            continue
        attacks.append(row)
    if not outages and not attacks:
        return ["Cloudflare Radar reported nothing in this window."]
    lines: list[str] = []
    shown = outages if not brief else outages[:BRIEF_OUTAGES]
    for row in shown:
        name = _flatten(row.get("name"), limit if brief else FULL_TEXT)
        lines.append(
            f"Cloudflare Radar. Outage: {name}, AU, started {_display(str(row.get('started')))}."
        )
    if brief and len(outages) > BRIEF_OUTAGES:
        extra = len(outages) - BRIEF_OUTAGES
        lines.append(f"{extra} more outages are in the full briefing.")
    shown_attacks = attacks if not brief else attacks[:1]
    for row in shown_attacks:
        layer = _flatten(row.get("layer"), limit if brief else FULL_TEXT)
        change = _flatten(row.get("change"), limit if brief else FULL_TEXT)
        lines.append(f"Cloudflare Radar. {layer}-layer attacks: {change}.")
    if brief and len(attacks) > 1:
        lines.append(f"{len(attacks) - 1} more attack summaries are in the full briefing.")
    return lines


def _is_au(location: str) -> bool:
    return location.casefold().strip() in {"au", "australia"}


def _sources(connectors: dict[str, dict]) -> tuple[list[str], list[str]]:
    lines: list[str] = []
    missing: list[str] = []
    for key, label in SOURCES:
        item = connectors[key]
        if item.get("status") != "ok":
            missing.append(key)
            continue
        lines.append(f"{label}, retrieved {_retrieved(item)}.")
    missing.sort()
    return lines, missing


def _headline(as_of: datetime, bullets: list[Bullet]) -> str:
    when = f"{WEEKDAYS[as_of.weekday()]} {as_of.day} {MONTHS[as_of.month]} {as_of.year}"
    if not bullets:
        return f"{when}: nothing needs action today."
    noun = "item" if len(bullets) == 1 else "items"
    verb = "needs" if len(bullets) == 1 else "need"
    return f"{when}: {len(bullets)} {noun} {verb} action today, led by {bullets[0].label}."


def _count(assets: list[Asset]) -> str:
    internet = sum(1 for asset in assets if asset.exposure == "internet")
    internal = sum(1 for asset in assets if asset.exposure == "internal")
    noun = "asset" if len(assets) == 1 else "assets"
    return f"{len(assets)} {noun} ({_exposure_bits(internet, internal)})"


def _exposure_bits(internet: int, internal: int) -> str:
    parts: list[str] = []
    if internet:
        parts.append(f"{internet} internet-facing")
    if internal:
        parts.append(f"{internal} internal")
    return ", ".join(parts)


def _cap(bullets: list[Bullet], limit: int | None) -> list[str]:
    if limit is None or len(bullets) <= limit:
        return [bullet.text for bullet in bullets]
    shown = [bullet.text for bullet in bullets[:limit]]
    extra = len(bullets) - limit
    noun = "item" if extra == 1 else "items"
    shown.append(f"{extra} more {noun} are in the full briefing.")
    return shown


def _body(lines: list[str]) -> str:
    if not lines:
        return "None in this window."
    return "\n".join(f"- {line}" if not line.startswith("- ") else line for line in lines)


if __name__ == "__main__":
    sys.exit(main())
