"""MISP core format export for the local intel store.

``cyberau-mcp store export --format misp`` writes one MISP event per advisory, with the
indicators and CVEs linked to that advisory as attributes, plus one event for indicators
that no exported advisory links to. The files follow the MISP core format
(draft-dulaunoy-misp-core-format) and are laid out as a MISP feed directory: one
``<event uuid>.json`` per event and a ``manifest.json`` index, so a MISP instance can read
the directory as a local feed.

Nothing is sent anywhere. Events are written with ``published: false`` and distribution
``0`` (your organisation only), so sharing is decided by a person in MISP after import.

TLP works like the record and DuckDB exports: the ceiling defaults to ``GREEN`` and
``--max-tlp`` raises or lowers it. Every event and attribute carries a ``tlp:`` tag from
the MISP ``tlp`` taxonomy. An event is tagged with the most restrictive marking of its
advisory and its attributes. A ceiling above ``GREEN`` is written to the audit log first
and the export fails closed if that write fails. See ``docs/intel/misp-export.md``.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import uuid
from datetime import UTC, datetime
from pathlib import Path

from .canonical import (
    EXPORT_DEFAULT_TLP,
    TLP_RANK,
    more_restrictive,
    require_tlp,
    tlp_allows,
)
from .db import open_store, store_data_dir
from .stix import SDO_NAMESPACE, export_audit_log, organisation_name
from .text import unwrap_untrusted

MISP_NAMESPACE = uuid.uuid5(SDO_NAMESPACE, "urn:cyber-au:misp")
MANIFEST = "manifest.json"
# MISP taxonomy "tlp" (MISP/misp-taxonomies, tlp/machinetag.json, version 10).
TLP_TAGS = {
    "CLEAR": ("tlp:clear", "#ffffff"),
    "GREEN": ("tlp:green", "#33FF00"),
    "AMBER": ("tlp:amber", "#FFC000"),
    "AMBER+STRICT": ("tlp:amber+strict", "#FFC000"),
    "RED": ("tlp:red", "#FF2B2B"),
}
# Store indicator type to MISP (type, category). Every pair is valid in the category and
# type table of the MISP core format draft.
ATTRIBUTE_TYPES = {
    "ipv4": ("ip-dst", "Network activity"),
    "ipv6": ("ip-dst", "Network activity"),
    "cidr": ("ip-dst", "Network activity"),
    "domain": ("domain", "Network activity"),
    "url": ("url", "Network activity"),
    "asn": ("AS", "Network activity"),
    "email": ("email-src", "Payload delivery"),
    "md5": ("md5", "Payload delivery"),
    "sha1": ("sha1", "Payload delivery"),
    "sha256": ("sha256", "Payload delivery"),
}
_DISTRIBUTION_ORG_ONLY = "0"
_DISTRIBUTION_INHERIT = "5"
_THREAT_UNDEFINED = "4"
_ANALYSIS_INITIAL = "0"
_INFO_MAX = 256
_COMMENT_MAX = 1000
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")


def export_misp(
    *,
    output: str | None = None,
    max_tlp: str | None = None,
    store: str | Path | None = None,
) -> dict:
    """Write MISP core format events to a feed directory and return a summary."""
    ceiling = EXPORT_DEFAULT_TLP if max_tlp is None else require_tlp(max_tlp)
    requested = output or f"misp-{datetime.now(UTC).date().isoformat()}"
    destination = resolve_export_dir(requested, store)
    relative = destination.relative_to(store_data_dir(store).resolve()).as_posix()
    events, omitted = build_events(max_tlp=ceiling, store=store)
    attribute_count = sum(len(item["Event"]["Attribute"]) for item in events)
    if TLP_RANK[ceiling] > TLP_RANK[EXPORT_DEFAULT_TLP]:
        # Fail closed: nothing is written unless the audit record is.
        export_audit_log(store).record(
            "export",
            tool="store_export_misp",
            args={
                "attribute_count": attribute_count,
                "event_count": len(events),
                "explicit_max_tlp": max_tlp is not None,
                "format": "misp",
                "max_tlp": ceiling,
                "output": relative,
            },
        )
    _write_feed(destination, events)
    return {
        "attributes": attribute_count,
        "events": len(events),
        "explicit_max_tlp": max_tlp is not None,
        "format": "misp",
        "max_tlp": ceiling,
        "omitted_above_tlp": omitted,
        "output": relative,
    }


def build_events(*, max_tlp: str, store: str | Path | None = None) -> tuple[list[dict], dict]:
    """Build the events in memory. Returns the events and the withheld counts."""
    ceiling = require_tlp(max_tlp)
    conn = open_store(store).connection()
    organisation = organisation_name()
    orgc = {
        "name": organisation,
        "uuid": str(uuid.uuid5(MISP_NAMESPACE, f"org:{organisation}")),
    }
    indicators: dict[str, dict] = {}
    withheld_indicators = 0
    for row in conn.execute("SELECT * FROM indicators ORDER BY id"):
        if not tlp_allows(row["tlp"], ceiling):
            withheld_indicators += 1
            continue
        if row["type"] not in ATTRIBUTE_TYPES:
            continue
        record = dict(row)
        record["sources"] = sorted(
            {
                item[0]
                for item in conn.execute(
                    "SELECT source_id FROM observations WHERE indicator_id = ?"
                    " UNION SELECT source_id FROM indicator_counters WHERE indicator_id = ?",
                    (row["id"], row["id"]),
                )
            }
        )
        indicators[row["id"]] = record
    advisories: list[dict] = []
    withheld_advisories = 0
    for row in conn.execute(
        """
        SELECT a.*, s.default_tlp AS tlp
        FROM advisories a JOIN sources s ON s.id = a.source_id
        ORDER BY a.id
        """
    ):
        if not tlp_allows(row["tlp"], ceiling):
            withheld_advisories += 1
            continue
        advisories.append(dict(row))
    links: dict[str, list[str]] = {}
    for row in conn.execute(
        "SELECT advisory_id, ref FROM advisory_refs ORDER BY advisory_id, ref_type, ref"
    ):
        links.setdefault(row["advisory_id"], []).append(row["ref"])
    for row in conn.execute("SELECT src_id, dst_id FROM relationships ORDER BY src_id, dst_id"):
        links.setdefault(row["src_id"], []).append(row["dst_id"])
        links.setdefault(row["dst_id"], []).append(row["src_id"])

    events: list[dict] = []
    linked: set[str] = set()
    for advisory in advisories:
        refs = links.get(advisory["id"], [])
        members = [indicators[ref] for ref in dict.fromkeys(refs) if ref in indicators]
        cves = sorted({ref.upper() for ref in refs if _CVE.fullmatch(ref.upper())})
        linked.update(item["id"] for item in members)
        events.append(_advisory_event(advisory, members, cves, orgc))
    loose = [record for key, record in indicators.items() if key not in linked]
    if loose:
        events.append(_indicator_event(loose, orgc))
    events.sort(key=lambda item: item["Event"]["uuid"])
    return events, {"advisories": withheld_advisories, "indicators": withheld_indicators}


def resolve_export_dir(requested: str, store: str | Path | None = None) -> Path:
    """Resolve a feed directory name under ``exports``. Only a plain name is accepted."""
    message = "MISP export name must be a plain directory name under plugin-data/cyber-au/exports"
    if not isinstance(requested, str) or not _NAME.fullmatch(requested) or ".." in requested:
        raise ValueError(message)
    unresolved = store_data_dir(store) / "exports"
    if unresolved.is_symlink():
        raise ValueError(message)
    candidate = unresolved / requested
    if candidate.is_symlink():
        raise ValueError("refusing to write through a symlink")
    if candidate.exists() and not candidate.is_dir():
        raise ValueError("MISP export path exists and is not a directory")
    return unresolved.resolve() / requested


def _advisory_event(advisory: dict, members: list[dict], cves: list[str], orgc: dict) -> dict:
    event_uuid = _uuid(f"event:advisory:{advisory['id']}")
    published = advisory["published_at"] or advisory["first_seen"]
    attributes = [
        _attribute(
            event_uuid,
            "link",
            "External analysis",
            advisory["url"],
            advisory["tlp"],
            stamp=published,
            comment=f"advisory {advisory['id']} from {advisory['source_id']}",
        )
    ]
    summary = unwrap_untrusted(advisory["summary"]) if advisory["summary"] else None
    if summary:
        attributes.append(
            _attribute(
                event_uuid,
                "text",
                "External analysis",
                summary,
                advisory["tlp"],
                stamp=published,
                comment="advisory summary, untrusted upstream text",
            )
        )
    for cve in cves:
        attributes.append(
            _attribute(event_uuid, "vulnerability", "External analysis", cve, "CLEAR", published)
        )
    attributes.extend(_indicator_attribute(event_uuid, record) for record in members)
    marking = advisory["tlp"]
    for record in members:
        marking = more_restrictive(marking, record["tlp"])
    stamps = [published, *(record["last_seen"] for record in members)]
    return _event(
        event_uuid,
        info=advisory["title"],
        date=published[:10],
        timestamp=max(stamps),
        marking=marking,
        orgc=orgc,
        attributes=attributes,
    )


def _indicator_event(records: list[dict], orgc: dict) -> dict:
    event_uuid = _uuid(f"event:indicators:{orgc['uuid']}")
    marking = "CLEAR"
    for record in records:
        marking = more_restrictive(marking, record["tlp"])
    latest = max(record["last_seen"] for record in records)
    return _event(
        event_uuid,
        info="Intel store indicators not linked to an exported advisory",
        date=latest[:10],
        timestamp=latest,
        marking=marking,
        orgc=orgc,
        attributes=[_indicator_attribute(event_uuid, record) for record in records],
    )


def _event(
    event_uuid: str,
    *,
    info: str,
    date: str,
    timestamp: str,
    marking: str,
    orgc: dict,
    attributes: list[dict],
) -> dict:
    attributes.sort(key=lambda item: item["uuid"])
    return {
        "Event": {
            "uuid": event_uuid,
            "info": _one_line(info, _INFO_MAX) or "Untitled advisory",
            "date": date,
            "threat_level_id": _THREAT_UNDEFINED,
            "analysis": _ANALYSIS_INITIAL,
            "distribution": _DISTRIBUTION_ORG_ONLY,
            "sharing_group_id": "0",
            "published": False,
            "timestamp": _unix(timestamp),
            "publish_timestamp": "0",
            "attribute_count": str(len(attributes)),
            "Orgc": dict(orgc),
            "Tag": [_tag(marking)],
            "Attribute": attributes,
        }
    }


def _indicator_attribute(event_uuid: str, record: dict) -> dict:
    kind, category = ATTRIBUTE_TYPES[record["type"]]
    verdict = record["verdict"] or "unknown"
    parts = [f"verdict {verdict}"]
    if record["confidence"] is not None:
        parts.append(f"confidence {record['confidence']}")
    if record["sources"]:
        parts.append("sources " + ", ".join(record["sources"]))
    attribute = _attribute(
        event_uuid,
        kind,
        category,
        record["value_norm"],
        record["tlp"],
        stamp=record["last_seen"],
        comment="; ".join(parts),
        to_ids=verdict == "malicious",
    )
    attribute["first_seen"] = _misp_time(record["first_seen"])
    attribute["last_seen"] = _misp_time(record["last_seen"])
    return attribute


def _attribute(
    event_uuid: str,
    kind: str,
    category: str,
    value: str,
    marking: str,
    stamp: str,
    *,
    comment: str = "",
    to_ids: bool = False,
) -> dict:
    return {
        "uuid": _uuid(f"attribute:{event_uuid}:{kind}:{value}"),
        "type": kind,
        "category": category,
        "value": value,
        "to_ids": to_ids,
        "distribution": _DISTRIBUTION_INHERIT,
        "timestamp": _unix(stamp),
        "comment": _one_line(comment, _COMMENT_MAX),
        "deleted": False,
        "disable_correlation": False,
        "Tag": [_tag(marking)],
    }


def _tag(marking: str) -> dict:
    name, colour = TLP_TAGS[require_tlp(marking)]
    return {"name": name, "colour": colour, "exportable": True}


def _write_feed(destination: Path, events: list[dict]) -> None:
    parent = destination.parent
    parent.mkdir(parents=True, exist_ok=True)
    partial = parent / (destination.name + ".partial")
    previous = parent / (destination.name + ".previous")
    for path in (partial, previous):
        if path.is_symlink():
            raise ValueError("refusing to write through a symlink")
        if path.exists():
            shutil.rmtree(path)
    partial.mkdir(mode=0o700)
    try:
        manifest: dict[str, dict] = {}
        for item in events:
            event = item["Event"]
            text = json.dumps(item, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
            (partial / f"{event['uuid']}.json").write_text(text, encoding="utf-8")
            manifest[event["uuid"]] = {
                "Orgc": event["Orgc"],
                "Tag": event["Tag"],
                "analysis": event["analysis"],
                "date": event["date"],
                "info": event["info"],
                "integrity:sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
                "threat_level_id": event["threat_level_id"],
                "timestamp": event["timestamp"],
            }
        (partial / MANIFEST).write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        if destination.exists():
            os.replace(destination, previous)
        os.replace(partial, destination)
    except BaseException:
        shutil.rmtree(partial, ignore_errors=True)
        raise
    shutil.rmtree(previous, ignore_errors=True)


def _uuid(key: str) -> str:
    return str(uuid.uuid5(MISP_NAMESPACE, key))


def _parse(stamp: str) -> datetime:
    return datetime.fromisoformat(stamp.replace("Z", "+00:00")).astimezone(UTC)


def _unix(stamp: str) -> str:
    return str(int(_parse(stamp).timestamp()))


def _misp_time(stamp: str) -> str:
    return _parse(stamp).isoformat(timespec="microseconds")


def _one_line(value: str, limit: int) -> str:
    return " ".join(str(value).split())[:limit]


__all__ = [
    "ATTRIBUTE_TYPES",
    "MANIFEST",
    "MISP_NAMESPACE",
    "TLP_TAGS",
    "build_events",
    "export_misp",
    "resolve_export_dir",
]
