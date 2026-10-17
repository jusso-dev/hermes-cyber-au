"""STIX 2.1 export and import for the local intel store.

Observable ids are the ids already stored on indicators. Domain objects use
a separate namespace. TLP:AMBER is included only when ``max_tlp`` asks for
it. TLP:AMBER+STRICT and TLP:RED are never written into a bundle.

See ``docs/intel/stix.md`` and ``docs/adr/0001-stix-sightings.md``.
"""

from __future__ import annotations

import copy
import json
import os
import re
import uuid
from collections.abc import Sequence
from pathlib import Path

from .api import (
    ensure_source,
    lookup,
    upsert_advisory,
    upsert_indicator,
    upsert_vulnerability,
)
from .canonical import (
    HASH_NAMES,
    SCO_TYPES,
    canonical_date,
    canonical_timestamp,
    more_restrictive,
    tlp_allows,
    utc_now,
)
from .db import open_store, resolve_db_path
from .text import clean_untrusted, unwrap_untrusted

# RFC 4122 URL namespace. Domain objects must not use the SCO namespace.
_URL_NAMESPACE = uuid.UUID("6ba7b811-9dad-11d1-80b4-00c04fd430c8")
SDO_NAMESPACE = uuid.uuid5(_URL_NAMESPACE, "urn:cyber-au:stix:sdo")
PRODUCER_TIMESTAMP = "2020-01-01T00:00:00.000Z"
STIX_TLP = ("CLEAR", "GREEN", "AMBER")
EXPORT_TYPES = ("ipv4", "ipv6", "domain", "url", "email", "md5", "sha1", "sha256")
_HASH_TO_STORE = {"MD5": "md5", "SHA-1": "sha1", "SHA-256": "sha256"}
_STORE_TO_SCO = {name: SCO_TYPES[name] for name in EXPORT_TYPES if name not in HASH_NAMES}
_INDICATOR_TYPES = {
    "malicious": "malicious-activity",
    "suspicious": "anomalous-activity",
}
_REL = re.compile(r"^[a-z0-9-]{1,64}$")
_SOURCE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_ORG_KEY = re.compile(r"^\s+organisation:\s*(.+?)\s*$")
_CYBER_AU = re.compile(r"^cyber_au:\s*$")

# OASIS CTI TC, cti-stix-common-objects, extension-definition-specifications/tlp-2.0.
# Ids are copied from the published examples. AMBER+STRICT and RED are listed
# so a bundle can be checked for them. Their objects are never emitted.
TLP_EXTENSION_ID = "extension-definition--60a3c5c5-0d10-413e-aab3-9e08dde9e88d"
TLP_NOT_EXPORTED = {
    "AMBER+STRICT": "marking-definition--939a9414-2ddd-4d32-a0cd-375ea402b003",
    "RED": "marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1",
}
_TLP_EXTENSION = {
    "created": "2022-10-01T00:00:00.000Z",
    "created_by_ref": "identity--b3bca3c2-1f3d-4b54-b44f-dac42c3a8f01",
    "description": "This defines TLP 2.0 as a STIX extension",
    "extension_types": ["property-extension"],
    "id": TLP_EXTENSION_ID,
    "modified": "2022-10-01T00:00:00.000Z",
    "name": "TLP 2.0",
    "schema": (
        "https://github.com/oasis-open/cti-stix-common-objects/tree/master/"
        "extension-definition-specifications/tlp-2.0"
    ),
    "spec_version": "2.1",
    "type": "extension-definition",
    "version": "1.0.0",
}
_TLP_MARKINGS = {
    "CLEAR": {
        "created": "2022-10-01T00:00:00.000Z",
        "extensions": {
            TLP_EXTENSION_ID: {"extension_type": "property-extension", "tlp_2_0": "clear"}
        },
        "id": "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "name": "TLP:CLEAR",
        "spec_version": "2.1",
        "type": "marking-definition",
    },
    "GREEN": {
        "created": "2022-10-01T00:00:00.000Z",
        "extensions": {
            TLP_EXTENSION_ID: {"extension_type": "property-extension", "tlp_2_0": "green"}
        },
        "id": "marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb",
        "name": "TLP:GREEN",
        "spec_version": "2.1",
        "type": "marking-definition",
    },
    "AMBER": {
        "created": "2022-10-01T00:00:00.000Z",
        "extensions": {
            TLP_EXTENSION_ID: {"extension_type": "property-extension", "tlp_2_0": "amber"}
        },
        "id": "marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421",
        "name": "TLP:AMBER",
        "spec_version": "2.1",
        "type": "marking-definition",
    },
}
_MARKING_TO_TLP = {body["id"]: name for name, body in _TLP_MARKINGS.items()}


def export_stix(
    *,
    since: str | None = None,
    kinds: Sequence[str] | None = None,
    max_tlp: str | None = None,
    output: str | None = None,
    store: str | Path | None = None,
) -> dict:
    """Build a deterministic STIX 2.1 bundle and optionally write it."""
    chosen = _require_kinds(kinds)
    ceiling, explicit = _require_stix_tlp(max_tlp)
    earliest = None if since is None else canonical_timestamp(canonical_date(since))
    destination = None if output is None else resolve_export_path(output, store)
    organisation = organisation_name()
    producer_id = _sdo_id("identity", organisation)
    loaded = _load(store, chosen, ceiling, earliest)
    objects = _bundle_objects(loaded, producer_id, organisation)
    bundle = {
        "id": _bundle_id([item["id"] for item in objects]),
        "objects": objects,
        "type": "bundle",
    }
    text = json.dumps(bundle, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    relative = None
    if destination is not None:
        _write_export(destination, text)
        relative = destination.resolve().relative_to(_data_dir(store).resolve()).as_posix()
    if ceiling == "AMBER":
        _audit_amber(store, explicit, len(objects), relative)
    return {
        "bundle": bundle,
        "explicit_max_tlp": explicit,
        "max_tlp": ceiling,
        "object_count": len(objects),
        "omitted_above_tlp": loaded["omitted_above_tlp"],
        "omitted_unsupported": loaded["omitted_unsupported"],
        "output": relative,
        "text": text,
    }


def import_stix(bundle: dict, *, path: str | Path | None = None) -> dict[str, int]:
    """Replay a bundle produced by :func:`export_stix` into the store."""
    if not isinstance(bundle, dict) or bundle.get("type") != "bundle":
        raise ValueError("STIX import expects a bundle")
    objects = bundle.get("objects")
    if not isinstance(objects, list):
        raise ValueError("STIX bundle is missing objects")
    indicators = _import_indicators(objects, path)
    vulnerabilities = _import_vulnerabilities(objects, path)
    advisories = _import_advisories(objects, path)
    relationships = _import_relationships(objects, path)
    return {
        "advisories": advisories,
        "indicators": indicators,
        "relationships": relationships,
        "vulnerabilities": vulnerabilities,
    }


def import_stix_file(file: str | Path, *, path: str | Path | None = None) -> dict[str, int]:
    """Read a bundle file and import it. The file is local data, not instructions."""
    text = Path(file).read_text(encoding="utf-8")
    try:
        bundle = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError("STIX bundle is not JSON") from exc
    return import_stix(bundle, path=path)


def organisation_name() -> str:
    """Name of the exporting organisation, from the environment or config."""
    env = os.environ.get("CYBERAU_ORG_NAME")
    if env is not None and env.strip():
        return _clean_org(env)
    for candidate in _config_paths():
        if not candidate.is_file():
            continue
        found = _org_in_config(candidate.read_text(encoding="utf-8"))
        if found:
            return _clean_org(found)
    return "cyber-au"


def resolve_export_path(requested: str, store: str | Path | None = None) -> Path:
    """Resolve a bundle path and refuse anything outside ``exports``."""
    if not isinstance(requested, str) or not requested.strip() or "\x00" in requested:
        raise ValueError("export path must stay under plugin-data/cyber-au/exports")
    root = (_data_dir(store) / "exports").resolve()
    if root.is_symlink():
        raise ValueError("export path must stay under plugin-data/cyber-au/exports")
    raw = Path(requested)
    if any(part == ".." for part in raw.parts):
        raise ValueError("export path must stay under plugin-data/cyber-au/exports")
    candidate = raw if raw.is_absolute() else root / raw
    resolved = candidate.resolve()
    if resolved != root and root not in resolved.parents:
        raise ValueError("export path must stay under plugin-data/cyber-au/exports")
    if resolved.suffix.lower() != ".json":
        raise ValueError("STIX export file must end in .json")
    if resolved.exists() and resolved.is_dir():
        raise ValueError("export path must be a file")
    return resolved


def _bundle_objects(loaded: dict, producer_id: str, organisation: str) -> list[dict]:
    objects: list[dict] = [
        {
            "created": PRODUCER_TIMESTAMP,
            "id": producer_id,
            "identity_class": "organization",
            "modified": PRODUCER_TIMESTAMP,
            "name": organisation,
            "spec_version": "2.1",
            "type": "identity",
        }
    ]
    markings: set[str] = set()
    index: dict[str, dict] = {}
    for record in loaded["indicators"]:
        sco, indicator, sightings = _indicator_objects(record, producer_id)
        markings.add(record["tlp"])
        objects.append(sco)
        index[record["id"]] = {"stix_id": sco["id"], "tlp": record["tlp"]}
        if indicator is not None:
            objects.append(indicator)
            objects.extend(sightings)
    for record in loaded["vulnerabilities"]:
        item = _vulnerability_object(record, producer_id)
        markings.add("CLEAR")
        objects.append(item)
        index[record["id"]] = {"stix_id": item["id"], "tlp": "CLEAR"}
    for record in loaded["advisories"]:
        item = _report_object(record, loaded["refs"].get(record["id"], []), index, producer_id)
        markings.add(record["tlp"])
        objects.append(item)
        index[record["id"]] = {"stix_id": item["id"], "tlp": record["tlp"]}
    for row in loaded["relationships"]:
        item = _relationship_object(row, index, producer_id)
        if item is None:
            continue
        objects.append(item)
    if markings:
        objects.append(copy.deepcopy(_TLP_EXTENSION))
        for name in sorted(markings):
            objects.append(copy.deepcopy(_TLP_MARKINGS[name]))
    objects.sort(key=lambda item: item["id"])
    return objects


def _indicator_objects(record: dict, producer_id: str) -> tuple[dict, dict | None, list[dict]]:
    marking = _TLP_MARKINGS[record["tlp"]]["id"]
    sco = _sco(record, marking)
    sources = [_source_item(record, item) for item in record["observations"]]
    verdict = record["verdict"] or "unknown"
    indicator = None
    sightings: list[dict] = []
    if verdict in _INDICATOR_TYPES:
        indicator_id = _sdo_id("indicator", record["id"])
        created = _stix_time(record["first_seen"])
        modified = _later(created, _stix_time(record["last_seen"]))
        indicator = {
            "confidence": record["confidence"] if record["confidence"] is not None else 0,
            "created": created,
            "created_by_ref": producer_id,
            "id": indicator_id,
            "indicator_types": [_INDICATOR_TYPES[verdict]],
            "labels": [verdict],
            "modified": modified,
            "object_marking_refs": [marking],
            "pattern": _pattern(record["type"], record["value_norm"]),
            "pattern_type": "stix",
            "spec_version": "2.1",
            "type": "indicator",
            "valid_from": created,
            "x_cyberau_sco_ref": record["id"],
            "x_cyberau_sources": sources,
            "x_cyberau_verdict": verdict,
        }
        for item in record["observations"]:
            if item["source_id"] != "analyst":
                continue
            sightings.append(_sighting(record, item, indicator_id, producer_id, marking))
    else:
        sco["x_cyberau_sources"] = sources
    return sco, indicator, sightings


def _sco(record: dict, marking: str) -> dict:
    sco: dict = {
        "id": record["id"],
        "object_marking_refs": [marking],
        "spec_version": "2.1",
        "x_cyberau_confidence": 0 if record["confidence"] is None else record["confidence"],
        "x_cyberau_first_seen": record["first_seen"],
        "x_cyberau_last_seen": record["last_seen"],
        "x_cyberau_store_type": record["type"],
        "x_cyberau_tlp": record["tlp"],
        "x_cyberau_value": record["value"],
        "x_cyberau_verdict": record["verdict"] or "unknown",
    }
    if record["type"] in HASH_NAMES:
        sco["type"] = "file"
        sco["hashes"] = {HASH_NAMES[record["type"]]: record["value_norm"]}
    else:
        sco["type"] = _STORE_TO_SCO[record["type"]]
        sco["value"] = record["value_norm"]
    return sco


def _source_item(record: dict, observation: dict) -> dict:
    item: dict = {
        "observed_at": observation["observed_at"],
        "source_id": observation["source_id"],
        "value": record["value"],
    }
    if observation["source_ref"]:
        item["source_ref"] = observation["source_ref"]
    if observation["verdict"]:
        item["verdict"] = observation["verdict"]
    if observation["confidence"] is not None:
        item["confidence"] = observation["confidence"]
    if observation["tags"]:
        item["tags"] = list(observation["tags"])
    note = unwrap_untrusted(observation["note"]) if observation["note"] else None
    if note:
        item["note"] = note
    return item


def _sighting(
    record: dict, observation: dict, indicator_id: str, producer_id: str, marking: str
) -> dict:
    seen = _stix_time(observation["observed_at"])
    key = json.dumps(
        {
            "confidence": observation["confidence"],
            "indicator": record["id"],
            "note": unwrap_untrusted(observation["note"]) if observation["note"] else None,
            "observed_at": observation["observed_at"],
            "source_id": observation["source_id"],
            "source_ref": observation["source_ref"],
            "tags": list(observation["tags"]),
            "verdict": observation["verdict"],
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    sighting = {
        "count": 1,
        "created": seen,
        "created_by_ref": producer_id,
        "first_seen": seen,
        "id": _sdo_id("sighting", key),
        "last_seen": seen,
        "modified": seen,
        "object_marking_refs": [marking],
        "sighting_of_ref": indicator_id,
        "spec_version": "2.1",
        "type": "sighting",
        "where_sighted_refs": [producer_id],
        "x_cyberau_source_id": observation["source_id"],
    }
    if observation["verdict"]:
        sighting["x_cyberau_verdict"] = observation["verdict"]
    return sighting


def _vulnerability_object(record: dict, producer_id: str) -> dict:
    stamped = _stix_time(record["updated_at"])
    item = {
        "created": stamped,
        "created_by_ref": producer_id,
        "external_references": [{"external_id": record["cve_id"], "source_name": "cve"}],
        "id": _sdo_id("vulnerability", record["cve_id"]),
        "modified": stamped,
        "name": record["cve_id"],
        "object_marking_refs": [_TLP_MARKINGS["CLEAR"]["id"]],
        "spec_version": "2.1",
        "type": "vulnerability",
    }
    kev = _compact(
        {
            "date_added": record["kev_date_added"],
            "due_date": record["kev_due_date"],
            "ransomware": record["kev_ransomware"],
        }
    )
    if kev:
        item["x_cyberau_kev"] = kev
    epss = _compact(
        {
            "date": record["epss_date"],
            "epss": record["epss"],
            "percentile": record["epss_percentile"],
        }
    )
    if epss:
        item["x_cyberau_epss"] = epss
    if record["cvss_v3"] is not None:
        item["x_cyberau_cvss_v3"] = record["cvss_v3"]
    if record["cvss_v4"] is not None:
        item["x_cyberau_cvss_v4"] = record["cvss_v4"]
    if record["cwe"]:
        item["x_cyberau_cwe"] = record["cwe"]
    return item


def _report_object(record: dict, refs: list[str], index: dict[str, dict], producer_id: str) -> dict:
    created = _stix_time(record["first_seen"])
    published = _stix_time(record["published_at"] or record["first_seen"])
    object_refs = sorted({index[ref]["stix_id"] for ref in refs if ref in index} or {producer_id})
    item = {
        "created": created,
        "created_by_ref": producer_id,
        "external_references": [{"source_name": record["source_id"], "url": record["url"]}],
        "id": _sdo_id("report", record["id"]),
        "modified": _later(created, published),
        "name": record["title"],
        "object_marking_refs": [_TLP_MARKINGS[record["tlp"]]["id"]],
        "object_refs": object_refs,
        "published": published,
        "report_types": ["threat-report"],
        "spec_version": "2.1",
        "type": "report",
        "x_cyberau_advisory_id": record["id"],
    }
    summary = unwrap_untrusted(record["summary"]) if record["summary"] else None
    if summary:
        item["description"] = summary
    return item


def _relationship_object(row: dict, index: dict[str, dict], producer_id: str) -> dict | None:
    left = index.get(row["src_id"])
    right = index.get(row["dst_id"])
    if left is None or right is None or not _REL.fullmatch(row["rel"] or ""):
        return None
    stamped = _stix_time(row["first_seen"]) if row["first_seen"] else PRODUCER_TIMESTAMP
    marking = _TLP_MARKINGS[more_restrictive(left["tlp"], right["tlp"])]["id"]
    item = {
        "created": stamped,
        "created_by_ref": producer_id,
        "id": _sdo_id("relationship", f"{row['src_id']}|{row['rel']}|{row['dst_id']}"),
        "modified": stamped,
        "object_marking_refs": [marking],
        "relationship_type": row["rel"],
        "source_ref": left["stix_id"],
        "spec_version": "2.1",
        "target_ref": right["stix_id"],
        "type": "relationship",
        "x_cyberau_dst_id": row["dst_id"],
        "x_cyberau_rel": row["rel"],
        "x_cyberau_src_id": row["src_id"],
    }
    if row["source_id"] and _SOURCE.fullmatch(row["source_id"]):
        item["x_cyberau_source_id"] = row["source_id"]
    return item


def _load(
    store: str | Path | None,
    kinds: tuple[str, ...],
    ceiling: str,
    earliest: str | None,
) -> dict:
    handle = open_store(store)
    conn = handle.connection()
    omitted_above = 0
    omitted_unsupported = 0
    indicators: list[dict] = []
    if "indicator" in kinds:
        rows = list(conn.execute("SELECT id, type, tlp, last_seen FROM indicators ORDER BY id"))
        for row in rows:
            if earliest is not None and row["last_seen"] < earliest:
                continue
            if not tlp_allows(row["tlp"], ceiling):
                omitted_above += 1
                continue
            if row["type"] not in EXPORT_TYPES:
                omitted_unsupported += 1
                continue
            indicators.append(_one(store, "indicator", row["id"]))
    advisories: list[dict] = []
    if "advisory" in kinds:
        rows = list(
            conn.execute(
                """
                SELECT a.id, a.published_at, a.first_seen, s.default_tlp AS tlp
                FROM advisories a JOIN sources s ON s.id = a.source_id
                ORDER BY a.id
                """
            )
        )
        for row in rows:
            moment = row["published_at"] or row["first_seen"]
            if earliest is not None and moment < earliest:
                continue
            if not tlp_allows(row["tlp"], ceiling):
                omitted_above += 1
                continue
            advisories.append(_one(store, "advisory", row["id"]))
    vulnerabilities: list[dict] = []
    if "vulnerability" in kinds:
        rows = list(conn.execute("SELECT cve_id, updated_at FROM vulnerabilities ORDER BY cve_id"))
        for row in rows:
            if earliest is not None and row["updated_at"] < earliest:
                continue
            vulnerabilities.append(_one(store, "vulnerability", row["cve_id"]))
    refs: dict[str, list[str]] = {}
    for row in conn.execute(
        "SELECT advisory_id, ref FROM advisory_refs ORDER BY advisory_id, ref_type, ref"
    ):
        refs.setdefault(row["advisory_id"], []).append(row["ref"])
    relationships = [
        dict(row)
        for row in conn.execute(
            """
            SELECT src_id, rel, dst_id, source_id, first_seen
            FROM relationships ORDER BY src_id, rel, dst_id
            """
        )
    ]
    return {
        "advisories": advisories,
        "indicators": indicators,
        "omitted_above_tlp": omitted_above,
        "omitted_unsupported": omitted_unsupported,
        "refs": refs,
        "relationships": relationships,
        "vulnerabilities": vulnerabilities,
    }


def _one(store: str | Path | None, kind: str, ref: str) -> dict:
    for record in lookup(ref, path=store):
        if record["kind"] == kind and record["id"] == ref:
            return record
    raise ValueError("store record disappeared during export")


def _import_indicators(objects: list, path: str | Path | None) -> int:
    indicators = {
        item.get("x_cyberau_sco_ref"): item
        for item in objects
        if isinstance(item, dict) and item.get("type") == "indicator"
    }
    seen: set[str] = set()
    for item in objects:
        if not isinstance(item, dict) or item.get("type") not in {*SCO_TYPES.values(), "file"}:
            continue
        store_type, value_norm = _store_type_and_value(item)
        if store_type is None or not isinstance(item.get("id"), str):
            continue
        if item["id"] in seen:
            continue
        seen.add(item["id"])
        linked = indicators.get(item["id"])
        sources = item.get("x_cyberau_sources")
        if isinstance(linked, dict) and isinstance(linked.get("x_cyberau_sources"), list):
            sources = linked["x_cyberau_sources"]
        if not isinstance(sources, list) or not sources:
            sources = [
                {
                    "confidence": item.get("x_cyberau_confidence"),
                    "observed_at": item.get("x_cyberau_first_seen") or "2020-01-01T00:00:00Z",
                    "source_id": "stix-import",
                    "verdict": item.get("x_cyberau_verdict"),
                }
            ]
        original = item.get("x_cyberau_value")
        if not isinstance(original, str):
            original = value_norm
        marking = item.get("x_cyberau_tlp")
        if not isinstance(marking, str):
            marking = "CLEAR"
        for source in sources:
            if not isinstance(source, dict):
                raise ValueError("STIX indicator sources are invalid")
            observed = source.get("observed_at") or item.get("x_cyberau_first_seen")
            if not isinstance(observed, str):
                observed = "2020-01-01T00:00:00Z"
            confidence = source.get("confidence")
            if isinstance(confidence, bool) or not isinstance(confidence, int):
                confidence = None
            upsert_indicator(
                store_type,
                original,
                source=str(source.get("source_id") or "stix-import"),
                observed_at=observed,
                raw=_raw(source),
                verdict=source.get("verdict") if isinstance(source.get("verdict"), str) else None,
                confidence=confidence,
                tags=source.get("tags") if isinstance(source.get("tags"), list) else (),
                tlp=marking,
                source_ref=source.get("source_ref")
                if isinstance(source.get("source_ref"), str)
                else None,
                note=source.get("note") if isinstance(source.get("note"), str) else None,
                path=path,
            )
    return len(seen)


def _store_type_and_value(item: dict) -> tuple[str | None, str]:
    declared = item.get("x_cyberau_store_type")
    if isinstance(declared, str) and declared in EXPORT_TYPES:
        if declared in HASH_NAMES:
            hashes = item.get("hashes") if isinstance(item.get("hashes"), dict) else {}
            value = hashes.get(HASH_NAMES[declared])
            if isinstance(value, str):
                return declared, value
        elif isinstance(item.get("value"), str):
            return declared, item["value"]
    if item.get("type") == "file" and isinstance(item.get("hashes"), dict):
        for name, store_type in _HASH_TO_STORE.items():
            value = item["hashes"].get(name)
            if isinstance(value, str):
                return store_type, value
    reverse = {sco: store for store, sco in _STORE_TO_SCO.items()}
    store_type = reverse.get(item.get("type"))
    if store_type and isinstance(item.get("value"), str):
        return store_type, item["value"]
    return None, ""


def _import_vulnerabilities(objects: list, path: str | Path | None) -> int:
    count = 0
    for item in objects:
        if not isinstance(item, dict) or item.get("type") != "vulnerability":
            continue
        cve = _cve_of(item)
        if cve is None:
            continue
        fields: dict = {"updated_at": item.get("modified") or item.get("created")}
        kev = item.get("x_cyberau_kev")
        if isinstance(kev, dict):
            fields["kev_date_added"] = kev.get("date_added")
            fields["kev_due_date"] = kev.get("due_date")
            fields["kev_ransomware"] = kev.get("ransomware")
        epss = item.get("x_cyberau_epss")
        if isinstance(epss, dict):
            fields["epss"] = epss.get("epss")
            fields["epss_percentile"] = epss.get("percentile")
            fields["epss_date"] = epss.get("date")
        if item.get("x_cyberau_cvss_v3") is not None:
            fields["cvss_v3"] = item.get("x_cyberau_cvss_v3")
        if item.get("x_cyberau_cvss_v4") is not None:
            fields["cvss_v4"] = item.get("x_cyberau_cvss_v4")
        if isinstance(item.get("x_cyberau_cwe"), str):
            fields["cwe"] = item["x_cyberau_cwe"]
        present = {key: value for key, value in fields.items() if value is not None}
        upsert_vulnerability(cve, path=path, **present)
        count += 1
    return count


def _import_advisories(objects: list, path: str | Path | None) -> int:
    count = 0
    for item in objects:
        if not isinstance(item, dict) or item.get("type") != "report":
            continue
        advisory_id = item.get("x_cyberau_advisory_id")
        refs = item.get("external_references")
        if not isinstance(advisory_id, str) or not isinstance(refs, list) or not refs:
            continue
        first = refs[0] if isinstance(refs[0], dict) else {}
        source = first.get("source_name")
        url = first.get("url")
        if not isinstance(source, str) or not isinstance(url, str):
            continue
        marking = "CLEAR"
        for ref in item.get("object_marking_refs") or []:
            if ref in _MARKING_TO_TLP:
                marking = more_restrictive(marking, _MARKING_TO_TLP[ref])
        ensure_source(source, name=source, default_tlp=marking, path=path)
        created = upsert_advisory(
            advisory_id,
            source=source,
            title=str(item.get("name") or advisory_id),
            url=url,
            published_at=item.get("published") if isinstance(item.get("published"), str) else None,
            summary=item.get("description") if isinstance(item.get("description"), str) else None,
            content_sha256=None,
            path=path,
        )
        count += 1 if created else 0
    return count


def _import_relationships(objects: list, path: str | Path | None) -> int:
    count = 0
    handle = open_store(path)
    with handle.transaction():
        conn = handle.connection()
        for item in objects:
            if not isinstance(item, dict) or item.get("type") != "relationship":
                continue
            src = item.get("x_cyberau_src_id")
            dst = item.get("x_cyberau_dst_id")
            rel = item.get("x_cyberau_rel") or item.get("relationship_type")
            if not isinstance(src, str) or not isinstance(dst, str) or not isinstance(rel, str):
                continue
            if not _REL.fullmatch(rel):
                continue
            source = item.get("x_cyberau_source_id")
            source_id = source if isinstance(source, str) and _SOURCE.fullmatch(source) else None
            seen = item.get("created") if isinstance(item.get("created"), str) else None
            cursor = conn.execute(
                """
                INSERT OR IGNORE INTO relationships
                    (src_id, rel, dst_id, source_id, first_seen)
                VALUES (?, ?, ?, ?, ?)
                """,
                (src, rel, dst, source_id, seen),
            )
            count += cursor.rowcount
    return count


def _cve_of(item: dict) -> str | None:
    for ref in item.get("external_references") or []:
        if isinstance(ref, dict) and ref.get("source_name") == "cve":
            external = ref.get("external_id")
            if isinstance(external, str):
                return external
    name = item.get("name")
    return name if isinstance(name, str) and name.upper().startswith("CVE-") else None


def _audit_amber(store: str | Path | None, explicit: bool, count: int, output: str | None) -> None:
    moment = utc_now()
    directory = _data_dir(store) / "audit"
    directory.mkdir(parents=True, exist_ok=True)
    record = {
        "event": "export",
        "explicit_max_tlp": explicit,
        "format": "stix21",
        "max_tlp": "AMBER",
        "object_count": count,
        "output": output,
        "tool": "intel_export_stix",
        "ts": moment,
    }
    line = json.dumps(record, ensure_ascii=False, sort_keys=True)
    with (directory / f"{moment[:10]}.jsonl").open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")


def _write_export(destination: Path, text: str) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + ".tmp")
    try:
        temporary.write_text(text, encoding="utf-8")
        temporary.replace(destination)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def _data_dir(store: str | Path | None) -> Path:
    return resolve_db_path(store).parent


def _config_paths() -> list[Path]:
    paths: list[Path] = []
    for key in ("CYBERAU_HOME", "HERMES_HOME"):
        value = os.environ.get(key)
        if value:
            paths.append(Path(value) / "config.yaml")
    paths.append(Path.cwd() / "config.yaml")
    return paths


def _org_in_config(text: str) -> str | None:
    in_block = False
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        if _CYBER_AU.fullmatch(line):
            in_block = True
            continue
        if in_block and not raw.startswith((" ", "\t")):
            in_block = False
        if not in_block:
            continue
        match = _ORG_KEY.fullmatch(line)
        if match:
            return _unquote(match.group(1).strip())
    return None


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value


def _clean_org(value: str) -> str:
    text = clean_untrusted(value, max_len=200)
    if not text:
        raise ValueError("organisation name is empty")
    return text


def _require_kinds(kinds: Sequence[str] | None) -> tuple[str, ...]:
    if kinds is None:
        return ("indicator", "vulnerability", "advisory")
    if isinstance(kinds, str) or not kinds:
        raise ValueError("kinds must be a list")
    chosen = tuple(kinds)
    allowed = {"indicator", "vulnerability", "advisory"}
    if any(kind not in allowed for kind in chosen):
        raise ValueError("kinds must be indicator, vulnerability or advisory")
    return chosen


def _require_stix_tlp(value: str | None) -> tuple[str, bool]:
    if value is None:
        return "CLEAR", False
    if value not in STIX_TLP:
        raise ValueError("STIX max_tlp must be CLEAR, GREEN or AMBER")
    return value, True


def _pattern(indicator_type: str, value_norm: str) -> str:
    literal = value_norm.replace("\\", "\\\\").replace("'", "\\'")
    if indicator_type in HASH_NAMES:
        return f"[file:hashes.'{HASH_NAMES[indicator_type]}' = '{literal}']"
    return f"[{_STORE_TO_SCO[indicator_type]}:value = '{literal}']"


def _sdo_id(kind: str, key: str) -> str:
    return f"{kind}--{uuid.uuid5(SDO_NAMESPACE, f'{kind}:{key}')}"


def _bundle_id(object_ids: list[str]) -> str:
    name = json.dumps(object_ids, separators=(",", ":"))
    return f"bundle--{uuid.uuid5(SDO_NAMESPACE, name)}"


def _stix_time(value: str) -> str:
    text = canonical_timestamp(value)
    if text.endswith("Z") and "." not in text:
        return text[:-1] + ".000Z"
    return text


def _later(created: str, modified: str) -> str:
    return modified if modified >= created else created


def _compact(values: dict) -> dict:
    return {key: value for key, value in values.items() if value is not None}


def _raw(source: dict) -> bytes:
    return json.dumps(source, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()


__all__ = [
    "EXPORT_TYPES",
    "SDO_NAMESPACE",
    "TLP_NOT_EXPORTED",
    "export_stix",
    "import_stix",
    "import_stix_file",
    "organisation_name",
    "resolve_export_path",
]
