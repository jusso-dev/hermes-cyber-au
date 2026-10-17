"""Read-only MITRE ATT&CK (STIX 2.1) connector."""

import json
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Literal

from cyberau_common import USER_AGENT
from cyberau_common.cache import HttpCache
from cyberau_common.egress import EgressPolicy
from cyberau_common.envelope import envelope, untrusted_text
from cyberau_common.http import HttpClient
from cyberau_common.ratelimit import RateLimiter
from cyberau_common.secrets import redact
from cyberau_common.server import Connector, Probe, ToolSpec, register_connector
from pydantic import Field

INDEX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json"
BUNDLE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "{domain}-attack/{domain}-attack.json"
)
ATTRIBUTION = (
    "MITRE ATT&CK is a registered trademark of The MITRE Corporation. ATT&CK content is used "
    "under the ATT&CK Terms of Use (https://attack.mitre.org/resources/terms-of-use/). "
    "This connector is not endorsed by MITRE."
)
DOMAINS = ("enterprise", "mobile", "ics")
_Domain = Literal["enterprise", "mobile", "ics"]
_TechniqueId = Annotated[str, Field(pattern=r"^T\d{4}(\.\d{3})?$")]
_Limit = Annotated[int, Field(ge=1, le=50)]
_PACKAGE = Path(__file__).resolve().parents[2]
_TECHNIQUE = re.compile(r"T\d{4}(\.\d{3})?")
_GROUP_ID = re.compile(r"G\d{4}")
_CITATION = re.compile(r"\s*\(Citation: [^)]*\)")
_LINK = re.compile(r"\[([^\]]+)\]\([^)]*\)")
_EXT_ID = re.compile(r"[A-Z]{1,3}\d{4}(\.\d{3})?")
_URL = re.compile(r"https://(attack|collaborate)\.mitre\.org/[A-Za-z0-9/._-]*")
_SHORTNAME = re.compile(r"[a-z0-9][a-z0-9-]{0,59}")
_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z")
_PLATFORMS = frozenset(
    {
        "Android",
        "Containers",
        "Control Server",
        "Data Historian",
        "Engineering Workstation",
        "ESXi",
        "Embedded",
        "Field Controller/RTU/PLC/IED",
        "Google Workspace",
        "Human-Machine Interface",
        "IaaS",
        "Identity Provider",
        "Input/Output Server",
        "iOS",
        "Linux",
        "macOS",
        "Network Devices",
        "None",
        "Office 365",
        "Office Suite",
        "PRE",
        "Safety Instrumented System/Protection Relay",
        "SaaS",
        "Windows",
    }
)
_SHIPPED_NOTE = (
    "served the excerpt shipped with the package, which is hand-written test data and not "
    "current ATT&CK content; run with network access to read the real bundles"
)
_VERSION = re.compile(r"\d+(\.\d+)*")
_SOFTWARE = ("malware", "tool")
_KINDS = {
    "attack-pattern",
    "intrusion-set",
    "malware",
    "tool",
    "course-of-action",
    "x-mitre-tactic",
    "x-mitre-detection-strategy",
}
_DESCRIPTION_MAX = 1200
_SUMMARY_MAX = 300
_DETECTION_MAX = 2000
_TRANSPORT = None
_SLEEP = time.sleep
_RESOLVER = None
_MODELS: dict[tuple[str, int, int], "_Model"] = {}


def attack_technique(technique_id: _TechniqueId) -> dict:
    tid = technique_id.strip().upper() if isinstance(technique_id, str) else ""
    if not _TECHNIQUE.fullmatch(tid):
        return _envelope(
            None, "snapshot", warnings=("technique_id must look like T1059 or T1059.001",)
        )
    warnings: list[str] = []
    first: _Loaded | None = None
    for domain in DOMAINS:
        loaded = _load(domain)
        warnings.extend(loaded.warnings)
        if loaded.model is None:
            continue
        first = first or loaded
        obj = loaded.model.by_ext.get(tid)
        if obj is not None and obj["type"] == "attack-pattern":
            return _envelope(
                _technique_record(loaded.model, obj),
                loaded.cache,
                loaded.urls,
                loaded.version,
                warnings,
            )
        gone = loaded.model.inactive.get(tid)
        if gone is not None:
            status, replacement = gone
            note = f"{tid} is {status} in ATT&CK {loaded.version}"
            if replacement:
                note += f" and was replaced by {replacement}"
            warnings.append(note)
            return _envelope(None, loaded.cache, loaded.urls, loaded.version, warnings)
    warnings.append(f"no active technique {tid} in the ATT&CK domains that could be read")
    return _envelope(
        None,
        first.cache if first else "snapshot",
        first.urls if first else [INDEX_URL],
        first.version if first else None,
        warnings,
    )


def attack_search(query: str, domain: _Domain = "enterprise", limit: _Limit = 10) -> dict:
    if not isinstance(query, str) or len(query.strip()) < 2:
        return _envelope([], "snapshot", warnings=("query must be at least 2 characters",))
    if domain not in DOMAINS:
        return _envelope([], "snapshot", warnings=("domain must be enterprise, mobile or ics",))
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 50:
        return _envelope([], "snapshot", warnings=("limit must be between 1 and 50",))
    loaded = _load(domain)
    if loaded.model is None:
        return _envelope([], loaded.cache, loaded.urls, None, loaded.warnings)
    rows = _search(loaded.model, query, limit)
    warnings = list(loaded.warnings)
    if not rows:
        warnings.append(f"nothing in {domain} ATT&CK matches {query.strip()!r}")
    return _envelope(rows, loaded.cache, loaded.urls, loaded.version, warnings)


def attack_group(name_or_id: str) -> dict:
    wanted = name_or_id.strip() if isinstance(name_or_id, str) else ""
    if len(wanted) < 2:
        return _envelope(None, "snapshot", warnings=("name_or_id must be a group name or id",))
    warnings: list[str] = []
    first: _Loaded | None = None
    for domain in DOMAINS:
        loaded = _load(domain)
        warnings.extend(loaded.warnings)
        if loaded.model is None:
            continue
        first = first or loaded
        matches = _find_groups(loaded.model, wanted)
        if matches:
            if len(matches) > 1:
                warnings.append(
                    f"{len(matches)} groups match {wanted!r}; returning {matches[0]['_id']}"
                )
            return _envelope(
                _group_record(loaded.model, matches[0]),
                loaded.cache,
                loaded.urls,
                loaded.version,
                warnings,
            )
        gone = loaded.model.inactive.get(wanted.upper())
        if gone is not None:
            warnings.append(f"{wanted.upper()} is {gone[0]} in ATT&CK {loaded.version}")
            return _envelope(None, loaded.cache, loaded.urls, loaded.version, warnings)
    warnings.append(f"no active group matches {wanted!r}")
    return _envelope(
        None,
        first.cache if first else "snapshot",
        first.urls if first else [INDEX_URL],
        first.version if first else None,
        warnings,
    )


def connector() -> Connector:
    return _AttackConnector()


class _AttackConnector(Connector):
    def __init__(self) -> None:
        super().__init__(
            key="mitre-attack",
            server_name="attack",
            attribution=ATTRIBUTION,
            tools=[
                ToolSpec(
                    "attack_technique",
                    "One ATT&CK technique or sub-technique with tactics, mitigations, detection.",
                    attack_technique,
                ),
                ToolSpec(
                    "attack_search",
                    "Search ATT&CK techniques, groups and software by keyword.",
                    attack_search,
                ),
                ToolSpec(
                    "attack_group",
                    "One ATT&CK group with aliases and the techniques it uses.",
                    attack_group,
                ),
            ],
        )

    def health(self, *, live: bool, check_schema: bool = False) -> Probe:
        if check_schema and not live:
            payload, problem = _snapshot_payload("enterprise")
            problem = problem or schema_drift(payload)
            if problem:
                return Probe(self.key, False, problem)
            return Probe(self.key, True, "schema ok")
        if not live:
            return Probe(self.key, True, "offline ok")
        return _live_probe(self.key)


def schema_drift(payload) -> str | None:
    if not isinstance(payload, dict):
        return "ATT&CK payload is not an object"
    objects = payload.get("objects")
    if not isinstance(objects, list):
        return "ATT&CK schema drift, missing objects"
    for obj in objects:
        if not isinstance(obj, dict) or obj.get("type") != "attack-pattern":
            continue
        for key in ("id", "name", "external_references"):
            if key not in obj:
                return f"ATT&CK schema drift, technique has no {key}"
        return None
    return "ATT&CK schema drift, no techniques found"


@dataclass
class _Model:
    version: str
    domain: str
    by_ext: dict[str, dict] = field(default_factory=dict)
    by_id: dict[str, dict] = field(default_factory=dict)
    tactics: dict[str, tuple[str, str]] = field(default_factory=dict)
    out: dict[tuple[str, str], list[tuple[str, str]]] = field(default_factory=dict)
    into: dict[tuple[str, str], list[tuple[str, str]]] = field(default_factory=dict)
    inactive: dict[str, tuple[str, str]] = field(default_factory=dict)


@dataclass
class _Loaded:
    model: _Model | None
    version: str
    cache: str
    urls: list[str]
    warnings: list[str] = field(default_factory=list)


def _build(payload, domain: str, version: str) -> tuple[_Model | None, str | None]:
    problem = schema_drift(payload)
    if problem:
        return None, problem
    model = _Model(version=version, domain=domain)
    objects = [obj for obj in payload["objects"] if isinstance(obj, dict)]
    status: dict[str, str] = {}
    ext_of: dict[str, str] = {}
    for obj in objects:
        kind, stix_id = obj.get("type"), obj.get("id")
        if not isinstance(kind, str) or not isinstance(stix_id, str) or kind == "relationship":
            continue
        ext_id, _url = _external(obj)
        if ext_id:
            ext_of[stix_id] = ext_id
        if obj.get("revoked") is True:
            status[stix_id] = "revoked"
        elif obj.get("x_mitre_deprecated") is True:
            status[stix_id] = "deprecated"
        else:
            model.by_id[stix_id] = obj
    for stix_id, obj in model.by_id.items():
        ext_id, _url = _external(obj)
        if obj["type"] in _KINDS and ext_id:
            model.by_ext[ext_id.upper()] = obj
        if obj["type"] == "x-mitre-tactic" and obj.get("x_mitre_shortname"):
            model.tactics[str(obj["x_mitre_shortname"])] = (ext_id, str(obj.get("name") or ""))
    replaced_by: dict[str, str] = {}
    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        kind, source, target = (
            obj.get(k) for k in ("relationship_type", "source_ref", "target_ref")
        )
        if not all(isinstance(item, str) for item in (kind, source, target)):
            continue
        if obj.get("revoked") is True or obj.get("x_mitre_deprecated") is True:
            continue
        if kind == "revoked-by":
            replaced_by[source] = target
            continue
        if source not in model.by_id or target not in model.by_id:
            continue
        text = str(obj.get("description") or "")
        model.out.setdefault((source, kind), []).append((target, text))
        model.into.setdefault((target, kind), []).append((source, text))
    for stix_id, state in status.items():
        ext_id = ext_of.get(stix_id)
        if ext_id:
            model.inactive[ext_id.upper()] = (state, ext_of.get(replaced_by.get(stix_id, ""), ""))
    return model, None


def _technique_record(model: _Model, obj: dict) -> dict:
    tid, url = _external(obj)
    tactics = []
    for phase in obj.get("kill_chain_phases") or []:
        if not isinstance(phase, dict) or not str(phase.get("kill_chain_name", "")).startswith(
            "mitre-"
        ):
            continue
        short = str(phase.get("phase_name") or "")
        ext_id, name = model.tactics.get(short, ("", short))
        tactics.append(
            {"tactic_id": ext_id, "shortname": _shortname(short), "name": _text(name, 120)}
        )
    stix_id = obj["id"]
    data_sources = [str(item) for item in obj.get("x_mitre_data_sources") or []]
    notes = [str(obj.get("x_mitre_detection") or "")]
    strategies = []
    for source, _usage in model.into.get((stix_id, "detects"), []):
        found = model.by_id[source]
        if found["type"] == "x-mitre-detection-strategy":
            strategies.append(
                {"detection_id": _external(found)[0], "name": _text(found.get("name"), 200)}
            )
            for ref in found.get("x_mitre_analytic_refs") or []:
                analytic = model.by_id.get(ref)
                if analytic is None:
                    continue
                notes.append(str(analytic.get("description") or ""))
                for log in analytic.get("x_mitre_log_source_references") or []:
                    if isinstance(log, dict):
                        data_sources.append(
                            _component(model, log.get("x_mitre_data_component_ref"))
                        )
        elif found["type"] == "x-mitre-data-component":
            data_sources.append(_component(model, found["id"]))
    mitigations = []
    for source, how in model.into.get((stix_id, "mitigates"), []):
        found = model.by_id[source]
        mitigations.append(
            {
                "mitigation_id": _external(found)[0],
                "name": _text(found.get("name"), 200),
                "description": _text(how, _SUMMARY_MAX),
            }
        )
    subs = [
        {
            "technique_id": _external(model.by_id[source])[0],
            "name": _text(model.by_id[source].get("name"), 200),
        }
        for source, _t in model.into.get((stix_id, "subtechnique-of"), [])
    ]
    is_sub = bool(obj.get("x_mitre_is_subtechnique"))
    return {
        "technique_id": tid,
        "name": _text(obj.get("name"), 200),
        "domain": model.domain,
        "is_subtechnique": is_sub,
        "parent_id": tid.split(".")[0] if is_sub else None,
        "description": _text(obj.get("description"), _DESCRIPTION_MAX),
        "tactics": tactics,
        "platforms": [_platform(item) for item in obj.get("x_mitre_platforms") or []],
        "data_sources": [_text(item, 200) for item in sorted(set(filter(None, data_sources)))],
        "detection": (
            _text(" ".join(note for note in notes if note), _DETECTION_MAX)
            if any(note.strip() for note in notes)
            else None
        ),
        "detection_strategies": sorted(strategies, key=lambda row: row["detection_id"]),
        "mitigations": sorted(mitigations, key=lambda row: row["mitigation_id"]),
        "sub_techniques": sorted(subs, key=lambda row: row["technique_id"]),
        "url": url,
        "version": model.version,
        "modified": _timestamp(obj.get("modified")),
    }


def _component(model: _Model, ref) -> str:
    found = model.by_id.get(str(ref))
    if found is None or found.get("type") != "x-mitre-data-component":
        return ""
    parent = model.by_id.get(str(found.get("x_mitre_data_source_ref")))
    label = str(found.get("name") or "")
    return f"{parent.get('name')}: {label}" if parent and label else label


def _group_record(model: _Model, obj: dict) -> dict:
    stix_id = obj["id"]
    techniques, software = [], []
    for target, usage in model.out.get((stix_id, "uses"), []):
        found = model.by_id[target]
        if found["type"] == "attack-pattern":
            techniques.append(
                {
                    "technique_id": _external(found)[0],
                    "name": _text(found.get("name"), 200),
                    "usage": _text(usage, _SUMMARY_MAX),
                }
            )
        elif found["type"] in _SOFTWARE:
            software.append(
                {
                    "software_id": _external(found)[0],
                    "name": _text(found.get("name"), 200),
                    "type": found["type"],
                }
            )
    gid, url = _external(obj)
    return {
        "group_id": gid,
        "name": _text(obj.get("name"), 200),
        "aliases": [_text(item, 100) for item in _aliases(obj)],
        "description": _text(obj.get("description"), _DESCRIPTION_MAX),
        "techniques": sorted(techniques, key=lambda row: row["technique_id"]),
        "software": sorted(software, key=lambda row: row["software_id"]),
        "domain": model.domain,
        "url": url,
        "version": model.version,
        "modified": _timestamp(obj.get("modified")),
    }


def _find_groups(model: _Model, wanted: str) -> list[dict]:
    if _GROUP_ID.fullmatch(wanted.upper()):
        found = model.by_ext.get(wanted.upper())
        return (
            [dict(found, _id=wanted.upper())] if found and found["type"] == "intrusion-set" else []
        )
    needle = wanted.lower()
    matches = []
    for ext_id, obj in sorted(model.by_ext.items()):
        if obj["type"] != "intrusion-set":
            continue
        names = {str(obj.get("name") or "").lower()} | {item.lower() for item in _aliases(obj)}
        if needle in names:
            matches.append(dict(obj, _id=ext_id))
    return matches


def _search(model: _Model, query: str, limit: int) -> list[dict]:
    needle = query.strip().lower()
    ranked = []
    for ext_id, obj in model.by_ext.items():
        kind = obj["type"]
        if kind not in ("attack-pattern", "intrusion-set", *_SOFTWARE):
            continue
        name = str(obj.get("name") or "")
        aliases = _aliases(obj)
        if needle in (ext_id.lower(), name.lower()) or needle in (a.lower() for a in aliases):
            rank = 0
        elif needle in name.lower():
            rank = 1
        elif any(needle in alias.lower() for alias in aliases):
            rank = 2
        elif needle in str(obj.get("description") or "").lower():
            rank = 3
        else:
            continue
        ranked.append((rank, ext_id, obj))
    ranked.sort(key=lambda item: (item[0], item[1]))
    rows = []
    for _rank, ext_id, obj in ranked[:limit]:
        kind = obj["type"]
        label = {"attack-pattern": "technique", "intrusion-set": "group"}.get(kind, kind)
        if kind == "attack-pattern" and obj.get("x_mitre_is_subtechnique"):
            label = "sub-technique"
        rows.append(
            {
                "type": label,
                "id": ext_id,
                "name": _text(obj.get("name"), 200),
                "aliases": [_text(item, 100) for item in _aliases(obj) if item != obj.get("name")],
                "summary": _text(obj.get("description"), _SUMMARY_MAX),
                "domain": model.domain,
                "url": _external(obj)[1],
            }
        )
    return rows


def _aliases(obj: dict) -> list[str]:
    raw = obj.get("aliases") or obj.get("x_mitre_aliases") or []
    return [str(item) for item in raw if isinstance(item, str)]


def _external(obj: dict) -> tuple[str, str]:
    for ref in obj.get("external_references") or []:
        if (
            isinstance(ref, dict)
            and str(ref.get("source_name", "")).startswith("mitre-")
            and _EXT_ID.fullmatch(str(ref.get("external_id") or ""))
        ):
            url = str(ref.get("url") or "")
            return str(ref["external_id"]), url if _URL.fullmatch(url) else ""
    return "", ""


def _text(value, max_len: int) -> str:
    text = _LINK.sub(r"\1", _CITATION.sub("", str(value or "")))
    return untrusted_text(text, "attack", max_len)


def _shortname(value) -> str:
    text = str(value or "")
    return text if _SHORTNAME.fullmatch(text) else untrusted_text(text, "attack", 60)


def _platform(value) -> str:
    text = str(value or "")
    return text if text in _PLATFORMS else untrusted_text(text, "attack", 60)


def _timestamp(value) -> str:
    text = str(value or "")
    return text if _TIMESTAMP.fullmatch(text) else ""


def _load(domain: str, *, force_live: bool = False) -> _Loaded:
    pinned = os.environ.get("CYBERAU_ATTACK_SNAPSHOT")
    if not force_live and pinned:
        return _from_root(Path(pinned), domain, "snapshot", [])
    if not force_live and os.environ.get("CYBERAU_OFFLINE") == "1":
        return _stored_or_shipped(domain, [])
    text, cache, warning = _http(INDEX_URL, ttl=3600, stale_if_error=7 * 86400)
    if text is None:
        return _stored_or_shipped(domain, [warning])
    index = _loads(text)
    version = _latest(index, domain)
    if not version:
        return _stored_or_shipped(domain, [f"ATT&CK index has no {domain} version"])
    warnings = (
        ["ATT&CK index was served from cache after the live fetch failed"]
        if (cache == "stale")
        else []
    )
    urls = [INDEX_URL]
    path = _stored(version, domain)
    if path.is_file():
        model, problem = _parse_file(path, domain, version)
        if model is not None:
            return _Loaded(model, version, "stale" if cache == "stale" else "hit", urls, warnings)
        warnings.append(f"stored {domain} bundle was not usable: {problem}")
    url = BUNDLE_URL.format(domain=domain)
    body, _cache, warning = _http(url, ttl=86400, stale_if_error=0)
    if body is None:
        return _stored_or_shipped(domain, [*warnings, warning])
    model, problem = _build(_loads(body), domain, version)
    if model is None:
        return _stored_or_shipped(domain, [*warnings, f"{domain} bundle was not usable: {problem}"])
    _store(path, body)
    return _Loaded(model, version, "stale" if cache == "stale" else "miss", [*urls, url], warnings)


def _stored_or_shipped(domain: str, warnings: list[str]) -> _Loaded:
    kept = _stored_versions(domain)
    for version in kept:
        model, problem = _parse_file(_stored(version, domain), domain, version)
        if model is not None:
            note = [*warnings, f"served stored ATT&CK {version} {domain} snapshot"]
            return _Loaded(model, version, "stale", [INDEX_URL], [w for w in note if w])
        warnings = [*warnings, f"stored {domain} {version} was not usable: {problem}"]
    shipped = _from_root(_PACKAGE / "data", domain, "snapshot", [w for w in warnings if w])
    if shipped.model is not None:
        shipped.warnings.append(_SHIPPED_NOTE)
    return shipped


def _from_root(root: Path, domain: str, cache: str, warnings: list[str]) -> _Loaded:
    index = _loads_file(root / "index.json")
    version = _latest(index, domain) or _newest_dir(root, domain)
    if not version:
        return _Loaded(
            None, "", cache, [INDEX_URL], [*warnings, f"no {domain} snapshot is available"]
        )
    model, problem = _parse_file(root / version / f"{domain}-attack.json", domain, version)
    if model is None:
        return _Loaded(
            None,
            version,
            cache,
            [INDEX_URL],
            [*warnings, f"{domain} snapshot was not usable: {problem}"],
        )
    return _Loaded(model, version, cache, [INDEX_URL], warnings)


def _parse_file(path: Path, domain: str, version: str) -> tuple[_Model | None, str]:
    try:
        info = path.stat()
    except OSError as exc:
        return None, str(exc)
    key = (str(path), info.st_mtime_ns, info.st_size)
    if key in _MODELS:
        return _MODELS[key], ""
    payload = _loads_file(path)
    model, problem = _build(payload, domain, version)
    if model is None:
        return None, problem or "unreadable"
    _MODELS[key] = model
    return model, ""


def _snapshot_payload(domain: str) -> tuple[object, str | None]:
    root = Path(os.environ.get("CYBERAU_ATTACK_SNAPSHOT") or _PACKAGE / "data")
    version = _latest(_loads_file(root / "index.json"), domain) or _newest_dir(root, domain)
    if not version:
        return None, f"no {domain} snapshot is available"
    payload = _loads_file(root / version / f"{domain}-attack.json")
    return payload, None if payload is not None else f"{domain} snapshot is not valid JSON"


def _live_probe(key: str) -> Probe:
    text, _cache, warning = _http(INDEX_URL, ttl=0, stale_if_error=0, skip_cache=True)
    if text is None:
        return Probe(key, False, warning)
    version = _latest(_loads(text), "ics")
    if not version:
        return Probe(key, False, "ATT&CK index has no ICS version")
    body, _cache, warning = _http(
        BUNDLE_URL.format(domain="ics"), ttl=0, stale_if_error=0, skip_cache=True
    )
    if body is None:
        return Probe(key, False, warning)
    model, problem = _build(_loads(body), "ics", version)
    if model is None:
        return Probe(key, False, problem or "ICS bundle was not usable")
    checks = []
    technique = next((o for o in model.by_ext.values() if o["type"] == "attack-pattern"), None)
    if technique is not None:
        checks.append(("attack_technique", _technique_record(model, technique)))
    group = next((o for o in model.by_ext.values() if o["type"] == "intrusion-set"), None)
    if group is not None:
        checks.append(("attack_group", _group_record(model, group)))
    checks.append(("attack_search", _search(model, "a", 5)))
    for name, data in checks:
        problem = validate_response(name, _envelope(data, "miss", [INDEX_URL], version))
        if problem:
            return Probe(key, False, f"{name} response failed validation: {problem}")
    return Probe(key, True, f"live ok, ATT&CK {version}")


def validate_response(tool: str, payload: dict) -> str | None:
    """Check an envelope against schema/<tool>.response.json. None means it is valid."""
    import jsonschema

    schema = json.loads((_PACKAGE / "schema" / f"{tool}.response.json").read_text("utf-8"))
    errors = sorted(jsonschema.Draft202012Validator(schema).iter_errors(payload), key=str)
    return errors[0].message if errors else None


def _http(
    url: str, *, ttl: int, stale_if_error: int, skip_cache: bool = False
) -> tuple[str | None, str, str]:
    data_dir = _data_dir()
    client = HttpClient(
        "mitre-attack",
        policy=EgressPolicy(_allowlist(), "mitre-attack", resolver=_RESOLVER),
        cache=HttpCache(data_dir / "http_cache.sqlite"),
        limiter=RateLimiter(data_dir / "rate_limit.sqlite", sleeper=_SLEEP),
        user_agent=USER_AGENT,
        rate=1 / 36,
        burst=5,
        window="rolling",
        timeout=120,
        retries=3,
        transport=_TRANSPORT,
        sleeper=_SLEEP,
        max_bytes=256 * 1024 * 1024,
    )
    try:
        response = client.get(url, ttl=ttl, stale_if_error=stale_if_error, skip_cache=skip_cache)
    except Exception as exc:
        return None, "snapshot", redact(f"{url} could not be fetched: {exc}")
    finally:
        client.close()
    if response.status in (401, 403):
        return (
            None,
            response.cache,
            f"raw.githubusercontent.com refused the request ({response.status}). "
            "This connector needs no key or token; check the network path and try again later.",
        )
    if response.status == 429:
        return None, response.cache, "raw.githubusercontent.com is rate limiting this host (429)"
    if response.status >= 400:
        return None, response.cache, f"upstream status {response.status} for {url}"
    try:
        return response.body.decode("utf-8"), response.cache, ""
    except UnicodeDecodeError:
        return None, response.cache, f"{url} was not UTF-8"


def _latest(index, domain: str) -> str:
    if not isinstance(index, dict):
        return ""
    best = ""
    for collection in index.get("collections") or []:
        if not isinstance(collection, dict):
            continue
        if not str(collection.get("name", "")).lower().startswith(domain):
            continue
        for row in collection.get("versions") or []:
            version = str(row.get("version", "")) if isinstance(row, dict) else ""
            if _VERSION.fullmatch(version) and _key(version) > _key(best):
                best = version
    return best


def _key(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split(".")) if version else ()


def _newest_dir(root: Path, domain: str) -> str:
    versions = [
        path.parent.name
        for path in root.glob(f"*/{domain}-attack.json")
        if _VERSION.fullmatch(path.parent.name)
    ]
    return max(versions, key=_key, default="")


def _stored_versions(domain: str) -> list[str]:
    root = _data_dir() / "attack"
    versions = [
        path.parent.name
        for path in root.glob(f"*/{domain}-attack.json")
        if _VERSION.fullmatch(path.parent.name)
    ]
    return sorted(versions, key=_key, reverse=True)


def _stored(version: str, domain: str) -> Path:
    return _data_dir() / "attack" / version / f"{domain}-attack.json"


def _store(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(".tmp")
    temp.write_text(body, encoding="utf-8")
    os.replace(temp, path)


def _loads(text: str | None):
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _loads_file(path: Path):
    try:
        return _loads(path.read_text(encoding="utf-8"))
    except OSError:
        return None


def _envelope(data, cache: str, urls=None, data_as_of: str | None = None, warnings=()):
    return envelope(
        "mitre-attack",
        data,
        urls=list(urls or [INDEX_URL]),
        cache=cache,
        data_as_of=f"ATT&CK v{data_as_of}" if data_as_of else None,
        warnings=list(dict.fromkeys(item for item in warnings if item)),
        attribution=ATTRIBUTION,
    )


def _data_dir() -> Path:
    path = Path(os.environ.get("CYBERAU_DATA_DIR", "/tmp/cyberau-attack"))
    path.mkdir(parents=True, exist_ok=True)
    return path


def _allowlist() -> Path:
    return Path(__file__).resolve().parents[3] / "egress-allowlist.yaml"


register_connector("mitre-attack", connector)
