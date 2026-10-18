"""Read-only Flare tools. Tenant searches are the default. Nothing here creates identifiers."""

from __future__ import annotations

import json
import re
from datetime import UTC, date, datetime
from pathlib import Path

import yaml
from cyberau_common.envelope import envelope, untrusted_text
from cyberau_common.secrets import lookup, redact
from cyberau_common.server import Probe, ToolSpec, register_connector
from cyberau_common.snapshot import unavailable
from cyberau_premium.base import (
    ExposureFinding,
    HealthResult,
    PremiumConnector,
    Subject,
    Watchlist,
    clamp_to_terms,
    finding_id,
)
from cyberau_premium.catalog import get_vendor
from cyberau_premium.paths import data_dir
from cyberau_premium.present import finding_payload
from cyberau_premium.redact import redact_text
from cyberau_premium.store import ExposureStore
from jsonschema import Draft202012Validator

from cyberau_flare.client import (
    CREDENTIALS_URL,
    IDENTIFIERS_URL,
    TENANT_EVENTS_URL,
    Fetch,
    domain_query,
    fetch_domain_credentials,
    fetch_identifier_events,
    fetch_identifiers,
    fetch_tenant_events,
    fixture_dir,
    missing_key_warning,
    package_root,
    probe_token,
)
from cyberau_flare.quota import global_search_decision, quota_view

READ_TOOLS = (
    "search_tenant",
    "search_global",
    "search_validate_search_query",
    "events_get_event",
    "events_expand_event",
    "events_get_event_type",
    "identifiers_list",
    "identifiers_explain_event",
    "identifier_groups_list",
    "matching_policies_list",
    "severity_rules_list",
    "entities_search",
    "profile_get",
)
WRITE_TOOLS = (
    "identifiers_create",
    "identifier_groups_create",
    "matching_policies_create",
    "severity_rules_create",
)

DEFAULT_TYPES = (
    "stealer_log",
    "ransomleak",
    "leak",
    "illicit_networks",
    "listing",
    "infected_devices",
    "valid_credential",
)
_KIND = {
    "stealer_log": "infostealer_credential",
    "infected_devices": "infostealer_credential",
    "ransomleak": "leak_site_claim",
    "leak": "leak_site_claim",
    "valid_credential": "breach_credential",
    "illicit_networks": "dark_web_mention",
    "listing": "dark_web_mention",
    "forum_content": "dark_web_mention",
    "chat_message": "dark_web_mention",
    "paste": "dark_web_mention",
    "source_code": "dark_web_mention",
    "buckets": "dark_web_mention",
}
_SEVERITY = ("info", "low", "medium", "high", "critical")
TERMS_NOTICE = (
    "Commercial licence. Session cache for events and credentials. "
    "Store event metadata only. No STIX export of Flare content. "
    "No sharing outside the profile. Flare ships off until you set enabled: true."
)
_UNCONFIRMED = "The ransomware leak site claim is unconfirmed."
FIXTURE_WARNING = (
    "Served from the operator-supplied CYBERAU_FLARE_FIXTURES files, not a live Flare fetch."
)
_HOST = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$",
    re.IGNORECASE,
)


def _envelope(data, cache: str, warnings: tuple[str, ...] | list[str] = (), urls=()):
    state = cache if cache in {"hit", "miss", "stale", "snapshot"} else "snapshot"
    warnings = list(warnings)
    if fixture_dir() is not None:
        warnings.insert(0, FIXTURE_WARNING)
    return envelope(
        "flare",
        data,
        urls=list(urls),
        cache=state,
        warnings=warnings,
        attribution=get_vendor("flare").terms.attribution,
    )


def _unavailable(label: str, warnings) -> tuple[str, ...]:
    """Empty answer after a failed fetch. Nothing shipped is served in its place."""
    reason = "; ".join(str(item).rstrip(".") for item in warnings)
    return (unavailable(label, reason),)


def _schema_path(name: str):
    return package_root() / "schema" / name


def _reject(tool: str, payload: dict) -> str | None:
    schema = json.loads(_schema_path(f"{tool}.input.json").read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER)
    errors = sorted(validator.iter_errors(payload), key=lambda item: list(item.path))
    if not errors:
        return None
    return errors[0].message


def _provided(**values) -> dict:
    return {key: value for key, value in values.items() if value is not None}


def load_schema_sample() -> dict:
    raw = lookup("CYBERAU_FLARE_SCHEMA_FIXTURE")
    path = (
        package_root() / "tests" / "fixtures" / "flare_tenant_exposure_synthetic.json"
        if raw is None
        else Path(raw)
    )
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def load_mcp_tool_names() -> list[str]:
    path = package_root() / "tests" / "fixtures" / "mcp_tools_list.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    tools = payload.get("tools") if isinstance(payload, dict) else None
    if not isinstance(tools, list):
        return []
    names = []
    for item in tools:
        if isinstance(item, dict) and isinstance(item.get("name"), str):
            names.append(item["name"])
    return names


def schema_drift(payload: dict) -> str | None:
    items = payload.get("items")
    if not isinstance(items, list):
        return "Flare schema drift, missing items"
    if not items:
        return None
    first = items[0]
    if not isinstance(first, dict):
        return "Flare schema drift, missing metadata"
    metadata = first.get("metadata")
    if not isinstance(metadata, dict):
        return "Flare schema drift, missing metadata"
    for field in ("uid", "type", "estimated_created_at"):
        if field not in metadata:
            return f"Flare schema drift, missing {field}"
    return None


def mcp_drift(names: list[str]) -> str | None:
    known = set(READ_TOOLS) | set(WRITE_TOOLS)
    unknown = [name for name in names if name not in known]
    if unknown:
        return "Flare MCP tool list changed: " + ", ".join(unknown)
    return None


def allowed_mcp_tools(names: list[str]) -> list[str]:
    """Read tools only. Write tools never register."""
    return [name for name in names if name in READ_TOOLS]


def render_mcp_entry(entry: dict, *, enabled: bool = False) -> dict:
    include = [name for name in (entry.get("tools") or {}).get("include") or []]
    headers = {}
    for item in entry.get("headers") or []:
        name, raw = str(item).split("=", 1)
        headers[name] = raw.strip()
    return {
        "enabled": bool(enabled),
        "trust": entry.get("trust", "untrusted"),
        "url": entry.get("url"),
        "headers": headers,
        "lazy": bool(entry.get("lazy", True)),
        "timeout": entry.get("timeout", 120),
        "tools": {"include": include},
    }


def _profile_file(name: str):
    data = data_dir()
    if tuple(data.parts[-2:]) == ("plugin-data", "cyber-au"):
        return data.parent.parent / name
    return data / name


def load_watchlist() -> Watchlist:
    path = _profile_file("org-exposure.yaml")
    if tuple(data_dir().parts[-2:]) == ("plugin-data", "cyber-au"):
        path = data_dir().parent.parent / "watchlists" / "org-exposure.yaml"
    if not path.is_file():
        return Watchlist()
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        return Watchlist()
    return Watchlist.model_validate(raw)


def load_profile_config() -> dict:
    path = _profile_file("config.yaml")
    if not path.is_file():
        return {}
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return raw if isinstance(raw, dict) else {}


def _parse_time(value: str) -> datetime | None:
    text = value.replace("Z", "+00:00")
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return moment


def _sydney_start(day: str) -> datetime:
    from cyberau_premium.budget import SYDNEY

    return datetime.fromisoformat(day).replace(tzinfo=SYDNEY)


def _watch_values(watchlist: Watchlist) -> dict[str, str]:
    values: list[str] = []
    values.extend(watchlist.domains)
    values.extend(watchlist.email_domains)
    values.extend(watchlist.brands)
    values.extend(watchlist.abns)
    for item in watchlist.subsidiaries:
        name = item.get("name")
        if isinstance(name, str):
            values.append(name)
        for domain in item.get("domains") or []:
            if isinstance(domain, str):
                values.append(domain)
    excluded = {item.casefold() for item in watchlist.exclude}
    return {value.casefold(): value for value in values if value.casefold() not in excluded}


def _identifier_values(item: dict) -> set[str]:
    found: set[str] = set()
    name = item.get("name")
    if isinstance(name, str) and name.strip():
        found.add(name.casefold())
    data = item.get("data")
    if isinstance(data, dict):
        for key in ("fqdn", "keyword", "name"):
            value = data.get(key)
            if isinstance(value, str) and value.strip():
                found.add(value.casefold())
    return found


def compare_identifiers(watchlist: Watchlist, identifiers: list) -> dict:
    monitored: set[str] = set()
    upstream: list[str] = []
    for item in identifiers:
        if not isinstance(item, dict):
            continue
        monitored |= _identifier_values(item)
        name = item.get("name")
        if isinstance(name, str) and name.strip():
            upstream.append(name)
    watch = _watch_values(watchlist)
    missing = [watch[key] for key in sorted(set(watch) - monitored)]
    extra = sorted({name for name in upstream if name.casefold() not in watch})
    return {"missing_from_flare": missing, "not_on_watchlist": extra}


def premium_doctor_lines(watchlist: Watchlist, identifiers: list) -> list[str]:
    """Read-only gap list. This does not create identifiers in Flare."""
    report = compare_identifiers(watchlist, identifiers)
    return [
        f"flare: watchlist entry {item} is not monitored" for item in report["missing_from_flare"]
    ]


def _wrap(text: str) -> str:
    """Upstream text is redacted and wrapped. It is data, never instructions."""
    return untrusted_text(redact_text(text), "flare")


def _primary(item: dict) -> dict | None:
    identifiers = item.get("identifiers")
    if not isinstance(identifiers, list) or not identifiers:
        return None
    first = identifiers[0]
    return first if isinstance(first, dict) else None


def _subject(name: str, watchlist: Watchlist) -> Subject:
    folded = name.casefold()
    if folded in {item.casefold() for item in watchlist.email_domains}:
        kind = "email_domain"
    elif folded in {item.casefold() for item in watchlist.domains}:
        kind = "domain"
    elif folded in {item.casefold() for item in watchlist.brands}:
        kind = "brand"
    elif "." in name:
        kind = "domain"
    else:
        kind = "brand"
    entry = name if folded in watchlist.known_subjects() else None
    return Subject(type=kind, value=name, watchlist_entry=entry)


def _metadata(item: dict) -> dict | None:
    metadata = item.get("metadata")
    if not isinstance(metadata, dict):
        return None
    fields = ("uid", "type", "estimated_created_at")
    if not all(isinstance(metadata.get(field), str) for field in fields):
        return None
    return metadata


def _kept(
    item: dict,
    *,
    since: str | None,
    types: tuple[str, ...] | list[str],
    min_severity: str | None,
) -> bool:
    metadata = item.get("metadata") if isinstance(item, dict) else None
    if not isinstance(metadata, dict):
        return False
    event_type = metadata.get("type")
    if types and event_type not in types:
        return False
    if min_severity in _SEVERITY:
        severity = metadata.get("severity")
        rank = _SEVERITY.index(severity) if severity in _SEVERITY else -1
        if rank < _SEVERITY.index(min_severity):
            return False
    if since:
        moment = _parse_time(str(metadata.get("estimated_created_at") or ""))
        if moment is None or moment < _sydney_start(since):
            return False
    return True


def to_finding(item: dict, watchlist: Watchlist) -> ExposureFinding | None:
    metadata = _metadata(item)
    identifier = _primary(item)
    if metadata is None or identifier is None or not isinstance(identifier.get("name"), str):
        return None
    event_type = metadata["type"]
    kind = _KIND.get(event_type)
    if kind is None:
        return None
    moment = _parse_time(metadata["estimated_created_at"])
    if moment is None:
        return None
    name = identifier["name"]
    uid = metadata["uid"]
    finding = ExposureFinding(
        finding_id=finding_id("flare", kind, name, uid),
        vendor="flare",
        kind=kind,
        subject=_subject(name, watchlist),
        observed_at=moment,
        first_seen=moment,
        licence_scope="store_metadata",
        confidence="vendor_reported",
        source_ref=uid,
        stix_exportable=False,
        contains_personal_information=False,
    )
    return clamp_to_terms(finding, get_vendor("flare").terms)


def _summary(item: dict) -> str:
    highlights = item.get("highlights")
    if not isinstance(highlights, dict):
        return ""
    for key in ("title", "description"):
        values = highlights.get(key)
        if isinstance(values, list) and values and isinstance(values[0], str):
            return values[0].replace("<mark>", "").replace("</mark>", "")
    return ""


def normalise_event(item: dict, watchlist: Watchlist) -> dict | None:
    finding = to_finding(item, watchlist)
    metadata = _metadata(item)
    if finding is None or metadata is None:
        return None
    payload = finding_payload(finding)
    severity = metadata.get("severity")
    payload["severity"] = severity if severity in _SEVERITY else None
    payload["event_type"] = metadata.get("type")
    payload["estimated_created_at"] = metadata.get("estimated_created_at")
    identifier = _primary(item)
    if identifier is not None and isinstance(identifier.get("id"), int):
        payload["identifier_id"] = identifier["id"]
    summary = _summary(item)
    if summary:
        payload["summary"] = _wrap(summary)
    if metadata.get("type") == "ransomleak":
        payload["briefing"] = untrusted_text(_UNCONFIRMED, "flare")
    return payload


def _store(findings: list[ExposureFinding], watchlist: Watchlist) -> None:
    if not findings:
        return
    store = ExposureStore(data_dir() / "intel.sqlite")
    terms = get_vendor("flare").terms
    for finding in findings:
        store.write(finding, terms=terms, watchlist=watchlist)


def _events(
    fetched: Fetch, *, since, types, min_severity, watchlist: Watchlist
) -> tuple[list, list]:
    records = []
    findings = []
    for item in fetched.items:
        kept = isinstance(item, dict) and _kept(
            item, since=since, types=types, min_severity=min_severity
        )
        if not kept:
            continue
        record = normalise_event(item, watchlist)
        if record is None:
            continue
        records.append(record)
        finding = to_finding(item, watchlist)
        on_list = (
            finding is not None and finding.subject.value.casefold() in watchlist.known_subjects()
        )
        if on_list:
            findings.append(finding)
    return records, findings


def _search_body(
    since: str | None,
    types: list[str],
    min_severity: str | None,
    *,
    remediated: bool | None,
) -> dict:
    filters: dict = {"type": types}
    if min_severity:
        filters["severity"] = min_severity
    if since:
        filters["estimated_created_at"] = {"gte": _sydney_start(since).isoformat()}
    if remediated is False:
        filters["is_remediated"] = False
    return {"filters": filters}


def flare_tenant_exposure(
    since: str | None = None,
    types: list[str] | None = None,
    min_severity: str | None = None,
    limit: int = 100,
) -> dict:
    problem = _reject(
        "flare_tenant_exposure",
        _provided(since=since, types=types, min_severity=min_severity, limit=limit),
    )
    if problem:
        return _envelope([], "snapshot", (problem,))
    chosen = list(DEFAULT_TYPES if types is None else types)
    fetched = fetch_tenant_events(
        _search_body(since, chosen, min_severity, remediated=None),
        limit=limit,
    )
    if fetched.warnings and not fetched.items:
        warned = _unavailable("Flare tenant events", fetched.warnings)
        return _envelope([], fetched.cache, warned, urls=[TENANT_EVENTS_URL])
    watchlist = load_watchlist()
    records, findings = _events(
        fetched,
        since=since,
        types=chosen,
        min_severity=min_severity,
        watchlist=watchlist,
    )
    _store(findings, watchlist)
    warnings: list[str] = list(fetched.warnings)
    if fetched.items and not records and not fetched.warnings:
        usable = any(_metadata(item) for item in fetched.items if isinstance(item, dict))
        if not usable:
            warnings.append("Flare payload was not usable")
    return _envelope(records, fetched.cache, warnings, urls=[TENANT_EVENTS_URL])


def flare_identifier_events(
    identifier_id: int,
    since: str | None = None,
    include_remediated: bool = False,
) -> dict:
    problem = _reject(
        "flare_identifier_events",
        _provided(identifier_id=identifier_id, since=since, include_remediated=include_remediated),
    )
    if problem:
        return _envelope([], "snapshot", (problem,))
    url = f"https://api.flare.io/firework/v4/events/identifiers/{identifier_id}/_search"
    fetched = fetch_identifier_events(
        identifier_id,
        _search_body(
            since,
            list(DEFAULT_TYPES),
            None,
            remediated=False if not include_remediated else None,
        ),
        limit=100,
    )
    if fetched.warnings and not fetched.items:
        warned = _unavailable("Flare identifier events", fetched.warnings)
        return _envelope([], fetched.cache, warned, urls=[url])
    watchlist = load_watchlist()
    records, findings = _events(
        fetched,
        since=since,
        types=DEFAULT_TYPES,
        min_severity=None,
        watchlist=watchlist,
    )
    _store(findings, watchlist)
    return _envelope(records, fetched.cache, fetched.warnings, urls=[url])


def flare_identifiers() -> dict:
    fetched = fetch_identifiers()
    if fetched.warnings and not fetched.items:
        warned = _unavailable("Flare identifiers", fetched.warnings)
        return _envelope({}, fetched.cache, warned, urls=[IDENTIFIERS_URL])
    watchlist = load_watchlist()
    rows = []
    for item in fetched.items:
        if not isinstance(item, dict):
            continue
        name = item.get("name") if isinstance(item.get("name"), str) else ""
        kind = item.get("type") if isinstance(item.get("type"), str) else ""
        identifier = item.get("id")
        rows.append(
            {
                "id": identifier
                if isinstance(identifier, int) and not isinstance(identifier, bool)
                else None,
                "name": _wrap(name) if name else "",
                "type": _wrap(kind) if kind else "",
            }
        )
    raw_items = [item for item in fetched.items if isinstance(item, dict)]
    compared = compare_identifiers(watchlist, raw_items)
    data = {
        "identifiers": rows,
        "missing_from_flare": compared["missing_from_flare"],
        "not_on_watchlist": [_wrap(name) for name in compared["not_on_watchlist"]],
    }
    return _envelope(data, fetched.cache, fetched.warnings, urls=[IDENTIFIERS_URL])


def aggregate_credentials(items: list, *, since: str | None) -> list[dict]:
    """Counts by source type and imported date. Credential values are dropped."""
    start = _sydney_start(since) if since else None
    counts: dict[tuple[str, str], int] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        imported = _parse_time(str(item.get("imported_at") or ""))
        if start is not None and (imported is None or imported < start):
            continue
        day = imported.astimezone(_sydney_zone()).date().isoformat() if imported else "unknown"
        source = item.get("source") if isinstance(item.get("source"), dict) else {}
        source_type = source.get("id") or item.get("source_id") or "unknown"
        if not isinstance(source_type, str) or not source_type:
            source_type = "unknown"
        count_value = item.get("count")
        if isinstance(count_value, int) and not isinstance(count_value, bool):
            add = count_value
        else:
            add = 1
        counts[(source_type, day)] = counts.get((source_type, day), 0) + add
    return [
        {"source_type": _wrap(source_type), "imported_on": day, "count": count}
        for (source_type, day), count in sorted(counts.items())
    ]


def _sydney_zone():
    from cyberau_premium.budget import SYDNEY

    return SYDNEY


def flare_domain_credentials(domain: str, since: str | None = None) -> dict:
    problem = _reject("flare_domain_credentials", _provided(domain=domain, since=since))
    if problem or _HOST.fullmatch(domain) is None:
        return _envelope([], "snapshot", (problem or "domain must be a hostname",))
    # Global Search spends quota, so only the user's own email domains go out.
    if domain.casefold() not in {item.casefold() for item in load_watchlist().email_domains}:
        return _envelope([], "snapshot", ("domain is not a watchlist email domain",))
    # Tenant searches do not come through here. The floor is a hard stop.
    # Above the daily count the call asks and does not spend Global Search quota.
    config = load_profile_config()
    decision = global_search_decision(config, approved=False)
    if decision is not None:
        return _envelope([], "snapshot", (decision["message"],))
    since_iso = _sydney_start(since).isoformat() if since else None

    def gate() -> str | None:
        later = global_search_decision(config, approved=False)
        return None if later is None else later["message"]

    fetched = fetch_domain_credentials(domain_query(domain, since=since_iso, size=100), gate=gate)
    if fetched.warnings and not fetched.items:
        warned = _unavailable("Flare domain credentials", fetched.warnings)
        return _envelope([], fetched.cache, warned, urls=[CREDENTIALS_URL])
    rows = aggregate_credentials(fetched.items, since=since)
    return _envelope(rows, fetched.cache, fetched.warnings, urls=[CREDENTIALS_URL])


def flare_quota_status() -> dict:
    view = quota_view()
    warnings = ()
    if view["remaining"] is None:
        warnings = (
            unavailable("Flare Global Search quota", "no global search has been recorded yet"),
        )
    return _envelope(view, "snapshot", warnings)


class FlareConnector(PremiumConnector):
    def __init__(self) -> None:
        spec = get_vendor("flare")
        super().__init__(
            key="flare",
            server_name="flare",
            attribution=spec.terms.attribution,
            vendor=spec.server,
            licence_env=tuple(spec.licence_env),
            terms=spec.terms,
            quota=spec.quota,
            tools=[
                ToolSpec(
                    "flare_tenant_exposure",
                    "Tenant events since a date, as exposure kinds. No credential values.",
                    flare_tenant_exposure,
                ),
                ToolSpec(
                    "flare_identifier_events",
                    "Events for one monitored identifier.",
                    flare_identifier_events,
                ),
                ToolSpec(
                    "flare_identifiers",
                    "Identifiers monitored in the tenant, compared with the local watchlist.",
                    flare_identifiers,
                ),
                ToolSpec(
                    "flare_domain_credentials",
                    "Credential counts for one watchlist email domain. Spends Global Search quota.",
                    flare_domain_credentials,
                ),
                ToolSpec(
                    "flare_quota_status",
                    "Global Search searches remaining this month, from the last response header.",
                    flare_quota_status,
                ),
            ],
        )

    def exposure_for(self, watchlist: Watchlist, since: date) -> list[ExposureFinding]:
        problem = missing_key_warning()
        if problem and fixture_dir() is None:
            raise RuntimeError(problem)
        fetched = fetch_tenant_events(
            _search_body(since.isoformat(), list(DEFAULT_TYPES), None, remediated=None),
            limit=100,
        )
        if fetched.warnings and not fetched.items:
            raise RuntimeError(fetched.warnings[0])
        findings = []
        for item in fetched.items:
            if not isinstance(item, dict):
                continue
            if not _kept(item, since=since.isoformat(), types=DEFAULT_TYPES, min_severity=None):
                continue
            finding = to_finding(item, watchlist)
            if finding is None:
                continue
            if finding.subject.value.casefold() not in watchlist.known_subjects():
                continue
            findings.append(finding)
        _store(findings, watchlist)
        return findings

    def health_result(self, *, live: bool = False) -> HealthResult:
        result = super().health_result(live=False)
        if not live:
            return result
        if not result.configured:
            return HealthResult(configured=False, ok=False, detail="not configured")
        ok, detail = probe_token()
        return HealthResult(configured=True, ok=ok, detail=detail)

    def health(self, *, live: bool = False, check_schema: bool = False) -> Probe:
        if check_schema and not live:
            # Offline schema check only. The local copies are compared against the
            # schema and never returned as Flare data.
            problems = []
            drift = schema_drift(load_schema_sample())
            if drift:
                problems.append(drift)
            changed = mcp_drift(load_mcp_tool_names())
            if changed:
                problems.append(changed)
            if problems:
                return Probe(self.key, False, "; ".join(problems))
            return Probe(self.key, True, "schema ok")
        result = self.health_result(live=live)
        return Probe(self.key, result.ok, redact(result.detail))


def connector() -> FlareConnector:
    return FlareConnector()


register_connector("flare", connector)
