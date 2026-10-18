"""Read-only Information Security Manual OSCAL catalogue."""

import hashlib
import json
import os
import re
import time
from collections.abc import Callable
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Annotated, Literal

from cyberau_common import USER_AGENT
from cyberau_common.cache import HttpCache
from cyberau_common.egress import EgressPolicy
from cyberau_common.envelope import envelope, untrusted_text
from cyberau_common.http import HttpClient
from cyberau_common.ratelimit import RateLimiter
from cyberau_common.secrets import lookup, redact
from cyberau_common.server import Connector, Probe, ToolSpec, register_connector
from cyberau_common.snapshot import (
    check_shipped,
    read_shipped,
    snapshot_note,
    synthetic_marker,
    unavailable,
)
from pydantic import Field

RELEASES_API = "https://api.github.com/repos/AustralianCyberSecurityCentre/ism-oscal/releases"
RAW_ROOT = "https://raw.githubusercontent.com/AustralianCyberSecurityCentre/ism-oscal"
ATTRIBUTION = (
    "© Commonwealth of Australia 2024. Information Security Manual content is published by "
    "the Australian Signals Directorate under Creative Commons Attribution 4.0 International. "
    "This connector is not endorsed by ASD."
)
BASELINES = (
    "NON_CLASSIFIED",
    "OFFICIAL_SENSITIVE",
    "PROTECTED",
    "SECRET",
    "TOP_SECRET",
    "E8_ML1",
    "E8_ML2",
    "E8_ML3",
)
_Baseline = Literal[
    "NON_CLASSIFIED",
    "OFFICIAL_SENSITIVE",
    "PROTECTED",
    "SECRET",
    "TOP_SECRET",
    "E8_ML1",
    "E8_ML2",
    "E8_ML3",
]
_ControlId = Annotated[str, Field(pattern=r"^(ISM-)?\d{3,4}$|^ism-")]
_Query = Annotated[str, Field(min_length=2)]
_Limit = Annotated[int, Field(ge=1, le=50)]
_PACKAGE = Path(__file__).resolve().parents[2]
_LEVELS = {
    "NC": "NON_CLASSIFIED",
    "OS": "OFFICIAL_SENSITIVE",
    "P": "PROTECTED",
    "S": "SECRET",
    "TS": "TOP_SECRET",
}
_E8 = {"ML1": "E8_ML1", "ML2": "E8_ML2", "ML3": "E8_ML3"}
_TRANSPORT = None
_SLEEP = time.sleep
# The shipped release list is refused once it is this old. Catalogues for a tag do not expire.
SNAPSHOT_MAX_AGE_DAYS = 180
_TODAY: Callable[[], date] | None = None


def ism_get_control(control_id: _ControlId, release: str | None = None) -> dict:
    normalised = _normalise(control_id)
    if not normalised:
        return _envelope(None, "snapshot", warnings=("control_id is not an ISM id",))
    tag, warning = _tag(release)
    if warning:
        return _envelope(None, "snapshot", warnings=(warning,))
    controls, cache, note, digest = _controls(tag)
    if controls is None:
        return _envelope(None, cache, warnings=(note or f"{tag} catalogue was not usable",))
    record = controls.get(normalised)
    if record is None:
        return _envelope(
            None,
            cache,
            warnings=(f"no matching control {normalised} in {tag}",),
        )
    warnings = (note,) if note else ()
    return _envelope(_public(record, digest, tag), cache, _catalog_url(tag), tag, warnings)


def ism_search(
    query: _Query,
    baseline: _Baseline | None = None,
    release: str | None = None,
    limit: _Limit = 10,
) -> dict:
    if not isinstance(query, str) or len(query.strip()) < 2:
        return _envelope([], "snapshot", warnings=("query must be at least 2 characters",))
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 50:
        return _envelope([], "snapshot", warnings=("limit must be between 1 and 50",))
    if baseline and baseline not in BASELINES:
        return _envelope([], "snapshot", warnings=("baseline is not a known value",))
    tag, warning = _tag(release)
    if warning:
        return _envelope([], "snapshot", warnings=(warning,))
    controls, cache, note, digest = _controls(tag)
    if controls is None:
        return _envelope([], cache, warnings=(note or f"{tag} catalogue was not usable",))
    allowed, baseline_note = _baseline_ids(tag, baseline) if baseline else (None, "")
    if baseline_note:
        return _envelope([], cache, warnings=(baseline_note,))
    needle = query.strip().lower()
    rows = []
    for record in controls.values():
        if allowed is not None and record["control_id"] not in allowed:
            continue
        haystack = " ".join(
            (
                record["control_id"],
                record["title"],
                record["statement"],
                record["section"],
                record["guideline"],
            )
        ).lower()
        if needle not in haystack:
            continue
        rows.append(_public(record, digest, tag))
    warnings = []
    if note:
        warnings.append(note)
    if not rows:
        warnings.append(f"no controls match {query!r}")
    return _envelope(rows[:limit], cache, _catalog_url(tag), tag, tuple(warnings))


def ism_list_baseline(baseline: _Baseline, release: str | None = None) -> dict:
    if baseline not in BASELINES:
        return _envelope([], "snapshot", warnings=("baseline is not a known value",))
    tag, warning = _tag(release)
    if warning:
        return _envelope([], "snapshot", warnings=(warning,))
    allowed, note = _baseline_ids(tag, baseline)
    if note:
        return _envelope([], "snapshot", warnings=(note,))
    return _envelope(
        [{"baseline": baseline, "release": tag, "control_ids": allowed}],
        "snapshot",
        _profile_url(tag, baseline),
        tag,
    )


def ism_diff(from_release: str, to_release: str) -> dict:
    older, older_note = _tag(from_release)
    newer, newer_note = _tag(to_release)
    if older_note or newer_note:
        return _envelope([], "snapshot", warnings=(older_note or newer_note,))
    before, before_cache, before_note, _before_digest = _controls(older)
    after, after_cache, after_note, _after_digest = _controls(newer)
    warnings = [note for note in (before_note, after_note) if note]
    if before is None or after is None:
        warnings.append("one or both catalogues were not usable")
        return _envelope(None, "snapshot", warnings=tuple(warnings))
    added = sorted(set(after) - set(before))
    removed = sorted(set(before) - set(after))
    changed = []
    for control_id in sorted(set(before) & set(after)):
        if before[control_id]["statement"] == after[control_id]["statement"]:
            continue
        changed.append(
            {
                "control_id": control_id,
                "from_statement": untrusted_text(before[control_id]["statement"], "ism"),
                "to_statement": untrusted_text(after[control_id]["statement"], "ism"),
            }
        )
    cache = "stale" if "stale" in {before_cache, after_cache} else before_cache
    return _envelope(
        {
            "from_release": older,
            "to_release": newer,
            "added": added,
            "removed": removed,
            "changed": changed,
        },
        cache,
        [_catalog_url(older), _catalog_url(newer)],
        newer,
        tuple(warnings),
    )


def connector() -> Connector:
    return _IsmConnector()


class _IsmConnector(Connector):
    def __init__(self) -> None:
        super().__init__(
            key="asd-ism",
            server_name="ism",
            attribution=ATTRIBUTION,
            tools=[
                ToolSpec(
                    "ism_get_control",
                    "One ISM control from an OSCAL release.",
                    ism_get_control,
                ),
                ToolSpec(
                    "ism_search",
                    "Search ISM controls, optionally in one baseline.",
                    ism_search,
                ),
                ToolSpec(
                    "ism_list_baseline",
                    "Control ids in one ISM baseline.",
                    ism_list_baseline,
                ),
                ToolSpec(
                    "ism_diff",
                    "Controls added, removed, or changed between releases.",
                    ism_diff,
                ),
            ],
        )

    def health(self, *, live: bool, check_schema: bool = False) -> Probe:
        if check_schema and not live:
            tag, warning = _tag(None)
            if warning:
                return Probe(self.key, False, warning)
            text = _read_catalog(tag)
            problem = schema_drift(_loads(text) if text else None)
            if problem:
                return Probe(self.key, False, problem)
            return Probe(self.key, True, "schema ok")
        if not live:
            return Probe(self.key, True, "offline ok")
        payload, _cache, warning = _releases(force_live=True)
        if warning:
            return Probe(self.key, False, warning)
        rows = _release_rows(payload)
        if not rows or not rows[0].get("tag_name"):
            return Probe(self.key, False, "ISM release list has no tag_name")
        return Probe(self.key, True, "live ok")


def schema_drift(payload) -> str | None:
    if not isinstance(payload, dict):
        return "ISM payload is not an object"
    catalog = payload.get("catalog")
    if not isinstance(catalog, dict):
        return "ISM payload has no catalog"
    groups = catalog.get("groups")
    if not isinstance(groups, list):
        return "ISM schema drift, missing groups"
    control = _first_control(groups)
    if control is None:
        return None
    if "id" not in control:
        return "ISM schema drift, missing id"
    return None


def _controls(tag: str) -> tuple[dict | None, str, str, str]:
    text, cache, warning = _catalog_text(tag, force_live=False)
    if text is None:
        return None, cache, warning, ""
    payload = _loads(text)
    problem = schema_drift(payload)
    if problem:
        return None, cache, problem, ""
    found: dict[str, dict] = {}
    _walk(payload["catalog"].get("groups") or [], "", found)
    return found, cache, warning, hashlib.sha256(text.encode()).hexdigest()


def _catalog_text(tag: str, *, force_live: bool) -> tuple[str | None, str, str]:
    offline = os.environ.get("CYBERAU_OFFLINE") == "1" and not force_live
    if _override() is not None and not force_live:
        text = _read_catalog(tag)
        if text is None:
            return None, "snapshot", f"{tag} catalogue snapshot is missing"
        return text, "snapshot", ""
    if offline:
        return _shipped_catalog(tag, "offline")
    fetched, cache, warning = _http(
        _catalog_url(tag),
        api=False,
        ttl=7 * 86400,
        skip_cache=force_live,
    )
    if fetched is not None and not warning:
        return fetched, cache, ""
    if force_live:
        return None, "snapshot", warning or f"{tag} live fetch failed"
    return _shipped_catalog(tag, f"{tag} fetch failed: {warning or 'not usable'}")


def _shipped_catalog(tag: str, reason: str) -> tuple[str | None, str, str]:
    """A shipped catalogue is a full, published release, so it does not expire."""
    text = read_shipped(_PACKAGE / "data" / tag / "ISM_catalog.json")
    if text is None:
        return None, "snapshot", unavailable(f"ISM {tag} catalogue", reason)
    refused = synthetic_marker(text)
    if refused:
        return (
            None,
            "snapshot",
            unavailable(f"ISM {tag} catalogue", f"{reason}; shipped copy is test data"),
        )
    note = snapshot_note(f"ISM {tag} catalogue", _shipped_retrieved_on())
    return text, "snapshot", f"{reason}; {note}"


def _releases(*, force_live: bool = False) -> tuple[object, str, str]:
    offline = os.environ.get("CYBERAU_OFFLINE") == "1" and not force_live
    if _override() is not None and not force_live:
        path = _root() / "releases.json"
        if not path.is_file():
            return None, "snapshot", "ISM release snapshot is missing"
        return _loads(path.read_text(encoding="utf-8")), "snapshot", ""
    if offline:
        return _shipped_releases("offline")
    text, cache, warning = _http(RELEASES_API, api=True, ttl=12 * 3600, skip_cache=force_live)
    if text is None or warning:
        if force_live:
            return None, "snapshot", _github_warning(warning or "live fetch failed")
        return _shipped_releases(_github_warning(warning or "release list was not usable"))
    return _loads(text), cache, ""


def _shipped_releases(reason: str) -> tuple[object, str, str]:
    """The shipped release list picks the latest release, so it expires."""
    label = "ISM release list"
    text = read_shipped(_PACKAGE / "data" / "releases.json")
    payload = _loads(text)
    if text is None or not isinstance(payload, dict):
        return None, "snapshot", unavailable(label, reason)
    as_of = payload.get("retrieved_on")
    refused = check_shipped(
        text, as_of, label=label, max_age_days=SNAPSHOT_MAX_AGE_DAYS, today=_today()
    )
    if refused:
        return None, "snapshot", unavailable(label, f"{reason}; {refused}")
    note = snapshot_note(label, as_of)
    return payload, "snapshot", f"{reason}; {note}. A newer ISM release may exist"


def _shipped_retrieved_on() -> str | None:
    payload = _loads(read_shipped(_PACKAGE / "data" / "releases.json"))
    if isinstance(payload, dict) and payload.get("retrieved_on"):
        return str(payload["retrieved_on"])
    return None


def _baseline_ids(tag: str, baseline: str) -> tuple[list[str] | None, str]:
    name = f"ISM_{baseline}-baseline_profile.json"
    if _override() is not None:
        text = read_shipped(_root() / tag / name)
    else:
        # Published profiles do not change, so a shipped copy for this tag is current.
        text = read_shipped(_PACKAGE / "data" / tag / name)
        if text is None and os.environ.get("CYBERAU_OFFLINE") != "1":
            text, _cache, warning = _http(
                _profile_url(tag, baseline), api=False, ttl=7 * 86400, skip_cache=False
            )
            if warning:
                text = None
    if text is None:
        return None, f"{baseline} baseline snapshot is missing for {tag}"
    payload = _loads(text)
    if not isinstance(payload, dict):
        return None, f"{baseline} baseline snapshot was not usable"
    found = []
    for item in (payload.get("profile") or {}).get("imports") or []:
        for included in item.get("include-controls") or []:
            found.extend(included.get("with-ids") or [])
    return found, ""


def _http(
    url: str, *, api: bool, ttl: int, skip_cache: bool, budget: bool = True
) -> tuple[str | None, str, str]:
    """GET through the egress policy. ``budget`` applies the hourly per-tool GitHub limit."""
    secret = lookup("GITHUB_TOKEN") if api else None
    headers = {"accept": "application/vnd.github+json"} if api else {}
    if secret:
        headers["authorization"] = f"Bearer {secret}"
    data_dir = _data_dir()
    client = HttpClient(
        "asd-ism",
        policy=EgressPolicy(_allowlist(), "asd-ism"),
        cache=HttpCache(data_dir / "http_cache.sqlite"),
        limiter=RateLimiter(data_dir / "rate_limit.sqlite", sleeper=_SLEEP),
        user_agent=USER_AGENT,
        rate=4,
        burst=20,
        window="rolling",
        timeout=60,
        retries=3,
        transport=_TRANSPORT,
        sleeper=_SLEEP,
        auth_scope="github" if secret else "anonymous",
    )
    try:
        if budget:
            _limit("asd-ism:github", rate=10 / 3600, burst=10)
        response = client.get(
            url,
            headers=headers,
            ttl=ttl,
            stale_if_error=0,
            skip_cache=skip_cache,
        )
    except Exception as exc:
        return None, "snapshot", _clean(exc, secret)
    finally:
        client.close()
    if response.status == 403:
        return (
            None,
            response.cache,
            "GitHub refused the request (403). Set GITHUB_TOKEN to raise the rate limit.",
        )
    if response.status >= 400:
        return None, response.cache, f"upstream status {response.status}"
    try:
        text = response.body.decode("utf-8")
    except UnicodeDecodeError:
        return None, response.cache, "ISM payload was not UTF-8"
    warning = "served from cache after the live fetch failed" if response.cache == "stale" else ""
    return text, response.cache, warning


def _walk(nodes: list, section: str, found: dict) -> None:
    for node in nodes:
        title = " / ".join(part for part in (section, node.get("title")) if part)
        for control in node.get("controls") or []:
            if isinstance(control, dict) and control.get("id"):
                found[control["id"]] = _record(control, title)
        _walk(node.get("groups") or [], title, found)


def _record(control: dict, section: str) -> dict:
    statement = ""
    guideline = ""
    for part in control.get("parts") or []:
        prose = str(part.get("prose") or "")
        if part.get("name") == "statement" and not statement:
            statement = prose
        if part.get("name") == "guideline" and not guideline:
            guideline = prose
    applicability = []
    for prop in control.get("props") or []:
        name = prop.get("name")
        value = str(prop.get("value") or "")
        if name == "applicability" and value in _LEVELS:
            applicability.append(_LEVELS[value])
        if name == "essential-eight-applicability" and value in _E8:
            applicability.append(_E8[value])
    return {
        "control_id": control["id"],
        "title": str(control.get("title") or ""),
        "statement": statement,
        "guideline": guideline,
        "section": section,
        "applicability": applicability,
    }


def _public(record: dict, digest: str, tag: str) -> dict:
    return {
        "control_id": record["control_id"],
        "oscal_id": record["control_id"],
        "title": untrusted_text(record["title"], "ism"),
        "statement": untrusted_text(record["statement"], "ism"),
        "guideline": untrusted_text(record["guideline"], "ism") if record["guideline"] else "",
        "section": untrusted_text(record["section"], "ism"),
        "applicability": record["applicability"],
        "release": tag,
        "source_sha256": digest,
    }


def _first_control(nodes: list):
    for node in nodes:
        if not isinstance(node, dict):
            continue
        for control in node.get("controls") or []:
            if isinstance(control, dict):
                return control
        found = _first_control(node.get("groups") or [])
        if found is not None:
            return found
    return None


def _tag(release: str | None) -> tuple[str, str]:
    if release:
        text = release.strip()
        if not text:
            return "", "release is empty"
        return text if text.startswith("v") else f"v{text}", ""
    payload, _cache, warning = _releases()
    rows = _release_rows(payload)
    if not rows:
        return "", warning or "no ISM releases in the snapshot"
    rows.sort(key=lambda row: str(row.get("published_at") or ""), reverse=True)
    tag = str(rows[0].get("tag_name") or "")
    if not tag:
        return "", "ISM release list has no tag_name"
    return tag, ""


def _release_rows(payload) -> list[dict]:
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    if isinstance(payload, dict):
        rows = payload.get("releases")
        if isinstance(rows, list):
            return [row for row in rows if isinstance(row, dict)]
    return []


def _normalise(control_id: str) -> str:
    if not isinstance(control_id, str):
        return ""
    text = control_id.strip()
    if re.fullmatch(r"(?i)ISM-\d{3,4}", text) or re.fullmatch(r"\d{3,4}", text):
        number = re.search(r"\d+", text)
        return f"ism-{number.group(0).zfill(4)}" if number else ""
    if text.lower().startswith("ism-"):
        return text.lower()
    return ""


def _read_catalog(tag: str) -> str | None:
    path = _root() / tag / "ISM_catalog.json"
    if not path.is_file():
        return None
    return path.read_text(encoding="utf-8")


def _root() -> Path:
    return _override() or _PACKAGE / "data"


def _override() -> Path | None:
    """An operator-supplied snapshot directory. It is never checked for age."""
    override = os.environ.get("CYBERAU_ISM_SNAPSHOT")
    return Path(override) if override else None


def _today() -> date:
    return _TODAY() if _TODAY is not None else datetime.now(UTC).date()


def _catalog_url(tag: str) -> str:
    return f"{RAW_ROOT}/{tag}/ISM_catalog.json"


def _profile_url(tag: str, baseline: str) -> str:
    return f"{RAW_ROOT}/{tag}/ISM_{baseline}-baseline_profile.json"


def _loads(text: str | None):
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _github_warning(message: str) -> str:
    if "403" in message and "GITHUB_TOKEN" not in message:
        return "GitHub refused the request (403). Set GITHUB_TOKEN to raise the rate limit."
    return message


def _clean(exc: Exception, secret: str | None) -> str:
    message = redact(str(exc))
    if secret:
        message = message.replace(secret, "[REDACTED]")
    return _github_warning(message)


def _limit(key: str, *, rate: float, burst: int) -> None:
    RateLimiter(_data_dir() / "rate_limit.sqlite", sleeper=_SLEEP).acquire(
        key,
        rate=rate,
        burst=burst,
        window="rolling",
        timeout=60,
    )


def _envelope(data, cache: str, urls=None, data_as_of: str | None = None, warnings=()):
    if isinstance(urls, str):
        urls = [urls]
    return envelope(
        "asd-ism",
        data,
        urls=list(urls or []),
        cache=cache,
        data_as_of=data_as_of,
        warnings=warnings,
        attribution=ATTRIBUTION,
    )


def _data_dir() -> Path:
    path = Path(os.environ.get("CYBERAU_DATA_DIR", "/tmp/cyberau-ism"))
    path.mkdir(parents=True, exist_ok=True)
    return path


def _allowlist() -> Path:
    return Path(__file__).resolve().parents[3] / "egress-allowlist.yaml"


def rebuild_shipped_snapshot(destination: Path | None = None, keep: int = 2) -> dict:
    """Download the newest ``keep`` ISM releases in full and rewrite the shipped data.

    Fetches go through the connector's HTTP client, so the egress policy and rate
    limits apply. Nothing is written until every file has been fetched and parsed.
    Release directories outside the newest ``keep`` are removed.
    """
    if keep < 1:
        raise ValueError("keep must be at least 1")
    destination = destination or (_PACKAGE / "data")
    text, _cache, warning = _http(RELEASES_API, api=True, ttl=3600, skip_cache=True)
    if text is None or warning:
        raise RuntimeError(_github_warning(warning or "release list was not usable"))
    rows = [
        {"tag_name": str(row["tag_name"]), "published_at": str(row.get("published_at") or "")}
        for row in _release_rows(_loads(text))
        if row.get("tag_name") and not row.get("draft") and not row.get("prerelease")
    ]
    rows.sort(key=lambda row: row["published_at"], reverse=True)
    rows = rows[:keep]
    if not rows:
        raise RuntimeError("ISM release list had no releases")
    files: dict[str, dict[str, str]] = {}
    for row in rows:
        tag = row["tag_name"]
        if not re.fullmatch(r"v[0-9][0-9.]*", tag):
            raise RuntimeError(f"refusing unexpected ISM release tag {tag!r}")
        catalog, _cache, warning = _http(
            _catalog_url(tag), api=False, ttl=3600, skip_cache=True, budget=False
        )
        if catalog is None or warning:
            raise RuntimeError(warning or f"{tag} catalogue was not usable")
        problem = schema_drift(_loads(catalog))
        if problem:
            raise RuntimeError(f"{tag}: {problem}")
        files[tag] = {"ISM_catalog.json": catalog}
        for baseline in BASELINES:
            profile, _cache, warning = _http(
                _profile_url(tag, baseline), api=False, ttl=3600, skip_cache=True, budget=False
            )
            if profile is None or warning or not isinstance(_loads(profile), dict):
                raise RuntimeError(warning or f"{tag} {baseline} profile was not usable")
            files[tag][f"ISM_{baseline}-baseline_profile.json"] = profile
    destination.mkdir(parents=True, exist_ok=True)
    for tag, members in files.items():
        folder = destination / tag
        folder.mkdir(parents=True, exist_ok=True)
        for name, body in members.items():
            (folder / name).write_text(body, encoding="utf-8")
    kept = set(files)
    removed = []
    for folder in sorted(destination.iterdir()):
        if folder.is_dir() and (folder / "ISM_catalog.json").is_file() and folder.name not in kept:
            for child in folder.iterdir():
                child.unlink()
            folder.rmdir()
            removed.append(folder.name)
    retrieved_on = _today().isoformat()
    releases = {"retrieved_on": retrieved_on, "releases": rows}
    (destination / "releases.json").write_text(
        json.dumps(releases, indent=2) + "\n", encoding="utf-8"
    )
    return {
        "retrieved_on": retrieved_on,
        "kept": [row["tag_name"] for row in rows],
        "removed": removed,
    }


register_connector("asd-ism", connector)
