"""Feed freshness and provenance for the dashboard Sources page.

Standard library only. Every reader here opens files read-only and never
raises for a missing or broken file: it returns what it could read and a note.

Inputs, all optional:

- feeds/catalogue.yaml: one entry per source (name, server, keyed, poll, licence).
- The profile config.yaml: which MCP servers are listed and which are disabled.
- plugin-data/cyber-au/bootstrap-status.json: keyed servers whose variable was
  unset at the last bootstrap. The profile .env is never opened.
- Refresh status JSON written by ``cyberau-mcp refresh --status`` (or
  ``--catalogue``, which writes status.json beside the catalogue).
- The ASD ACSC connector's feed_status table (asd_advisories.sqlite).
- The intel store (intel.sqlite): stored rows and the newest date per source.
"""

from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit

STATUS_NAMES = ("feed-status.json", "feeds-status.json")
_DURATION_RE = re.compile(
    r"P(?:(?P<days>\d+)D)?(?:T(?:(?P<hours>\d+)H)?(?:(?P<minutes>\d+)M)?(?:(?P<seconds>\d+)S)?)?"
)


@dataclass
class SourceRow:
    id: str
    name: str
    server: str | None
    connector: str
    keyed: bool
    enabled: str
    key: str
    poll: str
    licence: str
    last_success: str | None = None
    last_error: str | None = None
    items: int | None = None
    data_as_of: str | None = None
    cache: str = "-"
    age: str = "never"
    state: str = "no run recorded"
    origins: list[str] = field(default_factory=list)


# --- small readers ------------------------------------------------------------------


def parse_duration(value: str) -> timedelta | None:
    """ISO 8601 duration with days, hours, minutes and seconds. None when unreadable."""
    match = _DURATION_RE.fullmatch(str(value or "").strip())
    if not match or str(value).strip() in ("P", "PT"):
        return None
    parts = {key: int(number) for key, number in match.groupdict().items() if number}
    return timedelta(**parts)


def parse_time(value: object) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC)


def age_text(then: datetime | None, now: datetime) -> str:
    if then is None:
        return "never"
    seconds = int((now - then).total_seconds())
    if seconds < 0:
        return "in the future"
    if seconds < 3600:
        return f"{max(seconds // 60, 0)}m"
    if seconds < 172800:
        return f"{seconds // 3600}h"
    return f"{seconds // 86400}d"


def _scalar(text: str) -> object:
    value = text.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    lowered = value.lower()
    if lowered in ("true", "false"):
        return lowered == "true"
    if lowered in ("null", "~", ""):
        return None
    return value


def _split_flow(body: str) -> list[str]:
    parts: list[str] = []
    depth = 0
    current = ""
    for char in body:
        if char in "[{":
            depth += 1
        elif char in "]}":
            depth -= 1
        if char == "," and depth == 0:
            parts.append(current)
            current = ""
        else:
            current += char
    if current.strip():
        parts.append(current)
    return parts


def _flow(value: str) -> object:
    value = value.strip()
    if value.startswith("{") and value.endswith("}"):
        result: dict[str, object] = {}
        for part in _split_flow(value[1:-1]):
            if ":" not in part:
                continue
            key, item = part.split(":", 1)
            result[key.strip()] = _flow(item)
        return result
    if value.startswith("[") and value.endswith("]"):
        return [_flow(item) for item in _split_flow(value[1:-1])]
    return _scalar(value)


def _strip_comment(line: str) -> str:
    if line.lstrip().startswith("#"):
        return ""
    return re.sub(r"\s+#.*$", "", line)


def parse_catalogue(text: str) -> list[dict]:
    """Read the feeds list of feeds/catalogue.yaml.

    A small reader for the shape that file uses (two-space list items, flow
    mappings and folded scalars), so the dashboard needs no YAML package.
    """
    feeds: list[dict] = []
    current: dict | None = None
    in_feeds = False
    folded_key: str | None = None
    for raw in text.splitlines():
        if folded_key is not None and current is not None:
            if raw.startswith("      ") or not raw.strip():
                if raw.strip():
                    joined = f"{current.get(folded_key) or ''} {raw.strip()}"
                    current[folded_key] = joined.strip()
                continue
            folded_key = None
        line = _strip_comment(raw).rstrip()
        if not line.strip():
            continue
        if not line.startswith(" "):
            in_feeds = line.strip() == "feeds:"
            current = None
            continue
        if not in_feeds:
            continue
        if line.startswith("  - "):
            current = {}
            feeds.append(current)
            line = "    " + line[4:]
        if current is None or not line.startswith("    ") or line.startswith("     "):
            continue
        body = line.strip()
        if ":" not in body:
            continue
        key, value = body.split(":", 1)
        key, value = key.strip(), value.strip()
        if value in (">-", ">", "|", "|-"):
            current[key] = ""
            folded_key = key
        elif value == "":
            current[key] = None
        else:
            current[key] = _flow(value)
    return [feed for feed in feeds if feed.get("id")]


def load_catalogue(path: Path | None) -> tuple[list[dict], str | None]:
    if path is None:
        return [], "No feed catalogue found. Start the server with --catalogue."
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return [], f"Could not read {path.name}."
    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError:
        yaml = None
    if yaml is not None:
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError:
            return [], f"{path.name} is not valid YAML."
        feeds = data.get("feeds") if isinstance(data, dict) else None
        if not isinstance(feeds, list):
            return [], f"{path.name} has no feeds list."
        return [feed for feed in feeds if isinstance(feed, dict) and feed.get("id")], None
    return parse_catalogue(text), None


def load_servers(config: Path) -> dict[str, bool] | None:
    """mcp_servers names in the profile config.yaml mapped to enabled. None when unreadable."""
    try:
        text = config.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    servers: dict[str, bool] = {}
    inside = False
    name: str | None = None
    indent: int | None = None
    for raw in text.splitlines():
        line = _strip_comment(raw).rstrip()
        if not line.strip():
            continue
        if not line.startswith(" "):
            inside = line.strip() == "mcp_servers:"
            name = None
            continue
        if not inside:
            continue
        width = len(line) - len(line.lstrip(" "))
        if indent is None:
            indent = width
        body = line.strip()
        if width == indent and body.endswith(":"):
            name = body[:-1].strip().strip("\"'")
            servers[name] = True
        elif name is not None and width > indent and body.replace(" ", "") == "enabled:false":
            servers[name] = False
    return servers


def load_missing_env(path: Path) -> dict[str, list[str]] | None:
    """Server name to variable names that were unset at the last bootstrap."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    missing: dict[str, list[str]] = {}
    items = (data.get("missing_env") or []) if isinstance(data, dict) else []
    for item in items:
        if isinstance(item, dict) and item.get("server"):
            missing.setdefault(str(item["server"]), []).append(str(item.get("variable") or ""))
    return missing


def load_present_env(path: Path) -> set[str] | None:
    """Variable names explicitly recorded by bootstrap, never their values."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    names = data.get("present_env") if isinstance(data, dict) else None
    if not isinstance(names, list) or not all(isinstance(name, str) for name in names):
        return None
    return set(names)


def load_refresh_status(paths: list[Path]) -> dict[str, dict]:
    """Merge every readable refresh status file. A later run of a source wins."""
    merged: dict[str, dict] = {}
    for path in paths:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        sources = data.get("sources") if isinstance(data, dict) else None
        if not isinstance(sources, dict):
            continue
        for key, entry in sources.items():
            if not isinstance(entry, dict):
                continue
            entry = {**entry, "_file": path.name}
            previous = merged.get(key)
            if previous is None or str(entry.get("last_run") or "") > str(
                previous.get("last_run") or ""
            ):
                merged[key] = entry
    return merged


def _connect_ro(path: Path) -> sqlite3.Connection | None:
    if not path.is_file():
        return None
    try:
        conn = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True, timeout=2)
    except sqlite3.Error:
        return None
    conn.row_factory = sqlite3.Row
    return conn


def load_asd_status(path: Path) -> list[dict]:
    conn = _connect_ro(path)
    if conn is None:
        return []
    try:
        rows = conn.execute(
            "SELECT feed, last_success, method, item_count, warning, data_as_of FROM feed_status"
        ).fetchall()
    except sqlite3.Error:
        return []
    finally:
        conn.close()
    return [dict(row) for row in rows]


def load_store_counts(path: Path) -> dict[str, dict]:
    """Stored rows and the newest date per intel store source id."""
    conn = _connect_ro(path)
    if conn is None:
        return {}
    found: dict[str, dict] = {}

    def add(source: str, count: int, newest: str | None) -> None:
        entry = found.setdefault(source, {"count": 0, "newest": None})
        entry["count"] += int(count or 0)
        if newest and (entry["newest"] is None or str(newest) > entry["newest"]):
            entry["newest"] = str(newest)

    queries = (
        "SELECT source_id, COUNT(*), MAX(first_seen) FROM advisories GROUP BY source_id",
        "SELECT source_id, COUNT(*), MAX(observed_at) FROM observations GROUP BY source_id",
    )
    try:
        for query in queries:
            try:
                for source, count, newest in conn.execute(query):
                    add(str(source), count, newest)
            except sqlite3.Error:
                continue
        try:
            row = conn.execute(
                "SELECT COUNT(*), MAX(updated_at) FROM vulnerabilities "
                "WHERE kev_date_added IS NOT NULL"
            ).fetchone()
            if row and row[0]:
                add("cisa-kev", row[0], row[1])
            row = conn.execute(
                "SELECT COUNT(*), MAX(epss_date) FROM vulnerabilities WHERE epss IS NOT NULL"
            ).fetchone()
            if row and row[0]:
                add("first-epss", row[0], row[1])
        except sqlite3.Error:
            pass
    finally:
        conn.close()
    return found


# --- assembling ---------------------------------------------------------------------


def _key_state(feed: dict, missing: dict[str, list[str]] | None, present: set[str] | None) -> str:
    auth = feed.get("auth") if isinstance(feed.get("auth"), dict) else {}
    names = [str(auth.get("env") or "")] + [str(item) for item in auth.get("env_also") or []]
    names = [name for name in names if name]
    if not names:
        return "not needed"
    if missing is None:
        return "unknown (no bootstrap status)"
    server = str(feed.get("server") or "")
    unset = [name for name in missing.get(server, []) if name in names]
    if unset:
        return "missing: " + ", ".join(unset)
    if auth.get("optional") and not feed.get("keyed"):
        return "optional"
    if present is None:
        return "unknown (not recorded at last bootstrap)"
    unset = [name for name in names if name not in present]
    if unset:
        return "missing: " + ", ".join(unset)
    return "set at last bootstrap"


def _enabled_state(feed: dict, servers: dict[str, bool] | None) -> str:
    server = feed.get("server")
    default = "on" if feed.get("enabled_by_default") else "off"
    if not server:
        return "no server entry"
    if servers is None:
        return f"unknown (default {default})"
    if server not in servers:
        return "not in config"
    return "enabled" if servers[server] else "disabled"


def build_rows(
    feeds: list[dict],
    *,
    servers: dict[str, bool] | None,
    missing: dict[str, list[str]] | None,
    refresh: dict[str, dict],
    asd: list[dict],
    store: dict[str, dict],
    now: datetime,
    present: set[str] | None = None,
) -> list[SourceRow]:
    rows: list[SourceRow] = []
    for feed in feeds:
        row = SourceRow(
            id=str(feed.get("id")),
            name=str(feed.get("name") or feed.get("id")),
            server=str(feed["server"]) if feed.get("server") else None,
            connector=str(feed.get("connector") or ""),
            keyed=bool(feed.get("keyed")),
            enabled=_enabled_state(feed, servers),
            key=_key_state(feed, missing, present),
            poll=str(feed.get("poll") or ""),
            licence=str(feed.get("licence") or "not stated"),
        )
        success: list[datetime] = []
        status = refresh.get(str(feed.get("refresh") or ""))
        if status:
            row.origins.append(f"refresh ({status.get('_file')})")
            when = parse_time(status.get("last_ok"))
            if when:
                success.append(when)
            if status.get("last_error"):
                row.last_error = str(status["last_error"])
            if status.get("item_count") is not None:
                row.items = int(status["item_count"])
        if row.connector == "asd-acsc" and asd:
            urls = feed.get("urls") or [feed.get("url")]
            expected = {
                urlsplit(str(url)).path.rstrip("/").rsplit("/", 1)[-1] for url in urls if url
            }
            selected = [item for item in asd if not expected or item.get("feed") in expected]
            row.origins.append("ASD feed status")
            methods = sorted({str(item.get("method") or "") for item in selected} - {""})
            row.cache = ", ".join(methods) or row.cache
            warnings = [str(item["warning"]) for item in selected if item.get("warning")]
            recorded = {
                str(item.get("feed"))
                for item in selected
                if parse_time(item.get("last_success")) is not None
            }
            missing_feeds = sorted(expected - recorded)
            if missing_feeds:
                warnings.append("no successful refresh for " + ", ".join(missing_feeds))
            if warnings and not row.last_error:
                row.last_error = "; ".join(warnings)
            # A recent aggregate refresh must not hide an older member feed.
            success = []
            for item in selected:
                when = parse_time(item.get("last_success"))
                if when:
                    success.append(when)
            dates = [str(item["data_as_of"]) for item in selected if item.get("data_as_of")]
            if dates:
                row.data_as_of = min(dates)
            if row.items is None:
                row.items = sum(int(item.get("item_count") or 0) for item in selected)
        stored = store.get(row.id) or store.get(row.connector)
        if stored:
            row.origins.append(f"intel store ({stored['count']} rows)")
            if row.items is None:
                row.items = stored["count"]
            if not row.data_as_of and stored.get("newest"):
                row.data_as_of = stored["newest"]
        last = (
            (min(success) if row.connector == "asd-acsc" and asd else max(success))
            if success
            else None
        )
        row.last_success = last.strftime("%Y-%m-%dT%H:%M:%SZ") if last else None
        row.age = age_text(last, now)
        row.state = _freshness(last, row.poll, row.last_error, now)
        rows.append(row)
    return rows


def _freshness(last: datetime | None, poll: str, error: str | None, now: datetime) -> str:
    if last is None:
        return "error" if error else "no run recorded"
    interval = parse_duration(poll)
    if interval and interval.total_seconds() > 0 and now - last > interval * 2:
        return "overdue"
    if error:
        return "error after last success"
    return "fresh"


def collect(
    profile: Path,
    *,
    catalogue: Path | None,
    status_files: list[Path],
    data_dir: Path,
    now: datetime | None = None,
) -> tuple[list[SourceRow], list[str]]:
    feeds, problem = load_catalogue(catalogue)
    notes = [problem] if problem else []
    servers = load_servers(profile / "config.yaml")
    if servers is None:
        notes.append("No profile config.yaml, so enabled state uses the catalogue default.")
    missing = load_missing_env(data_dir / "bootstrap-status.json")
    refresh = load_refresh_status(status_files)
    if not refresh:
        notes.append(
            "No refresh status file found. `cyberau-mcp refresh --status <file>` writes one."
        )
    rows = build_rows(
        feeds,
        servers=servers,
        missing=missing,
        refresh=refresh,
        asd=load_asd_status(data_dir / "asd_advisories.sqlite"),
        store=load_store_counts(data_dir / "intel.sqlite"),
        now=now or datetime.now(UTC),
        present=load_present_env(data_dir / "bootstrap-status.json"),
    )
    return rows, notes
