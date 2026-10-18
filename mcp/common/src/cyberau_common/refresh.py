"""``cyberau-mcp refresh``: pull keyless public feeds and optionally load the intel store.

Each source adapter fetches through its connector, so egress checks, caching
and rate limits stay in one place. A source that only answered from a stale
cache or a shipped snapshot counts as failed: refresh exists to get new data.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import logging
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from cyberau_common.secrets import redact

SUPPORTED = ("asd", "kev", "epss", "auscert", "feodo")
# Named by the nightly workflow but not refreshed here yet. They are reported
# as skipped so a run still covers every source it can.
NOT_YET = ("attack", "nvd", "abusech", "otx", "radar")
_LIVE = {"miss", "hit", "direct", "http11"}
_EPSS_BATCH = 100


@dataclass
class Result:
    source: str
    status: str = "ok"
    items: int = 0
    stored: int | None = None
    detail: str = ""
    rows: list[dict] = field(default_factory=list)

    def fail(self, detail: str) -> Result:
        self.status = "fail"
        self.detail = redact(detail)
        return self


@dataclass
class _Run:
    store: bool
    kev_catalog: dict | None = None


def refresh_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="cyberau-mcp refresh")
    parser.add_argument("--sources", required=True, help="Comma separated source keys")
    parser.add_argument("--optional-sources", default="", help="Sources whose failure is a warning")
    parser.add_argument("--store", action="store_true", help="Load results into the intel store")
    parser.add_argument("--snapshot-dir", help="Write one <source>.json per refreshed source")
    parser.add_argument("--catalogue", help="Feed catalogue path; status.json is written beside it")
    parser.add_argument("--status", help="Write per-source status JSON here")
    parser.add_argument("--summary", help="Write a Markdown summary here")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code or 0)

    required = _split(args.sources)
    optional = [key for key in _split(args.optional_sources) if key not in required]
    unknown = [key for key in required + optional if key not in SUPPORTED + NOT_YET]
    if not required:
        print("refresh failed: --sources is empty", file=sys.stderr)
        return 2
    if unknown:
        print(f"refresh failed: unknown sources: {', '.join(unknown)}", file=sys.stderr)
        return 2

    # Connector request logs go to stderr; the ingest script reports only the
    # first line of output, which must be the summary.
    logging.getLogger("httpx").setLevel(logging.WARNING)

    run = _Run(store=args.store)
    results = [_refresh_one(key, run) for key in [*required, *optional]]
    failed = [r for r in results if r.status == "fail" and r.source in required]

    print(_headline(results, failed))
    for result in results:
        print(_line(result))

    status_path = Path(args.status) if args.status else None
    if status_path is None and args.catalogue:
        status_path = Path(args.catalogue).parent / "status.json"
    if status_path is not None:
        _write_status(status_path, results)
    if args.snapshot_dir:
        _write_snapshots(Path(args.snapshot_dir), results)
    if args.summary:
        Path(args.summary).write_text(_summary(results, failed), encoding="utf-8")
    return 1 if failed else 0


def _refresh_one(key: str, run: _Run) -> Result:
    if key in NOT_YET:
        return Result(key, status="skipped", detail="no refresh adapter yet")
    adapter = _ADAPTERS[key]
    result = Result(key)
    try:
        adapter(result, run)
    except ModuleNotFoundError as exc:
        return result.fail(f"connector is not installed ({exc.name})")
    except Exception as exc:  # one source must not stop the others
        return result.fail(f"{type(exc).__name__}: {exc}")
    return result


# ASD ACSC


def _asd(result: Result, run: _Run) -> None:
    from cyberau_asd_acsc import source

    problems = []
    for feed in source.FEEDS:
        items, _cache, warning, method = source._items_for_feed(feed)
        if method not in _LIVE:
            problems.append(warning or f"{feed} was not fetched live")
            continue
        result.rows.extend(items)
    result.items = len(result.rows)
    if problems:
        result.fail("; ".join(problems))
        return
    if run.store:
        result.stored = _store_advisories(
            "asd-acsc",
            (
                {
                    "id": item["id"],
                    "title": item["title"],
                    "url": item["link"],
                    "published_at": item.get("published") or None,
                    "summary": item.get("summary") or None,
                }
                for item in result.rows
            ),
        )


# CISA KEV


def _kev(result: Result, run: _Run) -> None:
    catalog = _kev_catalog(run)
    rows = catalog.get("vulnerabilities") or []
    result.items = len(rows)
    result.rows = rows
    if run.store:
        api, _db = _store_modules()
        result.stored = api.ingest_kev_catalogue(catalog)


def _kev_catalog(run: _Run) -> dict:
    if run.kev_catalog is None:
        from cyberau_cisa_kev import source

        catalog, cache = source._catalog()
        if cache not in _LIVE:
            raise RuntimeError(f"KEV catalogue was not fetched live (cache {cache})")
        run.kev_catalog = catalog
    return run.kev_catalog


# FIRST EPSS, scored for every CVE in KEV


def _epss(result: Result, run: _Run) -> None:
    from cyberau_first_epss import source

    try:
        catalog = _kev_catalog(run)
    except Exception as exc:
        result.fail(f"EPSS needs the KEV catalogue for its CVE list: {exc}")
        return
    cves = sorted({str(row["cveID"]) for row in catalog.get("vulnerabilities") or []})
    for start in range(0, len(cves), _EPSS_BATCH):
        batch = cves[start : start + _EPSS_BATCH]
        payload, cache, warning = source._fetch({"cve": ",".join(batch)})
        if warning or payload is None or cache not in _LIVE:
            result.fail(warning or f"EPSS batch was not fetched live (cache {cache})")
            return
        rows, problems = source._rows(payload, history=False)
        if problems:
            result.fail("; ".join(problems))
            return
        result.rows.extend(rows)
    result.items = len(result.rows)
    if run.store:
        api, db = _store_modules()
        with db.open_store().transaction():
            for row in result.rows:
                api.upsert_vulnerability(
                    row["cve"],
                    epss=row["epss"],
                    epss_percentile=row["percentile"],
                    epss_date=row["date"],
                )
        result.stored = len(result.rows)


# AusCERT


def _auscert(result: Result, run: _Run) -> None:
    from cyberau_auscert import source

    feed = source._fetch(force_live=True)
    if feed.text is None or feed.cache not in _LIVE:
        result.fail("; ".join(feed.warnings) or "AusCERT feed was not fetched live")
        return
    root, problem = source._root(feed.text)
    if root is None:
        result.fail(problem or "AusCERT feed unusable")
        return
    records, _skipped = source._records(root)
    if feed.persist:
        source._persist(records)
    result.rows = [{**row, "stamp": row["stamp"].isoformat()} for row in records]
    result.items = len(records)
    if not records:
        result.fail("AusCERT feed contained no bulletins")
        return
    if run.store:
        result.stored = _store_advisories(
            "auscert",
            (
                {
                    "id": f"auscert:{row['bulletin_id']}",
                    "title": row["title"],
                    "url": row["link"],
                    "published_at": row["stamp"],
                    "summary": row.get("summary") or None,
                }
                for row in result.rows
            ),
        )


# Feodo Tracker, the keyless part of abuse.ch


def _feodo(result: Result, run: _Run) -> None:
    from cyberau_abusech import source

    envelope = source.feodo_blocklist()
    if envelope["cache"] not in _LIVE:
        warnings = envelope.get("warnings") or []
        result.fail("; ".join(warnings) or f"Feodo was not fetched live ({envelope['cache']})")
        return
    rows = [row for row in envelope["data"] if _ip_type(row.get("indicator"))]
    result.rows = rows
    result.items = len(rows)
    if run.store:
        api, db = _store_modules()
        now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        with db.open_store().transaction():
            for row in rows:
                tags = ["botnet-c2"] + ([row["malware"]] if row.get("malware") else [])
                api.upsert_indicator(
                    _ip_type(row["indicator"]),
                    row["indicator"],
                    source="feodo-tracker",
                    observed_at=row.get("last_online") or row.get("first_seen") or now,
                    raw=json.dumps(row, sort_keys=True).encode(),
                    verdict="malicious",
                    tags=tags,
                    source_ref=source.FEODO_URL,
                )
        result.stored = len(rows)


def _ip_type(value: object) -> str | None:
    try:
        address = ipaddress.ip_address(str(value))
    except ValueError:
        return None
    return "ipv4" if address.version == 4 else "ipv6"


_ADAPTERS: dict[str, Callable[[Result, _Run], None]] = {
    "asd": _asd,
    "kev": _kev,
    "epss": _epss,
    "auscert": _auscert,
    "feodo": _feodo,
}


# Intel store


def _store_modules():
    from cyberau_common.cli import _plugin_root

    root = _plugin_root()
    if root is None:
        raise RuntimeError("intel store is not installed")
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    from store import api, db

    return api, db


def _store_advisories(source_id: str, rows) -> int:
    api, db = _store_modules()
    count = 0
    with db.open_store().transaction():
        for row in rows:
            body = f"{row['title']}\n{row.get('summary') or ''}".encode()
            api.upsert_advisory(
                row["id"][:200],
                source=source_id,
                title=row["title"],
                url=row["url"],
                published_at=row["published_at"],
                summary=row["summary"],
                content_sha256=hashlib.sha256(body).hexdigest(),
            )
            count += 1
    return count


# Output


def _headline(results: list[Result], failed: list[Result]) -> str:
    if failed:
        first = failed[0]
        return f"refresh failed: {first.source}: {first.detail}"[:300]
    done = [f"{r.source} {r.items}" for r in results if r.status == "ok"]
    return "refresh ok: " + ", ".join(done)


def _line(result: Result) -> str:
    stored = "" if result.stored is None else f", stored {result.stored}"
    detail = f" ({result.detail})" if result.detail else ""
    return f"{result.source} {result.status} {result.items} items{stored}{detail}"


def _write_status(path: Path, results: list[Result]) -> None:
    try:
        previous = json.loads(path.read_text(encoding="utf-8")).get("sources", {})
    except (OSError, ValueError, AttributeError):
        previous = {}
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    sources = dict(previous) if isinstance(previous, dict) else {}
    for result in results:
        if result.status == "skipped":
            continue
        entry = dict(sources.get(result.source) or {})
        entry["last_run"] = now
        entry["status"] = result.status
        if result.status == "ok":
            entry["last_ok"] = now
            entry["item_count"] = result.items
            entry["last_error"] = None
        else:
            entry["last_error"] = result.detail
        sources[result.source] = entry
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"generated_at": now, "sources": dict(sorted(sources.items()))}
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _write_snapshots(directory: Path, results: list[Result]) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    for result in results:
        if result.status != "ok":
            continue
        text = json.dumps(result.rows, indent=1, sort_keys=True, default=str)
        (directory / f"{result.source}.json").write_text(text + "\n", encoding="utf-8")


def _summary(results: list[Result], failed: list[Result]) -> str:
    lines = [
        "## Intel refresh",
        "",
        "| Source | Status | Items | Detail |",
        "| --- | --- | ---: | --- |",
    ]
    for result in results:
        detail = result.detail.replace("|", "\\|").replace("\n", " ")
        lines.append(f"| {result.source} | {result.status} | {result.items} | {detail} |")
    lines.append("")
    lines.append("Some required sources failed." if failed else "All required sources refreshed.")
    return "\n".join(lines) + "\n"


def _split(value: str) -> list[str]:
    seen: list[str] = []
    for part in value.split(","):
        key = part.strip()
        if key and key not in seen:
            seen.append(key)
    return seen
