"""``cyberau-mcp refresh``: pull keyless public feeds and optionally load the intel store.

Each source adapter fetches through its connector, so egress checks, caching
and rate limits stay in one place. A source that only answered from a stale
cache or a shipped snapshot counts as failed: refresh exists to get new data.

Refresh does not write feed rows into the repository. Live intel goes into the
profile's intel store (``--store``), where connectors and skills read it, and
only per-source status is written beside the feed catalogue.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import logging
import os
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cyberau_common.secrets import redact

from . import api, db
from .canonical import utc_now
from .expiry import reconcile_indicators, reconcile_kev

# Cache states that mean the payload came from upstream within its lifetime.
_LIVE = {"miss", "hit", "direct", "http11"}
_EPSS_BATCH = 100


@dataclass
class Result:
    source: str
    status: str = "ok"
    items: int = 0
    stored: int | None = None
    expired: int | None = None
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


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="cyberau-mcp refresh")
    parser.add_argument("--sources", required=True, help="Comma separated source keys")
    parser.add_argument("--optional-sources", default="", help="Sources whose failure is a warning")
    parser.add_argument("--store", action="store_true", help="Load results into the intel store")
    parser.add_argument("--catalogue", help="Feed catalogue path; status.json is written beside it")
    parser.add_argument("--status", help="Write per-source status JSON here")
    parser.add_argument("--summary", help="Write a Markdown summary here")
    parser.add_argument(
        "--kev-snapshot",
        help="Write the freshly fetched CISA KEV catalogue to this local file",
    )
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code or 0)

    required = _split(args.sources)
    optional = [key for key in _split(args.optional_sources) if key not in required]
    unknown = [key for key in required + optional if key not in _ADAPTERS]
    if not required:
        print("refresh failed: --sources is empty", file=sys.stderr)
        return 2
    if unknown:
        print(f"refresh failed: unknown sources: {', '.join(unknown)}", file=sys.stderr)
        return 2
    selected = [*required, *optional]
    if args.kev_snapshot and "kev" not in selected:
        print(
            "refresh failed: --kev-snapshot requires kev in --sources or --optional-sources",
            file=sys.stderr,
        )
        return 2

    # Connector request logs go to stderr; the ingest script reports only the
    # first line of output, which must be the summary.
    logging.getLogger("httpx").setLevel(logging.WARNING)

    run = _Run(store=args.store)
    results = [_refresh_one(key, run) for key in selected]
    if args.kev_snapshot:
        kev = next(result for result in results if result.source == "kev")
        if kev.status == "ok" and run.kev_catalog is not None:
            try:
                _write_kev_snapshot(Path(args.kev_snapshot), run.kev_catalog)
            except OSError as exc:
                kev.fail(f"could not write KEV snapshot: {exc}")
    failed = [r for r in results if r.status == "fail" and r.source in required]

    print(_headline(results, failed))
    for result in results:
        print(_line(result))

    status_path = Path(args.status) if args.status else None
    if status_path is None and args.catalogue:
        status_path = Path(args.catalogue).parent / "status.json"
    if status_path is not None:
        _write_status(status_path, results)
    if args.summary:
        Path(args.summary).write_text(_summary(results, failed), encoding="utf-8")
    return 1 if failed else 0


def _refresh_one(key: str, run: _Run) -> Result:
    adapter = _ADAPTERS[key]
    result = Result(key)
    try:
        adapter(result, run)
    except ModuleNotFoundError as exc:
        return result.fail(f"connector is not installed ({exc.name})")
    except Exception as exc:  # one source must not stop the others
        return result.fail(f"{type(exc).__name__}: {exc}")
    return result


def _asd(result: Result, run: _Run) -> None:
    from cyberau_asd_acsc import source

    problems = []
    for feed in source.FEEDS:
        items, live, warning = source.poll_feed(feed)
        if not live:
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


def _kev(result: Result, run: _Run) -> None:
    catalog = _kev_catalog(run)
    rows = catalog.get("vulnerabilities") or []
    result.items = len(rows)
    result.rows = rows
    if run.store:
        result.stored = api.ingest_kev_catalogue(catalog)
        if rows:  # an empty catalogue is a broken fetch, not a withdrawn list
            result.expired = reconcile_kev(str(row["cveID"]) for row in rows)


def _kev_catalog(run: _Run) -> dict:
    if run.kev_catalog is None:
        from cyberau_cisa_kev import source

        catalog, cache = source.catalogue()
        if cache not in _LIVE:
            raise RuntimeError(f"KEV catalogue was not fetched live (cache {cache})")
        run.kev_catalog = catalog
    return run.kev_catalog


def _epss(result: Result, run: _Run) -> None:
    """Score every CVE in KEV. A separate EPSS job reads the KEV list from the store."""
    from cyberau_first_epss import source

    cves = api.kev_cves() if run.store and run.kev_catalog is None else []
    if not cves:
        try:
            catalog = _kev_catalog(run)
        except Exception as exc:
            result.fail(f"EPSS needs the KEV catalogue for its CVE list: {exc}")
            return
        cves = sorted({str(row["cveID"]) for row in catalog.get("vulnerabilities") or []})
    for start in range(0, len(cves), _EPSS_BATCH):
        batch = cves[start : start + _EPSS_BATCH]
        rows, cache, warning = source.score_batch(batch)
        if warning or rows is None or cache not in _LIVE:
            result.fail(warning or f"EPSS batch was not fetched live (cache {cache})")
            return
        result.rows.extend(rows)
    result.items = len(result.rows)
    if run.store:
        with db.open_store().transaction():
            for row in result.rows:
                api.upsert_vulnerability(
                    row["cve"],
                    epss=row["epss"],
                    epss_percentile=row["percentile"],
                    epss_date=row["date"],
                )
        result.stored = len(result.rows)


def _auscert(result: Result, run: _Run) -> None:
    from cyberau_auscert import source

    records, problem = source.poll_bulletins()
    if problem:
        result.fail(problem)
        return
    result.rows = [{**row, "stamp": row["stamp"].isoformat()} for row in records]
    result.items = len(records)
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


def _custom(result: Result, run: _Run) -> None:
    """The RSS and Atom feeds turned on in watchlists.yaml."""
    from cyberau_custom_feeds.config import load_config

    config = load_config()
    if not config.feeds:
        result.detail = "no custom feeds configured"
        return
    _ingest_feeds(result, run, config.feeds)


def _vulnfeeds(result: Result, run: _Run) -> None:
    """cve.now critical entries and pwn.watch incidents, from the shipped vuln-feeds pack."""
    from cyberau_custom_feeds.config import shipped_pack_feeds

    feeds, warnings = shipped_pack_feeds("vuln-feeds")
    if not feeds:
        result.fail("; ".join(warnings) or "the vuln-feeds pack has no feeds")
        return
    _ingest_feeds(result, run, feeds)


def _ingest_feeds(result: Result, run: _Run, feeds) -> None:
    from cyberau_custom_feeds import source

    problems = []
    stored = 0
    for feed in feeds:
        items, _cache, warning = source.fetch_items(feed)
        if warning:
            problems.append(warning)
            continue
        rows = [
            {
                "id": f"{feed.source_id}:{item['id']}",
                "title": item["title"],
                "url": item["url"] or item["guid"],
                "published_at": item["published"] or None,
                "summary": _feed_summary(item),
                "feed": feed.id,
            }
            for item in items
        ]
        result.rows.extend(rows)
        if run.store and rows:
            stored += _store_advisories(feed.source_id, rows)
    result.items = len(result.rows)
    if run.store:
        result.stored = stored
    if problems and len(problems) == len(feeds):
        result.fail("; ".join(problems))
    elif problems:
        # One flaky blog must not fail the rest. The run names what it skipped.
        result.detail = "skipped: " + "; ".join(problems)


def _feed_summary(item: dict) -> str | None:
    parts = [item["summary"]] if item["summary"] else []
    if item["categories"]:
        parts.append("Categories: " + ", ".join(item["categories"][:10]))
    return " ".join(parts) or None


# Daily vulnerability feeds: OSV, GitHub advisories, the CVE List, NVD, Exploit-DB, Metasploit


def _lookback() -> datetime:
    """How far back the daily feeds look. Overlap is safe: advisory ids are stable."""
    try:
        hours = int(os.environ.get("CYBERAU_FEED_LOOKBACK_HOURS") or 48)
    except ValueError:
        hours = 48
    return datetime.now(UTC) - timedelta(hours=min(max(hours, 1), 336))


def _finish_feed(result: Result, run: _Run, fetched, *, label: str) -> None:
    """Record a ``vuln-feeds`` fetch. Only a complete live answer is success."""
    result.rows = fetched.rows
    result.items = len(fetched.rows)
    problems = list(fetched.problems)
    if not fetched.live:
        problems.append(f"{label} was answered from a stale cache")
    if problems and not (fetched.rows and fetched.live):
        result.fail("; ".join(problems))
        return
    if problems:  # a partial answer still counts, and the run names what it skipped
        result.detail = "partial: " + "; ".join(problems)
    if run.store:
        result.stored = _store_vuln_rows(fetched.rows)


def _store_vuln_rows(rows: list[dict]) -> int:
    by_source: dict[str, list[dict]] = {}
    for item in rows:
        by_source.setdefault(item["source"], []).append(item)
    return sum(_store_advisories(source_id, group) for source_id, group in by_source.items())


def _osv(result: Result, run: _Run) -> None:
    """MAL- malicious package alerts, and the OSV-Scanner style scan of the asset purls."""
    from cyberau_vuln_feeds import source

    fetched = source.fetch_osv_malicious(_lookback())
    packages = _inventory_packages()
    if packages:
        scan = source.fetch_osv_scan(packages)
        fetched.rows.extend(scan.rows)
        fetched.problems.extend(scan.problems)
        fetched.live = fetched.live and scan.live
    _finish_feed(result, run, fetched, label="OSV")


def _inventory_packages() -> list[dict]:
    """The asset inventory's package URLs. A missing or unreadable inventory is no packages."""
    try:
        from . import assets

        path = assets.default_path()
        found = assets.read_inventory(path) if path is not None and path.is_file() else []
    except Exception:  # the scan is optional, a bad inventory must not stop the feed
        return []
    return [
        {"asset": asset.name, "purl": asset.get("purl")} for asset in found if asset.get("purl")
    ]


def _ghsa(result: Result, run: _Run) -> None:
    from cyberau_vuln_feeds import source

    _finish_feed(result, run, source.fetch_ghsa(_lookback()), label="GitHub advisories")


def _cvelist(result: Result, run: _Run) -> None:
    from cyberau_vuln_feeds import source

    _finish_feed(result, run, source.fetch_cvelist(_lookback()), label="cvelistV5")


def _exploitdb(result: Result, run: _Run) -> None:
    from cyberau_vuln_feeds import source

    _finish_feed(result, run, source.fetch_exploitdb(_lookback()), label="Exploit-DB")


def _metasploit(result: Result, run: _Run) -> None:
    from cyberau_vuln_feeds import source

    _finish_feed(result, run, source.fetch_metasploit(_lookback()), label="Metasploit")


def _nvd(result: Result, run: _Run) -> None:
    """CVEs published since the window opened that NVD scores Critical or High."""
    from cyberau_nvd import source

    day = _lookback().strftime("%Y-%m-%d")
    today = datetime.now(UTC).strftime("%Y-%m-%d")  # NVD needs both ends of a date range
    rows: list[dict] = []
    problems = []
    for severity in ("CRITICAL", "HIGH"):
        envelope = source.nvd_search(
            published_from=day, published_to=today, cvss_v3_severity=severity, limit=200
        )
        # An empty answer with a warning is a failed call, not a quiet day.
        if envelope["cache"] not in _LIVE or envelope.get("warnings"):
            problems.append("; ".join(envelope.get("warnings") or []) or "NVD was not live")
            continue
        rows.extend(envelope["data"] or [])
    result.rows = rows
    result.items = len(rows)
    if problems:
        result.fail("; ".join(problems))
        return
    if run.store:
        result.stored = _store_nvd(rows)


def _store_nvd(rows: list[dict]) -> int:
    from .text import unwrap_untrusted

    advisories = []
    with db.open_store().transaction():
        for cve in rows:
            cve_id = cve["cve_id"]
            cvss = cve.get("cvss") or {}
            fields: dict = {}
            if isinstance(cvss.get("score"), int | float):
                key = "cvss_v4" if cvss.get("version") == "cvssMetricV40" else "cvss_v3"
                fields[key] = float(cvss["score"])
            if cve.get("cwes"):
                fields["cwe"] = str(cve["cwes"][0])
            if fields:
                api.upsert_vulnerability(cve_id, **fields)
            text = unwrap_untrusted(cve.get("description") or "") or ""
            severity = str(cvss.get("severity") or "").lower()
            lead = f"Severity: {severity}. " if severity else ""
            score = f"CVSS {cvss['score']}. " if cvss.get("score") is not None else ""
            advisories.append(
                {
                    "id": f"nvd:{cve_id}",
                    "title": f"{cve_id}: {text[:160]}".strip(),
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    "published_at": None,
                    "summary": f"{lead}{score}{text}".strip() or None,
                }
            )
    return _store_advisories("nvd", advisories)


def _dependabot(result: Result, run: _Run) -> None:
    """Open critical and high Dependabot alerts on the owner's repositories. Needs a token."""
    from cyberau_vuln_feeds import source

    config = _dependabot_config()
    if config is None:
        result.detail = "no dependabot.yaml with repos in the profile data directory"
        return
    repos, token = config
    fetched = source.fetch_dependabot(repos, token)
    _finish_feed(result, run, fetched, label="Dependabot")


def _dependabot_config() -> tuple[list[str], str] | None:
    import re
    import stat

    import yaml
    from cyberau_custom_feeds.config import data_dir

    path = data_dir() / "dependabot.yaml"
    if not path.is_file():
        return None
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        raise RuntimeError("dependabot.yaml is not valid YAML") from None
    repos = [
        str(repo).strip()
        for repo in (data.get("repos") or [])
        if re.fullmatch(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}", str(repo).strip())
    ]
    if not repos:
        return None
    token = os.environ.get("GITHUB_DEPENDABOT_TOKEN", "").strip()
    token_file = data.get("token_file")
    if not token and token_file:
        key = Path(str(token_file)).expanduser()
        try:
            if key.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO):
                raise RuntimeError("the Dependabot token file must be chmod 600")
            token = key.read_text(encoding="utf-8").strip()
        except OSError:
            raise RuntimeError("the Dependabot token file is not readable") from None
    if not token:
        raise RuntimeError("no Dependabot token: set token_file in dependabot.yaml")
    return repos, token


def _feodo(result: Result, run: _Run) -> None:
    """Feodo Tracker, the keyless part of abuse.ch."""
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
        now = utc_now()
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
        if envelope.get("warnings"):  # only a clean, complete list may expire entries
            return
        result.expired = reconcile_indicators(
            "feodo-tracker", [(_ip_type(row["indicator"]), row["indicator"]) for row in rows]
        )


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
    "custom": _custom,
    "osv": _osv,
    "ghsa": _ghsa,
    "cvelist": _cvelist,
    "nvd": _nvd,
    "exploitdb": _exploitdb,
    "metasploit": _metasploit,
    "vulnfeeds": _vulnfeeds,
    "dependabot": _dependabot,
}
# Sources that need a credential. They can be named in --sources, but the keyless ingest
# scripts never run them and the feed catalogue gives them no refresh key.
KEYED = ("dependabot",)
SUPPORTED = tuple(key for key in _ADAPTERS if key not in KEYED)


def _store_advisories(source_id: str, rows) -> int:
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


def _headline(results: list[Result], failed: list[Result]) -> str:
    if failed:
        first = failed[0]
        return f"refresh failed: {first.source}: {first.detail}"[:300]
    done = [f"{r.source} {r.items}" for r in results if r.status == "ok"]
    return "refresh ok: " + ", ".join(done)


def _line(result: Result) -> str:
    stored = "" if result.stored is None else f", stored {result.stored}"
    if result.expired:
        stored += f", expired {result.expired}"
    detail = f" ({result.detail})" if result.detail else ""
    return f"{result.source} {result.status} {result.items} items{stored}{detail}"


def _write_status(path: Path, results: list[Result]) -> None:
    try:
        previous = json.loads(path.read_text(encoding="utf-8")).get("sources", {})
    except (OSError, ValueError, AttributeError):
        previous = {}
    now = utc_now()
    sources = dict(previous) if isinstance(previous, dict) else {}
    for result in results:
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


def _write_kev_snapshot(path: Path, catalogue: dict) -> None:
    """Atomically persist a live KEV catalogue for the local software watch."""
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix=".kev-", suffix=".json", dir=path.parent)
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as output:
            json.dump(catalogue, output, indent=2, sort_keys=True)
            output.write("\n")
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


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
