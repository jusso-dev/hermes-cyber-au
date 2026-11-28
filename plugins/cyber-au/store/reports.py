"""Board and executive report templates: a monthly cyber summary and an incident summary.

Both read only local material:

- the briefing history in the intel store, which is what the daily briefing is built
  from: KEV additions (``vulnerabilities``), advisories by feed (``advisories``), hostile
  indicators (``indicators``) and watchlist matches (``watchlist_matches``);
- the Essentials evidence register (``essentials_evidence``), when it has rows;
- an obligations JSON file, when the caller passes one. Any of these shapes is read: an
  ``aureg_deadline`` or ``aureg_obligation`` envelope, a list of envelopes, a document with
  an ``obligations`` list, or a plain list of obligation records;
- for the incident summary, an incident JSON file such as ``cyber-au demo triage --json``.

Every figure carries a source key (``S1``, ``S2``...). Appendix A lists each key as a
``Source:`` citation with how fresh the data is. Limitations and evidence references stay
in the report. Nothing here sends, posts or submits the report, and nothing contacts a
regulator.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from pathlib import Path

from .db import open_store, resolve_db_path
from .documents import Document, to_markdown, write_docx
from .evidence import (
    NOTICE as EVIDENCE_NOTICE,
)
from .evidence import (
    SEPARATION,
    build_report,
    gaps,
    summarise,
    today,
)

GUIDANCE = "This report is guidance. It is not legal advice, an audit or a certification."
NOT_SENT = "It was not sent, posted or submitted, and no regulator or person was contacted."
DEMO_BANNER = "DEMO DATA: synthetic records. Nothing in this report is real."
BODY_WORDS = 450
TITLE_LIMIT = 5
TITLE_SOURCES = ("asd-acsc", "auscert")
MAX_REFERENCES = 10
_DOMAIN = re.compile(r"\b((?:[a-z0-9-]+\.)+[a-z]{2,24})\b", re.IGNORECASE)
_IPV4 = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")
_URL_SCHEME = re.compile(r"\bhttp(s?)://", re.IGNORECASE)


@dataclass
class SourceRef:
    key: str
    name: str
    version: str
    retrieved: str
    detail: str

    def citation(self) -> str:
        name = self.name.replace(",", ";")
        version = (self.version or "none").replace(",", ";")
        return f"Source: {name}, {version}, retrieved {self.retrieved}"


@dataclass
class Figure:
    label: str
    value: str
    source: str


@dataclass
class Ledger:
    """Sources and figures collected while a report is built."""

    retrieved: str
    sources: list[SourceRef] = field(default_factory=list)
    figures: list[Figure] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)

    def source(self, name: str, version: str | None, detail: str) -> str:
        key = f"S{len(self.sources) + 1}"
        self.sources.append(SourceRef(key, name, version or "none", self.retrieved, detail))
        return key

    def figure(self, label: str, value: object, source: str) -> Figure:
        item = Figure(label, str(value), source)
        self.figures.append(item)
        return item


# Shared helpers


def defang(text: str) -> str:
    """Defang URLs, IPv4 addresses and domains once, for a page a person reads."""
    if "[.]" in text:
        return text
    out = _URL_SCHEME.sub(lambda m: f"hxxp{m.group(1)}://", text)
    out = _IPV4.sub(lambda m: "[.]".join(m.groups()), out)
    return _DOMAIN.sub(lambda m: m.group(1).replace(".", "[.]"), out)


def _day(value: object) -> str | None:
    text = str(value or "").strip()
    if len(text) >= 10:
        try:
            return date.fromisoformat(text[:10]).isoformat()
        except ValueError:
            return None
    return None


def _is_demo_store(store_file: Path) -> bool:
    return store_file.name == "intel-demo.sqlite" or (store_file.parent / "DEMO-DATA.txt").is_file()


def _source_names(conn) -> dict[str, str]:
    return {row["id"]: row["name"] for row in conn.execute("SELECT id, name FROM sources")}


def _range(start: date, end: date) -> tuple[str, str]:
    """Inclusive calendar days as a half-open UTC timestamp range."""
    return f"{start.isoformat()}T00:00:00Z", f"{(end + timedelta(days=1)).isoformat()}T00:00:00Z"


# Obligations input


def load_obligations(path: str | Path) -> tuple[list[dict], dict]:
    """Read an obligations JSON file. Return (records, provenance)."""
    file = Path(path)
    try:
        document = json.loads(file.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"cannot read obligations file {file.name}") from exc
    except ValueError as exc:
        raise ValueError(f"obligations file {file.name} is not JSON") from exc
    meta = {"name": f"obligations input {file.name}", "version": None, "retrieved": None}
    records: list[dict] = []

    def take(item: object) -> None:
        if isinstance(item, dict) and isinstance(item.get("data"), list | dict):
            meta["name"] = f"obligations input {file.name} ({item.get('source') or 'unnamed'})"
            meta["version"] = meta["version"] or item.get("data_as_of")
            meta["retrieved"] = meta["retrieved"] or _day(item.get("retrieved_at"))
            data = item["data"]
            for row in data if isinstance(data, list) else [data]:
                take(row)
        elif isinstance(item, dict) and isinstance(item.get("obligations"), list):
            meta["version"] = meta["version"] or item.get("data_as_of") or item.get("version")
            meta["retrieved"] = meta["retrieved"] or _day(item.get("retrieved_at"))
            for row in item["obligations"]:
                take(row)
        elif isinstance(item, dict) and (item.get("regime") or item.get("citation")):
            records.append(item)
        elif isinstance(item, list):
            for row in item:
                take(row)

    take(document)
    if isinstance(document, dict) and document.get("demo") is True:
        meta["demo"] = True
    return records, meta


def _obligation_row(item: dict) -> list[str]:
    deadlines = item.get("deadlines") or []
    due = [_text(d.get("due_at")) for d in deadlines if isinstance(d, dict) and d.get("due_at")]
    if not due and item.get("due_at"):
        due = [_text(item["due_at"])]
    return [
        _text(item.get("regime")).upper() or "unknown",
        _text(item.get("trigger")).replace("_", " ") or "not stated",
        _text(item.get("citation")) or "not stated",
        min(due) if due else "no clock",
    ]


def _text(value: object) -> str:
    from .text import clean_untrusted, unwrap_untrusted

    raw = str(value or "")
    inner = unwrap_untrusted(raw)
    return clean_untrusted(inner if inner is not None else raw, max_len=300)


def _add_obligations(doc: Document, ledger: Ledger, path: str | Path | None) -> list[list[str]]:
    if path is None:
        ledger.limitations.append(
            "No obligations input was given, so reporting obligations are not covered. "
            "Check them with the obligations checker or the au-regulatory connector."
        )
        return []
    records, meta = load_obligations(path)
    rows = [_obligation_row(item) for item in records]
    key = ledger.source(
        meta["name"],
        meta.get("version"),
        f"{len(rows)} obligation record(s) read from the file supplied. "
        f"Retrieved by its producer on {meta.get('retrieved') or 'an unknown date'}.",
    )
    if meta.get("retrieved"):
        ledger.sources[-1].retrieved = meta["retrieved"]
    ledger.figure("Reporting obligations flagged", len(rows), key)
    ledger.limitations.append(
        "Obligations come from the input file as supplied. They are not legal advice, and "
        "nothing was lodged or submitted."
    )
    if meta.get("retrieved") is None:
        ledger.limitations.append("The obligations input has no retrieval date.")
    doc.heading("Reporting obligations")
    if rows:
        doc.table(
            ["Regime", "Trigger", "Citation", "Earliest due", "Source"],
            [[*row, key] for row in rows],
        )
        noun = "obligation is" if len(rows) == 1 else "obligations are"
        doc.para(f"{len(rows)} {noun} listed. [{key}]")
    else:
        doc.para(f"The obligations input lists no obligations. [{key}]")
    return rows


def _add_register(
    doc: Document, ledger: Ledger, store: str | Path | None, on: date
) -> tuple[int, list[str]]:
    """Essentials register summary. Returns how many actions need work, and the source keys."""
    conn = open_store(store).connection()
    has_rows = conn.execute("SELECT 1 FROM essentials_evidence LIMIT 1").fetchone()
    if not has_rows:
        ledger.limitations.append(
            "The Essentials evidence register is empty, so Essentials progress is not reported."
        )
        return 0, []
    report = build_report(path=store, on=on)
    open_gaps = 0
    keys: list[str] = []
    rows = []
    for reference in report.references:
        view = report.views[reference.chapter]
        counts = summarise(view)
        key = ledger.source(
            f"Essentials evidence register ({reference.name})",
            reference.as_of,
            f"The organisation's own register in the intel store, checked against the "
            f"{reference.name} snapshot dated {reference.as_of or 'unknown'}. "
            "A self-assessment, not an ASD rating.",
        )
        keys.append(key)
        needs = counts["not met"] + counts["partial"]
        open_gaps += needs
        ledger.figure(f"{reference.name}: actions met", counts["met"], key)
        ledger.figure(f"{reference.name}: not met or partial", needs, key)
        ledger.figure(f"{reference.name}: no evidence yet", counts["unknown"], key)
        rows.append(
            [
                reference.name,
                f"{counts['met']} of {counts['total']}",
                str(needs),
                str(counts["unknown"]),
                str(counts["review overdue"]),
                key,
            ]
        )
        for item in view:
            if item["evidence"] and item["status"] in ("met", "partial"):
                ledger.references.append(
                    f"{item['action_id']} ({reference.chapter}, {item['status']}): "
                    f"{defang(item['evidence'])}. Source {item['source']}, gathered "
                    f"{item['evidence_date'] or 'unknown'}, {item['freshness']}."
                )
        for item in gaps(view)[:3]:
            if item["status"] in ("not met", "partial"):
                ledger.references.append(
                    f"Gap {item['action_id']} ({reference.chapter}, {item['status']}): "
                    f"owner {item['owner'] or 'not set'}. ASD action: {item['action']}"
                )
    doc.heading("Essentials progress (self-assessment)")
    doc.table(
        ["Chapter", "Met", "Not met or partial", "No evidence", "Review overdue", "Source"], rows
    )
    doc.para(f"{EVIDENCE_NOTICE} {SEPARATION}")
    if report.e8_rows:
        count = len(report.e8_rows)
        ledger.limitations.append(
            f"{count} Essential Eight requirement {'record is' if count == 1 else 'records are'} "
            "in the register. They are kept separate and are not counted in Essentials progress."
        )
    return open_gaps, keys


def _finish(doc: Document, ledger: Ledger, asks: list[str]) -> Document:
    doc.heading("Asks")
    if asks:
        for ask in asks:
            doc.para(ask)
    else:
        doc.para("No decision is needed from this report.")
    doc.heading("Appendix A: Sources")
    doc.para("Each figure above names a source key. The key is listed here with its freshness.")
    for item in ledger.sources:
        doc.bullet(f"[{item.key}] {item.citation()}. {item.detail}")
    doc.heading("Appendix B: Limitations")
    for line in ledger.limitations:
        doc.bullet(line)
    doc.bullet(GUIDANCE)
    doc.heading("Appendix C: Evidence references")
    if ledger.references:
        for line in ledger.references[:MAX_REFERENCES]:
            doc.bullet(line)
        if len(ledger.references) > MAX_REFERENCES:
            extra = len(ledger.references) - MAX_REFERENCES
            noun = "reference is" if extra == 1 else "references are"
            doc.bullet(f"{extra} more {noun} in the evidence register export.")
    else:
        doc.bullet("No evidence references were recorded.")
    return doc


# Monthly summary


def monthly_report(
    *,
    start: date,
    end: date,
    store: str | Path | None = None,
    obligations: str | Path | None = None,
    on: date | None = None,
) -> tuple[Document, Ledger]:
    """A one-page monthly cyber summary with sources in an appendix."""
    if end < start:
        raise ValueError("the period end is before its start")
    run_day = on or today()
    store_file = resolve_db_path(store)
    if not store_file.is_file():
        raise ValueError("the intel store does not exist yet. Run cyberau-mcp store init")
    conn = open_store(store).connection()
    names = _source_names(conn)
    ledger = Ledger(retrieved=run_day.isoformat())
    demo = _is_demo_store(store_file)
    period = f"{start.isoformat()} to {end.isoformat()}"
    low, high = _range(start, end)
    doc = Document("Monthly cyber summary")
    if demo:
        doc.para(DEMO_BANNER)
    doc.para(f"Period: {period}. Prepared {run_day.isoformat()}. Audience: executive team.")
    doc.para(f"{GUIDANCE} {NOT_SENT}")

    # KEV additions.
    kev = conn.execute(
        """
        SELECT cve_id, kev_ransomware, updated_at FROM vulnerabilities
        WHERE kev_date_added >= ? AND kev_date_added <= ? ORDER BY kev_date_added, cve_id
        """,
        (start.isoformat(), end.isoformat()),
    ).fetchall()
    newest = max((row["updated_at"][:10] for row in kev), default=None)
    kev_name = "DEMO KEV rows in the intel store" if demo else names.get("cisa-kev", "CISA KEV")
    kev_key = ledger.source(
        f"{kev_name} (local intel store)",
        newest,
        f"vulnerabilities rows with a KEV date added in {period}. "
        f"Newest row updated {newest or 'never'}.",
    )
    ransomware = sum(1 for row in kev if (row["kev_ransomware"] or "").lower() == "known")
    ledger.figure("KEV additions", len(kev), kev_key)
    ledger.figure("KEV additions linked to ransomware", ransomware, kev_key)
    if not kev:
        ledger.limitations.append(
            "No KEV additions are in the store for the period. If the KEV routine did not "
            "run, that is missing data, not a quiet month."
        )

    # Advisories by feed.
    advisories = conn.execute(
        """
        SELECT source_id, title, COALESCE(published_at, first_seen) AS seen FROM advisories
        WHERE COALESCE(published_at, first_seen) >= ? AND COALESCE(published_at, first_seen) < ?
        ORDER BY seen DESC, id
        """,
        (low, high),
    ).fetchall()
    by_source: dict[str, list] = {}
    for row in advisories:
        by_source.setdefault(row["source_id"], []).append(row)
    advisory_rows = []
    advisory_keys: list[str] = []
    titles: list[tuple[str, str]] = []
    for source_id in sorted(by_source):
        rows = by_source[source_id]
        newest_row = max(row["seen"][:10] for row in rows)
        key = ledger.source(
            f"{names.get(source_id, source_id)} (local intel store)",
            newest_row,
            f"advisories rows from {source_id} published or first seen in {period}. "
            f"Newest {newest_row}.",
        )
        ledger.figure(f"Advisories from {names.get(source_id, source_id)}", len(rows), key)
        advisory_rows.append([names.get(source_id, source_id), str(len(rows)), key])
        advisory_keys.append(key)
        if source_id in TITLE_SOURCES or demo:
            titles += [(defang(row["title"]), key) for row in rows[:TITLE_LIMIT]]
    if not advisories:
        ledger.limitations.append(
            "No advisories are in the store for the period. Feeds that were not ingested "
            "are missing, not quiet."
        )

    # Hostile indicators and watchlist matches, counts only.
    hostile = conn.execute(
        """
        SELECT COUNT(*) FROM indicators
        WHERE verdict IN ('malicious','suspicious') AND first_seen >= ? AND first_seen < ?
        """,
        (low, high),
    ).fetchone()[0]
    newest_indicator = conn.execute(
        "SELECT MAX(last_seen) FROM indicators WHERE verdict IN ('malicious','suspicious')"
    ).fetchone()[0]
    indicator_key = ledger.source(
        "DEMO indicators in the intel store" if demo else "Intel store indicators",
        _day(newest_indicator),
        f"indicators first seen in {period} with a malicious or suspicious verdict. "
        "Counts only; values stay in the store.",
    )
    ledger.figure("New hostile indicators", hostile, indicator_key)
    watch = conn.execute(
        "SELECT list, COUNT(*) AS n FROM watchlist_matches "
        "WHERE first_matched >= ? AND first_matched < ? GROUP BY list ORDER BY list",
        (low, high),
    ).fetchall()
    watch_run = conn.execute(
        "SELECT updated_at FROM routine_state WHERE routine = 'watchlist'"
    ).fetchone()
    watch_key = ledger.source(
        "Watchlist matches in the intel store",
        _day(watch_run["updated_at"]) if watch_run else None,
        f"watchlist_matches first matched in {period}. Counts only. Last watchlist run "
        f"{watch_run['updated_at'] if watch_run else 'not recorded'}.",
    )
    watch_total = sum(row["n"] for row in watch)
    ledger.figure("New watchlist matches", watch_total, watch_key)
    if watch_run is None:
        ledger.limitations.append(
            "The watchlist routine has no recorded run, so zero matches is not an all-clear."
        )

    # Body.
    doc.heading("Headline")
    doc.para(
        f"In {period}, {len(kev)} KEV additions and {len(advisories)} advisories reached our "
        f"intel store, and {hostile} new hostile indicators were recorded. "
        + " ".join(f"[{key}]" for key in (kev_key, *advisory_keys, indicator_key))
    )
    doc.heading("At a glance")
    glance = [
        ["KEV additions (known exploited vulnerabilities)", str(len(kev)), kev_key],
        ["of which linked to ransomware", str(ransomware), kev_key],
        *[[f"Advisories: {name}", count, key] for name, count, key in advisory_rows],
        ["New hostile indicators (counts only)", str(hostile), indicator_key],
        ["New watchlist matches (counts only)", str(watch_total), watch_key],
    ]
    doc.table(["Figure", "Value", "Source"], glance)
    doc.para("KEV is CISA's catalogue of vulnerabilities known to be exploited.")
    if titles:
        doc.heading("Advisories to note")
        for title, key in titles:
            doc.bullet(f"{title} (feed title, quoted) [{key}]")
    open_gaps, register_keys = _add_register(doc, ledger, store, run_day)
    obligation_rows = _add_obligations(doc, ledger, obligations)
    asks = []
    if open_gaps:
        asks.append(
            f"Proposal: confirm owners and dates for the {open_gaps} Essentials actions marked "
            "not met or partial. A person decides; this report does not act. "
            + " ".join(f"[{key}]" for key in register_keys)
        )
    if obligation_rows:
        asks.append(
            "Proposal: confirm who is accountable for each reporting obligation listed. "
            "This report does not contact any regulator."
        )
    if kev:
        asks.append(
            "Proposal: ask IT to confirm whether any KEV addition affects our systems. "
            "I don't know which of them apply to us from this data alone."
        )
    ledger.limitations.append(
        "Counts reflect what the local intel store held when the report was prepared."
    )
    ledger.limitations.append(
        "Feed text is untrusted. Titles are quoted as published and were not acted on."
    )
    if demo:
        ledger.limitations.append(DEMO_BANNER)
    return _finish(doc, ledger, asks), ledger


# Incident summary


def load_incident(path: str | Path) -> dict:
    file = Path(path)
    try:
        record = json.loads(file.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"cannot read incident file {file.name}") from exc
    except ValueError as exc:
        raise ValueError(f"incident file {file.name} is not JSON") from exc
    if not isinstance(record, dict):
        raise ValueError("incident file must be a JSON object")
    record.setdefault("_file", file.name)
    return record


def incident_report(
    incident: dict,
    *,
    store: str | Path | None = None,
    obligations: str | Path | None = None,
    on: date | None = None,
) -> tuple[Document, Ledger]:
    """A one-page incident summary for executives with sources in an appendix."""
    run_day = on or today()
    ledger = Ledger(retrieved=run_day.isoformat())
    demo = incident.get("demo") is True
    incident_id = _text(incident.get("alert_id") or incident.get("id")) or "unnamed"
    title = defang(_text(incident.get("title")) or "untitled incident")
    detected = _text(incident.get("detected_at")) or "unknown"
    source_name = _text(incident.get("source") or incident.get("dataset_source"))
    record_key = ledger.source(
        source_name or f"incident record {incident.get('_file', '')}".strip(),
        _text(incident.get("dataset_version") or incident.get("version")) or None,
        f"Incident record {incident_id} from file {incident.get('_file', 'supplied')}. "
        f"Prepared {_day(incident.get('retrieved')) or 'on an unknown date'}.",
    )
    if _day(incident.get("retrieved")):
        ledger.sources[-1].retrieved = _day(incident.get("retrieved"))
    observables = [item for item in incident.get("observables") or [] if isinstance(item, dict)]
    matches = [item for item in incident.get("matches") or [] if isinstance(item, dict)]
    hostile = [m for m in matches if m.get("verdict") in ("malicious", "suspicious")]
    attack = [item for item in incident.get("attack") or [] if isinstance(item, dict)]
    severity = _text(incident.get("severity")) or "not rated"
    reasons = [_text(item) for item in incident.get("severity_reasons") or []]
    ledger.figure("Local severity", severity, record_key)
    ledger.figure("Observables extracted", len(observables), record_key)
    ledger.figure("Observables matching hostile records", len(hostile), record_key)
    ledger.figure("ATT&CK techniques mapped", len(attack), record_key)

    doc = Document("Incident summary")
    if demo:
        doc.para(DEMO_BANNER)
    doc.para(
        f"Incident: {incident_id}. Detected: {detected}. Prepared {run_day.isoformat()}. "
        f"[{record_key}]"
    )
    doc.para(f"{GUIDANCE} {NOT_SENT}")
    doc.heading("Headline")
    doc.para(
        f"Our organisation is handling a {severity} incident: {title}. "
        f"{len(hostile)} of {len(observables)} observables match hostile records. [{record_key}]"
    )
    doc.heading("At a glance")
    doc.table(
        ["Figure", "Value", "Source"],
        [
            ["Local severity", severity, record_key],
            ["Observables extracted", str(len(observables)), record_key],
            ["Observables matching hostile records", str(len(hostile)), record_key],
            ["ATT&CK techniques mapped", str(len(attack)), record_key],
        ],
    )
    doc.heading("What happened and what it means")
    for reason in reasons[:3]:
        doc.bullet(f"{defang(reason)} [{record_key}]")
    for item in attack[:3]:
        doc.bullet(
            f"ATT&CK {_text(item.get('id'))} {_text(item.get('name'))}: the technique the "
            f"activity resembles, from a local mapping table. [{record_key}]"
        )
    pi = _text(incident.get("personal_information")) or "unknown"
    doc.bullet(
        f"Personal information on the affected system: {pi}. If yes or unknown, the "
        f"privacy team should assess a possible eligible data breach. [{record_key}]"
    )
    if "soci_asset" in incident:
        flag = "yes" if incident.get("soci_asset") else "no"
        doc.bullet(f"Critical infrastructure (SOCI) asset involved: {flag}. [{record_key}]")
    for item in hostile:
        value = defang(_text(item.get("value")))
        ledger.references.append(
            f"{_text(item.get('type'))} {value}: {_text(item.get('verdict'))}, confidence "
            f"{_text(item.get('confidence')) or 'unknown'}, record {_text(item.get('record'))}."
        )
    for item in incident.get("evidence") or []:
        ledger.references.append(defang(_text(item)))
    if _store_ready(store):
        _add_register(doc, ledger, store, run_day)
    obligation_rows = _add_obligations(doc, ledger, obligations)
    asks = [
        "Proposal: confirm the containment steps the response team recommends. A person "
        "approves each one; this report does not act.",
    ]
    if obligation_rows:
        asks.append(
            "Proposal: confirm who decides on and lodges each report listed under reporting "
            "obligations. This report does not contact any regulator."
        )
    ledger.limitations.append(
        "This summary restates the incident record. It does not add findings the record "
        "does not contain."
    )
    ledger.limitations.append(
        "Severity is the local triage rating, not an ASD or regulator classification."
    )
    if demo:
        ledger.limitations.append(DEMO_BANNER)
    return _finish(doc, ledger, asks), ledger


def _store_ready(store: str | Path | None) -> bool:
    try:
        return resolve_db_path(store).is_file()
    except ValueError:
        return False


# Output


def body_words(markdown: str) -> int:
    """Words before Appendix A: the one-page part of the report."""
    body = markdown.split("## Appendix A", 1)[0]
    return len(body.split())


def render(
    kind: str,
    *,
    fmt: str = "markdown",
    output: str | None = None,
    store: str | Path | None = None,
    **kwargs,
) -> dict | str:
    if kind == "monthly":
        doc, ledger = monthly_report(store=store, **kwargs)
    elif kind == "incident":
        doc, ledger = incident_report(store=store, **kwargs)
    else:
        raise ValueError("report kind must be monthly or incident")
    if fmt == "markdown":
        return to_markdown(doc)
    if fmt == "json":
        return {
            "kind": kind,
            "untrusted": True,
            "figures": [vars(item) for item in ledger.figures],
            "sources": [{**vars(item), "citation": item.citation()} for item in ledger.sources],
            "limitations": ledger.limitations,
            "references": ledger.references,
            "markdown": to_markdown(doc),
        }
    if fmt == "docx":
        day = ledger.retrieved
        written = write_docx(doc, output or f"{kind}-report-{day}.docx", store)
        return {"format": "docx", "kind": kind, "output": written, "sources": len(ledger.sources)}
    raise ValueError("format must be markdown, json or docx")


def parse_day(value: str) -> date:
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError as exc:
        raise ValueError("dates must be YYYY-MM-DD") from exc
