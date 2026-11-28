"""The Essentials evidence register and gap report.

Teams record their own evidence against ASD Essentials actions (and, kept separate,
Essential Eight requirements), then read a gap report by chapter or export the register
and report as xlsx or docx for management or an assessor.

Rules this module keeps:

- Every output says it is a self-assessment, not an ASD rating (:data:`NOTICE`).
- The two frameworks never mix. A row is keyed by framework. The Essentials summary reads
  only Essentials rows, and nothing here turns an Essential Eight maturity level into an
  Essentials result. ASD says the two do not map directly.
- Action ids and text come from the shipped ASD snapshot read through the asd-essentials
  connector. An Essentials action id is the ASD principle id plus its position in that
  principle, such as ``GOV-01.1``. The hash of the action text is stored with the row, so
  a later ASD wording change is shown as ``reference changed`` instead of silently
  carrying old evidence over.
- Every row keeps where its evidence came from (``source``), when it was gathered
  (``evidence_date``) and when it is due for review (``review_date``). Freshness is worked
  out when a report is read.
- Suggested next steps quote the ASD action text and cite the ASD chapter. Nothing is
  invented, sent, posted or submitted.
"""

from __future__ import annotations

import csv
import hashlib
import io
from dataclasses import dataclass
from datetime import date, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

from .canonical import canonical_date, utc_now
from .db import open_store, resolve_db_path
from .documents import Document, Sheet, to_markdown, write_docx, write_xlsx
from .text import clean_untrusted, unwrap_untrusted

SYDNEY = ZoneInfo("Australia/Sydney")
FRAMEWORKS = ("essentials", "essential-eight")
STATUSES = ("met", "partial", "not met", "unknown", "not applicable")
CHAPTERS = ("enterprise-it", "cloud", "ot")
STRATEGIES = (
    "patch_applications",
    "patch_operating_systems",
    "multi_factor_authentication",
    "restrict_admin_privileges",
    "application_control",
    "restrict_office_macros",
    "user_application_hardening",
    "regular_backups",
)
CHAPTER_NAMES = {
    "enterprise-it": "ASD Essentials for enterprise IT",
    "cloud": "ASD Essentials for cloud",
    "ot": "ASD Essentials for OT",
}
E8_SOURCE_NAME = "Essential Eight requirements"
# org.yaml environments map onto chapters when nothing has been recorded yet.
_ENVIRONMENT_CHAPTER = {"it": "enterprise-it", "cloud": "cloud", "ot": "ot"}
REVIEW_SOON_DAYS = 30
STALE_EVIDENCE_DAYS = 365
MAX_TEXT = 2000
GAP_ORDER = {"not met": 0, "partial": 1, "unknown": 2}

NOTICE = (
    "This is a self-assessment recorded by the organisation. It is not an ASD rating, "
    "an ASD assessment or an IRAP assessment."
)
SEPARATION = (
    "ASD Essentials and the Essential Eight are kept separate. Essential Eight maturity "
    "levels do not map directly to ASD Essentials effectiveness ratings, and this register "
    "does not convert one into the other."
)
PHASE_NOTE = "ASD priority phases only sequence work. A phase is not a maturity level."
READ_ONLY = "This report was not sent, posted or submitted to anyone."

COLUMNS = (
    "framework",
    "chapter",
    "action_id",
    "status",
    "evidence",
    "owner",
    "review_date",
    "source",
    "evidence_date",
)


class ReferenceUnavailable(ValueError):
    """The ASD snapshot could not be read, so ids cannot be checked."""


@dataclass(frozen=True)
class Action:
    chapter: str
    action_id: str
    principle_id: str
    principle: str
    text: str
    domains: tuple[str, ...]
    phase: int | None
    sha256: str


@dataclass(frozen=True)
class Reference:
    """One ASD chapter as served by the asd-essentials connector."""

    chapter: str
    name: str
    url: str
    as_of: str
    retrieved: str
    cache: str
    phase_note: str
    actions: tuple[Action, ...]

    def citation(self) -> str:
        return f"Source: {self.name}, {self.as_of or 'none'}, retrieved {self.retrieved}"

    def find(self, action_id: str) -> Action | None:
        return next((item for item in self.actions if item.action_id == action_id), None)


@dataclass(frozen=True)
class Requirement:
    strategy: str
    control_id: str
    statement: str
    levels: tuple[int, ...]
    sha256: str


@dataclass(frozen=True)
class E8Reference:
    as_of: str
    retrieved: str
    requirements: tuple[Requirement, ...]

    def citation(self) -> str:
        return f"Source: {E8_SOURCE_NAME}, {self.as_of or 'none'}, retrieved {self.retrieved}"

    def find(self, strategy: str, control_id: str) -> Requirement | None:
        return next(
            (
                item
                for item in self.requirements
                if item.strategy == strategy and item.control_id == control_id
            ),
            None,
        )


# Reference data


def today() -> date:
    from cyberau_common import runtime

    return runtime.today(SYDNEY)


def _source_module():
    try:
        from cyberau_asd_essentials import source
    except ImportError as exc:  # pragma: no cover - the workspace always installs it
        raise ReferenceUnavailable("the asd-essentials connector is not installed") from exc
    return source


def _plain(value: object) -> str:
    text = str(value or "")
    inner = unwrap_untrusted(text)
    return (inner if inner is not None else text).strip()


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _sydney_day(stamp: str) -> str:
    from datetime import datetime

    try:
        moment = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    except ValueError:
        return today().isoformat()
    return moment.astimezone(SYDNEY).date().isoformat()


def load_reference(chapter: str) -> Reference:
    """Read one Essentials chapter from the shipped snapshot."""
    if chapter not in CHAPTERS:
        raise ValueError(f"chapter must be one of {', '.join(CHAPTERS)}")
    result = _source_module().essentials_chapter(chapter)
    data = result.get("data")
    if not isinstance(data, dict) or not data.get("actions"):
        reason = "; ".join(result.get("warnings") or []) or "no actions returned"
        raise ReferenceUnavailable(f"ASD Essentials {chapter} is not available: {reason}")
    phase_of: dict[str, int] = {}
    for phase in data.get("priority_phases") or []:
        for domain in phase.get("domains") or []:
            phase_of.setdefault(domain, int(phase.get("phase")))
    counters: dict[str, int] = {}
    actions = []
    for item in data["actions"]:
        principle_id = str(item.get("principle_id") or "").strip()
        counters[principle_id] = counters.get(principle_id, 0) + 1
        text = _plain(item.get("action"))
        domains = tuple(item.get("domains") or ())
        phases = [phase_of[name] for name in domains if name in phase_of]
        actions.append(
            Action(
                chapter=chapter,
                action_id=f"{principle_id}.{counters[principle_id]}",
                principle_id=principle_id,
                principle=_plain(item.get("principle")),
                text=text,
                domains=domains,
                phase=min(phases) if phases else None,
                sha256=_digest(text),
            )
        )
    return Reference(
        chapter=chapter,
        name=CHAPTER_NAMES[chapter],
        url=str(data.get("url") or ""),
        as_of=str(result.get("data_as_of") or ""),
        retrieved=_sydney_day(str(result.get("retrieved_at") or "")),
        cache=str(result.get("cache") or ""),
        phase_note=_plain(data.get("priority_phases_note")),
        actions=tuple(actions),
    )


def load_e8_reference() -> E8Reference:
    """Read every Essential Eight requirement, by strategy, from the shipped snapshot."""
    source = _source_module()
    found: dict[tuple[str, str], Requirement] = {}
    as_of = retrieved = ""
    for strategy in STRATEGIES:
        for level in (1, 2, 3):
            result = source.e8_requirements(strategy, level)
            data = result.get("data")
            if not isinstance(data, dict):
                reason = "; ".join(result.get("warnings") or []) or "no data returned"
                raise ReferenceUnavailable(f"Essential Eight requirements unavailable: {reason}")
            as_of = str(result.get("data_as_of") or as_of)
            retrieved = _sydney_day(str(result.get("retrieved_at") or ""))
            for row in data.get("controls") or []:
                key = (strategy, str(row.get("control_id")))
                if key in found:
                    continue
                statement = _plain(row.get("statement"))
                found[key] = Requirement(
                    strategy=strategy,
                    control_id=key[1],
                    statement=statement,
                    levels=tuple(row.get("maturity_levels") or ()),
                    sha256=_digest(statement),
                )
    return E8Reference(as_of=as_of, retrieved=retrieved, requirements=tuple(found.values()))


# Recording


def _text(value: str | None, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{label} must be text")
    cleaned = clean_untrusted(value, max_len=MAX_TEXT)
    return cleaned or None


def _status(value: str) -> str:
    text = str(value or "").strip().lower().replace("_", " ").replace("-", " ")
    if text == "na" or text == "n/a":
        text = "not applicable"
    if text not in STATUSES:
        raise ValueError(
            f"status must be one of {', '.join(STATUSES)}. A maturity level is not a status."
        )
    return text


def record_evidence(
    framework: str,
    chapter: str,
    action_id: str,
    status: str,
    *,
    evidence: str | None = None,
    owner: str | None = None,
    review_date: str | None = None,
    source: str | None = None,
    evidence_date: str | None = None,
    path: str | Path | None = None,
    reference: Reference | E8Reference | None = None,
) -> dict:
    """Add or replace one register row after checking the id against the ASD snapshot."""
    framework = str(framework or "").strip().lower()
    if framework not in FRAMEWORKS:
        raise ValueError("framework must be essentials or essential-eight, kept separate")
    chapter = str(chapter or "").strip().lower()
    action_id = str(action_id or "").strip()
    kept_status = _status(status)
    if framework == "essentials":
        action_id = action_id.upper()
        if chapter not in CHAPTERS:
            raise ValueError(
                "an Essentials chapter is enterprise-it, cloud or ot. Record Essential Eight "
                "requirements with --framework essential-eight."
            )
        ref = reference if isinstance(reference, Reference) else load_reference(chapter)
        action = ref.find(action_id)
        if action is None:
            raise ValueError(
                f"{action_id} is not an action in {ref.name} ({ref.as_of}). "
                f"List the ids with: cyberau-mcp store evidence actions --chapter {chapter}"
            )
        digest, as_of = action.sha256, ref.as_of
    else:
        action_id = action_id.lower()
        if chapter not in STRATEGIES:
            raise ValueError(f"an Essential Eight chapter is a strategy: {', '.join(STRATEGIES)}")
        ref = reference if isinstance(reference, E8Reference) else load_e8_reference()
        requirement = ref.find(chapter, action_id)
        if requirement is None:
            raise ValueError(f"{action_id} is not an Essential Eight requirement for {chapter}")
        digest, as_of = requirement.sha256, ref.as_of
    kept_review = canonical_date(review_date.strip()) if review_date else None
    gathered = canonical_date(evidence_date.strip()) if evidence_date else today().isoformat()
    row = {
        "framework": framework,
        "chapter": chapter,
        "action_id": action_id,
        "status": kept_status,
        "evidence": _text(evidence, "evidence"),
        "owner": _text(owner, "owner"),
        "review_date": kept_review,
        "source": _text(source, "source") or "analyst",
        "evidence_date": gathered,
        "action_sha256": digest,
        "reference_as_of": as_of,
        "updated_at": utc_now(),
    }
    names = ", ".join(row)
    marks = ", ".join("?" for _ in row)
    with open_store(path).transaction() as conn:
        conn.execute(
            f"INSERT OR REPLACE INTO essentials_evidence ({names}) VALUES ({marks})",
            tuple(row.values()),
        )
    return row


def list_evidence(
    *,
    framework: str | None = None,
    chapter: str | None = None,
    path: str | Path | None = None,
) -> list[dict]:
    clauses, params = [], []
    if framework:
        clauses.append("framework = ?")
        params.append(framework)
    if chapter:
        clauses.append("chapter = ?")
        params.append(chapter)
    where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    conn = open_store(path).connection()
    rows = conn.execute(
        f"SELECT * FROM essentials_evidence{where} ORDER BY framework, chapter, action_id",
        params,
    ).fetchall()
    return [dict(row) for row in rows]


def import_csv(file: str | Path, *, path: str | Path | None = None) -> dict:
    """Load register rows from a CSV with the :data:`COLUMNS` header. All rows or none."""
    text = Path(file).read_text(encoding="utf-8-sig")
    reader = csv.DictReader(io.StringIO(text))
    missing = [
        name
        for name in ("framework", "chapter", "action_id", "status")
        if name not in (reader.fieldnames or [])
    ]
    if missing:
        raise ValueError(f"CSV is missing columns: {', '.join(missing)}")
    rows = list(reader)
    references: dict[str, Reference | E8Reference] = {}
    checked = []
    for number, raw in enumerate(rows, start=2):
        framework = (raw.get("framework") or "").strip().lower()
        chapter = (raw.get("chapter") or "").strip().lower()
        key = "e8" if framework == "essential-eight" else chapter
        if key not in references:
            try:
                references[key] = load_e8_reference() if key == "e8" else load_reference(chapter)
            except ValueError as exc:
                raise ValueError(f"line {number}: {exc}") from exc
        checked.append((number, raw, references[key]))
    store = open_store(path)
    written = 0
    with store.transaction():
        for number, raw, reference in checked:
            try:
                record_evidence(
                    raw.get("framework") or "",
                    raw.get("chapter") or "",
                    raw.get("action_id") or "",
                    raw.get("status") or "",
                    evidence=raw.get("evidence") or None,
                    owner=raw.get("owner") or None,
                    review_date=raw.get("review_date") or None,
                    source=raw.get("source") or None,
                    evidence_date=raw.get("evidence_date") or None,
                    path=path,
                    reference=reference,
                )
            except ValueError as exc:
                raise ValueError(f"line {number}: {exc}") from exc
            written += 1
    return {"imported": written}


# Reading


def freshness(row: dict | None, on: date | None = None) -> str:
    """How current a row is: not recorded, review overdue, stale, review due soon, current."""
    if not row:
        return "not recorded"
    day = on or today()
    review = row.get("review_date")
    if review and date.fromisoformat(review) < day:
        return "review overdue"
    gathered = row.get("evidence_date")
    if gathered and date.fromisoformat(gathered) < day - timedelta(days=STALE_EVIDENCE_DAYS):
        return "evidence older than 12 months"
    if not review:
        return "no review date"
    if date.fromisoformat(review) <= day + timedelta(days=REVIEW_SOON_DAYS):
        return "review due within 30 days"
    return "current"


def chapters_in_scope(chapters: list[str] | None, path: str | Path | None) -> list[str]:
    """Named chapters, else chapters with rows, else the org profile environments."""
    if chapters:
        bad = [item for item in chapters if item not in CHAPTERS]
        if bad:
            raise ValueError(f"chapter must be one of {', '.join(CHAPTERS)}")
        return list(dict.fromkeys(chapters))
    recorded = {row["chapter"] for row in list_evidence(framework="essentials", path=path)}
    if recorded:
        return [item for item in CHAPTERS if item in recorded]
    try:
        from .org import load_org

        environments = load_org().environments
    except Exception:  # noqa: BLE001 - a missing or broken org.yaml falls back to IT
        environments = ("it",)
    found = [_ENVIRONMENT_CHAPTER[item] for item in environments if item in _ENVIRONMENT_CHAPTER]
    return [item for item in CHAPTERS if item in found] or ["enterprise-it"]


def essentials_view(reference: Reference, rows: list[dict], on: date | None = None) -> list[dict]:
    """Every action in the chapter, joined with its row. Only Essentials rows are read."""
    recorded = {
        row["action_id"]: row
        for row in rows
        if row["framework"] == "essentials" and row["chapter"] == reference.chapter
    }
    view = []
    for action in reference.actions:
        row = recorded.get(action.action_id)
        view.append(
            {
                "chapter": reference.chapter,
                "action_id": action.action_id,
                "principle": f"{action.principle_id} {action.principle}",
                "action": action.text,
                "domains": ", ".join(action.domains) or "all domains",
                "priority_phase": action.phase,
                "status": row["status"] if row else "unknown",
                "evidence": (row or {}).get("evidence") or "",
                "owner": (row or {}).get("owner") or "",
                "review_date": (row or {}).get("review_date") or "",
                "source": (row or {}).get("source") or "not recorded",
                "evidence_date": (row or {}).get("evidence_date") or "",
                "freshness": freshness(row, on),
                "reference_changed": bool(row and row.get("action_sha256") != action.sha256),
            }
        )
    return view


def summarise(view: list[dict]) -> dict:
    counts = {status: 0 for status in STATUSES}
    for item in view:
        counts[item["status"]] += 1
    counts["total"] = len(view)
    counts["review overdue"] = sum(1 for item in view if item["freshness"] == "review overdue")
    return counts


def e8_view(reference: E8Reference, rows: list[dict], on: date | None = None) -> list[dict]:
    """Recorded Essential Eight rows only. No maturity level is worked out here."""
    view = []
    for row in rows:
        if row["framework"] != "essential-eight":
            continue
        requirement = reference.find(row["chapter"], row["action_id"])
        view.append(
            {
                "strategy": row["chapter"],
                "requirement_id": row["action_id"],
                "requirement": requirement.statement if requirement else "missing",
                "applies_at_e8_levels": ", ".join(str(n) for n in requirement.levels)
                if requirement
                else "",
                "status": row["status"],
                "evidence": row.get("evidence") or "",
                "owner": row.get("owner") or "",
                "review_date": row.get("review_date") or "",
                "source": row.get("source") or "",
                "evidence_date": row.get("evidence_date") or "",
                "freshness": freshness(row, on),
                "reference_changed": bool(
                    requirement is None or row.get("action_sha256") != requirement.sha256
                ),
            }
        )
    return view


def _next_step(item: dict) -> str:
    if item["status"] == "not met":
        return "Plan the work to put this ASD action in place and name an owner."
    if item["status"] == "partial":
        return "Close the part of this ASD action that is not yet in place."
    if item["freshness"] == "review overdue":
        return "Review the evidence again; the review date has passed."
    if item["reference_changed"]:
        return "ASD changed this action's wording. Check the evidence still fits."
    return "Record evidence for this ASD action, or mark it not applicable with a reason."


def gaps(view: list[dict]) -> list[dict]:
    """Actions that need work, most urgent first, then by ASD priority phase."""
    found = [
        item
        for item in view
        if item["status"] in GAP_ORDER
        or item["freshness"] == "review overdue"
        or item["reference_changed"]
    ]
    found.sort(
        key=lambda item: (
            GAP_ORDER.get(item["status"], 3),
            item["priority_phase"] or 99,
            item["action_id"],
        )
    )
    return [{**item, "next_step": _next_step(item)} for item in found]


@dataclass
class Report:
    on: date
    references: list[Reference]
    views: dict[str, list[dict]]
    e8: E8Reference | None
    e8_rows: list[dict]

    def to_json(self) -> dict:
        chapters = []
        for reference in self.references:
            view = self.views[reference.chapter]
            chapters.append(
                {
                    "chapter": reference.chapter,
                    "name": reference.name,
                    "url": reference.url,
                    "data_as_of": reference.as_of,
                    "citation": reference.citation(),
                    "summary": summarise(view),
                    "gaps": gaps(view),
                }
            )
        return {
            "untrusted": True,
            "notice": NOTICE,
            "separation": SEPARATION,
            "as_of": self.on.isoformat(),
            "essentials": chapters,
            "essential_eight": {
                "citation": self.e8.citation() if self.e8 else None,
                "rows": self.e8_rows,
            },
        }


def build_report(
    *,
    chapters: list[str] | None = None,
    path: str | Path | None = None,
    on: date | None = None,
) -> Report:
    day = on or today()
    rows = list_evidence(path=path)
    references = [load_reference(chapter) for chapter in chapters_in_scope(chapters, path)]
    views = {ref.chapter: essentials_view(ref, rows, day) for ref in references}
    e8_rows: list[dict] = []
    e8 = None
    if any(row["framework"] == "essential-eight" for row in rows):
        e8 = load_e8_reference()
        e8_rows = e8_view(e8, rows, day)
    return Report(day, references, views, e8, e8_rows)


# Documents


def gap_document(report: Report) -> Document:
    doc = Document("ASD Essentials gap report (self-assessment)")
    doc.para(NOTICE)
    doc.para(SEPARATION)
    doc.para(f"Prepared {report.on.isoformat()}. {READ_ONLY}")
    doc.heading("Summary by chapter")
    header = ["Chapter", "Actions", "Met", "Partial", "Not met", "Unknown", "Not applicable"]
    table = []
    for reference in report.references:
        counts = summarise(report.views[reference.chapter])
        table.append(
            [
                reference.name,
                counts["total"],
                counts["met"],
                counts["partial"],
                counts["not met"],
                counts["unknown"],
                counts["not applicable"],
            ]
        )
    doc.table(header, table)
    doc.para("Unknown means no evidence was recorded. It is not a failure.")
    doc.para(
        f"Source: hermes-cyber-au evidence register, none, retrieved {report.on.isoformat()}"
    )
    for reference in report.references:
        doc.para(reference.citation())
    for reference in report.references:
        listed = gaps(report.views[reference.chapter])
        doc.heading(reference.name)
        doc.para(
            f"{len(listed)} of {len(reference.actions)} actions need attention. "
            "The suggested next step for each is the ASD action text, quoted."
        )
        doc.para(PHASE_NOTE if not reference.phase_note else reference.phase_note)
        doc.table(
            ["Action", "Phase", "Status", "Next step", "ASD action", "Owner", "Freshness"],
            [
                [
                    item["action_id"],
                    item["priority_phase"] or "",
                    item["status"],
                    item["next_step"],
                    item["action"],
                    item["owner"] or "not set",
                    item["freshness"],
                ]
                for item in listed
            ],
        )
        doc.para(reference.citation())
        doc.para(f"Guidance: {reference.url}")
    if report.e8_rows:
        doc.heading("Essential Eight requirements (kept separate)")
        doc.para(
            "These are Essential Eight requirement records. They are not counted in the "
            "ASD Essentials figures above, and no Essentials result is derived from them."
        )
        doc.table(
            ["Strategy", "Requirement", "Status", "Owner", "Freshness"],
            [
                [
                    item["strategy"],
                    item["requirement_id"],
                    item["status"],
                    item["owner"] or "not set",
                    item["freshness"],
                ]
                for item in report.e8_rows
            ],
        )
        if report.e8:
            doc.para(report.e8.citation())
    doc.heading("Limitations")
    doc.bullet("Statuses are the organisation's own judgement from its own evidence.")
    doc.bullet("Actions with no record are shown as unknown, not as failures.")
    doc.bullet(
        "Action ids are the ASD principle id and the action's position in it, read from the "
        "ASD snapshot dated "
        + ", ".join(sorted({ref.as_of or "unknown" for ref in report.references}))
        + "."
    )
    doc.bullet("Rows marked reference changed were recorded against older ASD wording.")
    doc.para(NOTICE)
    return doc


def register_sheets(report: Report) -> list[Sheet]:
    about = Sheet(
        "About",
        ["Notice"],
        [
            [NOTICE],
            [SEPARATION],
            [f"Prepared {report.on.isoformat()}. {READ_ONLY}"],
            [PHASE_NOTE],
            *[[ref.citation()] for ref in report.references],
            *([[report.e8.citation()]] if report.e8 else []),
        ],
        widths={1: 120},
    )
    header = [
        "chapter",
        "action_id",
        "principle",
        "action",
        "domains",
        "priority_phase",
        "status",
        "evidence",
        "owner",
        "review_date",
        "source",
        "evidence_date",
        "freshness",
        "reference_changed",
    ]
    rows = []
    for reference in report.references:
        for item in report.views[reference.chapter]:
            rows.append(
                [
                    *(item[name] for name in header[:-1]),
                    "yes" if item["reference_changed"] else "no",
                ]
            )
    sheets = [
        about,
        Sheet("Essentials register", header, rows, widths={3: 30, 4: 60, 8: 40}),
        Sheet(
            "Gaps by chapter",
            ["chapter", "action_id", "priority_phase", "status", "next_step", "action", "owner"],
            [
                [
                    item["chapter"],
                    item["action_id"],
                    item["priority_phase"],
                    item["status"],
                    item["next_step"],
                    item["action"],
                    item["owner"],
                ]
                for reference in report.references
                for item in gaps(report.views[reference.chapter])
            ],
            widths={5: 50, 6: 60},
        ),
    ]
    if report.e8_rows:
        e8_header = list(report.e8_rows[0].keys())
        sheets.append(
            Sheet(
                "Essential Eight register",
                e8_header,
                [
                    [
                        ("yes" if value else "no") if name == "reference_changed" else value
                        for name, value in item.items()
                    ]
                    for item in report.e8_rows
                ],
                widths={3: 60},
            )
        )
    return sheets


def export(
    fmt: str,
    *,
    output: str | None = None,
    chapters: list[str] | None = None,
    path: str | Path | None = None,
    on: date | None = None,
) -> dict:
    """Write the register (xlsx) or the gap report (docx) under exports."""
    report = build_report(chapters=chapters, path=path, on=on)
    stem = f"essentials-{report.on.isoformat()}"
    if fmt == "xlsx":
        written = write_xlsx(register_sheets(report), output or f"{stem}-register.xlsx", path)
    elif fmt == "docx":
        written = write_docx(gap_document(report), output or f"{stem}-gaps.docx", path)
    else:
        raise ValueError("format must be xlsx or docx")
    return {
        "format": fmt,
        "output": written,
        "chapters": [ref.chapter for ref in report.references],
        "notice": NOTICE,
    }


def gap_markdown(
    *, chapters: list[str] | None = None, path: str | Path | None = None, on: date | None = None
) -> str:
    return to_markdown(gap_document(build_report(chapters=chapters, path=path, on=on)))


def chapter_actions(chapter: str) -> dict:
    reference = load_reference(chapter)
    return {
        "untrusted": True,
        "chapter": chapter,
        "citation": reference.citation(),
        "phase_note": reference.phase_note or PHASE_NOTE,
        "actions": [
            {
                "action_id": item.action_id,
                "principle": item.principle,
                "priority_phase": item.phase,
                "action": item.text,
            }
            for item in reference.actions
        ],
    }


def store_exists(path: str | Path | None) -> bool:
    return resolve_db_path(path).is_file()
