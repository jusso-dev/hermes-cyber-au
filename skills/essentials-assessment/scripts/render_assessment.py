"""Render an essentials assessment from supplied evidence and tool payloads.

The script does not use the network. Requirement text is copied only from a
tool payload. A missing source or a missing control stays missing.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

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
CHAPTERS = ("enterprise-it", "cloud", "ot")
STATUSES = {"met", "partial", "not met", "unknown"}
DISCLAIMER = (
    "This is a self-assessment aid. It is not an ASD assessment and it is not an IRAP assessment. "
    "This workbook was not sent and no one was notified."
)
PROPOSAL_GAP = (
    "Proposal: retrieve the missing sources and the missing evidence, then repeat this "
    "self-assessment before changing a control. Reversible by discarding this workbook."
)
PROPOSAL_CLEAR = (
    "Proposal: keep this workbook with the evidence. No control change is proposed. "
    "Reversible by discarding this workbook."
)
COLUMNS = "strategy_or_domain,requirement_id,requirement_text,evidence_ref,status,ism_ids,notes"
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")
_URL = re.compile(r"\b(https?)://([^\s/]+)(\S*)", re.IGNORECASE)
_EMAIL = re.compile(r"\b([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HOST = re.compile(r"(?i)^((?:[a-z0-9-]+\.)+[a-z]{2,})((?::\d+)?(?:[/?#].*)?)$")
_NO_RECORD = re.compile(r"(?i)\bno (?:backup )?evidence\b|\bno record\b")
_INSTRUCTION = re.compile(
    r"(?i)(ignore previous|essentials_publish|mark every control met|"
    r"post the workbook|email the workbook)"
)


@dataclass(frozen=True)
class Row:
    strategy_or_domain: str
    requirement_id: str
    requirement_text: str
    evidence_ref: str
    status: str
    ism_ids: str
    notes: str
    evidence_text: str = ""
    citations: tuple[str, ...] = ()


@dataclass
class Built:
    rows: list[Row] = field(default_factory=list)
    missing_sources: list[str] = field(default_factory=list)
    missing_controls: list[str] = field(default_factory=list)
    extras: list[str] = field(default_factory=list)
    phase_lines: list[str] = field(default_factory=list)
    maturity: str = ""


@dataclass(frozen=True)
class Report:
    rows: tuple[Row, ...]
    csv: str
    markdown: str


def defang_observable(value: str) -> str:
    """Defang one observable. Matches the skill standard for a single value."""
    text = value.strip()
    bare = _HOST.fullmatch(text)
    if bare:
        return bare.group(1).replace(".", "[.]") + bare.group(2)

    def url_sub(match: re.Match[str]) -> str:
        scheme = "hxxps" if match.group(1).lower() == "https" else "hxxp"
        host = match.group(2).replace(".", "[.]")
        return f"{scheme}://{host}{match.group(3)}"

    text = _URL.sub(url_sub, text)

    def email_sub(match: re.Match[str]) -> str:
        return f"{match.group(1)}[@]{match.group(2).replace('.', '[.]')}"

    text = _EMAIL.sub(email_sub, text)
    return _IPV4.sub(lambda match: match.group(0).replace(".", "[.]"), text)


def render(document: dict) -> Report:
    """Build the CSV workbook and the markdown report."""
    if not isinstance(document, dict):
        raise TypeError("assessment input must be a JSON object")
    as_of = _day(document.get("as_of"))
    built = Built()
    _add_e8(document, as_of, built)
    _add_essentials(document, as_of, built)
    _add_controls(document, as_of, built)
    _add_transition(document, as_of, built)
    _add_nist(document, as_of, built)
    _add_import(document, as_of, built)
    if not built.rows and not built.extras:
        built.rows.append(
            _row(
                "missing",
                "missing",
                "missing",
                "",
                "missing",
                "missing",
                "Nothing was requested. No framework was assumed.",
                "",
                (_cite("supplied evidence", "none", as_of),) if as_of else (),
            )
        )
    return Report(tuple(built.rows), _csv(built.rows), _markdown(built, as_of))


def _add_e8(document: dict, as_of: str, built: Built) -> None:
    if document.get("framework") not in {"essential-eight", "both"}:
        return
    strategies = document.get("strategies")
    if not isinstance(strategies, list) or not strategies:
        return
    payload = _payload(document, "e8")
    items = _evidence(document)
    if payload is None:
        _remember(built, "Essential Eight requirements (mcp__e8__e8_requirements)")
        citation = _cite("Essential Eight requirements", "missing", as_of)
        for raw_strategy in strategies:
            strategy = str(raw_strategy)
            matched = [
                item
                for item in items
                if item.get("strategy") == strategy and not item.get("requirement_id")
            ]
            refs, texts, instructions = _pack(matched)
            if texts or instructions:
                status = "missing"
                note = (
                    "Essential Eight requirements source missing "
                    "(mcp__e8__e8_requirements). Supplied evidence was recorded and was not scored."
                )
            else:
                status = "unknown"
                note = (
                    "No evidence supplied. Essential Eight requirements source missing "
                    "(mcp__e8__e8_requirements)."
                )
            if strategy not in STRATEGIES:
                note += (
                    " This strategy name is not an Essential Eight tool value."
                    " No strategy was substituted."
                )
            note = _with_instruction(note, instructions)
            citations = (citation,)
            if texts or instructions:
                evidence_cite = _cite("supplied evidence", "none", as_of)
                if evidence_cite:
                    citations = (citation, evidence_cite)
            built.rows.append(
                _row(
                    strategy,
                    "missing",
                    "missing",
                    refs,
                    status,
                    "missing",
                    note,
                    texts,
                    citations,
                )
            )
        built.maturity = "Essential Eight maturity: missing"
        return

    grouped: dict[str, list[dict]] = {}
    for block in payload.get("strategies") or []:
        if isinstance(block, dict) and isinstance(block.get("strategy"), str):
            grouped.setdefault(block["strategy"], []).append(block)
    citation = _cite(
        _source_name(payload, "Essential Eight requirements"),
        str(payload.get("version") or "missing"),
        str(payload.get("retrieved_at") or as_of),
    )
    scored: list[str] = []
    for raw_strategy in strategies:
        strategy = str(raw_strategy)
        requirements = _requirements(grouped.get(strategy, []))
        if strategy not in STRATEGIES:
            built.rows.append(
                _row(
                    strategy,
                    "missing",
                    "missing",
                    "",
                    "missing",
                    "missing",
                    (
                        "This strategy name is not an Essential Eight tool value."
                        " No strategy was substituted."
                    ),
                    "",
                    (citation,),
                )
            )
            scored.append(f"{strategy} missing")
            continue
        if not requirements:
            built.rows.append(
                _row(
                    strategy,
                    "missing",
                    "missing",
                    "",
                    "missing",
                    "missing",
                    "No requirement text was returned for this strategy.",
                    "",
                    (citation,),
                )
            )
            scored.append(f"{strategy} missing")
            continue
        level_status: dict[int, list[str]] = {}
        for level, requirement in requirements:
            requirement_id = str(requirement.get("id") or "missing")
            raw_text = requirement.get("text")
            text = raw_text.strip() if isinstance(raw_text, str) else ""
            matched = [
                item for item in items if item.get("requirement_id") == requirement_id
            ]
            refs, texts, instructions = _pack(matched)
            if not text:
                status = "missing"
                shown = "missing"
            else:
                shown = defang_observable(text)
                status = "unknown" if instructions else _score(matched)
            ism_cell, ism_note, ism_cites = _ism_ids(
                document, requirement.get("ism_ids") or [], as_of, built
            )
            note = ism_note
            if not text:
                note = "No requirement text was returned. " + note
            note = _with_instruction(note, instructions)
            if level is not None:
                level_status.setdefault(level, []).append(status)
            citations = tuple(item for item in (citation, *ism_cites) if item)
            if texts or instructions:
                evidence_cite = _cite("supplied evidence", "none", as_of)
                if evidence_cite:
                    citations = (*citations, evidence_cite)
            built.rows.append(
                _row(
                    strategy,
                    requirement_id,
                    shown,
                    refs,
                    status,
                    ism_cell,
                    note.strip(),
                    texts,
                    citations,
                )
            )
        levels = sorted(level_status)
        if levels and levels[0] > 1:
            built.extras.append(
                f"{strategy}: level 1 was not retrieved, so no lower level was awarded."
            )
        scored.append(f"{strategy} {_award(level_status)}")
    built.maturity = "Essential Eight maturity: " + "; ".join(scored)


def _add_essentials(document: dict, as_of: str, built: Built) -> None:
    if document.get("framework") not in {"essentials", "both"}:
        return
    chapter = document.get("chapter")
    payload = _payload(document, "essentials_chapter")
    items = _evidence(document)
    if chapter not in CHAPTERS or payload is None or payload.get("chapter") != chapter:
        _remember(built, "ASD Essentials chapter (mcp__e8__essentials_chapter)")
        label = str(chapter) if chapter in CHAPTERS else "missing"
        matched = [item for item in items if item.get("chapter") == chapter]
        refs, texts, instructions = _pack(matched)
        if texts or instructions:
            status = "missing"
            note = (
                "ASD Essentials chapter source missing (mcp__e8__essentials_chapter). "
                "Supplied evidence was recorded and was not scored."
            )
        else:
            status = "unknown"
            note = (
                "No evidence supplied. ASD Essentials chapter source missing "
                "(mcp__e8__essentials_chapter)."
            )
        if chapter not in CHAPTERS:
            note += " No chapter was assumed."
        note = _with_instruction(note, instructions)
        citations = (_cite("ASD Essentials chapter", "missing", as_of),)
        if texts or instructions:
            evidence_cite = _cite("supplied evidence", "none", as_of)
            if evidence_cite:
                citations = (*citations, evidence_cite)
        built.rows.append(
            _row(
                label,
                "missing",
                "missing",
                refs,
                status,
                "missing",
                note,
                texts,
                citations,
            )
        )
        built.phase_lines.append(
            "No priority phase was retrieved. A priority phase is not a maturity score."
        )
        return

    citation = _cite(
        _source_name(payload, "ASD Essentials chapter"),
        str(payload.get("version") or "missing"),
        str(payload.get("retrieved_at") or as_of),
    )
    counts: dict[str, list[int]] = {}
    domains = payload.get("domains") if isinstance(payload.get("domains"), list) else []
    for domain in domains:
        if not isinstance(domain, dict):
            continue
        domain_name = str(domain.get("domain") or "missing")
        phase = str(domain.get("phase") or "missing")
        actions = (
            domain.get("actions") if isinstance(domain.get("actions"), list) else []
        )
        for action in actions:
            if not isinstance(action, dict):
                continue
            action_id = str(action.get("id") or "missing")
            raw_text = action.get("text")
            text = raw_text.strip() if isinstance(raw_text, str) else ""
            matched = [
                item for item in items if item.get("requirement_id") == action_id
            ]
            refs, texts, instructions = _pack(matched)
            if not text:
                status = "missing"
                shown = "missing"
            else:
                shown = defang_observable(text)
                status = "unknown" if instructions else _score(matched)
            counts.setdefault(phase, [0, 0])
            counts[phase][1] += 1
            if status == "met":
                counts[phase][0] += 1
            note = _with_instruction("", instructions).strip()
            citations = (citation,)
            if texts or instructions:
                evidence_cite = _cite("supplied evidence", "none", as_of)
                if evidence_cite:
                    citations = (citation, evidence_cite)
            built.rows.append(
                _row(
                    f"{chapter}/{domain_name}",
                    action_id,
                    shown,
                    refs,
                    status,
                    "",
                    note,
                    texts,
                    citations,
                )
            )
    if not counts:
        built.phase_lines.append(
            "No priority phase was retrieved. A priority phase is not a maturity score."
        )
        return
    for phase in sorted(counts):
        met, total = counts[phase]
        built.phase_lines.append(
            f"priority phase {phase}: {met} of {total} actions met"
        )
    built.phase_lines.append("A priority phase is not a maturity score.")


def _add_controls(document: dict, as_of: str, built: Built) -> None:
    requested = document.get("controls_requested")
    if not isinstance(requested, list) or not requested:
        return
    payload = _payload(document, "ism")
    items = _evidence(document)
    if payload is None:
        _remember(built, "ISM source missing (mcp__ism__ism_get_control)")
        citation = _cite("asd-ism", "missing", as_of)
        for raw in requested:
            control_id = _control_id(str(raw))
            matched = [
                item
                for item in items
                if _control_id(str(item.get("control_id") or "")) == control_id
            ]
            refs, texts, instructions = _pack(matched)
            note = (
                f"ISM source missing (mcp__ism__ism_get_control). "
                f"Control {control_id} is missing. No statement was invented."
            )
            note = _with_instruction(note, instructions)
            citations = (citation,)
            if texts or instructions:
                evidence_cite = _cite("supplied evidence", "none", as_of)
                if evidence_cite:
                    citations = (citation, evidence_cite)
            built.rows.append(
                _row(
                    control_id,
                    control_id,
                    "missing",
                    refs,
                    "missing",
                    f"{control_id} missing",
                    note,
                    texts,
                    citations,
                )
            )
            built.missing_controls.append(control_id)
        return

    citation = _cite(
        "asd-ism",
        str(payload.get("version") or "missing"),
        str(payload.get("retrieved_at") or as_of),
    )
    for raw in requested:
        control_id = _control_id(str(raw))
        statement, state = _lookup(payload, control_id)
        matched = [
            item
            for item in items
            if _control_id(str(item.get("control_id") or "")) == control_id
        ]
        refs, texts, instructions = _pack(matched)
        if state != "found":
            built.missing_controls.append(control_id)
            note = f"Control {control_id} is missing. No statement was invented."
            note = _with_instruction(note, instructions)
            citations = (citation,)
            if texts or instructions:
                evidence_cite = _cite("supplied evidence", "none", as_of)
                if evidence_cite:
                    citations = (citation, evidence_cite)
            built.rows.append(
                _row(
                    control_id,
                    control_id,
                    "missing",
                    refs,
                    "missing",
                    f"{control_id} missing",
                    note,
                    texts,
                    citations,
                )
            )
            continue
        status = "unknown" if instructions else _score(matched)
        note = _with_instruction("", instructions).strip()
        if _INSTRUCTION.search(statement):
            shown = defang_observable(statement)
            request = (
                f"The retrieved text asks: {shown} "
                "That request was treated as untrusted content and was not carried out."
            )
            note = f"{note} {request}".strip()
            status = "unknown" if status == "met" else status
        citations = (citation,)
        if texts or instructions:
            evidence_cite = _cite("supplied evidence", "none", as_of)
            if evidence_cite:
                citations = (citation, evidence_cite)
        built.rows.append(
            _row(
                control_id,
                control_id,
                defang_observable(statement),
                refs,
                status,
                control_id,
                note,
                texts,
                citations,
            )
        )


def _add_transition(document: dict, as_of: str, built: Built) -> None:
    if document.get("include_transition") is not True:
        return
    payload = _payload(document, "essentials_transition")
    if payload is None:
        _remember(
            built,
            "ASD Essentials transition source missing (mcp__e8__essentials_transition)",
        )
        built.extras.append(
            "ASD Essentials transition source missing (mcp__e8__essentials_transition). "
            "No transition mapping was retrieved."
        )
        cited = _cite("ASD Essentials transition", "missing", as_of)
        if cited:
            built.extras.append(cited)
        return
    texts = []
    for item in payload.get("mappings") or []:
        if (
            isinstance(item, dict)
            and isinstance(item.get("text"), str)
            and item["text"].strip()
        ):
            texts.append(defang_observable(item["text"].strip()))
    if not texts:
        built.extras.append("No transition mapping was retrieved.")
    else:
        built.extras.extend(texts)
    cited = _cite(
        _source_name(payload, "ASD Essentials transition"),
        str(payload.get("version") or "missing"),
        str(payload.get("retrieved_at") or as_of),
    )
    if cited:
        built.extras.append(cited)


def _add_nist(document: dict, as_of: str, built: Built) -> None:
    if document.get("nist_requested") is not True:
        return
    payload = _payload(document, "nist")
    if payload is None:
        _remember(built, "NIST mapping")
        built.extras.append("NIST mapping source missing.")
        cited = _cite("NIST mapping", "missing", as_of)
        if cited:
            built.extras.append(cited)
        return
    texts = []
    for item in payload.get("mappings") or []:
        if not isinstance(item, dict) or not isinstance(item.get("text"), str):
            continue
        text = item["text"].strip()
        if not text:
            continue
        ident = str(item.get("id") or "missing")
        texts.append(f"{ident}: {defang_observable(text)}")
    if not texts:
        _remember(built, "NIST mapping")
        built.extras.append("NIST mapping source missing.")
        cited = _cite("NIST mapping", "missing", as_of)
    else:
        built.extras.extend(texts)
        cited = _cite(
            _source_name(payload, "NIST mapping"),
            str(payload.get("version") or "missing"),
            str(payload.get("retrieved_at") or as_of),
        )
    if cited:
        built.extras.append(cited)


def _add_import(document: dict, as_of: str, built: Built) -> None:
    if document.get("import_requested") is not True:
        return
    payload = _payload(document, "evidence_import")
    if payload is None:
        _remember(built, "M365-Secure evidence import (evidence_import)")
        raw_path = document.get("import_path")
        shown = (
            defang_observable(str(raw_path))
            if isinstance(raw_path, str) and raw_path
            else "missing"
        )
        built.extras.append(
            "M365-Secure evidence import source missing (evidence_import). "
            f"The report path was not imported: {shown}."
        )
        cited = _cite("M365-Secure evidence import", "missing", as_of)
        if cited:
            built.extras.append(cited)
        return
    records = payload.get("records") if isinstance(payload.get("records"), list) else []
    copied = [
        defang_observable(str(item.get("text")).strip())
        for item in records
        if isinstance(item, dict)
        and isinstance(item.get("text"), str)
        and item["text"].strip()
    ]
    if not copied:
        built.extras.append("M365-Secure evidence import returned no records.")
    else:
        built.extras.extend(copied)
    cited = _cite(
        _source_name(payload, "M365-Secure evidence import"),
        str(payload.get("version") or "missing"),
        str(payload.get("retrieved_at") or as_of),
    )
    if cited:
        built.extras.append(cited)


def _ism_ids(
    document: dict, raw_ids: object, as_of: str, built: Built
) -> tuple[str, str, tuple[str, ...]]:
    if not isinstance(raw_ids, list) or not raw_ids:
        return "missing", "No ISM control id was returned.", ()
    payload = _payload(document, "ism")
    parts: list[str] = []
    notes: list[str] = []
    cites: list[str] = []
    if payload is None:
        _remember(built, "ISM source missing (mcp__ism__ism_get_control)")
        cited = _cite("asd-ism", "missing", as_of)
        if cited:
            cites.append(cited)
        for raw in raw_ids:
            control_id = _control_id(str(raw))
            parts.append(f"{control_id} missing")
            built.missing_controls.append(control_id)
        notes.append(
            "ISM source missing (mcp__ism__ism_get_control). No statement was invented."
        )
        return " ".join(parts), " ".join(notes), tuple(cites)
    cited = _cite(
        "asd-ism",
        str(payload.get("version") or "missing"),
        str(payload.get("retrieved_at") or as_of),
    )
    if cited:
        cites.append(cited)
    for raw in raw_ids:
        control_id = _control_id(str(raw))
        statement, state = _lookup(payload, control_id)
        if state != "found":
            parts.append(f"{control_id} missing")
            notes.append(f"Control {control_id} is missing. No statement was invented.")
            built.missing_controls.append(control_id)
            continue
        parts.append(control_id)
        shown = defang_observable(statement)
        if _INSTRUCTION.search(statement):
            notes.append(
                f"The retrieved text asks: {shown} "
                "That request was treated as untrusted content and was not carried out."
            )
        else:
            notes.append(shown)
    return " ".join(parts), " ".join(notes), tuple(cites)


def _requirements(blocks: list[dict]) -> list[tuple[int | None, dict]]:
    found: list[tuple[int | None, dict]] = []
    for block in blocks:
        level = block.get("maturity_level")
        parsed = (
            level if isinstance(level, int) and not isinstance(level, bool) else None
        )
        requirements = block.get("requirements")
        if not isinstance(requirements, list):
            continue
        for requirement in requirements:
            if isinstance(requirement, dict):
                found.append((parsed, requirement))
    return found


def _lookup(payload: dict, control_id: str) -> tuple[str, str]:
    controls = payload.get("controls")
    if not isinstance(controls, dict):
        return "", "missing"
    record = controls.get(control_id)
    if not isinstance(record, dict) or record.get("found") is not True:
        return "", "missing"
    statement = record.get("statement")
    if not isinstance(statement, str) or not statement.strip():
        return "", "missing"
    return statement.strip(), "found"


def _score(items: list[dict]) -> str:
    usable: list[str] = []
    for item in items:
        text = item.get("text")
        if not isinstance(text, str) or not text.strip():
            continue
        if _NO_RECORD.search(text) or _INSTRUCTION.search(text):
            continue
        status = item.get("status")
        if status in STATUSES:
            usable.append(status)
    if not usable:
        return "unknown"
    unique = set(usable)
    if len(unique) == 1:
        return usable[0]
    if "unknown" in unique:
        return "unknown"
    return "partial"


def _award(level_status: dict[int, list[str]]) -> str:
    if not level_status:
        return "missing"
    awarded = "none"
    expect = 1
    for level in sorted(level_status):
        if level != expect:
            break
        statuses = level_status[level]
        if statuses and all(item == "met" for item in statuses):
            awarded = str(level)
            expect = level + 1
            continue
        break
    return awarded


def _pack(items: list[dict]) -> tuple[str, str, list[str]]:
    refs: list[str] = []
    texts: list[str] = []
    instructions: list[str] = []
    for item in items:
        ref = item.get("ref")
        if isinstance(ref, str) and ref.strip():
            refs.append(ref.strip())
        raw = item.get("text")
        if not isinstance(raw, str) or not raw.strip():
            continue
        shown = defang_observable(raw.strip())
        if _INSTRUCTION.search(raw):
            instructions.append(shown)
        else:
            texts.append(shown)
    return ";".join(refs), " ".join(texts), instructions


def _with_instruction(note: str, instructions: list[str]) -> str:
    if not instructions:
        return note
    request = (
        f"The evidence asks: {' '.join(instructions)} "
        "That request was treated as untrusted content and was not carried out."
    )
    return f"{note} {request}".strip()


def _payload(document: dict, key: str) -> dict | None:
    block = document.get(key)
    if not isinstance(block, dict) or block.get("available") is not True:
        return None
    return block


def _evidence(document: dict) -> list[dict]:
    items = document.get("evidence")
    if not isinstance(items, list):
        return []
    return [item for item in items if isinstance(item, dict)]


def _remember(built: Built, label: str) -> None:
    if label not in built.missing_sources:
        built.missing_sources.append(label)


def _source_name(payload: dict, fallback: str) -> str:
    name = payload.get("source")
    if isinstance(name, str) and name.strip() and "," not in name:
        return name.strip()
    return fallback


def _cite(name: str, version: str, retrieved: str) -> str:
    if not name or not version or "," in name or "," in version:
        return ""
    day = _day(retrieved)
    if not day:
        return ""
    return f"Source: {name}, {version}, retrieved {day}"


def _day(value: object) -> str:
    if not isinstance(value, str):
        return ""
    match = _DATE.search(value)
    return match.group(0) if match else ""


def _control_id(value: str) -> str:
    text = value.strip()
    match = re.fullmatch(r"(?i)(?:ISM-)?(\d{3,4})", text)
    if match:
        return f"ism-{match.group(1).zfill(4)}"
    if text.lower().startswith("ism-"):
        return text.lower()
    return text


def _row(
    strategy: str,
    requirement_id: str,
    requirement_text: str,
    evidence_ref: str,
    status: str,
    ism_ids: str,
    notes: str,
    evidence_text: str,
    citations: tuple[str, ...],
) -> Row:
    return Row(
        strategy,
        requirement_id,
        requirement_text,
        evidence_ref,
        status,
        ism_ids,
        notes.strip(),
        evidence_text.strip(),
        tuple(item for item in citations if item),
    )


def _csv(rows: list[Row]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(COLUMNS.split(","))
    for row in rows:
        notes = row.notes
        if row.evidence_text:
            notes = f"{notes} Evidence: {row.evidence_text}".strip()
        if row.citations:
            notes = f"{notes} {' '.join(row.citations)}".strip()
        writer.writerow(
            [
                row.strategy_or_domain,
                row.requirement_id,
                row.requirement_text,
                row.evidence_ref,
                row.status,
                row.ism_ids,
                notes,
            ]
        )
    return buffer.getvalue()


def _markdown(built: Built, as_of: str) -> str:
    lines = [
        "# Essentials assessment",
        "",
        DISCLAIMER,
        "",
        f"Workbook columns: {COLUMNS}",
        "",
        "## Summary",
        "",
        (
            "| strategy_or_domain | requirement_id | requirement_text"
            " | evidence_ref | status | ism_ids |"
        ),
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for row in built.rows:
        lines.append(
            "| "
            + " | ".join(
                _cell(part)
                for part in (
                    row.strategy_or_domain,
                    row.requirement_id,
                    row.requirement_text,
                    row.evidence_ref,
                    row.status,
                    row.ism_ids,
                )
            )
            + " |"
        )
    if built.maturity:
        lines.extend(["", built.maturity])
    if built.phase_lines:
        lines.append("")
        lines.extend(built.phase_lines)
    lines.extend(["", "## Findings", ""])
    if not built.rows:
        lines.append("No rows.")
        lines.append("")
    for row in built.rows:
        lines.extend(
            [
                f"### {row.strategy_or_domain}",
                "",
                f"Requirement id: {row.requirement_id}",
                f"Requirement text: {row.requirement_text}",
                f"Evidence ref: {row.evidence_ref or 'none'}",
                f"Status: {row.status}",
                f"ISM ids: {row.ism_ids or 'none'}",
                row.notes or "No note.",
            ]
        )
        if row.evidence_text:
            label = f"Evidence {row.evidence_ref}" if row.evidence_ref else "Evidence"
            lines.append(f"{label}: {row.evidence_text}")
        elif row.status == "unknown":
            lines.append("Evidence: none")
        lines.extend(row.citations)
        lines.append("")
    if built.extras:
        lines.extend(built.extras)
        lines.append("")
    lines.extend(["## Gaps by priority", ""])
    lines.extend(_gaps(built))
    lines.extend(["", "## Next 90 days", "", _proposal(built), ""])
    if not as_of:
        lines.append("Retrieval date: missing")
        lines.append("")
    return "\n".join(lines)


def _gaps(built: Built) -> list[str]:
    sources = "; ".join(built.missing_sources) if built.missing_sources else "none"
    controls = (
        ", ".join(dict.fromkeys(built.missing_controls))
        if built.missing_controls
        else "none"
    )
    unknown = [row.strategy_or_domain for row in built.rows if row.status == "unknown"]
    unscored = [
        row.evidence_ref
        for row in built.rows
        if row.status == "missing" and row.evidence_ref
    ]
    return [
        f"1. Missing sources: {sources}.",
        f"2. Missing controls: {controls}.",
        "3. Unknown evidence: " + (", ".join(unknown) if unknown else "none") + ".",
        "4. Unscored evidence: " + (", ".join(unscored) if unscored else "none") + ".",
    ]


def _proposal(built: Built) -> str:
    open_row = any(row.status != "met" for row in built.rows)
    if built.missing_sources or built.missing_controls or open_row or not built.rows:
        return PROPOSAL_GAP
    return PROPOSAL_CLEAR


def _cell(value: str) -> str:
    return value.replace("|", "/").replace("\n", " ")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="render_assessment")
    parser.add_argument("document", type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)
    try:
        loaded = json.loads(args.document.read_text(encoding="utf-8"))
        report = render(loaded)
    except (OSError, json.JSONDecodeError, ValueError, TypeError) as exc:
        print(f"Assessment input error: {exc}", file=sys.stderr)
        return 2
    sys.stdout.write(report.markdown)
    if args.out:
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / "assessment.csv").write_text(report.csv, encoding="utf-8")
        (args.out / "assessment.md").write_text(report.markdown, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
