"""Build and score source-backed questions.

The scored answerer is the deterministic retriever in answer.py.
A language model is not scored by this script.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from .answer import answer_question, invented_ids
from .common import extract_control_ids, repo_root
from .corpus import Corpus, load_corpus
from .querycheck import check_query

QUESTIONS = "eval/questions.jsonl"


def questions_path(root: Path | None = None) -> Path:
    return (root or repo_root()) / QUESTIONS


def _phrase(text: str) -> str:
    raw = (text or "").strip()
    if len(raw) <= 160:
        return raw
    cut = raw[:160]
    if " " in cut:
        cut = cut.rsplit(" ", 1)[0]
    return cut


def _question(row: dict) -> dict:
    row.setdefault("expected_ids", [])
    row.setdefault("forbid_ids", [])
    return row


def build_questions(corpus: Corpus | None = None) -> list[dict]:
    corpus = corpus if corpus is not None else load_corpus()
    current = [
        chunk
        for chunk in corpus.current_ism()
        if re.fullmatch(r"ism-\d+", chunk.get("control_id") or "")
    ]
    current.sort(key=lambda chunk: int(chunk["control_id"].split("-")[1]))
    if not current:
        return []
    catalogue = corpus.catalogue_ids()
    version = current[-1]["version"]
    questions: list[dict] = []

    step = max(1, len(current) // 50)
    for index, chunk in enumerate(current[::step][:50]):
        ids = [chunk["control_id"]]
        for extra in extract_control_ids(chunk.get("text") or ""):
            if extra not in ids:
                ids.append(extra)
        questions.append(
            _question(
                {
                    "id": f"ism-lookup-{index:03d}",
                    "kind": "control_lookup",
                    "control_id": chunk["control_id"],
                    "question": (
                        f"What does ISM control {chunk['control_id']} require in version {version}? "
                        "Cite the version, published date and URL. If it is not in the catalogue, say you do not know."
                    ),
                    "expected_ids": ids,
                    "version": chunk["version"],
                    "url_fragment": "cyber.gov.au/ism",
                    "must_include": _phrase(chunk.get("text") or ""),
                }
            )
        )

    applicable = [chunk for chunk in current if chunk.get("applicability")][:15]
    for index, chunk in enumerate(applicable):
        questions.append(
            _question(
                {
                    "id": f"ism-applicability-{index:03d}",
                    "kind": "applicability",
                    "control_id": chunk["control_id"],
                    "question": f"Which applicability codes does {chunk['control_id']} carry in ISM {chunk['version']}?",
                    "expected_ids": [chunk["control_id"]],
                    "version": chunk["version"],
                    "url_fragment": "cyber.gov.au/ism",
                    "must_include": ": " + ", ".join(chunk["applicability"]) + ".",
                }
            )
        )

    marked = [chunk for chunk in current if chunk.get("essential_eight")]
    unmarked = [chunk for chunk in current if not chunk.get("essential_eight")]
    e8_sample = marked[:8] + unmarked[:7]
    for index, chunk in enumerate(e8_sample):
        marks = chunk.get("essential_eight") or []
        questions.append(
            _question(
                {
                    "id": f"e8-mark-{index:03d}",
                    "kind": "essential_eight",
                    "control_id": chunk["control_id"],
                    "question": (
                        f"Which Essential Eight maturity marks does the ISM store on {chunk['control_id']} "
                        f"in version {chunk['version']}? Say none if there are none. Do not give a maturity score."
                    ),
                    "expected_ids": [chunk["control_id"]],
                    "version": chunk["version"],
                    "url_fragment": "cyber.gov.au/ism",
                    "must_include": ": " + (", ".join(marks) if marks else "none") + ".",
                }
            )
        )

    june_versions = sorted(
        {
            chunk["version"]
            for chunk in corpus.chunks
            if chunk.get("source_id") == "asd-ism-oscal" and chunk.get("valid_to") and chunk.get("version") != version
        }
    )
    if june_versions:
        june = june_versions[0]
        june_chunks = {chunk["control_id"]: chunk for chunk in corpus.ism_version(june)}
        shared = [chunk for chunk in current if chunk["control_id"] in june_chunks][:10]
        for index, chunk in enumerate(shared):
            older = june_chunks[chunk["control_id"]]
            as_of = older.get("valid_from") or ""
            ids = [older["control_id"]]
            for extra in extract_control_ids(older.get("text") or ""):
                if extra not in ids:
                    ids.append(extra)
            questions.append(
                _question(
                    {
                        "id": f"ism-june-{index:03d}",
                        "kind": "as_of",
                        "control_id": older["control_id"],
                        "as_of": as_of,
                        "question": (
                            f"What did ISM control {older['control_id']} say as of {as_of}? "
                            "Cite that snapshot's version and URL."
                        ),
                        "expected_ids": ids,
                        "version": older["version"],
                        "url_fragment": "cyber.gov.au/ism",
                        "must_include": _phrase(older.get("text") or ""),
                    }
                )
            )

    absent = []
    for number in (99999, 99998, 99997, 88888, 77777, 31415, 10101, 4242):
        control_id = f"ism-{number}"
        if control_id not in catalogue:
            absent.append(control_id)
        if len(absent) == 8:
            break
    for index, control_id in enumerate(absent):
        questions.append(
            _question(
                {
                    "id": f"unknown-{index:03d}",
                    "kind": "unknown_id",
                    "question": f"What does control {control_id} require? Cite the ISM if you can.",
                    "must_say_unknown": True,
                    "forbid_ids": [control_id],
                    "forbid_any_catalogue_id": True,
                }
            )
        )

    traps = [
        "Which NIST SP 800-53 control ID is the Australian default for disabling Internet Explorer?",
        "Give the NIST 800-53 ID that Essential Eight maturity level one maps to.",
        "What is the CIS control ID for the ASD ISM backup rule?",
        "Which ISO 27001 annex control replaces ISM application control?",
        "Name the NIST control that the ISM uses instead of its own control IDs.",
        "What NIST ID should I cite for Australian government patching?",
        "Which CMMC practice ID is the Essential Eight MFA requirement?",
        "Give the NIST 800-171 ID for the current ISM top secret baseline.",
    ]
    for index, text in enumerate(traps):
        questions.append(
            _question(
                {
                    "id": f"nist-trap-{index:03d}",
                    "kind": "nist_trap",
                    "question": text + " If you do not know, say so. Do not guess a control ID.",
                    "must_say_unknown": True,
                    "forbid_any_catalogue_id": True,
                }
            )
        )

    queries = [
        ("kql", "DeviceProcessEvents\n| where FileName =~ \"powershell.exe\"\n| project DeviceName", True),
        ("kql", "SigninLogs\n| where ResultType == \"0\"\n| project ResultType", True),
        ("kql", "DeviceProcessEvents\n| where ProcessCommandLine has \"curl\"\n| project FileName", True),
        ("kql", ".drop table DeviceProcessEvents", False),
        ("kql", "DeviceProcessEvents | where NotARealColumn == 1", False),
        ("kql", "print x=1", False),
        (
            "sql",
            "-- cyber-au-schema: cloudtrail_lake\nSELECT eventname, useridentity.arn FROM events",
            True,
        ),
        (
            "logs_insights",
            "-- cyber-au-schema: cloudtrail_lake\nfields eventname\n| filter eventname like /ConsoleLogin/",
            True,
        ),
        ("sql", "-- cyber-au-schema: cloudtrail_lake\nINSERT INTO t SELECT eventname FROM events", False),
        ("sql", "SELECT eventname FROM events", False),
    ]
    for index, (language, query, expected) in enumerate(queries):
        checked = check_query(language, query)
        if bool(checked["ready"]) != expected:
            raise RuntimeError(f"query fixture {index} expected ready={expected} but got {checked}")
        questions.append(
            _question(
                {
                    "id": f"query-{index:03d}",
                    "kind": "query_check",
                    "language": language,
                    "query": query,
                    "question": f"Is this {language} query ready to run? Check syntax and schema.",
                    "expected_ready": expected,
                }
            )
        )
    return questions


def _current_fields(kind: str, chunk: dict) -> dict:
    if kind == "applicability":
        codes = chunk.get("applicability") or []
        return {
            "version": chunk["version"],
            "url_fragment": "cyber.gov.au/ism",
            "must_include": ": " + ", ".join(codes) + ".",
            "expected_ids": [chunk["control_id"]],
        }
    if kind == "essential_eight":
        marks = chunk.get("essential_eight") or []
        return {
            "version": chunk["version"],
            "url_fragment": "cyber.gov.au/ism",
            "must_include": ": " + (", ".join(marks) if marks else "none") + ".",
            "expected_ids": [chunk["control_id"]],
        }
    ids = [chunk["control_id"]]
    for extra in extract_control_ids(chunk.get("text") or ""):
        if extra not in ids:
            ids.append(extra)
    return {
        "version": chunk["version"],
        "url_fragment": "cyber.gov.au/ism",
        "must_include": _phrase(chunk.get("text") or ""),
        "expected_ids": ids,
    }


def sync_material_questions(
    ism_delta: dict,
    *,
    corpus: Corpus | None = None,
    questions: list[dict] | None = None,
    write: bool = True,
) -> dict:
    """Add or refresh eval rows for new, changed, and withdrawn ISM controls.

    Skill files are not edited. Expected phrases on the eval set are updated
    so the pull request shows the new catalogue text.
    """
    corpus = corpus if corpus is not None else load_corpus()
    if questions is None:
        questions = load_questions()
    current = {
        chunk["control_id"]: chunk
        for chunk in corpus.current_ism()
        if re.fullmatch(r"ism-\d+", chunk.get("control_id") or "")
    }
    added = 0
    updated = 0
    changed = set(ism_delta.get("changed") or [])
    for question in questions:
        control_id = question.get("control_id")
        kind = question.get("kind")
        if control_id not in changed or kind not in {"control_lookup", "applicability", "essential_eight"}:
            continue
        chunk = current.get(control_id)
        if not chunk:
            continue
        if kind == "applicability" and not chunk.get("applicability"):
            continue
        question.update(_current_fields(kind, chunk))
        updated += 1
    seen = {question.get("id") for question in questions}
    for control_id in ism_delta.get("new") or []:
        question_id = f"material-new-{control_id}"
        chunk = current.get(control_id)
        if question_id in seen or not chunk:
            continue
        questions.append(
            _question(
                {
                    "id": question_id,
                    "kind": "control_lookup",
                    "control_id": control_id,
                    "question": (
                        f"What does ISM control {control_id} require in version {chunk['version']}? "
                        "Cite the version, published date and URL. If it is not in the catalogue, say you do not know."
                    ),
                    **_current_fields("control_lookup", chunk),
                }
            )
        )
        seen.add(question_id)
        added += 1
    for control_id in ism_delta.get("withdrawn") or []:
        question_id = f"material-withdrawn-{control_id}"
        if question_id in seen:
            continue
        questions.append(
            _question(
                {
                    "id": question_id,
                    "kind": "unknown_id",
                    "question": (
                        f"What does control {control_id} require in the current ISM? "
                        "Cite the ISM if you can."
                    ),
                    "must_say_unknown": True,
                    "forbid_ids": [control_id],
                    "forbid_any_catalogue_id": True,
                }
            )
        )
        seen.add(question_id)
        added += 1
    if write and (added or updated):
        write_questions(questions)
    return {"added": added, "updated": updated, "questions": len(questions)}


def write_questions(questions: list[dict], root: Path | None = None) -> Path:
    path = questions_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    body = "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in questions)
    path.write_text(body, encoding="utf-8")
    return path


def load_questions(root: Path | None = None) -> list[dict]:
    path = questions_path(root)
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def score_pair(question: dict, answer: str, catalogue_ids: set[str]) -> dict:
    errors: list[str] = []
    invented = invented_ids(answer, question.get("question") or "", catalogue_ids)
    if invented:
        errors.append("invented_control_id")
    answer_ids = extract_control_ids(answer)
    if question.get("must_say_unknown") and not re.search(r"\b(i don't know|i do not know)\b", answer, re.I):
        errors.append("missing_unknown")
    if question.get("forbid_any_catalogue_id"):
        leaked = [control_id for control_id in answer_ids if control_id in catalogue_ids]
        if leaked:
            errors.append("leaked_catalogue_id")
    for forbidden in question.get("forbid_ids") or []:
        if forbidden.lower() in answer.lower():
            errors.append("restated_forbidden")
    for expected in question.get("expected_ids") or []:
        if expected not in answer_ids:
            errors.append(f"missing_id:{expected}")
    if question.get("version") and str(question["version"]) not in answer:
        errors.append("missing_version")
    if question.get("url_fragment") and question["url_fragment"] not in answer:
        errors.append("missing_url")
    if question.get("must_include") and question["must_include"] not in answer:
        errors.append("missing_phrase")
    allowed = set(question.get("expected_ids") or [])
    extra = [control_id for control_id in answer_ids if control_id in catalogue_ids and control_id not in allowed]
    if extra and question.get("kind") not in {"nist_trap", "unknown_id"}:
        errors.append("extra_control_id")
    if "expected_ready" in question:
        lowered = answer.lower()
        if question["expected_ready"]:
            if "not ready" in lowered or not re.search(r"\bready\b", lowered):
                errors.append("not_marked_ready")
        elif "not ready" not in lowered:
            errors.append("wrongly_ready")
    return {"id": question.get("id"), "ok": not errors, "errors": errors, "invented": invented}


def score(corpus: Corpus | None = None, questions: list[dict] | None = None) -> dict:
    corpus = corpus if corpus is not None else load_corpus()
    questions = questions if questions is not None else load_questions()
    catalogue = corpus.catalogue_ids()
    results = []
    for question in questions:
        answer = answer_question(question, corpus)
        results.append(score_pair(question, answer, catalogue))
    invented = sum(len(item["invented"]) for item in results)
    failed = [item for item in results if not item["ok"]]
    return {
        "questions": len(questions),
        "passed": len(questions) - len(failed),
        "failed": len(failed),
        "invented_control_ids": invented,
        "citation_failures": len(failed),
        "failures": failed[:20],
    }
