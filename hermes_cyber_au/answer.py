"""Deterministic answers from the ingested corpus.

This is the retriever the eval scores. It is not a language model.
Unknown control IDs produce "I don't know." Nearby IDs are not suggested.
"""

from __future__ import annotations

from .common import extract_control_ids, normalise_control_id
from .corpus import Corpus, load_corpus
from .querycheck import check_query

UNKNOWN = "I don't know."


def _cite(chunk: dict) -> str:
    version = chunk.get("version") or "unspecified"
    published = chunk.get("published") or "unspecified"
    retrieved = chunk.get("retrieved_at") or ""
    when = f"published {published}" if published else f"retrieved {retrieved}; the source did not state a published date"
    lines = [
        chunk.get("text") or "",
        "",
        f"Source: {chunk.get('publisher') or chunk.get('source_id')}, version {version}, {when}.",
        f"URL: {chunk.get('url') or ''}",
        "Evidence class: prepared_not_observed. Catalogue text is not an observation of a live system.",
    ]
    if chunk.get("instruction_like"):
        lines.append("The source text matched an instruction-like pattern. It was not followed.")
    return "\n".join(lines).strip()


def _legend_line(corpus: Corpus, code: str, version: str) -> str:
    header = corpus.headers.get("asd-ism-oscal") or {}
    for item in header.get("versions") or []:
        if item.get("version") != version:
            continue
        legend = (item.get("applicability_legend") or {}).get(code) or {}
        if legend.get("verified") == "exact" and legend.get("label"):
            return f"{code} ({legend['label']})"
    return code


def answer_control(corpus: Corpus, control_id: str, *, as_of: str | None = None) -> str:
    canonical = normalise_control_id(control_id)
    if not canonical.startswith("ism-"):
        return UNKNOWN
    hits = corpus.by_control(canonical, as_of=as_of)
    if not hits:
        if as_of:
            return f"{UNKNOWN} No ingested ISM snapshot covers {as_of}."
        return UNKNOWN
    chunk = hits[-1]
    codes = chunk.get("applicability") or []
    rendered = ", ".join(_legend_line(corpus, code, str(chunk.get("version") or "")) for code in codes) or "none stored"
    e8 = ", ".join(chunk.get("essential_eight") or []) or "none stored"
    return (
        f"{canonical}: {_cite(chunk)}\n"
        f"Applicability: {rendered}.\n"
        f"Essential Eight marks stored on the control: {e8}."
    )


def answer_applicability(corpus: Corpus, control_id: str) -> str:
    canonical = normalise_control_id(control_id)
    hits = corpus.by_control(canonical)
    if not hits:
        return UNKNOWN
    chunk = hits[-1]
    codes = chunk.get("applicability") or []
    raw = ", ".join(codes) if codes else "none stored"
    version = chunk.get("version") or "unspecified"
    published = chunk.get("published") or "unspecified"
    return (
        f"{canonical} applicability in version {version}, published {published}: {raw}.\n"
        f"URL: {chunk.get('url') or ''}\n"
        "Evidence class: prepared_not_observed."
    )


def answer_e8(corpus: Corpus, control_id: str) -> str:
    canonical = normalise_control_id(control_id)
    hits = corpus.by_control(canonical)
    if not hits:
        return UNKNOWN
    chunk = hits[-1]
    marks = chunk.get("essential_eight") or []
    shown = ", ".join(marks) if marks else "none"
    version = chunk.get("version") or "unspecified"
    published = chunk.get("published") or "unspecified"
    return (
        f"{canonical} Essential Eight marks in version {version}, published {published}: {shown}.\n"
        f"URL: {chunk.get('url') or ''}\n"
        "Evidence class: prepared_not_observed. Marks on a control are not a maturity score."
    )


def answer_unknown() -> str:
    return f"{UNKNOWN} That control ID is not in the ingested ISM catalogues."


def answer_nist_trap() -> str:
    return (
        f"{UNKNOWN} The default framework for this pack is the Australian ISM and the Essential Eight. "
        "Ask for a NIST mapping if you want one. I will not guess a control ID."
    )


def answer_query(language: str, query: str) -> str:
    checked = check_query(language, query)
    if checked.get("ready"):
        return f"ready\n{query}\nChecker: {checked['language']} passed offline syntax and schema checks."
    errors = "; ".join(checked.get("errors") or ["not ready"])
    return f"not ready\n{errors}"


def answer_question(question: dict, corpus: Corpus | None = None) -> str:
    corpus = corpus if corpus is not None else load_corpus()
    kind = question.get("kind")
    if kind == "control_lookup":
        return answer_control(corpus, question["control_id"])
    if kind == "applicability":
        return answer_applicability(corpus, question["control_id"])
    if kind == "essential_eight":
        return answer_e8(corpus, question["control_id"])
    if kind == "as_of":
        return answer_control(corpus, question["control_id"], as_of=question.get("as_of"))
    if kind == "unknown_id":
        return answer_unknown()
    if kind == "nist_trap":
        return answer_nist_trap()
    if kind == "query_check":
        return answer_query(question.get("language") or "", question.get("query") or "")
    if kind == "corpus_quote":
        chunk_id = question.get("chunk_id")
        for chunk in corpus.chunks:
            if chunk.get("chunk_id") == chunk_id:
                return _cite(chunk)
        return UNKNOWN
    return UNKNOWN


def invented_ids(answer: str, question: str, catalogue_ids: set[str]) -> list[str]:
    """A control ID is invented when the answer uses one the catalogue does not contain.

    An ID that is already in the question is not counted here. Unknown-ID
    questions still forbid restating that ID via the scorer.
    """
    asked = set(extract_control_ids(question))
    found = []
    for control_id in extract_control_ids(answer):
        if control_id in catalogue_ids or control_id in asked:
            continue
        if control_id not in found:
            found.append(control_id)
    return found
