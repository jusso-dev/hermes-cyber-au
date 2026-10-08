"""Read-only health check. This does not edit SOUL.md, cron, or Hermes config."""

from __future__ import annotations

import importlib.util
from typing import Any

from . import __version__
from .common import repo_root, sha256_text
from .corpus import load_corpus
from .evalscore import load_questions, score
from .live import status as live_status
from .osint import status as osint_status


def _omh() -> str:
    if importlib.util.find_spec("omh") is None:
        return "absent"
    try:
        importlib.import_module("omh.workflows.source_trust")
        importlib.import_module("omh.workflows.decision_gates")
    except Exception:
        return "present_but_unusable"
    return "importable"


def doctor() -> dict[str, Any]:
    corpus = load_corpus()
    current = corpus.current_ism()
    versions = sorted({chunk.get("version") or "" for chunk in corpus.chunks if chunk.get("source_id") == "asd-ism-oscal"})
    questions = load_questions()
    eval_report: dict[str, Any]
    if questions and corpus.chunks:
        eval_report = score(corpus, questions)
        eval_report.pop("failures", None)
    else:
        eval_report = {"questions": len(questions), "status": "not_built"}
    allowlist = repo_root() / "knowledge" / "sources.json"
    return {
        "version": __version__,
        "snapshot_chunks": len(corpus.chunks),
        "ism_current_controls": len(current),
        "ism_versions": versions,
        "eval": eval_report,
        "live": live_status(),
        "osint": osint_status(),
        "omh": _omh(),
        "omh_profile_pack": "shipped_not_loaded",
        "write_approval": "recommend skills.write_approval and memory.write_approval; doctor did not change config",
        "cron": "not_installed_by_doctor",
        "persona": "overlay_shipped_not_applied",
        "allowlist_sha256": sha256_text(allowlist.read_text(encoding="utf-8")) if allowlist.exists() else "",
        "guidance": "Guidance only. Not a certification. Not affiliated with ASD.",
    }
