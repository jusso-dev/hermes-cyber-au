"""Command line for the pack. Installing cron or the persona requires an explicit flag."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .common import hermes_home, sydney_now
from .doctor import doctor
from .evalscore import build_questions, score, write_questions
from .gates import answer_gate, open_response_gate
from .live import status as live_status
from .osint import status as osint_status
from .querycheck import check_query
from .refresh import refresh


def _print(payload: dict) -> None:
    json.dump(payload, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")


def persona_text() -> str:
    path = Path(__file__).resolve().parents[1] / "persona" / "SOUL.md"
    return path.read_text(encoding="utf-8")


def apply_persona(soul_path: Path) -> dict:
    block = persona_text().strip() + "\n"
    start = "<!-- hermes-cyber-au:start -->"
    end = "<!-- hermes-cyber-au:end -->"
    existing = soul_path.read_text(encoding="utf-8") if soul_path.exists() else ""
    if start in existing and end in existing:
        head, rest = existing.split(start, 1)
        _, tail = rest.split(end, 1)
        updated = f"{head}{block}{tail.lstrip()}"
    else:
        updated = existing.rstrip() + ("\n\n" if existing.strip() else "") + block
    soul_path.parent.mkdir(parents=True, exist_ok=True)
    soul_path.write_text(updated, encoding="utf-8")
    return {"applied": True, "path": str(soul_path)}


def cron_snippet() -> str:
    return (
        "0 6 * * * TZ=Australia/Sydney hermes-cyber-au refresh\n"
        "# Hermes cron, only if you want it on this machine:\n"
        "# copy scripts/cyber_au_refresh.py to ~/.hermes/scripts/cyber_au_refresh.py\n"
        "# hermes cron create '0 6 * * *' --name cyber-au-refresh --script cyber_au_refresh.py --no-agent\n"
        "# The script stays silent unless the Australia/Sydney hour is 6.\n"
    )


def dispatch_namespace(args) -> int:
    command = getattr(args, "cyber_au_command", None) or getattr(args, "cmd", None)
    if command == "doctor":
        _print(doctor())
        return 0
    if command == "refresh":
        result = refresh(apply_pin=bool(getattr(args, "apply_pin", False)))
        public = {key: result[key] for key in ("baseline", "material", "ism", "failures", "sources", "chunks", "stale_skills", "strategies_verified", "eval_questions")}
        if result.get("baseline"):
            questions = build_questions()
            write_questions(questions)
            public["eval"] = score()
        elif result.get("material"):
            public["eval"] = score()
        if result.get("material") or result.get("baseline"):
            _print(public)
        elif getattr(args, "verbose", False):
            _print(public)
        eval_report = public.get("eval")
        if eval_report and (eval_report.get("invented_control_ids") or eval_report.get("failed")):
            return 1
        return 0
    if command == "eval":
        report = score()
        _print(report)
        if report.get("questions", 0) < 100 or report.get("invented_control_ids") or report.get("failed"):
            return 1
        return 0
    if command == "search":
        from .plugin import tool_search

        sys.stdout.write(tool_search({"query": args.query}) + "\n")
        return 0
    if command == "control":
        from .plugin import tool_control

        sys.stdout.write(tool_control({"control_id": args.control_id, "as_of": args.as_of}) + "\n")
        return 0
    if command == "check-query":
        _print(check_query(args.language, args.query))
        return 0
    if command == "persona":
        if getattr(args, "apply", False):
            _print(apply_persona(hermes_home() / "SOUL.md"))
        else:
            sys.stdout.write(persona_text())
        return 0
    if command == "install-cron":
        if getattr(args, "apply", False):
            target = hermes_home() / "scripts" / "cyber-au-cron.txt"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(cron_snippet(), encoding="utf-8")
            _print({"applied": True, "path": str(target), "registered_with_hermes": False, "sydney_hour": sydney_now().hour})
        else:
            sys.stdout.write(cron_snippet())
        return 0
    if command == "gate":
        _print(open_response_gate("response", "operator", args.proposal))
        return 0
    if command == "approve":
        try:
            _print(answer_gate(args.gate_id, args.choice, args.actor))
        except ValueError as exc:
            _print({"ok": False, "error": str(exc), "executed": False})
            return 1
        return 0
    if command == "status":
        _print({"live": live_status(), "osint": osint_status()})
        return 0
    return 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="hermes-cyber-au")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("doctor")
    refresh_parser = sub.add_parser("refresh")
    refresh_parser.add_argument("--apply-pin", action="store_true")
    refresh_parser.add_argument("--verbose", action="store_true")
    sub.add_parser("eval")
    search = sub.add_parser("search")
    search.add_argument("query")
    control = sub.add_parser("control")
    control.add_argument("control_id")
    control.add_argument("--as-of", default="")
    check = sub.add_parser("check-query")
    check.add_argument("language")
    check.add_argument("query")
    persona = sub.add_parser("persona")
    persona.add_argument("--apply", action="store_true")
    cron = sub.add_parser("install-cron")
    cron.add_argument("--apply", action="store_true")
    gate = sub.add_parser("gate")
    gate.add_argument("proposal")
    approve = sub.add_parser("approve")
    approve.add_argument("gate_id")
    approve.add_argument("choice")
    approve.add_argument("--actor", required=True)
    sub.add_parser("status")
    args = parser.parse_args(argv)
    return dispatch_namespace(args)


if __name__ == "__main__":
    raise SystemExit(main())
