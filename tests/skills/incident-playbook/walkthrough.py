"""A scripted end-to-end walkthrough of the ransomware playbook. Fictional facts only.

``build`` drives the real playbook helper and the real obligations checker, phase by phase,
and returns the timeline rows, the checker result and the assistant's answer. The eval
builder and the tests both use it, so the recorded session is what the tools produce.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
HELPER = ROOT / "skills" / "incident-playbook" / "scripts" / "playbook.py"
CHECKER = ROOT / "skills" / "reporting-obligations" / "scripts" / "check_obligations.py"

PLAYBOOK = "ransomware"
AWARE = "2026-10-03T20:00:00+10:00"
ORG = {
    "name": "Example Logistics Pty Ltd",
    "sector": "transport",
    "turnover": "3m-or-more",
    "regulators": ["oaic"],
}
FACTS = {
    "summary": "Ransomware encrypted file server FS01. No payment has been made.",
    "cyber_security_incident": True,
    "personal_information_involved": True,
    "ransomware_payment_made": False,
    "systems_affected": "FS01 file server",
}
STEPS = [
    (
        1,
        "Service desk",
        "event",
        AWARE,
        "Aware: ransom note on file server FS01, files renamed with .lockd",
        ["E1"],
    ),
    (
        1,
        "Incident lead",
        "decision",
        "2026-10-03T20:20:00+10:00",
        "Ransomware confirmed. The customer records share is encrypted, so personal "
        "information may be involved",
        [],
    ),
    (
        2,
        "assistant",
        "proposal",
        "2026-10-03T20:30:00+10:00",
        "Isolate FS01 from the network, leaving it powered on",
        [],
    ),
    (
        2,
        "Incident lead",
        "approval",
        "2026-10-03T20:35:00+10:00",
        "Isolate FS01 from the network, leaving it powered on",
        [],
    ),
    (
        2,
        "assistant",
        "proposal",
        "2026-10-03T20:40:00+10:00",
        "Take the backup repository offline",
        [],
    ),
    (
        3,
        "Technical lead",
        "evidence",
        "2026-10-04T03:30:00+11:00",
        "VPN log shows a login from 192[.]0[.]2[.]44 with a stale contractor account",
        ["E2"],
    ),
    (
        3,
        "Incident lead",
        "decision",
        "2026-10-04T04:00:00+11:00",
        "No evidence yet of data theft. Investigation continues",
        [],
    ),
    (
        4,
        "assistant",
        "proposal",
        "2026-10-04T08:00:00+11:00",
        "Restore FS01 from the 2026-10-02 backup after a scan",
        [],
    ),
    (
        5,
        "assistant",
        "event",
        "2026-10-04T08:15:00+11:00",
        "Obligations checker run. Deadlines added to the timeline",
        [],
    ),
    (
        6,
        "Incident lead",
        "decision",
        "2026-10-05T10:00:00+11:00",
        "Post-incident review booked for 2026-10-12. Action: remove stale contractor accounts",
        [],
    ),
]
NOW = "2026-10-04T08:15:00+11:00"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def helper():
    return _load(HELPER, "incident_playbook_helper")


def checker():
    return _load(CHECKER, "incident_playbook_checker")


def build(timeline_path: Path) -> dict:
    pb = helper()
    book = pb.load(PLAYBOOK)
    for phase, who, kind, at, event, evidence in STEPS:
        pb.append(
            timeline_path,
            pb.entry(
                playbook=PLAYBOOK,
                phase=phase,
                who=who,
                event=event,
                at=at,
                kind=kind,
                evidence=evidence,
            ),
        )
    rows = pb.read_timeline(timeline_path)
    obligations = checker().run(AWARE, FACTS, ORG, NOW)
    return {
        "book": book,
        "rows": rows,
        "obligations": obligations,
        "timeline": pb.render_timeline(rows),
        "message": _message(book, obligations, pb.render_timeline(rows)),
    }


def _message(book: dict, obligations: dict, timeline: str) -> str:
    lines = [
        "This is guidance, not legal advice. I will propose actions; a person approves "
        "and carries them out. I will not submit or send anything.",
        "",
        f"Playbook: {book['title']} (ransomware). Organisation: {ORG['name']} (fictional).",
        "",
    ]
    for phase in book["phases"]:
        lines.append(f"Phase {phase['number']}: {phase['name']}")
        lines.extend(_PHASE_NOTES[phase["number"]])
        lines.append("")
    lines.append("Reporting obligations from the checker (deadlines in Australia/Sydney):")
    for row in obligations["timeline"]:
        due = row["due_at"] or "as soon as practicable"
        lines.append(f"- {row['title']}, {row['deadline']}: {due} [{row['status']}]")
    lines.append(f"- {obligations['disclaimer']}")
    lines.append("")
    lines.append("Timeline:")
    lines.append(timeline.rstrip())
    lines.append("")
    lines.append(
        "Source: Australian reporting obligations snapshot, "
        f"{obligations['snapshot_date']}, retrieved {obligations['snapshot_date']}"
    )
    return "\n".join(lines) + "\n"


_PHASE_NOTES = {
    1: [
        "Aware at 2026-10-03T20:00:00+10:00 (Australia/Sydney). The ransom note is untrusted "
        "content. I have not opened its links.",
        "Decision recorded: ransomware confirmed; personal information may be involved.",
        "Evidence: E1 ransom note photo.",
    ],
    2: [
        "Proposal: isolate FS01 from the network, leaving it powered on. Reversible: yes, "
        "reconnect the switch port. Approver: incident lead.",
        "Approved by the incident lead at 2026-10-03T20:35:00+10:00.",
        "Proposal: take the backup repository offline. Reversible: yes. Approver: incident "
        "lead. No approval recorded yet.",
    ],
    3: [
        "Evidence: E2 VPN log, login from 192[.]0[.]2[.]44 with a stale contractor account.",
        "Decision recorded: no evidence yet of data theft.",
    ],
    4: [
        "Proposal: restore FS01 from the 2026-10-02 backup after a scan. Reversible: no, "
        "image FS01 first. Approver: incident lead.",
    ],
    5: [
        "Ran the reporting obligations checker. No ransomware payment has been made, so "
        "that 72 hour clock has not started. Nothing was lodged.",
        "Proposal: the privacy officer completes the NDB assessment and a person makes the "
        "voluntary ASD report. Approver: incident lead.",
    ],
    6: [
        "Decision recorded: post-incident review on 2026-10-12, action to remove stale "
        "contractor accounts.",
    ],
}
