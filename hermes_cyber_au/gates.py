"""Human approval before any response proposal is released.

When Oh My Hermes is importable, the gate is opened in OMH and this pack does
not answer it. OMH's decision-gate tool accepts only a host-authenticated
connector event, which chat text is not.

When OMH is absent, a local gate is stored under the Hermes home. Approving it
releases the proposal text to the operator. This pack still does not call a
write API. Configured live credentials are read-only, and there is no write
client in this code.
"""

from __future__ import annotations

import json
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .common import data_home, sha256_text


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _path(home: Path | None = None) -> Path:
    root = home or data_home()
    path = root / "gates.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _load(home: Path | None) -> list[dict[str, Any]]:
    path = _path(home)
    if not path.exists():
        return []
    return json.loads(path.read_text(encoding="utf-8"))


def _save(records: list[dict[str, Any]], home: Path | None) -> None:
    _path(home).write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")


def try_omh_open(subject: str) -> dict[str, Any]:
    """Open an OMH gate if the package is installed. Never fake a receipt."""
    try:
        from omh.workflows.decision_gates import build_decision_gate  # type: ignore
    except (ImportError, ModuleNotFoundError):
        return {"omh": "absent"}
    try:
        record = build_decision_gate(
            run_id=f"cyber-au-{secrets.token_hex(4)}",
            subject_class="external_effect",
            subject_ref=subject[:120],
            blocked_transition="executor_dispatch_observed",
            checkpoint_ref=sha256_text(subject)[:16],
            question_code="confirm_external_effect",
            risk_class="costly_to_reverse",
            choices=("approve", "decline", "defer"),
            approver="human",
            safety_profile_revision="hermes-cyber-au",
        )
    except Exception as exc:  # OMH refused the shape. Do not invent a success.
        return {"omh": "present", "opened": False, "reason": type(exc).__name__}
    return {
        "omh": "present",
        "opened": True,
        "gate_id": record.get("gate_id"),
        "note": "Answer this gate through OMH's authenticated connector. Chat text is not approval.",
        "executed": False,
    }


def open_response_gate(action: str, target: str, proposal: str, home: Path | None = None) -> dict[str, Any]:
    omh = try_omh_open(f"{action}:{target}")
    if omh.get("opened"):
        return {
            "status": "open",
            "backend": "omh",
            "executed": False,
            "omh": omh,
            "evidence_class": "prepared_not_observed",
        }
    gate_id = secrets.token_hex(8)
    record = {
        "gate_id": gate_id,
        "status": "open",
        "action": action,
        "target": target,
        "proposal_sha256": sha256_text(proposal),
        "proposal": proposal,
        "opened_at": _now(),
        "choice": "",
        "actor": "",
        "backend": "local_fallback",
        "omh": omh.get("omh", "absent"),
        "executed": False,
    }
    records = _load(home)
    records.append(record)
    _save(records, home)
    public = dict(record)
    public.pop("proposal", None)
    public["evidence_class"] = "prepared_not_observed"
    public["note"] = "Local gate because OMH is not importable. The proposal is withheld until a human approves it."
    return public


def answer_gate(gate_id: str, choice: str, actor: str, home: Path | None = None) -> dict[str, Any]:
    if choice not in {"approve", "decline", "defer"}:
        raise ValueError("choice must be approve, decline or defer")
    if not actor.strip():
        raise ValueError("actor is required")
    records = _load(home)
    for record in records:
        if record["gate_id"] != gate_id:
            continue
        if record["status"] != "open":
            raise ValueError("gate is not open")
        if record.get("backend") == "omh":
            raise ValueError("this gate is owned by OMH; answer it there")
        record["status"] = "answered"
        record["choice"] = choice
        record["actor"] = actor.strip()
        record["decided_at"] = _now()
        _save(records, home)
        released = choice == "approve"
        return {
            "gate_id": gate_id,
            "status": "answered",
            "choice": choice,
            "executed": False,
            "proposal": record["proposal"] if released else "",
            "note": (
                "Approval releases the proposal text only. This pack did not run a write or a response action."
                if released
                else "Proposal stays withheld."
            ),
            "evidence_class": "prepared_not_observed",
        }
    raise ValueError("unknown gate")
