"""Global Search remaining count and the user's floor. No secrets are stored."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from cyberau_premium.budget import SYDNEY
from cyberau_premium.catalog import vendor_config
from cyberau_premium.paths import data_dir

_FILE = "flare-quota.json"


def _path():
    return data_dir() / _FILE


def load_quota() -> dict:
    path = _path()
    if not path.is_file():
        return {"remaining": None, "recorded_at": None, "by_day": {}}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"remaining": None, "recorded_at": None, "by_day": {}}
    if not isinstance(payload, dict):
        return {"remaining": None, "recorded_at": None, "by_day": {}}
    by_day = payload.get("by_day")
    if not isinstance(by_day, dict):
        by_day = {}
    remaining = payload.get("remaining")
    if isinstance(remaining, bool) or not isinstance(remaining, int):
        remaining = None
    recorded = payload.get("recorded_at")
    if not isinstance(recorded, str):
        recorded = None
    return {"remaining": remaining, "recorded_at": recorded, "by_day": by_day}


def _write(state: dict) -> None:
    path = _path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, separators=(",", ":")), encoding="utf-8")


def record_global_search(remaining: int | None, *, now: datetime | None = None) -> None:
    """Remember one Global Search and, when the header parsed, how many remain."""
    moment = now or datetime.now(UTC)
    state = load_quota()
    day = moment.astimezone(SYDNEY).date().isoformat()
    by_day = state["by_day"]
    by_day[day] = int(by_day.get(day) or 0) + 1
    if remaining is not None:
        state["remaining"] = remaining
        state["recorded_at"] = moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    _write(state)


def searches_today(now: datetime | None = None) -> int:
    moment = now or datetime.now(UTC)
    day = moment.astimezone(SYDNEY).date().isoformat()
    value = load_quota()["by_day"].get(day) or 0
    return int(value) if isinstance(value, int) else 0


def quota_view(now: datetime | None = None) -> dict:
    state = load_quota()
    return {
        "remaining": state["remaining"],
        "recorded_at": state["recorded_at"],
        "global_searches_today": searches_today(now),
    }


def _whole(value) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def global_search_decision(
    config: dict | None,
    *,
    approved: bool = False,
    now: datetime | None = None,
) -> dict | None:
    """Block under the user's floor, or ask above the daily count. None means allow.

    The floor is a hard stop. Approval does not bypass it. The daily count asks
    once; an approved call may proceed when the floor is clear.
    """
    block = vendor_config(config, "flare")
    floor = _whole(block.get("global_search_floor"))
    daily = _whole(block.get("global_searches_per_day"))
    state = load_quota()
    remaining = state["remaining"]
    if floor is not None and remaining is not None and remaining < floor:
        return {
            "decision": "block",
            "block": True,
            "needs_approval": False,
            "message": (
                f"Blocked flare: global searches remaining {remaining} is below the floor {floor}."
            ),
        }
    used = searches_today(now)
    if daily is not None and used >= daily and not approved:
        return {
            "decision": "ask",
            "block": False,
            "needs_approval": True,
            "message": (
                f"Approval required for flare: global searches today {used} "
                f"is above the daily threshold {daily}."
            ),
        }
    return None
