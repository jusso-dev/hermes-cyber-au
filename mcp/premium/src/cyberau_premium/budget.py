"""Quota and cost ledger. Months are Australia/Sydney."""

from __future__ import annotations

import logging
import sqlite3
from collections.abc import Callable
from datetime import datetime
from typing import Literal
from zoneinfo import ZoneInfo

from pydantic import BaseModel, ConfigDict

from cyberau_premium.base import QuotaPolicy
from cyberau_premium.paths import data_dir

SYDNEY = ZoneInfo("Australia/Sydney")
LOGGER = logging.getLogger("cyberau.premium")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS premium_ledger (
    vendor TEXT NOT NULL,
    day TEXT NOT NULL,
    month TEXT NOT NULL,
    calls INTEGER NOT NULL,
    cost_units REAL NOT NULL,
    routine INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (vendor, day, routine)
);
CREATE TABLE IF NOT EXISTS premium_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vendor TEXT NOT NULL,
    at TEXT NOT NULL,
    decision TEXT NOT NULL,
    reason TEXT NOT NULL
);
"""


class BudgetSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    quota: QuotaPolicy
    max_pages: int = 5
    routine_share: float = 0.5


class Usage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    calls_today: int
    calls_month: int
    cost_month: float
    routine_calls_today: int
    routine_calls_month: int
    routine_cost_month: float


class Decision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: Literal["allow", "block", "ask"]
    message: str
    limit: str | None = None


def sydney_keys(now: datetime) -> tuple[str, str]:
    zoned = now.astimezone(SYDNEY)
    return zoned.date().isoformat(), zoned.strftime("%Y-%m")


def _scaled_int(limit: int | None, share: float, routine: bool) -> int | None:
    if limit is None:
        return None
    if not routine:
        return limit
    return int(limit * share)


def _scaled_float(limit: float | None, share: float, routine: bool) -> float | None:
    if limit is None:
        return None
    if not routine:
        return limit
    return limit * share


class BudgetLedger:
    def __init__(self, path=None, *, now: Callable[[], datetime] | None = None):
        self.path = path or (data_dir() / "premium-ledger.sqlite")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._now = now or datetime.now
        with self._connect() as conn:
            conn.executescript(_SCHEMA)

    def usage(self, vendor: str, *, now: datetime | None = None) -> Usage:
        moment = now or self._now()
        day, month = sydney_keys(moment)
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT day, calls, cost_units, routine
                FROM premium_ledger
                WHERE vendor = ? AND month = ?
                """,
                (vendor, month),
            ).fetchall()
        calls_today = calls_month = routine_today = routine_month = 0
        cost_month = routine_cost = 0.0
        for row_day, calls, cost, routine in rows:
            calls_month += calls
            cost_month += cost
            if routine:
                routine_month += calls
                routine_cost += cost
            if row_day == day:
                calls_today += calls
                if routine:
                    routine_today += calls
        return Usage(
            calls_today=calls_today,
            calls_month=calls_month,
            cost_month=cost_month,
            routine_calls_today=routine_today,
            routine_calls_month=routine_month,
            routine_cost_month=routine_cost,
        )

    def gate(
        self,
        vendor: str,
        settings: BudgetSettings,
        *,
        routine: bool = False,
        approved: bool = False,
        now: datetime | None = None,
    ) -> Decision:
        decision = self.assess(
            vendor,
            settings,
            routine=routine,
            approved=approved,
            now=now,
        )
        if decision.decision == "allow":
            self.commit(vendor, settings.quota.cost_units_per_call, routine=routine, now=now)
        else:
            self.log(vendor, decision.decision, decision.message, now=now)
            if decision.decision == "block":
                LOGGER.warning("%s", decision.message)
        return decision

    def assess(
        self,
        vendor: str,
        settings: BudgetSettings,
        *,
        routine: bool = False,
        approved: bool = False,
        now: datetime | None = None,
    ) -> Decision:
        quota = settings.quota
        usage = self.usage(vendor, now=now)
        cost = quota.cost_units_per_call
        share = settings.routine_share
        tripped = _first_limit(usage, quota, cost, share, routine)
        if tripped is not None:
            name, value = tripped
            if quota.hard_stop:
                return Decision(
                    decision="block",
                    message=_block_message(vendor, name, value, routine=routine, share=share),
                    limit=name,
                )
            message = (
                f"{vendor} is over {name} limit {value}, and hard_stop is off. The call is allowed."
            )
            LOGGER.warning("%s", message)
        if (
            quota.approval_above_units is not None
            and cost > quota.approval_above_units
            and not approved
        ):
            return Decision(
                decision="ask",
                message=(
                    f"Approval required for {vendor}: cost {cost} is above "
                    f"approval_above_units {quota.approval_above_units}."
                ),
                limit="approval_above_units",
            )
        return Decision(decision="allow", message="")

    def commit(
        self,
        vendor: str,
        cost_units: float,
        *,
        routine: bool = False,
        now: datetime | None = None,
    ) -> None:
        moment = now or self._now()
        day, month = sydney_keys(moment)
        flag = 1 if routine else 0
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO premium_ledger (vendor, day, month, calls, cost_units, routine)
                VALUES (?, ?, ?, 1, ?, ?)
                ON CONFLICT(vendor, day, routine) DO UPDATE SET
                    calls = calls + 1,
                    cost_units = cost_units + excluded.cost_units
                """,
                (vendor, day, month, cost_units, flag),
            )

    def log(self, vendor: str, decision: str, reason: str, *, now: datetime | None = None) -> None:
        moment = now or self._now()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO premium_events (vendor, at, decision, reason)
                VALUES (?, ?, ?, ?)
                """,
                (vendor, moment.isoformat(), decision, reason),
            )

    def events(self, vendor: str) -> list[tuple[str, str]]:
        with self._connect() as conn:
            return conn.execute(
                "SELECT decision, reason FROM premium_events WHERE vendor = ? ORDER BY id",
                (vendor,),
            ).fetchall()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=5)


def _first_limit(
    usage: Usage,
    quota: QuotaPolicy,
    cost: float,
    share: float,
    routine: bool,
) -> tuple[str, int | float] | None:
    day_limit = _scaled_int(quota.calls_per_day, share, routine)
    day_used = usage.routine_calls_today if routine else usage.calls_today
    if routine and quota.calls_per_day is not None and usage.calls_today + 1 > quota.calls_per_day:
        return ("calls_per_day", quota.calls_per_day)
    if day_limit is not None and day_used + 1 > day_limit:
        return ("calls_per_day", day_limit)

    month_limit = _scaled_int(quota.calls_per_month, share, routine)
    month_used = usage.routine_calls_month if routine else usage.calls_month
    if (
        routine
        and quota.calls_per_month is not None
        and usage.calls_month + 1 > quota.calls_per_month
    ):
        return ("calls_per_month", quota.calls_per_month)
    if month_limit is not None and month_used + 1 > month_limit:
        return ("calls_per_month", month_limit)

    budget_limit = _scaled_float(quota.monthly_budget_units, share, routine)
    cost_used = usage.routine_cost_month if routine else usage.cost_month
    if (
        routine
        and quota.monthly_budget_units is not None
        and usage.cost_month + cost > quota.monthly_budget_units + 1e-9
    ):
        return ("monthly_budget_units", quota.monthly_budget_units)
    if budget_limit is not None and cost_used + cost > budget_limit + 1e-9:
        return ("monthly_budget_units", budget_limit)
    return None


def _block_message(
    vendor: str,
    limit: str,
    value: int | float,
    *,
    routine: bool,
    share: float,
) -> str:
    shown = int(value) if isinstance(value, float) and value.is_integer() else value
    if routine:
        percent = int(share * 100)
        return f"Blocked {vendor}: {limit} limit is {shown} (routine share {percent}%)."
    return f"Blocked {vendor}: {limit} limit is {shown}."
