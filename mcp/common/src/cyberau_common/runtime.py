"""What a connector reads from its environment, and the HTTP client built from it.

- ``CYBERAU_DATA_DIR``: where a connector keeps its HTTP cache, rate limiter and local
  stores. The profile sets it. Without it each connector uses its own ``/tmp/cyberau-<name>``.
- ``CYBERAU_EGRESS_ALLOWLIST``: the egress allowlist. The rendered MCP config sets it for
  every server. Without it the ``mcp/egress-allowlist.yaml`` next to the code is used.
- ``CYBERAU_OFFLINE=1``: answer from caches and operator snapshots only.
- ``CYBERAU_TODAY=YYYY-MM-DD``: pin the date, for tests and replays.

Operator snapshots (``CYBERAU_<SOURCE>_SNAPSHOT``) are files the operator supplies. A
connector reads only that file, never data shipped in the repo or the package.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterable
from datetime import UTC, date, datetime, tzinfo
from pathlib import Path

from cyberau_common.cache import HttpCache
from cyberau_common.egress import EgressPolicy
from cyberau_common.http import HttpClient
from cyberau_common.ratelimit import RateLimiter
from cyberau_common.snapshot import parse_day

# mcp/common/src/cyberau_common/runtime.py -> mcp/. Bootstrap installs the workspace
# editable, so this is the profile's mcp/ copy as well as the checkout's.
MCP_DIR = Path(__file__).resolve().parents[3]
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def _env(name: str) -> str:
    return os.environ.get(name, "").strip()


def data_dir(default_name: str, *, mode: int = 0o777) -> Path:
    """The connector's state directory, created if missing."""
    raw = _env("CYBERAU_DATA_DIR")
    path = Path(raw) if raw else Path("/tmp") / f"cyberau-{default_name}"
    path.mkdir(mode=mode, parents=True, exist_ok=True)
    return path


def allowlist_path() -> Path:
    raw = _env("CYBERAU_EGRESS_ALLOWLIST")
    return Path(raw) if raw else MCP_DIR / "egress-allowlist.yaml"


def offline() -> bool:
    return os.environ.get("CYBERAU_OFFLINE") == "1"


def pinned_day() -> date | None:
    """The date in CYBERAU_TODAY, or None when it is unset or not a date."""
    return parse_day(_env("CYBERAU_TODAY"))


def today(tz: tzinfo | None = None) -> date:
    """CYBERAU_TODAY, else the current date in ``tz`` (local time when ``tz`` is None)."""
    return pinned_day() or datetime.now(tz).date()


def load_json(text: str | None):
    """Parsed JSON, or None for empty or malformed text."""
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def load_json_object(text: str | None) -> dict | None:
    value = load_json(text)
    return value if isinstance(value, dict) else None


def iso(moment: datetime) -> str:
    """UTC timestamp to the second. A naive datetime is taken as UTC."""
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC).strftime(TIMESTAMP_FORMAT)


def utc_now_iso() -> str:
    return iso(datetime.now(UTC))


def parse_iso(value: object, *, to_utc: bool = False) -> datetime | None:
    """An aware datetime from ISO 8601 text, or None. No offset means UTC. The offset is
    kept unless ``to_utc`` is set."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC) if to_utc else parsed


def merge_cache_states(states: Iterable[str]) -> str:
    """One envelope cache state for several fetches: the least fresh one wins."""
    seen = set(states)
    for state in ("stale", "miss", "hit"):
        if state in seen:
            return state
    return "snapshot"


def http_cache(directory: Path) -> HttpCache:
    return HttpCache(directory / "http_cache.sqlite")


def rate_limiter(directory: Path, *, clock=None, sleeper=None) -> RateLimiter:
    return RateLimiter(directory / "rate_limit.sqlite", clock=clock, sleeper=sleeper)


def http_client(
    key: str,
    *,
    directory: Path | None = None,
    rate: float,
    burst: int,
    user_agent: str,
    resolver=None,
    policy: EgressPolicy | None = None,
    cache: HttpCache | None = None,
    limiter=None,
    limiter_clock=None,
    limiter_sleeper=None,
    **options,
) -> HttpClient:
    """An HttpClient held to the egress allowlist, with the cache and rate limiter in
    ``directory``. ``policy``, ``cache`` and ``limiter`` replace the default ones.
    ``options`` (timeout, retries, auth_scope, offline, transport, sleeper, rng, ...)
    go to HttpClient unchanged."""
    if policy is None:
        policy = EgressPolicy(allowlist_path(), key, resolver=resolver)
    if (cache is None or limiter is None) and directory is None:
        raise ValueError("directory is required for the default cache and rate limiter")
    if cache is None:
        cache = http_cache(directory)
    if limiter is None:
        limiter = rate_limiter(directory, clock=limiter_clock, sleeper=limiter_sleeper)
    return HttpClient(
        key,
        policy=policy,
        cache=cache,
        limiter=limiter,
        user_agent=user_agent,
        rate=rate,
        burst=burst,
        **options,
    )
