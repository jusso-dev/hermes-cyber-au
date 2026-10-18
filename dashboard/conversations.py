"""Read-only snapshots of Hermes sessions and role handoffs.

A snapshot is a short excerpt of a stored conversation. The system prompt,
tool arguments, and secret-shaped text are left out. This module only reads.
"""

from __future__ import annotations

import json
import re
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from zoneinfo import ZoneInfo

try:
    SYDNEY = ZoneInfo("Australia/Sydney")
except Exception:
    SYDNEY = UTC

SESSION_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,80}")
PROFILE_NAME_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,40}")

SNAPSHOT_TURNS = 4
SNAPSHOT_CHARS = 240
PAGE_TURNS = 80
PAGE_CHARS = 1500
SESSION_LIMIT = 12

ROLES = {"watcher", "analyst", "skeptic", "briefer", "librarian"}

_SECRET = re.compile(
    r"(?i)(?:api[_-]?key|token|password|secret|authorization)\s*[:=]\s*\S+"
    r"|sk-[A-Za-z0-9]{8,}"
    r"|Bearer\s+\S+"
)


def redact(text: str) -> str:
    return _SECRET.sub("[redacted]", text)


def role_name(profile: Path) -> str:
    marker = profile / "plugin-data" / "cyber-au" / "profile-role"
    try:
        raw = marker.read_text(encoding="utf-8")
    except OSError:
        raw = ""
    token = raw.strip().split()[0] if raw.strip() else ""
    if token in ROLES:
        return token
    return profile.name


def profile_roots(profile: Path) -> list[Path]:
    """This profile, plus sibling profiles that already have a session store."""
    roots: list[Path] = []
    if profile.is_dir():
        roots.append(profile)
    parent = profile.parent
    if parent.name != "profiles":
        return roots
    try:
        parent_real = parent.resolve()
    except OSError:
        return roots
    try:
        children = sorted(parent.iterdir())
    except OSError:
        return roots
    for child in children:
        if not child.is_dir() or child == profile or not (child / "state.db").is_file():
            continue
        if not PROFILE_NAME_RE.fullmatch(child.name):
            continue
        try:
            if not child.is_symlink() and child.resolve().parent == parent_real:
                roots.append(child)
        except OSError:
            continue
    return roots


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return {str(row[1]) for row in rows}


def _open_store(path: Path) -> sqlite3.Connection | None:
    if not path.is_file():
        return None
    uri = path.resolve().as_uri() + "?mode=ro"
    try:
        return sqlite3.connect(uri, uri=True, timeout=1)
    except sqlite3.Error:
        return None


def _when(value: object) -> str:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        try:
            moment = datetime.fromtimestamp(float(value), UTC).astimezone(SYDNEY)
        except (OverflowError, OSError, ValueError):
            return ""
        return moment.strftime("%Y-%m-%d %H:%M %Z")
    if isinstance(value, str) and value.strip():
        return value.strip()[:40]
    return ""


def _text_from(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    if isinstance(value, str):
        stripped = value.strip()
        if stripped[:1] in "{[":
            try:
                parsed = json.loads(stripped)
            except ValueError:
                return value
            return _text_from(parsed)
        return value
    if isinstance(value, list):
        return "\n".join(part for part in (_text_from(item) for item in value) if part)
    if isinstance(value, dict):
        for key in ("text", "content"):
            if key in value:
                return _text_from(value[key])
        return ""
    return ""


def _turns(conn: sqlite3.Connection, session_id: str) -> list[dict]:
    columns = _columns(conn, "messages")
    if "session_id" not in columns or "role" not in columns:
        return []
    wanted = ["id", "role"]
    for name in ("content", "tool_name", "timestamp", "active"):
        if name in columns:
            wanted.append(name)
    sql = f"SELECT {', '.join(wanted)} FROM messages WHERE session_id = ? ORDER BY id"
    try:
        rows = conn.execute(sql, (session_id,)).fetchall()
    except sqlite3.Error:
        return []
    index = {name: pos for pos, name in enumerate(wanted)}
    turns: list[dict] = []
    for row in rows:
        role = row[index["role"]]
        if role == "system":
            continue
        tool = row[index["tool_name"]] if "tool_name" in index else None
        if role == "tool":
            label = "tool"
            text = f"Used {tool}" if tool else "Used a tool"
        else:
            label = "person" if role == "user" else "hermes"
            raw = row[index["content"]] if "content" in index else ""
            text = redact(_text_from(raw)).strip()
            if not text:
                continue
        stamp = row[index["timestamp"]] if "timestamp" in index else None
        turns.append({"label": label, "text": text, "when": _when(stamp)})
    return turns


def list_sessions(profile: Path) -> tuple[list[dict], str | None]:
    """Return (sessions, problem). Each session includes its turns."""
    conn = _open_store(profile / "state.db")
    if conn is None:
        if (profile / "state.db").is_file():
            return [], "The session store could not be read."
        return [], None
    try:
        columns = _columns(conn, "sessions")
        if "id" not in columns:
            return [], None
        fields = ["id"]
        for name in (
            "title",
            "source",
            "model",
            "started_at",
            "last_activity_at",
            "message_count",
            "profile_name",
            "hidden",
        ):
            if name in columns:
                fields.append(name)
        order = "id"
        if "last_activity_at" in columns and "started_at" in columns:
            order = "COALESCE(last_activity_at, started_at)"
        elif "last_activity_at" in columns:
            order = "last_activity_at"
        hidden = " WHERE COALESCE(hidden, 0) = 0" if "hidden" in columns else ""
        sql = (
            f"SELECT {', '.join(fields)} FROM sessions{hidden} "
            f"ORDER BY {order} DESC LIMIT {SESSION_LIMIT}"
        )
        try:
            rows = conn.execute(sql).fetchall()
        except sqlite3.Error:
            return [], "The session store could not be read."
        index = {name: pos for pos, name in enumerate(fields)}
        found: list[dict] = []
        speaker = role_name(profile)
        for row in rows:
            session_id = str(row[index["id"]] or "")
            if not SESSION_ID_RE.fullmatch(session_id):
                continue
            title = ""
            if "title" in index and row[index["title"]]:
                title = " ".join(str(row[index["title"]]).split())
            started = row[index["started_at"]] if "started_at" in index else None
            activity = row[index["last_activity_at"]] if "last_activity_at" in index else None
            turns = _turns(conn, session_id)
            for turn in turns:
                if turn["label"] == "hermes":
                    turn["label"] = speaker
            found.append(
                {
                    "id": session_id,
                    "profile": profile.name,
                    "speaker": speaker,
                    "title": title or session_id,
                    "source": str(row[index["source"]])
                    if "source" in index and row[index["source"]]
                    else "",
                    "model": str(row[index["model"]])
                    if "model" in index and row[index["model"]]
                    else "",
                    "when": _when(activity or started),
                    "count": row[index["message_count"]]
                    if "message_count" in index
                    else len(turns),
                    "turns": turns,
                }
            )
        return found, None
    finally:
        conn.close()


def session_count(profile: Path) -> int:
    """Number of visible session snapshots the dashboard can show."""
    return sum(len(list_sessions(root)[0]) for root in profile_roots(profile))


def find_session(profile: Path, session_id: str) -> dict | None:
    if not SESSION_ID_RE.fullmatch(session_id):
        return None
    for root in profile_roots(profile):
        sessions, _problem = list_sessions(root)
        for session in sessions:
            if session["id"] == session_id and session["profile"] == root.name:
                return session
    return None


def handoff_threads(records: list[dict]) -> list[list[dict]]:
    """Group handoff records into chronological conversations."""
    ordered = list(reversed(records))
    by_id: dict[str, dict] = {}
    for record in ordered:
        identity = record.get("id")
        if isinstance(identity, str) and identity:
            by_id[identity] = record
    children: dict[str, list[dict]] = {}
    roots: list[dict] = []
    for record in ordered:
        parent = record.get("parent_id")
        if isinstance(parent, str) and parent in by_id:
            children.setdefault(parent, []).append(record)
        else:
            roots.append(record)
    threads: list[list[dict]] = []
    for root in roots:
        chain = [root]
        identity = root.get("id")
        if isinstance(identity, str):
            chain.extend(children.get(identity, []))
        threads.append(chain)
    return threads
