"""Append-only, hash-chained audit log.

Records live in daily files named ``YYYY-MM-DD.jsonl`` under the audit
directory (``plugin-data/cyber-au/audit`` in a Hermes home). Each line is
one JSON object. The hex ``hash`` is SHA-256 over the previous record's
hash concatenated with the canonical JSON of this record without its
``hash`` field. Canonical JSON is UTF-8, with keys sorted at every level
and no insignificant whitespace.

Results are hashed. The hash and byte length are stored, and the result
body is not. Argument values that are credentials are replaced with
``[REDACTED]`` before the line is written. ``args_sha256`` commits to the
original arguments so an assessor can match a call without the log holding
the secret.

``audit verify`` walks the chain and reports the file line number of the
first record that was edited, removed or reordered. Files older than the
retention window (90 days unless configured) are removed when a new record
is written. A write tool is blocked when the log cannot be written. A read
tool still runs, with a warning.

Forwarding to syslog or a Sentinel endpoint is intentionally absent. It
belongs to a later release and stays off.
"""

from __future__ import annotations

import argparse
import csv
import fcntl
import hashlib
import io
import json
import logging
import math
import os
import re
import sys
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta, tzinfo
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import yaml

from cyberau_common.secrets import redact

logger = logging.getLogger("cyberau.audit")

GENESIS = "0" * 64
EVENTS = frozenset(
    {
        "session_start",
        "session_end",
        "tool_call",
        "tool_blocked",
        "approval",
        "export",
        "delivery",
        "config_change",
    }
)
_LOG_NAME = re.compile(r"^(\d{4}-\d{2}-\d{2})\.jsonl$")
_POINTER = re.compile(r"^(\d+) ([0-9a-f]{64}) (\d{4}-\d{2}-\d{2})$")
_SECRET_ENV = re.compile(r"(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|PASSWD)", re.IGNORECASE)
_WRITE_TOKENS = frozenset(
    {
        "export",
        "deliver",
        "delivery",
        "write",
        "delete",
        "update",
        "create",
        "add",
        "put",
        "post",
        "set",
        "import",
        "submit",
        "send",
        "store",
        "remove",
        "insert",
        "drop",
        "approve",
        "config",
    }
)
_READ_TOKENS = frozenset(
    {
        "search",
        "get",
        "list",
        "read",
        "lookup",
        "query",
        "fetch",
        "health",
        "verify",
        "show",
        "describe",
        "status",
        "digest",
        "brief",
        "check",
        "find",
        "count",
        "probe",
    }
)
_SECRET_KEY_EXACT = frozenset(
    {
        "key",
        "token",
        "secret",
        "password",
        "passwd",
        "apikey",
        "credential",
        "credentials",
        "authtoken",
        "accesstoken",
        "refreshtoken",
        "privatekey",
        "authkey",
        "authorization",
    }
)
_SECRET_KEY_SUFFIXES = (
    "apikey",
    "apitoken",
    "token",
    "secret",
    "password",
    "credential",
    "authkey",
)
_CSV_FIELDS = (
    "ts",
    "seq",
    "session_id",
    "task_id",
    "event",
    "tool",
    "args_redacted",
    "args_sha256",
    "result_sha256",
    "result_bytes",
    "duration_ms",
    "flags",
    "prev_hash",
    "hash",
)
_DIST_CACHE: tuple[float, frozenset[str]] | None = None

_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


class AuditError(Exception):
    """Base error for the audit log."""


class AuditWriteError(AuditError):
    """The audit log could not be written."""


class AuditUsageError(AuditError):
    """The audit command was called incorrectly."""


class AuditVerifyError(AuditError):
    """The hash chain failed at one line."""

    def __init__(self, reason: str, *, line_number: int, path: Path):
        super().__init__(reason)
        self.reason = reason
        self.line_number = line_number
        self.path = path


@dataclass(frozen=True)
class _Pointer:
    seq: int
    digest: str
    day: date


class _SydneyTime(tzinfo):
    """Australia/Sydney offsets used when the system zone database is missing.

    AEDT (UTC+11) runs from 02:00 on the first Sunday in October until 03:00
    on the first Sunday in April. The rest of the year is AEST (UTC+10).
    This matches the rule in force since 2008.
    """

    def utcoffset(self, dt: datetime | None) -> timedelta:
        return timedelta(hours=11 if _is_aedt(dt) else 10)

    def dst(self, dt: datetime | None) -> timedelta:
        return timedelta(hours=1 if _is_aedt(dt) else 0)

    def tzname(self, dt: datetime | None) -> str:
        return "AEDT" if _is_aedt(dt) else "AEST"


def _nth_sunday(year: int, month: int) -> datetime:
    first = date(year, month, 1)
    offset = (6 - first.weekday()) % 7
    return datetime(year, month, 1 + offset)


def _is_aedt(dt: datetime | None) -> bool:
    if dt is None:
        return False
    wall = dt.replace(tzinfo=None)
    start = _nth_sunday(wall.year, 10).replace(hour=2)
    end = _nth_sunday(wall.year, 4).replace(hour=3)
    return wall >= start or wall < end


def load_zone(name: str) -> tzinfo:
    """Return a timezone, with an Australia/Sydney fallback that needs no zone data."""
    try:
        return ZoneInfo(name)
    except ZoneInfoNotFoundError:
        if name == "Australia/Sydney":
            return _SydneyTime()
        raise AuditError(f"unknown timezone {name}") from None


def canonical_json(value: object) -> str:
    """Serialise a JSON value with sorted keys and no insignificant whitespace."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def chain_hash(prev_hash: str, body: Mapping[str, object]) -> str:
    """SHA-256 of ``prev_hash`` plus the canonical record without ``hash``."""
    payload = prev_hash + canonical_json(dict(body))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def default_audit_dir() -> Path:
    """Resolve the audit directory from the environment or the Hermes home."""
    override = os.environ.get("CYBERAU_AUDIT_LOG_PATH")
    if override:
        return Path(override)
    data = os.environ.get("CYBERAU_DATA_DIR")
    if data:
        return Path(data) / "audit"
    hermes = os.environ.get("HERMES_HOME")
    home = Path(hermes) if hermes else Path.home() / ".hermes"
    return home / "plugin-data" / "cyber-au" / "audit"


def tool_writes(tool_name: str, **kwargs: object) -> bool:
    """Return whether a tool can change state.

    An explicit ``writes`` or ``read_only`` hint wins. Otherwise the tool
    name is split into tokens. Unknown tools are treated as writes so a
    failed audit log fails closed.
    """
    if kwargs.get("writes") is not None:
        return bool(kwargs["writes"])
    if kwargs.get("read_only") is not None:
        return not bool(kwargs["read_only"])
    if kwargs.get("readOnlyHint") is not None:
        return not bool(kwargs["readOnlyHint"])
    tokens = {token for token in re.split(r"[^a-z0-9]+", tool_name.lower()) if token}
    if tokens & _WRITE_TOKENS:
        return True
    if tokens & _READ_TOKENS:
        return False
    return True


def _is_secret_key(name: str) -> bool:
    norm = re.sub(r"[^a-z0-9]", "", name.lower())
    if norm in _SECRET_KEY_EXACT or norm.endswith(_SECRET_KEY_SUFFIXES):
        return True
    return "authorization" in norm


def _distribution_secret_names() -> frozenset[str]:
    global _DIST_CACHE
    path = _find_distribution()
    if path is None:
        return frozenset()
    try:
        mtime = path.stat().st_mtime
    except OSError:
        return frozenset()
    if _DIST_CACHE is not None and _DIST_CACHE[0] == mtime:
        return _DIST_CACHE[1]
    names: set[str] = set()
    try:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return frozenset()
    for item in loaded.get("env_requires") or []:
        if isinstance(item, dict) and item.get("name"):
            names.add(str(item["name"]))
    found = frozenset(names)
    _DIST_CACHE = (mtime, found)
    return found


def _find_distribution() -> Path | None:
    override = os.environ.get("CYBERAU_DISTRIBUTION")
    if override:
        path = Path(override)
        return path if path.is_file() else None
    start = Path(__file__).resolve()
    for parent in start.parents:
        candidate = parent / "distribution.yaml"
        if candidate.is_file():
            return candidate
    return None


def secret_values() -> tuple[str, ...]:
    """Return secret environment values that must not appear in the log."""
    names = _distribution_secret_names()
    found: list[str] = []
    seen: set[str] = set()
    for name, value in os.environ.items():
        if name not in names and _SECRET_ENV.search(name) is None:
            continue
        if len(value) < 8 or value == "[REDACTED]" or value in seen:
            continue
        seen.add(value)
        found.append(value)
    found.sort(key=len, reverse=True)
    return tuple(found)


def redact_text(text: str, secrets: tuple[str, ...] | None = None) -> str:
    """Redact header, query and known environment secrets in a string."""
    cleaned = redact(text)
    for secret in secrets if secrets is not None else secret_values():
        if secret in cleaned:
            cleaned = cleaned.replace(secret, "[REDACTED]")
    return cleaned


def redact_value(value: object, secrets: tuple[str, ...] | None = None) -> object:
    """Redact secret-shaped keys and values in a JSON structure."""
    known = secrets if secrets is not None else secret_values()
    return _redact(value, known)


def _redact(value: object, secrets: tuple[str, ...]) -> object:
    if isinstance(value, dict):
        cleaned: dict[str, object] = {}
        for key, item in value.items():
            name = str(key)
            if _is_secret_key(name):
                cleaned[name] = "[REDACTED]"
            else:
                cleaned[name] = _redact(item, secrets)
        return cleaned
    if isinstance(value, list):
        return [_redact(item, secrets) for item in value]
    if isinstance(value, str):
        return redact_text(value, secrets)
    return value


def _json_ready(value: object) -> object:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("audit values must be finite numbers")
        return value
    if isinstance(value, dict):
        return {str(key): _json_ready(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_ready(item) for item in value]
    raise ValueError("audit values must be JSON types")


def _digest_bytes(raw: bytes) -> tuple[str, int]:
    return hashlib.sha256(raw).hexdigest(), len(raw)


def _result_digest(result: object) -> tuple[str, int] | None:
    if result is None:
        return None
    if isinstance(result, bytes):
        return _digest_bytes(result)
    if isinstance(result, str):
        return _digest_bytes(result.encode("utf-8"))
    return _digest_bytes(canonical_json(_json_ready(result)).encode("utf-8"))


class AuditLog:
    """Daily JSONL hash chain stored under the audit directory."""

    def __init__(
        self,
        directory: Path | str | None = None,
        *,
        retention_days: int | None = None,
        timezone_name: str | None = None,
        clock: Callable[[], datetime] | None = None,
    ):
        self._directory = Path(directory) if directory is not None else None
        if retention_days is None:
            raw = os.environ.get("CYBERAU_AUDIT_RETENTION_DAYS", "90")
            try:
                retention_days = int(raw)
            except ValueError as exc:
                raise ValueError("CYBERAU_AUDIT_RETENTION_DAYS must be an integer") from exc
        if retention_days < 1:
            raise ValueError("retention_days must be at least 1")
        self.retention_days = retention_days
        self.timezone_name = timezone_name or os.environ.get("CYBERAU_AUDIT_TZ", "Australia/Sydney")
        self.zone = load_zone(self.timezone_name)
        self._clock = clock
        self._pruned_on: date | None = None

    @property
    def directory(self) -> Path:
        if self._directory is None:
            self._directory = default_audit_dir()
        return self._directory

    def probe(self) -> None:
        """Confirm the chain tip and that today's file can be opened for append."""
        with self._exclusive_lock():
            _prev_seq, _prev_hash, latest_day = self._append_expectation()
            day = self._today()
            if latest_day is not None and day < latest_day:
                raise AuditWriteError("audit clock moved to an earlier day")
            path = self._file(day)
            flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY | _NOFOLLOW
            fd = os.open(path, flags, 0o600)
            os.close(fd)

    def record(
        self,
        event: str,
        *,
        session_id: str | None = None,
        task_id: str | None = None,
        tool: str | None = None,
        args: object | None = None,
        result: object | None = None,
        duration_ms: int | None = None,
        flags: list[str] | None = None,
    ) -> dict[str, object]:
        """Append one event and return the stored record."""
        if event not in EVENTS:
            raise ValueError(f"unknown audit event: {event}")
        if duration_ms is not None and (
            isinstance(duration_ms, bool) or not isinstance(duration_ms, int) or duration_ms < 0
        ):
            raise ValueError("duration_ms must be a positive integer or zero")
        secrets = secret_values()
        try:
            with self._exclusive_lock():
                self._prune_if_due()
                prev_seq, prev_hash, latest_day = self._append_expectation()
                day = self._today()
                if latest_day is not None and day < latest_day:
                    raise AuditWriteError("audit clock moved to an earlier day")
                body: dict[str, object] = {
                    "event": event,
                    "prev_hash": prev_hash,
                    "seq": prev_seq + 1,
                    "ts": self._timestamp(),
                }
                if session_id:
                    body["session_id"] = redact_text(session_id, secrets)
                if task_id:
                    body["task_id"] = redact_text(task_id, secrets)
                if tool:
                    body["tool"] = redact_text(tool, secrets)
                if args is not None:
                    ready = _json_ready(args)
                    body["args_sha256"] = hashlib.sha256(
                        canonical_json(ready).encode("utf-8")
                    ).hexdigest()
                    body["args_redacted"] = redact_value(ready, secrets)
                digested = _result_digest(result)
                if digested is not None:
                    body["result_sha256"], body["result_bytes"] = digested
                if duration_ms is not None:
                    body["duration_ms"] = duration_ms
                if flags:
                    body["flags"] = [redact_text(str(flag), secrets) for flag in flags]
                self._refuse_secrets(body, secrets)
                digest = chain_hash(prev_hash, body)
                stored = dict(body)
                stored["hash"] = digest
                line = canonical_json(stored)
                path = self._file(day)
                self._append_line(path, line)
                self._write_pointer("HEAD", _Pointer(prev_seq + 1, digest, day))
                return stored
        except AuditWriteError:
            raise
        except OSError as exc:
            raise AuditWriteError("audit log is not writable") from exc

    def verify(self, from_date: date | None = None) -> int:
        """Check the chain. Return the number of records checked."""
        directory = self.directory
        if not directory.is_dir():
            return 0
        with self._shared_lock():
            files = self._log_files()
            earlier = [
                path for path in files if from_date is not None and _file_day(path) < from_date
            ]
            selected = [
                path for path in files if from_date is None or _file_day(path) >= from_date
            ]
            expected_seq, expected_prev = self._start_expectation(earlier)
            seen = 0
            last_path: Path | None = None
            last_line = 0
            last_seq = expected_seq
            last_hash = expected_prev
            for path in selected:
                for line_number, record in self._iter_file(path):
                    self._check_record(
                        record,
                        line_number=line_number,
                        path=path,
                        expected_seq=expected_seq,
                        expected_prev=expected_prev,
                    )
                    expected_seq = int(record["seq"]) + 1
                    expected_prev = str(record["hash"])
                    last_path = path
                    last_line = line_number
                    last_seq = int(record["seq"])
                    last_hash = str(record["hash"])
                    seen += 1
            self._check_head(
                from_date=from_date,
                selected=selected,
                files=files,
                seen=seen,
                last_path=last_path,
                last_line=last_line,
                last_seq=last_seq,
                last_hash=last_hash,
            )
            return seen

    def export(self, since: date, *, fmt: str) -> str:
        """Return records on or after ``since`` as JSONL or CSV text.

        The chain is verified first. A broken log is not exported.
        """
        if fmt not in {"jsonl", "csv"}:
            raise AuditUsageError("format must be jsonl or csv")
        self.verify()
        rows = [
            record
            for _path, _line, record in self.iter_records()
            if _record_day(record, self.zone) >= since
        ]
        if fmt == "jsonl":
            if not rows:
                return ""
            return "".join(canonical_json(record) + "\n" for record in rows)
        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=_CSV_FIELDS, lineterminator="\n")
        writer.writeheader()
        for record in rows:
            writer.writerow(_csv_row(record))
        return buffer.getvalue()

    def iter_records(self) -> Iterator[tuple[Path, int, dict[str, object]]]:
        if not self.directory.is_dir():
            return
        for path in self._log_files():
            for line_number, record in self._iter_file(path):
                yield path, line_number, record

    def prune(self) -> list[Path]:
        """Remove daily files older than the retention window."""
        if not self.directory.is_dir():
            return []
        with self._exclusive_lock():
            return self._prune(self._today())

    def _today(self) -> date:
        return self._now().date()

    def _now(self) -> datetime:
        when = self._clock() if self._clock else datetime.now(UTC)
        if when.tzinfo is None:
            return when.replace(tzinfo=self.zone)
        return when.astimezone(self.zone)

    def _timestamp(self) -> str:
        return self._now().isoformat(timespec="milliseconds")

    def _file(self, day: date) -> Path:
        return self.directory / f"{day.isoformat()}.jsonl"

    def _log_files(self) -> list[Path]:
        files = [path for path in self.directory.iterdir() if _LOG_NAME.match(path.name)]
        files.sort(key=lambda path: path.name)
        return files

    def _prune_if_due(self) -> None:
        today = self._today()
        if self._pruned_on == today:
            return
        self._prune(today)
        self._pruned_on = today

    def _prune(self, today: date) -> list[Path]:
        cutoff = today - timedelta(days=self.retention_days)
        removed: list[Path] = []
        removed_tip: dict[str, object] | None = None
        for path in self._log_files():
            if _file_day(path) >= cutoff:
                break
            last = _tail_record(path)
            if last is not None:
                removed_tip = last
            path.unlink()
            removed.append(path)
        if removed_tip is not None:
            self._write_pointer(
                "anchor",
                _Pointer(
                    int(removed_tip["seq"]),
                    str(removed_tip["hash"]),
                    _record_day(removed_tip, self.zone),
                ),
            )
        if removed and not self._log_files():
            head = self.directory / "HEAD"
            if head.exists():
                head.unlink()
        return removed

    def _append_expectation(self) -> tuple[int, str, date | None]:
        latest = self._latest_nonempty()
        head = self._read_pointer("HEAD", error=AuditWriteError)
        if latest is None:
            if head is not None:
                raise AuditWriteError("committed head does not match the log")
            anchor = self._read_pointer("anchor", error=AuditWriteError)
            if anchor is not None:
                return anchor.seq, anchor.digest, None
            return 0, GENESIS, None
        last = _tail_record(latest)
        if last is None or head is None:
            raise AuditWriteError("committed head does not match the log")
        body = {key: value for key, value in last.items() if key != "hash"}
        if chain_hash(str(last.get("prev_hash", "")), body) != str(last.get("hash")):
            raise AuditWriteError("committed head does not match the log")
        if head.seq != int(last["seq"]) or head.digest != str(last["hash"]):
            raise AuditWriteError("committed head does not match the log")
        return int(last["seq"]), str(last["hash"]), _file_day(latest)

    def _latest_nonempty(self) -> Path | None:
        found: Path | None = None
        for path in self._log_files():
            if path.stat().st_size > 0:
                found = path
        return found

    def _start_expectation(self, earlier: list[Path]) -> tuple[int, str]:
        """Return the sequence and previous hash the next checked record must have."""
        for path in reversed(earlier):
            last = _tail_record(path)
            if last is not None:
                return int(last["seq"]) + 1, str(last["hash"])
        anchor = self._read_pointer("anchor", error=AuditVerifyError)
        if anchor is not None:
            return anchor.seq + 1, anchor.digest
        return 1, GENESIS

    def _iter_file(self, path: Path) -> Iterator[tuple[int, dict[str, object]]]:
        text = _read_text(path)
        if text == "":
            return
        for line_number, line in enumerate(text.splitlines(), start=1):
            if line == "":
                raise AuditVerifyError(
                    "blank line in the audit log", line_number=line_number, path=path
                )
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError as exc:
                raise AuditVerifyError(
                    "record is not valid JSON", line_number=line_number, path=path
                ) from exc
            if not isinstance(parsed, dict):
                raise AuditVerifyError(
                    "record is not an object", line_number=line_number, path=path
                )
            if canonical_json(parsed) != line:
                raise AuditVerifyError(
                    "line is not canonical JSON", line_number=line_number, path=path
                )
            yield line_number, parsed

    def _check_record(
        self,
        record: dict[str, object],
        *,
        line_number: int,
        path: Path,
        expected_seq: int,
        expected_prev: str,
    ) -> None:
        required = ("ts", "seq", "event", "prev_hash", "hash")
        missing = [name for name in required if name not in record]
        if missing:
            raise AuditVerifyError(
                f"record is missing {', '.join(missing)}",
                line_number=line_number,
                path=path,
            )
        if record["event"] not in EVENTS:
            raise AuditVerifyError("unknown event", line_number=line_number, path=path)
        if isinstance(record["seq"], bool) or not isinstance(record["seq"], int):
            raise AuditVerifyError("sequence is not an integer", line_number=line_number, path=path)
        if record["seq"] != expected_seq:
            raise AuditVerifyError(
                f"sequence is {record['seq']}, expected {expected_seq}",
                line_number=line_number,
                path=path,
            )
        if record["prev_hash"] != expected_prev:
            raise AuditVerifyError(
                "previous hash does not match", line_number=line_number, path=path
            )
        body = {key: value for key, value in record.items() if key != "hash"}
        expect = chain_hash(str(record["prev_hash"]), body)
        if record["hash"] != expect:
            raise AuditVerifyError("record hash does not match", line_number=line_number, path=path)

    def _check_head(
        self,
        *,
        from_date: date | None,
        selected: list[Path],
        files: list[Path],
        seen: int,
        last_path: Path | None,
        last_line: int,
        last_seq: int,
        last_hash: str,
    ) -> None:
        covers_tip = from_date is None or not files or (selected and selected[-1] == files[-1])
        if not covers_tip:
            return
        head = self._read_pointer("HEAD", error=AuditVerifyError)
        if seen == 0:
            if head is not None and from_date is None:
                raise AuditVerifyError(
                    "committed head does not match the log",
                    line_number=1,
                    path=self.directory / "HEAD",
                )
            return
        assert last_path is not None
        if head is None:
            raise AuditVerifyError(
                "committed head is missing", line_number=last_line, path=last_path
            )
        if head.seq == last_seq and head.digest == last_hash:
            return
        if head.seq > last_seq:
            raise AuditVerifyError(
                "chain tip does not match the committed head",
                line_number=last_line + (head.seq - last_seq),
                path=last_path,
            )
        raise AuditVerifyError(
            "chain tip does not match the committed head",
            line_number=last_line,
            path=last_path,
        )

    def _refuse_secrets(self, body: Mapping[str, object], secrets: tuple[str, ...]) -> None:
        if not secrets:
            return
        visible = {
            key: body[key]
            for key in ("session_id", "task_id", "tool", "args_redacted", "flags")
            if key in body
        }
        if not visible:
            return
        blob = canonical_json(visible)
        for secret in secrets:
            if secret in blob:
                raise AuditWriteError("refusing to write a secret into the audit log")

    def _append_line(self, path: Path, line: str) -> None:
        flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY | _NOFOLLOW
        fd = os.open(path, flags, 0o600)
        try:
            os.write(fd, (line + "\n").encode("utf-8"))
        finally:
            os.close(fd)

    def _write_pointer(self, name: str, pointer: _Pointer) -> None:
        path = self.directory / name
        temporary = self.directory / f".{name}.tmp"
        payload = f"{pointer.seq} {pointer.digest} {pointer.day.isoformat()}\n"
        temporary.write_text(payload, encoding="utf-8")
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)

    def _read_pointer(self, name: str, *, error: type[AuditError]) -> _Pointer | None:
        path = self.directory / name
        if not path.exists():
            return None
        text = path.read_text(encoding="utf-8").strip()
        match = _POINTER.match(text)
        if match is None:
            if error is AuditVerifyError:
                raise AuditVerifyError(
                    f"{name} pointer is not valid",
                    line_number=1,
                    path=path,
                )
            raise error(f"{name} pointer is not valid")
        return _Pointer(int(match.group(1)), match.group(2), date.fromisoformat(match.group(3)))

    @contextmanager
    def _exclusive_lock(self):
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(self.directory / ".lock", os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    @contextmanager
    def _shared_lock(self):
        path = self.directory / ".lock"
        if not path.exists():
            yield
            return
        fd = os.open(path, os.O_RDONLY)
        try:
            fcntl.flock(fd, fcntl.LOCK_SH)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)


def _file_day(path: Path) -> date:
    match = _LOG_NAME.match(path.name)
    if match is None:
        raise AuditError(f"not an audit file: {path.name}")
    return date.fromisoformat(match.group(1))


def _record_day(record: Mapping[str, object], zone: tzinfo) -> date:
    parsed = datetime.fromisoformat(str(record["ts"]))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=zone)
    return parsed.astimezone(zone).date()


def _tail_line(path: Path) -> str | None:
    with path.open("rb") as handle:
        handle.seek(0, os.SEEK_END)
        remaining = handle.tell()
        if remaining == 0:
            return None
        buffer = b""
        while remaining > 0:
            step = min(8192, remaining)
            remaining -= step
            handle.seek(remaining)
            buffer = handle.read(step) + buffer
            stripped = buffer.rstrip(b"\n")
            split_at = stripped.rfind(b"\n")
            if split_at != -1:
                return stripped[split_at + 1 :].decode("utf-8")
        stripped = buffer.rstrip(b"\n")
        return stripped.decode("utf-8") if stripped else None


def _tail_record(path: Path) -> dict[str, object] | None:
    line = _tail_line(path)
    if line is None:
        return None
    try:
        parsed = json.loads(line)
    except json.JSONDecodeError as exc:
        raise AuditWriteError("audit tail is not valid JSON") from exc
    if not isinstance(parsed, dict):
        raise AuditWriteError("audit tail is not an object")
    return parsed


def _read_text(path: Path) -> str:
    fd = os.open(path, os.O_RDONLY | _NOFOLLOW)
    try:
        chunks: list[bytes] = []
        while True:
            block = os.read(fd, 65536)
            if not block:
                break
            chunks.append(block)
    finally:
        os.close(fd)
    return b"".join(chunks).decode("utf-8")


def _csv_row(record: Mapping[str, object]) -> dict[str, object]:
    row: dict[str, object] = {}
    for field in _CSV_FIELDS:
        value = record.get(field, "")
        if field in {"args_redacted", "flags"} and value != "":
            row[field] = canonical_json(value)
        elif value is None:
            row[field] = ""
        else:
            row[field] = value
    return row


class AuditHooks:
    """Hermes hook callbacks that record activity and fail closed for writes."""

    def __init__(self, log: AuditLog | None = None):
        self.log = log or AuditLog()
        self.last_warning: str | None = None

    def pre_tool_call(self, tool_name: str, args: dict | None = None, task_id: str = "", **kwargs):
        """Block write tools when the log cannot be written. Read tools continue."""
        writes = tool_writes(tool_name, **kwargs)
        blocked = bool(kwargs.get("blocked"))
        try:
            self.log.probe()
            if blocked:
                message = redact_text(str(kwargs.get("block_message") or "tool blocked"))
                self.record_block(tool_name, args, task_id=task_id, reason=message)
                return {"action": "block", "message": message}
        except Exception:
            if writes or blocked:
                return {
                    "action": "block",
                    "message": "audit log is not writable; write tools are blocked",
                }
            self._warn(tool_name)
            return None
        return None

    def post_tool_call(
        self,
        tool_name: str,
        args: dict | None = None,
        result: object = None,
        task_id: str = "",
        duration_ms: int = 0,
        **kwargs,
    ) -> None:
        """Record the tool result. Export and delivery tools use their own events."""
        try:
            if kwargs.get("approved"):
                self.record_approval(
                    tool_name,
                    args,
                    approved=True,
                    task_id=task_id,
                    session_id=str(kwargs.get("session_id") or ""),
                )
            event = _tool_event(tool_name)
            self.log.record(
                event,
                tool=tool_name,
                args=args if args is not None else {},
                result=result,
                task_id=task_id or None,
                session_id=_optional_text(kwargs.get("session_id")),
                duration_ms=duration_ms,
            )
        except Exception:
            if tool_writes(tool_name, **kwargs):
                logger.error("audit log did not record write tool %s", redact_text(tool_name))
            else:
                self._warn(tool_name)

    def on_session_start(
        self, session_id: str, model: str = "", platform: str = "", **kwargs
    ) -> None:
        try:
            flags = [item for item in (platform, model) if item]
            self.log.record("session_start", session_id=session_id, flags=flags or None)
        except Exception:
            self._warn("session_start")

    def on_session_end(
        self,
        session_id: str,
        completed: bool = False,
        interrupted: bool = False,
        model: str = "",
        platform: str = "",
        **kwargs,
    ) -> None:
        try:
            flags = []
            if completed:
                flags.append("completed")
            if interrupted:
                flags.append("interrupted")
            if platform:
                flags.append(platform)
            self.log.record("session_end", session_id=session_id, flags=flags or None)
        except Exception:
            self._warn("session_end")

    def record_approval(
        self,
        tool_name: str,
        args: dict | None = None,
        *,
        approved: bool,
        task_id: str = "",
        session_id: str = "",
    ) -> dict[str, object]:
        return self.log.record(
            "approval",
            tool=tool_name,
            args=args,
            task_id=task_id or None,
            session_id=session_id or None,
            flags=["approved" if approved else "denied"],
        )

    def record_block(
        self,
        tool_name: str,
        args: dict | None = None,
        *,
        task_id: str = "",
        reason: str = "",
    ) -> dict[str, object]:
        payload: dict[str, object] = {}
        if reason:
            payload["reason"] = reason
        if args:
            payload["args"] = args
        return self.log.record(
            "tool_blocked",
            tool=tool_name,
            args=payload or None,
            task_id=task_id or None,
            flags=["blocked"],
        )

    def record_export(
        self,
        tool_name: str = "export",
        args: dict | None = None,
        result: object = None,
        *,
        task_id: str = "",
        duration_ms: int | None = None,
    ) -> dict[str, object]:
        return self.log.record(
            "export",
            tool=tool_name,
            args=args,
            result=result,
            task_id=task_id or None,
            duration_ms=duration_ms,
        )

    def record_delivery(
        self,
        tool_name: str = "delivery",
        args: dict | None = None,
        result: object = None,
        *,
        task_id: str = "",
        duration_ms: int | None = None,
    ) -> dict[str, object]:
        return self.log.record(
            "delivery",
            tool=tool_name,
            args=args,
            result=result,
            task_id=task_id or None,
            duration_ms=duration_ms,
        )

    def record_config_change(
        self,
        key: str,
        new_value: object,
        old_value: object = None,
        *,
        session_id: str = "",
    ) -> dict[str, object]:
        return self.log.record(
            "config_change",
            tool="config",
            session_id=session_id or None,
            args={"key": key, "old": old_value, "new": new_value},
        )

    def _warn(self, tool_name: str) -> None:
        safe = redact_text(tool_name)
        self.last_warning = (
            f"audit log is not writable; read tool {safe} continued without a record"
        )
        logger.warning("%s", self.last_warning)


def _tool_event(tool_name: str) -> str:
    tokens = {token for token in re.split(r"[^a-z0-9]+", tool_name.lower()) if token}
    if "export" in tokens:
        return "export"
    if "deliver" in tokens or "delivery" in tokens:
        return "delivery"
    return "tool_call"


def _optional_text(value: object) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text or None


def setup_cli(parser: argparse.ArgumentParser) -> None:
    """Add ``audit verify`` and ``audit export`` to a cyber-au command parser."""
    commands = parser.add_subparsers(dest="cyber_au_command", required=True)
    audit = commands.add_parser("audit", help="Check or export the tamper-evident audit log")
    audit_commands = audit.add_subparsers(dest="audit_command", required=True)
    verify = audit_commands.add_parser("verify", help="Check the hash chain")
    verify.add_argument("--from", dest="from_date", help="First day to check, as YYYY-MM-DD")
    export = audit_commands.add_parser("export", help="Export records as jsonl or csv")
    export.add_argument("--since", required=True, help="First day to include, as YYYY-MM-DD")
    export.add_argument("--format", dest="export_format", required=True, choices=("jsonl", "csv"))


def main(argv: list[str] | None = None) -> int:
    """Run ``cyber-au audit verify`` or ``cyber-au audit export``."""
    parser = argparse.ArgumentParser(prog="cyber-au")
    setup_cli(parser)
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        code = exc.code
        return int(code) if isinstance(code, int) else 2
    return dispatch(args)


def dispatch(args: argparse.Namespace, log: AuditLog | None = None) -> int:
    """Run a parsed audit command. Returns a process status."""
    try:
        audit = log or AuditLog()
        if args.audit_command == "verify":
            count = audit.verify(_parse_date(args.from_date) if args.from_date else None)
            print(f"audit chain verified ({count} records)")
            return 0
        if args.audit_command == "export":
            since = _parse_date(args.since)
            sys.stdout.write(audit.export(since, fmt=args.export_format))
            return 0
        print("unknown audit command", file=sys.stderr)
        return 2
    except AuditVerifyError as exc:
        print(
            f"audit verify failed: {exc.path.name} line {exc.line_number}: {exc.reason}",
            file=sys.stderr,
        )
        return 1
    except AuditUsageError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except AuditError as exc:
        print(str(exc), file=sys.stderr)
        return 1


def _parse_date(value: str) -> date:
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise AuditUsageError("date must be YYYY-MM-DD") from exc


def register_hooks(ctx: object, hooks: AuditHooks | None = None) -> AuditHooks:
    """Register the audit callbacks on a Hermes plugin context."""
    audit = hooks or AuditHooks()
    register = getattr(ctx, "register_hook")
    register("pre_tool_call", audit.pre_tool_call)
    register("post_tool_call", audit.post_tool_call)
    register("on_session_start", audit.on_session_start)
    register("on_session_end", audit.on_session_end)
    return audit


def register_cli(ctx: object) -> None:
    """Register ``hermes cyber-au audit`` on a Hermes plugin context."""
    register = getattr(ctx, "register_cli_command")
    register(
        name="cyber-au",
        help="Check or export the cyber-au audit log",
        setup_fn=setup_cli,
        handler_fn=lambda args: dispatch(args),
    )


def add_audit_parser(commands) -> None:
    """Attach the audit command to an existing cyber-au subparser group.

    The plugin skeleton owns the rest of the ``cyber-au`` command. It should
    call this instead of registering a second top-level command.
    """
    audit = commands.add_parser("audit", help="Check or export the tamper-evident audit log")
    audit_commands = audit.add_subparsers(dest="audit_command", required=True)
    verify = audit_commands.add_parser("verify", help="Check the hash chain")
    verify.add_argument("--from", dest="from_date", help="First day to check, as YYYY-MM-DD")
    export = audit_commands.add_parser("export", help="Export records as jsonl or csv")
    export.add_argument("--since", required=True, help="First day to include, as YYYY-MM-DD")
    export.add_argument("--format", dest="export_format", required=True, choices=("jsonl", "csv"))
