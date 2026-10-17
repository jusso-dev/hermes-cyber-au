"""Read-only web dashboard for one Hermes profile of the hermes-cyber-au distribution.

It shows the cron jobs in the profile, the newest report each job wrote, any handoffs,
a short snapshot of each stored conversation, and whether a chat has been opened.
It never writes to the profile and never runs a job.

Standard library only (Python 3.11 or later). Run it with:

    python3 dashboard/server.py --profile ~/.hermes/profiles/cyber-au

It binds to 127.0.0.1 by default. Do not publish it on the public internet. It has no
login. On a homelab, publish the port on the LAN or Tailscale address only.
"""

from __future__ import annotations

import argparse
import html
import importlib.util
import json
import os
import re
import sys
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlsplit

DEFAULT_BIND = "127.0.0.1"
DEFAULT_PORT = 8765
DOCKER_PROFILE = Path("/opt/data/profiles/cyber-au")
CHAT_COMMAND = "hermes -p cyber-au chat"

JOB_ID_RE = re.compile(r"[a-z0-9-]+")
REPORT_NAME_RE = re.compile(r"\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}\.md")

ERROR_LIMIT = 400
CLAIM_LIMIT = 200
HANDOFF_LIMIT = 50
REPORT_MAX_BYTES = 1024 * 1024
HANDOFFS_MAX_BYTES = 4 * 1024 * 1024

SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


def _load_conversations():
    path = Path(__file__).with_name("conversations.py")
    spec = importlib.util.spec_from_file_location("cyberau_dashboard_conversations", path)
    if spec is None or spec.loader is None:
        raise ImportError(str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


conversations = _load_conversations()


def default_profile() -> Path:
    """Profile path: $CYBERAU_PROFILE_HOME, else the container path if present, else ~/.hermes."""
    env = os.environ.get("CYBERAU_PROFILE_HOME", "").strip()
    if env:
        return Path(env).expanduser()
    if DOCKER_PROFILE.is_dir():
        return DOCKER_PROFILE
    return Path.home() / ".hermes" / "profiles" / "cyber-au"


def esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def truncate(value: object, limit: int) -> str:
    text = " ".join(str(value).split())
    if len(text) <= limit:
        return text
    return text[: limit - 3].rstrip() + "..."


# --- data loading -------------------------------------------------------------------


def load_jobs(profile: Path) -> tuple[list[dict], str | None]:
    """Return (jobs, problem). A missing or broken file gives an empty list and a message."""
    path = profile / "cron" / "jobs.json"
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return [], f"No cron/jobs.json found in {profile}."
    except (OSError, UnicodeDecodeError) as exc:
        return [], f"Could not read cron/jobs.json: {exc.__class__.__name__}."
    try:
        data = json.loads(raw)
    except ValueError:
        return [], "cron/jobs.json is not valid JSON."
    jobs = data.get("jobs") if isinstance(data, dict) else data
    if not isinstance(jobs, list):
        return [], "cron/jobs.json has no jobs list."
    return [job for job in jobs if isinstance(job, dict)], None


def schedule_text(job: dict) -> str:
    display = job.get("schedule_display")
    if display:
        return str(display)
    schedule = job.get("schedule")
    if isinstance(schedule, str):
        return schedule
    if isinstance(schedule, dict):
        for key in ("display", "expr"):
            if schedule.get(key):
                return str(schedule[key])
        if schedule.get("minutes"):
            return f"every {schedule['minutes']}m"
    return "not set"


def state_text(job: dict) -> str:
    state = job.get("state")
    if state:
        return str(state)
    if job.get("paused_at") or job.get("enabled") is False:
        return "paused"
    if job.get("enabled") is True:
        return "enabled"
    return "not recorded (definition only)"


def report_dir(profile: Path, job_id: str) -> Path | None:
    if not JOB_ID_RE.fullmatch(job_id):
        return None
    return profile / "cron" / "output" / job_id


def latest_report(profile: Path, job_id: str) -> Path | None:
    """Newest report whose name matches the report pattern. The name sorts by time."""
    directory = report_dir(profile, job_id)
    if directory is None:
        return None
    try:
        names = [
            entry.name
            for entry in directory.iterdir()
            if REPORT_NAME_RE.fullmatch(entry.name) and entry.is_file()
        ]
    except OSError:
        return None
    if not names:
        return None
    return directory / max(names)


def safe_report_path(profile: Path, job_id: str, filename: str) -> Path | None:
    """Resolve a report, or None unless every rule in the brief holds."""
    if not JOB_ID_RE.fullmatch(job_id) or not REPORT_NAME_RE.fullmatch(filename):
        return None
    directory = report_dir(profile, job_id)
    if directory is None:
        return None
    try:
        base = directory.resolve(strict=True)
        target = (directory / filename).resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    if target.parent != base or not target.is_file():
        return None
    return target


def read_report(path: Path) -> str | None:
    try:
        with path.open("rb") as handle:
            data = handle.read(REPORT_MAX_BYTES + 1)
    except OSError:
        return None
    note = ""
    if len(data) > REPORT_MAX_BYTES:
        data = data[:REPORT_MAX_BYTES]
        note = "\n\n(Report cut short for display.)"
    return data.decode("utf-8", errors="replace") + note


def handoffs_path(profile: Path) -> Path | None:
    candidates = [profile / "handoffs.jsonl"]
    data_dir = os.environ.get("CYBERAU_DATA_DIR", "").strip()
    if data_dir:
        candidates.append(Path(data_dir).expanduser() / "handoffs.jsonl")
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def load_handoffs(path: Path) -> tuple[list[dict], int]:
    """Return (newest-first records, count of unreadable lines)."""
    try:
        with path.open("rb") as handle:
            raw = handle.read(HANDOFFS_MAX_BYTES + 1)
    except OSError:
        return [], 0
    lines = raw.decode("utf-8", errors="replace").splitlines()
    if len(raw) > HANDOFFS_MAX_BYTES:
        lines = lines[1:]  # the first line may be cut
    records: list[dict] = []
    bad = 0
    for line in lines:
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except ValueError:
            bad += 1
            continue
        if isinstance(record, dict):
            records.append(record)
        else:
            bad += 1
    records.reverse()
    return records, bad


def session_summary(profile: Path) -> int:
    """Number of entries in <profile>/sessions, 0 when absent or empty."""
    try:
        return sum(1 for _ in (profile / "sessions").iterdir())
    except OSError:
        return 0


# --- markdown and HTML --------------------------------------------------------------

_HEADING_RE = re.compile(r"(#{1,6})[ \t]+(.*?)[ \t#]*$")
_BULLET_RE = re.compile(r"[-*][ \t]+(.*)")


def render_markdown(text: str) -> str:
    """Headings, bullet lists, fenced code and paragraphs. Every piece of text is escaped."""
    out: list[str] = []
    paragraph: list[str] = []
    bullets: list[str] = []
    code: list[str] | None = None

    def flush() -> None:
        if paragraph:
            out.append("<p>" + esc(" ".join(paragraph)) + "</p>")
            paragraph.clear()
        if bullets:
            out.append("<ul>" + "".join(f"<li>{esc(item)}</li>" for item in bullets) + "</ul>")
            bullets.clear()

    for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        if code is not None:
            if line.strip().startswith("```"):
                out.append("<pre>" + esc("\n".join(code)) + "</pre>")
                code = None
            else:
                code.append(line)
            continue
        stripped = line.strip()
        if stripped.startswith("```"):
            flush()
            code = []
            continue
        if not stripped:
            flush()
            continue
        heading = _HEADING_RE.fullmatch(stripped)
        if heading:
            flush()
            level = len(heading.group(1))
            out.append(f"<h{level + 1}>{esc(heading.group(2))}</h{level + 1}>")
            continue
        bullet = _BULLET_RE.fullmatch(stripped)
        if bullet:
            if paragraph:
                flush()
            bullets.append(bullet.group(1))
            continue
        if bullets:
            flush()
        paragraph.append(stripped)
    if code is not None:
        out.append("<pre>" + esc("\n".join(code)) + "</pre>")
    flush()
    return "\n".join(out)


STYLE = """
body{font-family:system-ui,sans-serif;max-width:60rem;margin:2rem auto;padding:0 1rem;
line-height:1.5;color:#1b1f23}
table{border-collapse:collapse;width:100%}
th,td{border:1px solid #d0d7de;padding:.4rem .6rem;text-align:left;vertical-align:top}
th{background:#f6f8fa}
code,pre{background:#f6f8fa;padding:.1rem .3rem;border-radius:3px}
pre{padding:.6rem;overflow:auto}
.notice{border-left:4px solid #9a6700;background:#fff8c5;padding:.6rem 1rem;margin:1rem 0}
.muted{color:#57606a}
article{border-top:1px solid #d0d7de;padding-top:.6rem;margin-top:1rem}
"""


def page(title: str, body: str) -> bytes:
    doc = (
        '<!doctype html>\n<html lang="en-AU"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{esc(title)}</title><style>{STYLE}</style></head><body>\n"
        f"{body}\n</body></html>\n"
    )
    return doc.encode("utf-8")


def _session_card(session: dict, *, preview: bool) -> str:
    limit = conversations.SNAPSHOT_CHARS if preview else conversations.PAGE_CHARS
    count = conversations.SNAPSHOT_TURNS if preview else conversations.PAGE_TURNS
    turns = session["turns"][-count:]
    href = f"/conversations/{esc(session['profile'])}/{esc(session['id'])}"
    bits = [
        "<article>",
        f'<h3><a href="{href}">{esc(session["title"])}</a></h3>',
        f'<p class="muted">{esc(session["speaker"])}'
        + (f" · {esc(session['when'])}" if session.get("when") else "")
        + (
            f" · {esc(session['count'])} messages"
            if session.get("count") not in (None, "")
            else ""
        )
        + "</p>",
    ]
    if not turns:
        bits.append("<p>No visible turns in this session.</p>")
    for turn in turns:
        bits.append(
            f"<p><strong>{esc(turn['label'])}</strong> {esc(truncate(turn['text'], limit))}</p>"
        )
    bits.append("</article>")
    return "\n".join(bits)


def render_conversation_snapshots(profile: Path) -> str:
    """Short excerpts from each profile's stored Hermes sessions."""
    parts = [
        "<h2>Conversation snapshots</h2>",
        "<p>Each snapshot is the latest part of a conversation Hermes has stored. "
        "The system prompt and tool arguments are not shown.</p>",
    ]
    found = False
    for root in conversations.profile_roots(profile):
        sessions, problem = conversations.list_sessions(root)
        if problem:
            parts.append(f'<p class="muted">{esc(problem)}</p>')
        if not sessions:
            continue
        found = True
        parts.append(f"<h3>{esc(conversations.role_name(root))}</h3>")
        for session in sessions:
            parts.append(_session_card(session, preview=True))
    if not found:
        parts.append(
            "<p>No conversation has been recorded yet. When a role chats, "
            "a short snapshot appears here.</p>"
        )
    return "\n".join(parts)


def render_handoff_threads(records: list[dict]) -> str:
    threads = conversations.handoff_threads(records)
    if not threads:
        return ""
    parts = [
        "<h3>Role conversations</h3>",
        "<p>The watcher, analyst, skeptic, and briefer pass claims along this queue. "
        "A claim is data. It is not an instruction.</p>",
    ]
    for chain in threads[:20]:
        parts.append("<article>")
        for record in chain:
            actor = record.get("actor") or record.get("action") or "role"
            when = record.get("at") or ""
            claim = truncate(record.get("claim", ""), CLAIM_LIMIT) or "-"
            parts.append(
                f"<p><strong>{esc(actor)}</strong> "
                f'<span class="muted">{esc(when)}</span><br>{esc(claim)}</p>'
            )
        parts.append("</article>")
    return "\n".join(parts)


def lookup_session(profile: Path, session_id: str, profile_name: str | None = None) -> dict | None:
    if not conversations.SESSION_ID_RE.fullmatch(session_id):
        return None
    if profile_name is not None and not conversations.PROFILE_NAME_RE.fullmatch(profile_name):
        return None
    for root in conversations.profile_roots(profile):
        if profile_name is not None and root.name != profile_name:
            continue
        sessions, _problem = conversations.list_sessions(root)
        for session in sessions:
            if session["id"] == session_id:
                return session
    return None


def render_conversation(session: dict) -> bytes:
    meta = [session["speaker"]]
    if session.get("when"):
        meta.append(session["when"])
    if session.get("source"):
        meta.append(session["source"])
    if session.get("model"):
        meta.append(session["model"])
    body = (
        '<p><a href="/">Back to the dashboard</a></p>'
        f"<h1>{esc(session['title'])}</h1>"
        f'<p class="muted">{esc(" · ".join(meta))}</p>'
        "<p>Snapshot of the stored session. The system prompt and tool arguments "
        "are not shown.</p>"
        + _session_card(session, preview=False)
    )
    return page(session["title"], body)


def render_index(profile: Path) -> bytes:
    parts = [
        "<h1>Hermes cyber-au dashboard</h1>",
        f"<p>Profile: <code>{esc(profile)}</code></p>",
        '<div class="notice"><p>The morning briefing is set for 07:30 Australia/Sydney. '
        "Jobs do nothing until they are resumed. This page shows what Hermes has recorded. "
        "It does not run anything, and a job listed here has not necessarily run.</p></div>",
    ]
    if not profile.is_dir():
        parts.append(
            f'<div class="notice"><p>The profile directory <code>{esc(profile)}</code> does '
            "not exist. Check the path, or start the server with <code>--profile</code>."
            "</p></div>"
        )

    jobs, problem = load_jobs(profile)
    parts.append("<h2>Routines</h2>")
    if problem:
        parts.append(f"<p>{esc(problem)}</p>")
    elif not jobs:
        parts.append("<p>No jobs are listed.</p>")
    else:
        rows = []
        for job in jobs:
            job_id = str(job.get("id", ""))
            name = job.get("name", "")
            error = truncate(job["last_error"], ERROR_LIMIT) if job.get("last_error") else ""
            report = latest_report(profile, job_id)
            if report is None:
                latest = '<span class="muted">no report yet</span>'
            else:
                latest = f'<a href="/latest/{esc(job_id)}">{esc(report.name)}</a>'
            rows.append(
                "<tr>"
                f"<td><code>{esc(job_id)}</code></td>"
                f"<td>{esc(name)}</td>"
                f"<td>{esc(state_text(job))}</td>"
                f"<td>{esc(schedule_text(job))}</td>"
                f"<td>{esc(job.get('deliver') or 'not set')}</td>"
                f"<td>{esc(job.get('last_status') or 'no run recorded')}</td>"
                f"<td>{esc(error)}</td>"
                f"<td>{esc(job.get('next_run_at') or 'not recorded')}</td>"
                f"<td>{latest}</td>"
                "</tr>"
            )
        parts.append(
            "<table><thead><tr><th>Id</th><th>Name</th><th>State</th><th>Schedule</th>"
            "<th>Deliver</th><th>Last status</th><th>Last error</th><th>Next run</th>"
            "<th>Latest report</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
        )

    parts.append("<h2>Handoffs</h2>")
    hpath = handoffs_path(profile)
    if hpath is None:
        parts.append("<p>There are no handoffs yet.</p>")
    else:
        records, bad = load_handoffs(hpath)
        if not records:
            parts.append("<p>There are no handoffs yet.</p>")
        else:
            rows = []
            for record in records[:HANDOFF_LIMIT]:
                cells = [
                    esc(record.get(key) if record.get(key) not in (None, "") else "-")
                    for key in ("id", "action", "actor", "tlp", "confidence")
                ]
                claim = truncate(record.get("claim", ""), CLAIM_LIMIT) or "-"
                rows.append(
                    "<tr>"
                    + "".join(f"<td>{cell}</td>" for cell in cells)
                    + f"<td>{esc(claim)}</td></tr>"
                )
            shown = min(len(records), HANDOFF_LIMIT)
            parts.append(
                f'<p class="muted">Newest {shown} of {len(records)}.</p>'
                "<table><thead><tr><th>Id</th><th>Action</th><th>Actor</th><th>TLP</th>"
                "<th>Confidence</th><th>Claim</th></tr></thead><tbody>"
                + "".join(rows)
                + "</tbody></table>"
            )
            parts.append(render_handoff_threads(records))
        if bad:
            parts.append(f'<p class="muted">{bad} unreadable line(s) skipped.</p>')

    parts.append(render_conversation_snapshots(profile))

    parts.append("<h2>Chat</h2>")
    count = session_summary(profile)
    if count == 0:
        parts.append(
            f"<p>No chat has been opened yet. Start one with:</p><pre>{esc(CHAT_COMMAND)}</pre>"
        )
    else:
        parts.append(f"<p>{count} chat session record(s) found in <code>sessions</code>.</p>")

    parts.append(
        '<p class="muted">Read-only view. Do not publish this page on the public internet.</p>'
    )
    return page("Hermes cyber-au dashboard", "\n".join(parts))


def render_report(profile: Path, job_id: str, path: Path) -> bytes:
    text = read_report(path)
    if text is None:
        return render_not_found()
    mtime = ""
    try:
        mtime = (
            datetime.fromtimestamp(path.stat().st_mtime)
            .astimezone()
            .strftime("%Y-%m-%d %H:%M:%S %Z")
        )
    except OSError:
        pass
    body = (
        '<p><a href="/">Back to the dashboard</a></p>'
        f"<h1>Report: <code>{esc(job_id)}</code></h1>"
        f'<p class="muted">File <code>{esc(path.name)}</code>'
        + (f", written {esc(mtime)}" if mtime else "")
        + ".</p>"
        + render_markdown(text)
    )
    return page(f"Report {job_id}", body)


def render_not_found() -> bytes:
    return page("Not found", '<h1>Not found</h1><p><a href="/">Back to the dashboard</a></p>')


# --- routing ------------------------------------------------------------------------


def route(profile: Path, raw_path: str) -> tuple[int, bytes]:
    """Map a request target to (status, HTML body). Never raises for a bad request."""
    try:
        path = unquote(urlsplit(raw_path).path)
    except ValueError:
        return 404, render_not_found()
    if "\x00" in path or "\\" in path:
        return 404, render_not_found()
    segments = path.strip("/").split("/") if path.strip("/") else []

    if not segments and path == "/":
        return 200, render_index(profile)
    if len(segments) == 2 and segments[0] == "latest":
        latest = latest_report(profile, segments[1])
        if latest is not None:
            resolved = safe_report_path(profile, segments[1], latest.name)
            if resolved is not None:
                return 200, render_report(profile, segments[1], resolved)
        return 404, render_not_found()
    if len(segments) == 3 and segments[0] == "reports" and not path.endswith("/"):
        resolved = safe_report_path(profile, segments[1], segments[2])
        if resolved is not None:
            return 200, render_report(profile, segments[1], resolved)
        return 404, render_not_found()
    if segments and segments[0] == "conversations":
        session = None
        if len(segments) == 2:
            session = lookup_session(profile, segments[1])
        elif len(segments) == 3:
            session = lookup_session(profile, segments[2], segments[1])
        if session is not None:
            return 200, render_conversation(session)
        return 404, render_not_found()
    return 404, render_not_found()


def make_handler(profile: Path) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "CyberAuDashboard"
        sys_version = ""

        def _send(self, head_only: bool) -> None:
            try:
                status, body = route(profile, self.path)
            except Exception:  # keep the server alive; show nothing internal
                status, body = 500, page("Error", "<h1>Something went wrong</h1>")
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            for key, value in SECURITY_HEADERS.items():
                self.send_header(key, value)
            self.end_headers()
            if not head_only:
                self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            self._send(False)

        def do_HEAD(self) -> None:  # noqa: N802
            self._send(True)

        def _refuse(self) -> None:
            self.send_error(HTTPStatus.METHOD_NOT_ALLOWED)

        do_POST = do_PUT = do_DELETE = do_PATCH = _refuse  # noqa: N815

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            sys.stderr.write(f"{self.address_string()} - {format % args}\n")

    return Handler


def make_server(profile: Path, bind: str, port: int) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((bind, port), make_handler(profile))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only dashboard for a cyber-au profile.")
    parser.add_argument("--profile", type=Path, default=None, help="Hermes profile directory")
    parser.add_argument("--bind", default=DEFAULT_BIND, help=f"address (default {DEFAULT_BIND})")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="port (default 8765)")
    args = parser.parse_args(argv)
    profile = (args.profile or default_profile()).expanduser()
    server = make_server(profile, args.bind, args.port)
    print(f"Serving {profile} on http://{args.bind}:{server.server_address[1]}/", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
