"""Health checks for a cyber-au profile. Read-only unless --fix is set.

The profile ``.env`` is never opened. Mode is taken from ``lstat`` only.
Secret values are not written into check text.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from urllib.parse import quote

import yaml

SNAPSHOT_MAX_AGE_DAYS = 7
WAL_WARN_BYTES = 64 * 1024 * 1024
_VERSION = re.compile(r"(\d+)\.(\d+)\.(\d+)")
_RANGE = re.compile(r"^(>=|<=|>|<|==)\s*(\d+\.\d+\.\d+)\s*$")
_PLACEHOLDER = re.compile(r"\$\{(?:env:)?([A-Za-z_][A-Za-z0-9_]*)\}")
_STORE_TABLES = (
    "schema_version",
    "sources",
    "indicators",
    "observations",
    "vulnerabilities",
    "advisories",
)
_COUNT_TABLES = ("indicators", "observations", "vulnerabilities", "advisories")
_SAFE_ENV = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "SYSTEMROOT")
_SNAPSHOTS = (
    ("snapshot.ism", "ISM", ("asd-ism",)),
    ("snapshot.e8", "Essential Eight", ("e8", "asd-essentials", "essentials")),
    ("snapshot.attack", "ATT&CK", ("attack", "mitre-attack")),
    ("snapshot.kev", "KEV", ("cisa-kev",)),
)

Health = Callable[[str, bool], tuple[int, str]]
VersionFn = Callable[[], str]


@dataclass
class Check:
    id: str
    status: str
    detail: str
    fix: str = ""

    def to_dict(self) -> dict:
        payload = {"id": self.id, "status": self.status, "detail": self.detail}
        if self.fix:
            payload["fix"] = self.fix
        return payload


@dataclass
class Report:
    version: str
    checks: list[Check]
    actions: list[str] = field(default_factory=list)

    def exit_code(self) -> int:
        return 1 if any(item.status == "fail" for item in self.checks) else 0

    def to_dict(self) -> dict:
        payload: dict = {
            "version": self.version,
            "checks": [item.to_dict() for item in self.checks],
        }
        if self.actions:
            payload["actions"] = list(self.actions)
        return payload


@dataclass
class Context:
    root: Path
    home: Path
    environ: Mapping[str, str]
    offline: bool
    today: date
    hermes_version: VersionFn
    health: Health

    @property
    def data_dir(self) -> Path:
        override = self.environ.get("CYBERAU_DATA_DIR")
        if override:
            path = Path(override).expanduser()
            if not path.is_absolute():
                path = self.root / path
            return path
        return self.home / "plugin-data" / "cyber-au"


def distribution_root() -> Path:
    override = os.environ.get("CYBERAU_ROOT")
    if override:
        return Path(override).expanduser()
    candidate = Path(__file__).resolve().parents[2]
    if (candidate / "distribution.yaml").is_file():
        return candidate
    home = os.environ.get("HERMES_HOME")
    if home and (Path(home).expanduser() / "distribution.yaml").is_file():
        return Path(home).expanduser()
    return candidate


def profile_home(root: Path) -> Path:
    home = os.environ.get("HERMES_HOME")
    if home:
        return Path(home).expanduser()
    return root


def execute(
    *,
    root: Path | None = None,
    home: Path | None = None,
    offline: bool = False,
    fix: bool = False,
    environ: Mapping[str, str] | None = None,
    today: date | None = None,
    hermes_version: VersionFn | None = None,
    health: Health | None = None,
) -> Report:
    env = environ if environ is not None else os.environ
    base = root or distribution_root()
    ctx = Context(
        root=base,
        home=home or profile_home(base),
        environ=env,
        offline=offline,
        today=_resolve_today(env, today),
        hermes_version=hermes_version or default_hermes_version,
        health=health or default_health(base, env),
    )
    actions: list[str] = []
    if fix:
        actions = [redact(action, env) for action in apply_fixes(ctx)]
    checks = collect_checks(ctx)
    return Report(version=_distribution_version(ctx.root), checks=checks, actions=actions)


def collect_checks(ctx: Context) -> list[Check]:
    checks = [
        check_hermes_version(ctx),
        check_plugin_enabled(ctx),
        check_plugin_tools(ctx),
        check_venv(ctx),
    ]
    checks.extend(check_connectors(ctx))
    checks.extend(check_store(ctx))
    checks.extend(check_snapshots(ctx))
    checks.append(check_cron(ctx))
    checks.extend(check_security(ctx))
    return [_sealed(item, ctx.environ) for item in checks]


def check_hermes_version(ctx: Context) -> Check:
    spec = _hermes_requires(ctx.root)
    if not spec:
        return _item(
            "hermes.version",
            "fail",
            "hermes_requires is missing from distribution.yaml",
            "Set hermes_requires in distribution.yaml, for example >=0.22.2.",
        )
    if _RANGE.match(spec) is None:
        return _item(
            "hermes.version",
            "fail",
            "hermes_requires is not a version range",
            "Use a range such as >=0.22.2.",
        )
    try:
        raw = ctx.hermes_version()
    except (OSError, subprocess.TimeoutExpired):
        raw = ""
    found = _parse_version(raw or "")
    if found is None:
        return _item(
            "hermes.version",
            "fail",
            "hermes is not available",
            f"Install Hermes {spec} and re-run cyber-au doctor.",
        )
    if not _satisfies(found, spec):
        text = ".".join(str(part) for part in found)
        return _item(
            "hermes.version",
            "fail",
            f"Hermes {text} does not satisfy {spec}",
            "Run hermes update so the installed Hermes meets hermes_requires.",
        )
    text = ".".join(str(part) for part in found)
    return _item("hermes.version", "ok", f"Hermes {text} satisfies {spec}")


def check_plugin_enabled(ctx: Context) -> Check:
    config, problem = _load_mapping(_config_path(ctx))
    if problem == "invalid":
        return _item(
            "plugin.enabled",
            "fail",
            "config.yaml could not be parsed",
            "Fix config.yaml, then run hermes plugins enable cyber-au.",
        )
    profile = _profile_name(ctx.root)
    enabled = _enabled_plugins(config or {})
    if "cyber-au" in enabled:
        return _item("plugin.enabled", "ok", "plugin cyber-au is enabled")
    return _item(
        "plugin.enabled",
        "fail",
        "plugin cyber-au is not enabled",
        f"Run hermes -p {profile} plugins enable cyber-au.",
    )


def check_plugin_tools(ctx: Context) -> Check:
    plugin_dir = ctx.root / "plugins" / "cyber-au"
    manifest_path = plugin_dir / "plugin.yaml"
    if not manifest_path.is_file():
        return _item(
            "plugin.tools",
            "fail",
            "plugins/cyber-au is not installed",
            "Install the cyber-au plugin from this distribution.",
        )
    manifest, problem = _load_mapping(manifest_path)
    if problem:
        return _item(
            "plugin.tools",
            "fail",
            "plugin.yaml could not be parsed",
            "Repair plugins/cyber-au/plugin.yaml.",
        )
    declared = [
        item
        for item in (manifest or {}).get("provides_tools") or []
        if isinstance(item, str)
    ]
    registered, error = _registered_tools(plugin_dir)
    if error:
        return _item(
            "plugin.tools",
            "fail",
            error,
            "Repair plugins/cyber-au so register() loads.",
        )
    missing = [name for name in declared if name not in registered]
    extra = [name for name in registered if name not in declared]
    if missing or extra:
        parts = []
        if missing:
            parts.append("missing " + ", ".join(missing))
        if extra:
            parts.append("extra " + ", ".join(extra))
        return _item(
            "plugin.tools",
            "fail",
            "registered tools do not match provides_tools: " + "; ".join(parts),
            "Make provides_tools list the same tools register() registers.",
        )
    if declared:
        detail = "registered tools match provides_tools"
    else:
        detail = "no tools declared and none registered"
    return _item("plugin.tools", "ok", detail)


def check_venv(ctx: Context) -> Check:
    venv = ctx.root / "mcp" / ".venv"
    lock = ctx.root / "mcp" / "uv.lock"
    if not lock.is_file():
        return _item(
            "mcp.venv",
            "fail",
            "mcp/uv.lock is missing",
            "Restore mcp/uv.lock, then run install/bootstrap.sh.",
        )
    if not venv.is_dir():
        return _item(
            "mcp.venv",
            "fail",
            "mcp/.venv is not present",
            "Run install/bootstrap.sh to create mcp/.venv from mcp/uv.lock.",
        )
    expected = _file_sha256(lock)
    stamp_path = venv / ".cyberau-lock-sha256"
    if not stamp_path.is_file():
        return _item(
            "mcp.venv",
            "fail",
            "lockfile hash is not recorded",
            "Re-run install/bootstrap.sh so mcp/.venv records the uv.lock hash.",
        )
    recorded = stamp_path.read_text(encoding="utf-8").strip()
    if recorded != expected:
        return _item(
            "mcp.venv",
            "fail",
            "lockfile hash does not match mcp/uv.lock",
            "Re-run install/bootstrap.sh so the venv matches mcp/uv.lock.",
        )
    return _item("mcp.venv", "ok", "mcp/.venv is present and matches the lockfile")


def check_connectors(ctx: Context) -> list[Check]:
    catalogue, catalogue_problem = _server_catalogue(ctx.root)
    config, config_problem = _load_mapping(_config_path(ctx))
    if config_problem == "invalid":
        return [
            _item(
                "connector.servers",
                "fail",
                "config.yaml could not be parsed",
                "Fix config.yaml before checking connectors.",
            )
        ]
    rendered = (config or {}).get("mcp_servers") or {}
    if not isinstance(rendered, dict):
        return [
            _item(
                "connector.servers",
                "fail",
                "mcp_servers is not a mapping",
                "Set mcp_servers to a mapping in config.yaml.",
            )
        ]
    if catalogue_problem == "invalid":
        return [
            _item(
                "connector.servers",
                "fail",
                "mcp/servers.yaml could not be parsed",
                "Repair mcp/servers.yaml.",
            )
        ]
    names = list(rendered) if rendered else list(catalogue)
    if not names:
        return [
            _item(
                "connector.servers",
                "warn",
                "no mcp servers are configured",
                "Render mcp_servers from mcp/servers.yaml with install/bootstrap.sh.",
            )
        ]
    checks = []
    for name in names:
        if not isinstance(name, str):
            continue
        base = dict(catalogue.get(name) or {})
        overlay = rendered.get(name) or {}
        if isinstance(overlay, dict):
            base.update(overlay)
        base["name"] = name
        checks.append(_connector_check(ctx, name, base, from_config=bool(rendered)))
    return checks


def check_store(ctx: Context) -> list[Check]:
    path = ctx.data_dir / "intel.sqlite"
    if not path.is_file():
        return [
            _item(
                "store.schema",
                "fail",
                "intel store is not initialised",
                "Run cyberau-mcp store init.",
            )
        ]
    uri = "file://" + quote(path.resolve().as_posix()) + "?mode=ro"
    try:
        connection = sqlite3.connect(uri, uri=True)
    except sqlite3.Error:
        return [
            _item(
                "store.schema",
                "fail",
                "intel store could not be read",
                "Restore plugin-data/cyber-au/intel.sqlite from a backup.",
            )
        ]
    try:
        return _store_checks(ctx, connection, path)
    finally:
        connection.close()


def check_snapshots(ctx: Context) -> list[Check]:
    return [_snapshot_check(ctx, spec) for spec in _SNAPSHOTS]


def check_cron(ctx: Context) -> Check:
    path = _jobs_path(ctx)
    if path is None:
        return _item(
            "cron.jobs",
            "fail",
            "cron/jobs.json is missing",
            "Restore cron/jobs.json from the distribution.",
        )
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return _item(
            "cron.jobs",
            "fail",
            "cron/jobs.json could not be parsed",
            "Repair cron/jobs.json so jobs is a list.",
        )
    jobs = payload.get("jobs") if isinstance(payload, dict) else None
    if not isinstance(jobs, list):
        return _item(
            "cron.jobs",
            "fail",
            "cron/jobs.json jobs is not a list",
            "Set jobs to a list in cron/jobs.json.",
        )
    if not jobs:
        return _item(
            "cron.jobs",
            "warn",
            "no cron jobs are shipped",
            "Add the paused routines to cron/jobs.json.",
        )
    parts: list[str] = []
    statuses: list[str] = []
    failed_id = ""
    for job in jobs:
        if not isinstance(job, dict):
            parts.append("one job is not an object")
            statuses.append("fail")
            continue
        job_id = str(job.get("id") or job.get("name") or "job")
        state = _job_state(job)
        last = _last_run_status(job)
        if state == "unknown":
            statuses.append("warn")
            parts.append(f"{job_id} pause state is not recorded")
            continue
        if last and last.lower() in {"fail", "failed", "error"}:
            statuses.append("fail")
            failed_id = failed_id or job_id
            parts.append(f"{job_id} {state}, last run failed")
            continue
        if state == "enabled" and not last:
            statuses.append("warn")
            parts.append(f"{job_id} enabled, no run yet")
            continue
        statuses.append("ok")
        if last:
            parts.append(f"{job_id} {state}, last run {last}")
        else:
            parts.append(f"{job_id} {state}, no run yet")
    status = _worst(statuses)
    fix = ""
    if failed_id:
        fix = f"Inspect the last run of {failed_id} with hermes cron."
    elif status == "warn":
        fix = "Record paused or enabled on each job, then resume the ones you want."
    return _item("cron.jobs", status, "; ".join(parts), fix)


def check_security(ctx: Context) -> list[Check]:
    return [
        _check_private_urls(ctx),
        _check_audit(ctx),
        _check_egress(ctx),
        _check_env_mode(ctx),
    ]


def apply_fixes(ctx: Context) -> list[str]:
    """Create the audit directory, chmod 600 .env, and re-run bootstrap."""
    actions: list[str] = []
    audit = ctx.data_dir / "audit"
    if not audit.is_dir():
        try:
            audit.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass
        if audit.is_dir():
            actions.append("created the audit log directory")
    env_path = ctx.home / ".env"
    try:
        info = os.lstat(env_path)
    except OSError:
        info = None
    if (
        info is not None
        and stat.S_ISREG(info.st_mode)
        and not stat.S_ISLNK(info.st_mode)
        and stat.S_IMODE(info.st_mode) != 0o600
    ):
        try:
            os.chmod(env_path, 0o600)
        except OSError:
            pass
        else:
            actions.append("chmod 600 .env")
    actions.extend(_maybe_bootstrap(ctx))
    return actions


def format_text(report: Report) -> str:
    lines = [f"cyber-au doctor {report.version}"]
    if report.actions:
        lines.append("actions:")
        for action in report.actions:
            lines.append(f"  - {action}")
    for item in report.checks:
        lines.append(f"{item.status:4}  {item.id}  {item.detail}")
        if item.fix:
            lines.append(f"      fix: {item.fix}")
    failed = sum(1 for item in report.checks if item.status == "fail")
    warnings = sum(1 for item in report.checks if item.status == "warn")
    lines.append(f"{failed} failed, {warnings} warnings")
    return "\n".join(lines) + "\n"


def format_json(report: Report) -> str:
    return json.dumps(report.to_dict(), indent=2) + "\n"


def default_hermes_version() -> str:
    proc = subprocess.run(
        ["hermes", "--version"],
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    return (proc.stdout or "") + (proc.stderr or "")


def default_health(root: Path, environ: Mapping[str, str]) -> Health:
    def run(name: str, live: bool) -> tuple[int, str]:
        binary = _health_binary(root)
        if binary is None:
            return 127, "cyberau-mcp is not installed"
        flag = "--live" if live else "--offline"
        try:
            proc = subprocess.run(
                [str(binary), "health", name, flag],
                check=False,
                capture_output=True,
                text=True,
                timeout=60 if live else 20,
                env=_probe_env(environ, live=live),
            )
        except subprocess.TimeoutExpired:
            return 1, "health probe timed out"
        except OSError:
            return 127, "cyberau-mcp could not be started"
        output = redact((proc.stdout or "") + (proc.stderr or ""), environ)
        return proc.returncode, output.strip()

    return run


def redact(text: str, environ: Mapping[str, str]) -> str:
    cleaned = text
    values = sorted(
        {value for value in environ.values() if isinstance(value, str) and len(value) >= 8},
        key=len,
        reverse=True,
    )
    for value in values:
        if value in cleaned:
            cleaned = cleaned.replace(value, "[redacted]")
    return cleaned


def _connector_check(ctx: Context, name: str, spec: dict, *, from_config: bool) -> Check:
    check_id = f"connector.{name}"
    key = _connector_key(spec, name)
    if not _connector_installed(ctx.root, key):
        return _item(
            check_id,
            "fail",
            "not installed",
            f"Install the {key} connector.",
        )
    enabled = _is_enabled(spec)
    parts = ["enabled" if enabled else "disabled"]
    statuses = ["ok" if enabled else "warn"]
    findings = _env_findings(spec, ctx.environ, enabled=enabled)
    for status, detail in findings:
        statuses.append(status)
        parts.append(detail)
    probe_status, probe_detail = _probe(ctx, _health_target(spec, key), enabled=enabled)
    statuses.append(probe_status)
    parts.append(probe_detail)
    if not from_config:
        parts.append("read from mcp/servers.yaml")
    status = _worst(statuses)
    fix = _connector_fix(name, findings, probe_status, enabled)
    return _item(check_id, status, "; ".join(parts), fix)


def _probe(ctx: Context, target: str, *, enabled: bool) -> tuple[str, str]:
    code, output = ctx.health(target, False)
    offline_ok = code == 0
    if not offline_ok:
        detail = _short(output) or "offline probe failed"
        return "fail", f"offline probe failed: {detail}"
    if ctx.offline or not enabled:
        why = "doctor --offline" if ctx.offline else "server is disabled"
        return "ok", f"offline probe passed; live probe skipped ({why})"
    live_code, live_output = ctx.health(target, True)
    if live_code != 0:
        detail = _short(live_output) or "live probe failed"
        return "fail", f"offline probe passed; live probe failed: {detail}"
    return "ok", "offline probe passed; live probe passed"


def _env_findings(
    spec: dict, environ: Mapping[str, str], *, enabled: bool
) -> list[tuple[str, str]]:
    required = {
        item for item in (spec.get("required_env") or []) if isinstance(item, str)
    }
    findings: list[tuple[str, str]] = []
    seen: set[str] = set()
    env_field = spec.get("env")
    if isinstance(env_field, dict):
        for key, value in env_field.items():
            if not isinstance(key, str):
                continue
            if isinstance(value, str) and "${" not in value and value.strip():
                findings.append(("fail", f"{key} is set to a literal value"))
                seen.add(key)
                continue
            for name in _PLACEHOLDER.findall(value if isinstance(value, str) else ""):
                if name in seen:
                    continue
                seen.add(name)
                findings.extend(
                    _presence(name, required=name in required, enabled=enabled, environ=environ)
                )
    elif isinstance(env_field, list):
        for item in env_field:
            if not isinstance(item, str):
                continue
            if "${" not in item and "=" in item and item.split("=", 1)[1].strip():
                key = item.split("=", 1)[0].strip()
                findings.append(("fail", f"{key} is set to a literal value"))
                seen.add(key)
                continue
            for name in _PLACEHOLDER.findall(item):
                if name in seen:
                    continue
                seen.add(name)
                findings.extend(
                    _presence(name, required=name in required, enabled=enabled, environ=environ)
                )
    for name in required:
        if name not in seen:
            findings.extend(_presence(name, required=True, enabled=enabled, environ=environ))
    return [item for item in findings if item[0] != "ok"]


def _presence(
    name: str, *, required: bool, enabled: bool, environ: Mapping[str, str]
) -> list[tuple[str, str]]:
    if _env_present(name, environ):
        return [("ok", f"{name} is set")]
    if required and enabled:
        return [("fail", f"{name} is not set")]
    return [("warn", f"{name} is not set")]


def _connector_fix(
    name: str,
    findings: list[tuple[str, str]],
    probe_status: str,
    enabled: bool,
) -> str:
    if probe_status == "fail":
        return f"Run cyberau-mcp health for {name} and install/bootstrap.sh if the venv is missing."
    literals = [detail for status, detail in findings if "literal" in detail and status == "fail"]
    if literals:
        return "Replace literal mcp server env values with ${VAR} placeholders."
    missing = [
        detail.split(" ", 1)[0]
        for status, detail in findings
        if detail.endswith("is not set")
    ]
    if missing:
        names = ", ".join(missing)
        return (
            f"Export {names} in the profile environment. "
            "hermes -p cyber-au loads .env without printing the value."
        )
    if not enabled:
        return f"Set mcp_servers.{name}.enabled to true when this source should run."
    return ""


def _store_checks(ctx: Context, connection: sqlite3.Connection, path: Path) -> list[Check]:
    schema = _schema_check(ctx, connection)
    if schema.status == "fail":
        return [schema]
    rows = _row_check(connection)
    ingest = _ingest_check(connection)
    wal = _wal_check(path)
    return [schema, rows, ingest, wal]


def _schema_check(ctx: Context, connection: sqlite3.Connection) -> Check:
    try:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
    except sqlite3.Error:
        return _item(
            "store.schema",
            "fail",
            "intel store could not be read",
            "Restore plugin-data/cyber-au/intel.sqlite from a backup.",
        )
    missing = [name for name in _STORE_TABLES if name not in tables]
    if missing:
        return _item(
            "store.schema",
            "fail",
            "intel store is missing " + ", ".join(missing),
            "Run the store migrations in plugins/cyber-au/store/migrations.",
        )
    try:
        row = connection.execute("SELECT MAX(version) FROM schema_version").fetchone()
    except sqlite3.Error:
        return _item(
            "store.schema",
            "fail",
            "schema version could not be read",
            "Run the store migrations in plugins/cyber-au/store/migrations.",
        )
    version = None if row is None else row[0]
    if not isinstance(version, int):
        return _item(
            "store.schema",
            "fail",
            "schema version is missing",
            "Run the store migrations in plugins/cyber-au/store/migrations.",
        )
    expected = _expected_schema(ctx.root)
    if expected is not None and version != expected:
        return _item(
            "store.schema",
            "fail",
            f"schema version {version}, expected {expected}",
            "Run the store migrations in plugins/cyber-au/store/migrations.",
        )
    return _item("store.schema", "ok", f"schema version {version}")


def _row_check(connection: sqlite3.Connection) -> Check:
    counts = []
    try:
        for table in _COUNT_TABLES:
            row = connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
            counts.append(f"{table} {row[0]}")
    except sqlite3.Error:
        return _item(
            "store.rows",
            "fail",
            "row counts could not be read",
            "Run the store migrations in plugins/cyber-au/store/migrations.",
        )
    return _item("store.rows", "ok", ", ".join(counts))


def _ingest_check(connection: sqlite3.Connection) -> Check:
    try:
        rows = connection.execute(
            "SELECT source_id, MAX(observed_at) FROM observations GROUP BY source_id"
        ).fetchall()
    except sqlite3.Error:
        return _item(
            "store.ingest",
            "fail",
            "last ingest could not be read",
            "Run the store migrations in plugins/cyber-au/store/migrations.",
        )
    if not rows:
        return _item(
            "store.ingest",
            "warn",
            "no ingests recorded",
            "Run the public ingest job once the cron scripts are installed.",
        )
    parts = []
    for source_id, observed_at in rows:
        parts.append(f"{source_id} {observed_at}")
    return _item("store.ingest", "ok", "; ".join(parts))


def _wal_check(path: Path) -> Check:
    wal = path.parent / f"{path.name}-wal"
    try:
        size = wal.stat().st_size if wal.is_file() else 0
    except OSError:
        return _item(
            "store.wal",
            "fail",
            "WAL size could not be read",
            "Check the intel store directory is readable.",
        )
    detail = f"WAL is {size} bytes"
    if size > WAL_WARN_BYTES:
        return _item(
            "store.wal",
            "warn",
            detail,
            "Checkpoint the intel store when the routines maintenance job is installed.",
        )
    return _item("store.wal", "ok", detail)


def _snapshot_check(ctx: Context, spec: tuple[str, str, tuple[str, ...]]) -> Check:
    check_id, label, directories = spec
    directory = _snapshot_dir(ctx.root, directories)
    if directory is None:
        return _item(
            check_id,
            "warn",
            "not installed",
            f"Install the {label} connector.",
        )
    version, day, problem = _read_snapshot(check_id, directory)
    if problem:
        return _item(
            check_id,
            "fail",
            problem,
            f"Refresh the {label} snapshot.",
        )
    if day is None:
        return _item(
            check_id,
            "warn",
            f"{label} {_version_phrase(check_id, version)} has no date",
            f"Refresh the {label} snapshot.",
        )
    days = (ctx.today - day).days
    phrase = _age_phrase(days)
    detail = f"{label} {_version_phrase(check_id, version)}, {phrase}"
    if days > SNAPSHOT_MAX_AGE_DAYS or days < 0:
        return _item(
            check_id,
            "warn",
            detail,
            f"Refresh the {label} snapshot. It is older than 7 days."
            if days > SNAPSHOT_MAX_AGE_DAYS
            else f"Refresh the {label} snapshot. The date is in the future.",
        )
    return _item(check_id, "ok", detail)


def _read_snapshot(check_id: str, directory: Path) -> tuple[str, date | None, str]:
    if check_id == "snapshot.ism":
        return _read_ism(directory)
    if check_id == "snapshot.kev":
        return _read_kev(directory)
    return _read_dated_manifest(directory)


def _read_ism(directory: Path) -> tuple[str, date | None, str]:
    path = directory / "data" / "releases.json"
    if not path.is_file():
        return "", None, "snapshot is missing"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return "", None, "snapshot could not be read"
    rows = payload.get("releases") if isinstance(payload, dict) else None
    if not isinstance(rows, list) or not rows:
        return "", None, "snapshot is missing"
    chosen = ""
    chosen_day: date | None = None
    for row in rows:
        if not isinstance(row, dict):
            continue
        tag = str(row.get("tag_name") or "")
        day = parse_day(str(row.get("published_at") or ""))
        if chosen_day is None or (day is not None and day >= chosen_day):
            chosen = tag or chosen
            chosen_day = day or chosen_day
    if not chosen:
        return "", None, "snapshot is missing"
    return chosen, chosen_day, ""


def _read_kev(directory: Path) -> tuple[str, date | None, str]:
    path = directory / "data" / "kev.json"
    if not path.is_file():
        return "", None, "snapshot is missing"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return "", None, "snapshot could not be read"
    if not isinstance(payload, dict):
        return "", None, "snapshot could not be read"
    version = str(payload.get("catalogVersion") or "")
    if not version:
        return "", None, "snapshot is missing"
    day = parse_day(str(payload.get("dateReleased") or "")) or parse_day(version)
    return version, day, ""


def _read_dated_manifest(directory: Path) -> tuple[str, date | None, str]:
    path = directory / "data" / "manifest.json"
    if not path.is_file():
        return "", None, "snapshot is missing"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return "", None, "snapshot could not be read"
    if not isinstance(payload, dict):
        return "", None, "snapshot could not be read"
    version = str(payload.get("version") or payload.get("data_date") or "")
    day = parse_day(str(payload.get("data_date") or payload.get("published_at") or version))
    if not version and day is None:
        return "", None, "snapshot is missing"
    return version, day, ""


def _version_phrase(check_id: str, version: str) -> str:
    if check_id == "snapshot.ism":
        return f"release {version}"
    if check_id == "snapshot.kev":
        return f"catalogue version {version}"
    if check_id == "snapshot.attack":
        return f"version {version}"
    return f"data date {version}" if version else "data date"


def _check_private_urls(ctx: Context) -> Check:
    config, problem = _load_mapping(_config_path(ctx))
    if problem == "invalid":
        return _item(
            "security.private_urls",
            "fail",
            "config.yaml could not be parsed",
            "Set security.allow_private_urls to false in config.yaml.",
        )
    security = (config or {}).get("security") or {}
    if not isinstance(security, dict) or "allow_private_urls" not in security:
        return _item(
            "security.private_urls",
            "fail",
            "security.allow_private_urls is not set",
            "Set security.allow_private_urls to false in config.yaml.",
        )
    if security.get("allow_private_urls") is False:
        return _item("security.private_urls", "ok", "security.allow_private_urls is false")
    return _item(
        "security.private_urls",
        "fail",
        "security.allow_private_urls is not false",
        "Set security.allow_private_urls to false in config.yaml.",
    )


def _check_audit(ctx: Context) -> Check:
    directory = ctx.data_dir / "audit"
    if not directory.exists():
        return _item(
            "security.audit_log",
            "fail",
            "audit log directory is missing",
            "Create plugin-data/cyber-au/audit, or re-run cyber-au doctor --fix.",
        )
    if not directory.is_dir() or not os.access(directory, os.W_OK):
        return _item(
            "security.audit_log",
            "fail",
            "audit log directory is not writable",
            "Make plugin-data/cyber-au/audit a directory you can write to.",
        )
    return _item("security.audit_log", "ok", "audit log directory is writable")


def _check_egress(ctx: Context) -> Check:
    path = ctx.root / "mcp" / "egress-allowlist.yaml"
    payload, problem = _load_mapping(path)
    if problem == "missing":
        return _item(
            "security.egress",
            "fail",
            "egress allowlist is missing",
            "Restore mcp/egress-allowlist.yaml.",
        )
    if problem:
        return _item(
            "security.egress",
            "fail",
            "egress allowlist could not be parsed",
            "Repair mcp/egress-allowlist.yaml.",
        )
    connectors = (payload or {}).get("connectors")
    if not isinstance(connectors, dict) or not connectors:
        return _item(
            "security.egress",
            "fail",
            "egress allowlist has no connectors",
            "Add a connectors mapping to mcp/egress-allowlist.yaml.",
        )
    missing = []
    for name, spec in _installed_servers(ctx):
        key = _connector_key(spec, name)
        entry = connectors.get(key)
        hosts = entry.get("hosts") if isinstance(entry, dict) else None
        if not hosts:
            missing.append(key)
    if missing:
        return _item(
            "security.egress",
            "fail",
            "egress allowlist has no hosts for " + ", ".join(missing),
            "Add those connectors to mcp/egress-allowlist.yaml.",
        )
    return _item(
        "security.egress",
        "ok",
        f"egress allowlist loaded for {len(connectors)} connectors",
    )


def _check_env_mode(ctx: Context) -> Check:
    """Report ``.env`` mode. The file is not opened."""
    env_path = ctx.home / ".env"
    try:
        info = os.lstat(env_path)
    except OSError:
        return _item(
            "security.env_mode",
            "warn",
            ".env is not present",
            "Copy .env.template to .env and run chmod 600 .env.",
        )
    if stat.S_ISLNK(info.st_mode):
        return _item(
            "security.env_mode",
            "fail",
            ".env is a symlink",
            "Replace the .env symlink with a regular file mode 600.",
        )
    if not stat.S_ISREG(info.st_mode):
        return _item(
            "security.env_mode",
            "fail",
            ".env is not a regular file",
            "Replace .env with a regular file mode 600.",
        )
    mode = stat.S_IMODE(info.st_mode)
    if mode != 0o600:
        return _item(
            "security.env_mode",
            "fail",
            f".env mode is {mode:03o}",
            "Run chmod 600 .env.",
        )
    return _item("security.env_mode", "ok", ".env mode is 600")


def _maybe_bootstrap(ctx: Context) -> list[str]:
    if not _venv_needs_bootstrap(ctx):
        return []
    script = ctx.root / "install" / "bootstrap.sh"
    if not script.is_file():
        return []
    profile = _profile_name(ctx.root)
    command = ["sh", str(script), "--profile", profile, "--non-interactive"]
    if ctx.offline:
        command.append("--offline")
    try:
        proc = subprocess.run(
            command,
            check=False,
            cwd=ctx.root,
            capture_output=True,
            text=True,
            timeout=180,
            env=_child_env(ctx),
        )
    except (OSError, subprocess.TimeoutExpired):
        return ["re-ran install/bootstrap.sh, exit 1"]
    if proc.returncode == 0:
        return ["re-ran install/bootstrap.sh"]
    return [f"re-ran install/bootstrap.sh, exit {proc.returncode}"]


def _venv_needs_bootstrap(ctx: Context) -> bool:
    venv = ctx.root / "mcp" / ".venv"
    lock = ctx.root / "mcp" / "uv.lock"
    if not lock.is_file() or not venv.is_dir():
        return True
    stamp = venv / ".cyberau-lock-sha256"
    if not stamp.is_file():
        return True
    return stamp.read_text(encoding="utf-8").strip() != _file_sha256(lock)


def _installed_servers(ctx: Context) -> list[tuple[str, dict]]:
    catalogue, problem = _server_catalogue(ctx.root)
    if problem:
        catalogue = {}
    config, config_problem = _load_mapping(_config_path(ctx))
    rendered = {}
    if not config_problem and isinstance(config, dict):
        candidate = config.get("mcp_servers") or {}
        if isinstance(candidate, dict):
            rendered = candidate
    names = list(rendered) if rendered else list(catalogue)
    servers = []
    for name in names:
        if not isinstance(name, str):
            continue
        spec = dict(catalogue.get(name) or {})
        overlay = rendered.get(name) or {}
        if isinstance(overlay, dict):
            spec.update(overlay)
        if _connector_installed(ctx.root, _connector_key(spec, name)):
            servers.append((name, spec))
    return servers


def _server_catalogue(root: Path) -> tuple[dict, str]:
    payload, problem = _load_mapping(root / "mcp" / "servers.yaml")
    if problem:
        return {}, problem
    servers = (payload or {}).get("servers")
    if servers is None:
        return {}, ""
    if not isinstance(servers, dict):
        return {}, "invalid"
    return servers, ""


def _connector_installed(root: Path, key: str) -> bool:
    if (root / "mcp" / key / "pyproject.toml").is_file():
        return True
    stub = root / "mcp" / "common" / "src" / "cyberau_common" / "stub.py"
    return key == "stub" and stub.is_file()


def _snapshot_dir(root: Path, names: tuple[str, ...]) -> Path | None:
    for name in names:
        directory = root / "mcp" / name
        if (directory / "pyproject.toml").is_file():
            return directory
    return None


def _connector_key(spec: dict, name: str) -> str:
    connector = spec.get("connector")
    if isinstance(connector, str) and connector:
        return connector
    return name


def _health_target(spec: dict, key: str) -> str:
    args = spec.get("args") or []
    if isinstance(args, list) and "serve" in args:
        index = args.index("serve")
        if index + 1 < len(args) and isinstance(args[index + 1], str):
            return args[index + 1]
    return key


def _is_enabled(spec: dict) -> bool:
    if "enabled" in spec:
        return bool(spec.get("enabled"))
    if "enabled_by_default" in spec:
        return bool(spec.get("enabled_by_default"))
    return True


def _enabled_plugins(config: dict) -> set[str]:
    plugins = config.get("plugins") or {}
    if not isinstance(plugins, dict):
        return set()
    enabled = plugins.get("enabled")
    found: set[str] = set()
    if isinstance(enabled, list):
        for item in enabled:
            if isinstance(item, str):
                found.add(item)
            elif isinstance(item, dict) and isinstance(item.get("name"), str):
                found.add(item["name"])
    elif isinstance(enabled, dict):
        for name, value in enabled.items():
            if value:
                found.add(str(name))
    return found


def _registered_tools(plugin_dir: Path) -> tuple[list[str], str]:
    init = plugin_dir / "__init__.py"
    if not init.is_file():
        return [], "plugins/cyber-au is not installed"
    name = f"cyberau_doctor_plugin_{_load_count()}"
    spec = importlib.util.spec_from_file_location(
        name,
        init,
        submodule_search_locations=[str(plugin_dir)],
    )
    if spec is None or spec.loader is None:
        return [], "plugin could not be loaded"
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
        recorder = _Recorder()
        module.register(recorder)
    except Exception as exc:
        return [], f"plugin could not be loaded ({type(exc).__name__})"
    return recorder.tools, ""


class _Recorder:
    def __init__(self) -> None:
        self.tools: list[str] = []

    def register_tool(self, name: str | None = None, **kwargs) -> None:
        tool = name or kwargs.get("name")
        if isinstance(tool, str):
            self.tools.append(tool)

    def __getattr__(self, _name: str):
        def _noop(*_args, **_kwargs):
            return None

        return _noop


_LOADS = 0


def _load_count() -> int:
    global _LOADS
    _LOADS += 1
    return _LOADS


def _expected_schema(root: Path) -> int | None:
    directory = root / "plugins" / "cyber-au" / "store" / "migrations"
    if not directory.is_dir():
        return None
    numbers = []
    for path in directory.glob("*.sql"):
        match = re.match(r"(\d+)", path.name)
        if match:
            numbers.append(int(match.group(1)))
    return max(numbers) if numbers else None


def _jobs_path(ctx: Context) -> Path | None:
    home_jobs = ctx.home / "cron" / "jobs.json"
    root_jobs = ctx.root / "cron" / "jobs.json"
    if home_jobs.is_file():
        return home_jobs
    if root_jobs.is_file():
        return root_jobs
    return None


def _job_state(job: dict) -> str:
    if "paused" in job:
        return "paused" if job.get("paused") else "enabled"
    if "enabled" in job:
        return "enabled" if job.get("enabled") else "paused"
    state = str(job.get("state") or "").lower()
    if state in {"paused", "disabled"}:
        return "paused"
    if state in {"enabled", "active"}:
        return "enabled"
    return "unknown"


def _last_run_status(job: dict) -> str | None:
    for key in ("last_status", "last_run_status"):
        value = job.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    last = job.get("last_run")
    if isinstance(last, dict):
        value = last.get("status")
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _config_path(ctx: Context) -> Path:
    home_config = ctx.home / "config.yaml"
    if home_config.is_file():
        return home_config
    return ctx.root / "config.yaml"


def _profile_name(root: Path) -> str:
    payload, problem = _load_mapping(root / "distribution.yaml")
    if problem or not isinstance(payload, dict):
        return "cyber-au"
    name = payload.get("name")
    if isinstance(name, str) and name.strip():
        return name.strip()
    return "cyber-au"


def _distribution_version(root: Path) -> str:
    payload, problem = _load_mapping(root / "distribution.yaml")
    if problem or not isinstance(payload, dict):
        return "unknown"
    version = payload.get("version")
    if version is None:
        return "unknown"
    return str(version)


def _hermes_requires(root: Path) -> str:
    payload, problem = _load_mapping(root / "distribution.yaml")
    if problem or not isinstance(payload, dict):
        return ""
    spec = payload.get("hermes_requires")
    if not isinstance(spec, str):
        return ""
    return spec.strip()


def _load_mapping(path: Path) -> tuple[dict | None, str]:
    if not path.is_file():
        return None, "missing"
    try:
        text = path.read_text(encoding="utf-8")
        data = yaml.safe_load(text)
    except (OSError, UnicodeError, yaml.YAMLError):
        return None, "invalid"
    if data is None:
        return {}, ""
    if not isinstance(data, dict):
        return None, "invalid"
    return data, ""


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _health_binary(root: Path) -> Path | None:
    candidates = (
        root / "mcp" / ".venv" / "bin" / "cyberau-mcp",
        root / "mcp" / ".venv" / "Scripts" / "cyberau-mcp.exe",
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    found = shutil.which("cyberau-mcp")
    if found:
        return Path(found)
    return None


def _probe_env(environ: Mapping[str, str], *, live: bool) -> dict[str, str]:
    base: dict[str, str] = {}
    for key in _SAFE_ENV:
        value = os.environ.get(key)
        if value:
            base[key] = value
    for key, value in environ.items():
        if key in _SAFE_ENV or key.startswith("CYBERAU_") or key == "HERMES_HOME":
            base[key] = value
        elif live and _credential_name(key):
            base[key] = value
    return base


def _credential_name(key: str) -> bool:
    return key.endswith(("_API_KEY", "_TOKEN", "_AUTH_KEY", "_PASSWORD"))


def _child_env(ctx: Context) -> dict[str, str]:
    base = {}
    for key in _SAFE_ENV:
        value = os.environ.get(key)
        if value:
            base[key] = value
    for key, value in ctx.environ.items():
        if key.startswith("CYBERAU_") or key == "HERMES_HOME":
            base[key] = value
    return base


def _resolve_today(environ: Mapping[str, str], today: date | None) -> date:
    if today is not None:
        return today
    parsed = parse_day(environ.get("CYBERAU_TODAY", ""))
    if parsed is not None:
        return parsed
    return date.today()


def parse_day(value: str) -> date | None:
    text = value.strip()
    if not text:
        return None
    if re.fullmatch(r"\d{4}\.\d{2}\.\d{2}", text):
        text = text.replace(".", "-")
    if "T" in text:
        text = text.split("T", 1)[0]
    try:
        return date.fromisoformat(text)
    except ValueError:
        return None


def _parse_version(text: str) -> tuple[int, int, int] | None:
    match = _VERSION.search(text)
    if match is None:
        return None
    major, minor, patch = (int(part) for part in match.groups())
    return major, minor, patch


def _satisfies(found: tuple[int, int, int], spec: str) -> bool:
    match = _RANGE.match(spec)
    if match is None:
        return False
    op, raw = match.groups()
    required = _parse_version(raw)
    if required is None:
        return False
    if op == ">=":
        return found >= required
    if op == "<=":
        return found <= required
    if op == ">":
        return found > required
    if op == "<":
        return found < required
    return found == required


def _age_phrase(days: int) -> str:
    if days == 1:
        return "1 day old"
    if days == -1:
        return "1 day in the future"
    if days < 0:
        return f"{-days} days in the future"
    return f"{days} days old"


def _env_present(name: str, environ: Mapping[str, str]) -> bool:
    value = environ.get(name)
    return isinstance(value, str) and value.strip() != ""


def _short(text: str) -> str:
    cleaned = " ".join(text.split())
    if len(cleaned) > 180:
        return cleaned[:180]
    return cleaned


def _worst(statuses: list[str]) -> str:
    if "fail" in statuses:
        return "fail"
    if "warn" in statuses:
        return "warn"
    return "ok"


def _item(check_id: str, status: str, detail: str, fix: str = "") -> Check:
    if status == "ok":
        fix = ""
    return Check(check_id, status, detail, fix)


def _sealed(item: Check, environ: Mapping[str, str]) -> Check:
    return Check(
        item.id,
        item.status,
        redact(item.detail, environ),
        redact(item.fix, environ),
    )
