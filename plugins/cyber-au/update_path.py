"""Apply a cyber-au distribution update and migrate the intel store.

Distribution-owned files are replaced. Cron jobs merge by id and new jobs arrive
paused. `.env`, memories, the intel store, profile-root `backups/`, and local
`config.yaml` edits stay in place unless `force_config` is set.
"""

from __future__ import annotations

import io
import json
import os
import re
import shutil
import sqlite3
import subprocess
import tarfile
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

USER_OWNED_ROOTS = frozenset(
    {
        "memories",
        "sessions",
        "plans",
        "workspace",
        "home",
        "backups",
        "cache",
        "local",
        "logs",
        ".env",
        "auth.json",
        "plugin-data",
        "state.db",
        "state.db-shm",
        "state.db-wal",
        "credentials.json",
    }
)

# Authored cron fields. Scheduler state (enabled, paused, next run) is not in this set,
# so a job the operator enabled stays enabled. Matches Hermes job_definition.py.
JOB_DEFINITION_FIELDS = frozenset(
    {
        "name",
        "prompt",
        "skills",
        "skill",
        "model",
        "provider",
        "base_url",
        "script",
        "no_agent",
        "monitor_script",
        "monitor_url",
        "context_from",
        "schedule",
        "schedule_display",
        "deliver",
        "origin",
        "enabled_toolsets",
        "workdir",
        "attach_to_session",
        "reasoning_effort",
        "failure_deliver",
    }
)

PAUSED_REASON = "Installed from a profile distribution; review it, then resume."
_MIGRATION_RE = re.compile(r"^(\d{4})_.*\.sql$")
_TRANSACTION_WORDS = frozenset({"BEGIN", "COMMIT", "ROLLBACK", "END"})


class UpdateError(Exception):
    """The update stopped before it finished."""


class MigrationFailure(UpdateError):
    """A migration failed and the intel store was restored."""

    def __init__(self, message: str, backup: Path) -> None:
        super().__init__(message)
        self.backup = backup


@dataclass(frozen=True)
class Manifest:
    name: str
    version: str
    hermes_requires: str
    distribution_owned: list[str]


def read_manifest(path: Path) -> Manifest:
    """Read the distribution.yaml subset this updater needs."""
    if not path.is_file():
        raise UpdateError(f"No distribution manifest at {path}")
    data = _parse_simple_yaml(path.read_text(encoding="utf-8"))
    owned = data.get("distribution_owned") or []
    if not isinstance(owned, list):
        raise UpdateError(f"{path} distribution_owned must be a list")
    return Manifest(
        name=str(data.get("name") or ""),
        version=str(data.get("version") or ""),
        hermes_requires=str(data.get("hermes_requires") or ""),
        distribution_owned=[str(item) for item in owned],
    )


def intel_store_path(profile: Path) -> Path:
    return profile / "plugin-data" / "cyber-au" / "intel.sqlite"


def backup_dir(profile: Path) -> Path:
    return profile / "plugin-data" / "cyber-au" / "backups"


def repo_migrations() -> Path:
    return Path(__file__).resolve().parent / "store" / "migrations"


def resolve_migrations(profile: Path, override: Path | None = None) -> Path:
    if override is not None:
        return override
    shipped = profile / "plugins" / "cyber-au" / "store" / "migrations"
    if shipped.is_dir() and any(shipped.glob("[0-9][0-9][0-9][0-9]_*.sql")):
        return shipped
    return repo_migrations()


def list_migrations(directory: Path) -> list[Path]:
    if not directory.is_dir():
        return []
    found = [
        path for path in directory.iterdir() if path.is_file() and _MIGRATION_RE.match(path.name)
    ]
    return sorted(found, key=lambda path: path.name)


def migration_id(name: str) -> str:
    match = _MIGRATION_RE.match(name)
    if match:
        return match.group(1)
    if re.fullmatch(r"\d{4}", name):
        return name
    raise UpdateError(f"Migration name must look like NNNN_description.sql: {name}")


def apply_distribution(source: Path, profile: Path, *, force_config: bool = False) -> None:
    """Replace distribution-owned files in `profile` from `source`."""
    manifest = read_manifest(source / "distribution.yaml")
    profile.mkdir(parents=True, exist_ok=True)
    if _owns_cron(manifest.distribution_owned) and (source / "cron" / "jobs.json").is_file():
        merge_cron_store(source / "cron" / "jobs.json", profile / "cron" / "jobs.json")
    for rel in manifest.distribution_owned:
        _apply_entry(source, profile, rel, force_config=force_config)


def merge_cron_store(shipped_path: Path, dest_path: Path, *, now: str | None = None) -> None:
    """Merge shipped jobs into the profile store by id. New ids arrive paused."""
    shipped = _load_jobs(shipped_path)
    local = _load_jobs(dest_path) if dest_path.is_file() else []
    merged = _merge_jobs(local, shipped, now=now or datetime.now(UTC).isoformat())
    _save_jobs(dest_path, merged)


def applied_schema_ids(profile: Path) -> set[str]:
    """Return migration ids already recorded. Does not create or modify the store."""
    store = intel_store_path(profile)
    if not store.is_file() or store.is_symlink():
        return set()
    uri = store.resolve().as_uri() + "?mode=ro"
    try:
        conn = sqlite3.connect(uri, uri=True)
    except sqlite3.Error as exc:
        raise UpdateError(f"Could not read the intel store: {exc}") from exc
    try:
        exists = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'"
        ).fetchone()
        if exists is None:
            return set()
        rows = conn.execute("SELECT version FROM schema_migrations").fetchall()
    except sqlite3.Error as exc:
        raise UpdateError(f"Could not read schema versions: {exc}") from exc
    finally:
        conn.close()
    return {migration_id(str(row[0])) for row in rows}


def assert_store_can_move_to(profile: Path, migrations: Path) -> None:
    """Refuse when the target release does not contain every applied migration."""
    applied = applied_schema_ids(profile)
    if not applied:
        return
    target = {migration_id(path.name) for path in list_migrations(migrations)}
    missing = sorted(applied - target)
    if not missing:
        return
    current = max(applied)
    older = max(target) if target else "none"
    raise UpdateError(
        f"Refusing to downgrade the intel store from schema {current} to schema {older}. "
        "Store downgrades are not supported. The profile was left unchanged. "
        f"Applied migrations not in the target release: {', '.join(missing)}."
    )


def migrate(profile: Path, migrations: Path | None = None) -> None:
    """Apply pending SQL files in a transaction, after a store backup.

    On failure the store is put back and the backup path is printed.
    """
    directory = resolve_migrations(profile, migrations)
    pending = _pending_migrations(profile, directory)
    if not pending:
        return
    store = intel_store_path(profile)
    if store.is_symlink():
        raise UpdateError(f"Refusing to migrate through a symlinked intel store: {store}")
    _assert_inside(profile, store)
    existed = store.is_file()
    store.parent.mkdir(parents=True, exist_ok=True)
    if not existed:
        sqlite3.connect(store).close()
    backup: Path | None = None
    try:
        backup = _backup_store(profile, store)
        _apply_pending(store, pending)
    except (sqlite3.Error, UpdateError) as exc:
        if backup is None and not existed and store.exists() and not store.is_symlink():
            store.unlink()
        elif backup is not None:
            _restore_snapshot(backup, store, existed=existed)
        if isinstance(exc, MigrationFailure):
            raise
        name = getattr(exc, "migration_name", None) or "migration"
        detail = exc
        if backup is None:
            raise UpdateError(
                f"Migration {name} failed before a backup was written: {detail}"
            ) from exc
        message = (
            f"Migration {name} failed: {detail}. "
            "The intel store was left unchanged. "
            f"Backup: {backup}"
        )
        print(message)
        raise MigrationFailure(message, backup) from exc


def export_git_tag(repo: Path, tag: str, dest: Path) -> None:
    """Extract `tag` from a local git checkout. Does not fetch from a remote."""
    archive = subprocess.run(
        ["git", "-C", str(repo), "archive", "--format=tar", tag],
        check=False,
        capture_output=True,
    )
    if archive.returncode != 0:
        detail = archive.stderr.decode("utf-8", errors="replace").strip()
        raise UpdateError(f"Could not read tag {tag}: {detail or 'git archive failed'}")
    _extract_archive(archive.stdout, dest)


def run_update(
    *,
    profile_home: Path,
    profile: str = "cyber-au",
    source: Path | None = None,
    to_tag: str | None = None,
    force_config: bool = False,
    hermes_runner=None,
    bootstrap_runner=None,
    doctor_runner=None,
) -> int:
    """Update one profile, then bootstrap and doctor.

    `source` applies a local checkout. `to_tag` reinstalls that tag from `source`
    when `source` is a git checkout. With neither, Hermes runs `profile update`.
    """
    staging: Path | None = None
    try:
        if to_tag:
            repo = source or _git_root(Path(__file__).resolve())
            if repo is None:
                raise UpdateError("Pass --source as the git checkout that contains the tag.")
            staging = Path(tempfile.mkdtemp(prefix="cyber-au-update-"))
            export_git_tag(repo, to_tag, staging)
            assert_store_can_move_to(
                profile_home, staging / "plugins" / "cyber-au" / "store" / "migrations"
            )
            apply_distribution(staging, profile_home, force_config=force_config)
        elif source is not None:
            apply_distribution(source, profile_home, force_config=force_config)
        else:
            args = ["profile", "update", profile, "--yes"]
            if force_config:
                args.append("--force-config")
            runner = hermes_runner or default_hermes
            code = runner(args)
            if code != 0:
                return code
        boot = bootstrap_runner or default_bootstrap
        code = boot(profile_home, profile)
        if code != 0:
            return code
        doctor = doctor_runner or default_doctor
        return doctor(profile)
    finally:
        if staging is not None and staging.name.startswith("cyber-au-update-"):
            shutil.rmtree(staging, ignore_errors=True)


def default_hermes(args: list[str]) -> int:
    exe = shutil.which("hermes")
    if not exe:
        raise UpdateError("hermes is not on PATH. Pass --source to update from a local checkout.")
    completed = subprocess.run([exe, *args], check=False)
    return completed.returncode


def default_bootstrap(profile_home: Path, profile: str) -> int:
    script = find_bootstrap()
    completed = subprocess.run(
        [
            "sh",
            str(script),
            "--profile",
            profile,
            "--profile-home",
            str(profile_home),
        ],
        check=False,
    )
    return completed.returncode


def default_doctor(profile: str) -> int:
    exe = shutil.which("hermes")
    if not exe:
        print("doctor skipped: hermes is not on PATH")
        return 0
    completed = subprocess.run(
        [exe, "-p", profile, "cyber-au", "doctor"],
        check=False,
    )
    return completed.returncode


def default_profile_home(profile: str) -> Path:
    env_home = os.environ.get("HERMES_HOME")
    if env_home:
        return Path(env_home)
    exe = shutil.which("hermes")
    if exe:
        completed = subprocess.run(
            [exe, "-p", profile, "config", "path", "--home"],
            check=False,
            capture_output=True,
            text=True,
        )
        reported = completed.stdout.strip()
        if completed.returncode == 0 and reported:
            return Path(reported)
    return Path.home() / ".hermes" / "profiles" / profile


def find_bootstrap() -> Path:
    plugin_dir = Path(__file__).resolve().parent
    # Repo checkout: parents[1] is the repository root.
    # Installed profile: parents[1] is the profile root, which owns install/bootstrap.sh.
    candidate = plugin_dir.parents[1] / "install" / "bootstrap.sh"
    if candidate.is_file():
        return candidate
    raise UpdateError("install/bootstrap.sh was not found next to the cyber-au plugin")


def _git_root(start: Path) -> Path | None:
    for candidate in [start, *start.parents]:
        if (candidate / ".git").exists():
            return candidate
    return None


def _owns_cron(owned: list[str]) -> bool:
    return any(item.strip("/") in {"cron", "cron/jobs.json"} for item in owned)


def _apply_entry(source: Path, profile: Path, rel: str, *, force_config: bool) -> None:
    parts = tuple(part for part in rel.split("/") if part and part != ".")
    if not parts or ".." in parts or parts[0] in USER_OWNED_ROOTS or ".env" in parts:
        return
    if parts[0] == "cron":
        return
    src = source.joinpath(*parts)
    if not src.exists() or src.is_symlink():
        if src.is_symlink():
            raise UpdateError(f"Refusing to copy symlink {src}")
        return
    if parts == (".env.template",):
        _replace(src, profile / ".env.EXAMPLE", profile)
        return
    if parts == ("config.yaml",) and not force_config and (profile / "config.yaml").is_file():
        return
    dest = profile.joinpath(*parts)
    if src.is_dir() and len(parts) == 1:
        _merge_dir(src, dest, profile)
        return
    _replace(src, dest, profile)


def _merge_dir(src: Path, dest: Path, profile: Path) -> None:
    _assert_inside(profile, dest)
    dest.mkdir(parents=True, exist_ok=True)
    for child in src.iterdir():
        if child.name in USER_OWNED_ROOTS or child.name == ".env":
            continue
        if child.is_symlink():
            raise UpdateError(f"Refusing to copy symlink {child}")
        target = dest / child.name
        if child.is_dir():
            _replace(child, target, profile)
        else:
            _replace(child, target, profile)


def _replace(src: Path, dest: Path, profile: Path) -> None:
    if dest.name == ".env" or _is_user_owned(profile, dest):
        return
    _assert_inside(profile, dest)
    if dest.is_symlink():
        raise UpdateError(f"{dest} is a symlink; refusing to replace it")
    dest.parent.mkdir(parents=True, exist_ok=True)
    _refuse_nested_symlinks(src)
    if dest.is_dir() and not dest.is_symlink():
        shutil.rmtree(dest)
    elif dest.exists():
        dest.unlink()
    if src.is_dir():
        shutil.copytree(src, dest, symlinks=False)
        return
    shutil.copy2(src, dest)


def _refuse_nested_symlinks(src: Path) -> None:
    if src.is_symlink():
        raise UpdateError(f"Refusing to copy symlink {src}")
    if not src.is_dir():
        return
    for child in src.rglob("*"):
        if child.is_symlink():
            raise UpdateError(f"Refusing to copy symlink {child}")


def _is_user_owned(profile: Path, dest: Path) -> bool:
    try:
        rel = dest.resolve().relative_to(profile.resolve())
    except ValueError:
        return False
    return bool(rel.parts) and (rel.parts[0] in USER_OWNED_ROOTS or ".env" in rel.parts)


def _assert_inside(profile: Path, dest: Path) -> None:
    profile_root = profile.resolve()
    target = dest.resolve()
    if target != profile_root and profile_root not in target.parents:
        raise UpdateError(f"Refusing to write outside the profile: {dest}")


def _load_jobs(path: Path) -> list[dict]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise UpdateError(f"Could not read cron jobs {path}: {exc}") from exc
    if isinstance(data, dict):
        jobs = data.get("jobs", [])
    elif isinstance(data, list):
        jobs = data
    else:
        raise UpdateError(f"{path} must be a list or an object with a jobs list")
    if not isinstance(jobs, list):
        raise UpdateError(f"{path} jobs field must be a list")
    loaded: list[dict] = []
    for index, job in enumerate(jobs):
        if not isinstance(job, dict) or not job.get("id"):
            raise UpdateError(f"{path} job {index} needs an id")
        loaded.append(job)
    return loaded


def _save_jobs(path: Path, jobs: list[dict]) -> None:
    profile = path.parent.parent
    _assert_inside(profile, path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps({"jobs": jobs}, indent=2, ensure_ascii=False) + "\n"
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(payload, encoding="utf-8")
    temporary.replace(path)


def _merge_jobs(local: list[dict], shipped: list[dict], *, now: str) -> list[dict]:
    incoming = {str(job["id"]): job for job in shipped}
    merged: list[dict] = []
    seen: set[str] = set()
    for job in local:
        job_id = str(job["id"])
        authored = incoming.get(job_id)
        if authored is None:
            merged.append(job)
        else:
            merged.append(_merge_job(job, authored))
        seen.add(job_id)
    for job in shipped:
        job_id = str(job["id"])
        if job_id in seen:
            continue
        seed = {
            "id": job_id,
            "enabled": False,
            "state": "paused",
            "paused_at": now,
            "paused_reason": PAUSED_REASON,
            "created_at": now,
            "next_run_at": None,
        }
        merged.append(_merge_job(seed, job))
    return merged


def _merge_job(local: dict, authored: dict) -> dict:
    merged = {key: value for key, value in local.items() if key not in JOB_DEFINITION_FIELDS}
    for key in JOB_DEFINITION_FIELDS:
        if key in authored:
            merged[key] = authored[key]
    merged["id"] = local.get("id") or authored.get("id")
    if "repeat" in local or "repeat" in authored:
        local_repeat = local.get("repeat") if isinstance(local.get("repeat"), dict) else {}
        authored_repeat = authored.get("repeat") if isinstance(authored.get("repeat"), dict) else {}
        merged["repeat"] = {
            "completed": local_repeat.get("completed", 0),
            "times": authored_repeat.get("times"),
        }
    return merged


def _parse_simple_yaml(text: str) -> dict:
    """Parse scalars and one-level lists. Enough for distribution.yaml."""
    root: dict = {}
    current_key: str | None = None
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if raw[:1] in {" ", "\t"}:
            if current_key is None or not stripped.startswith("- "):
                continue
            root.setdefault(current_key, [])
            if not isinstance(root[current_key], list):
                root[current_key] = []
            root[current_key].append(_unquote(stripped[2:].strip()))
            continue
        if ":" not in stripped:
            continue
        key, _, value = stripped.partition(":")
        current_key = key.strip()
        value = value.strip()
        if value == "" or value == "|" or value == ">":
            root[current_key] = []
            continue
        root[current_key] = _unquote(value)
    return root


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value


def _pending_migrations(profile: Path, directory: Path) -> list[Path]:
    applied = applied_schema_ids(profile)
    pending = []
    for path in list_migrations(directory):
        if migration_id(path.name) not in applied:
            pending.append(path)
    return pending


def _backup_store(profile: Path, store: Path) -> Path:
    directory = backup_dir(profile)
    directory.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    candidate = directory / f"{stamp}-pre-migrate-intel.sqlite"
    counter = 2
    while candidate.exists():
        candidate = directory / f"{stamp}-pre-migrate-intel-{counter}.sqlite"
        counter += 1
    _snapshot(store, candidate)
    return candidate


def _snapshot(store: Path, dest: Path) -> None:
    source = sqlite3.connect(store)
    try:
        target = sqlite3.connect(dest)
        try:
            source.backup(target)
        finally:
            target.close()
    finally:
        source.close()


def _restore_snapshot(backup: Path, store: Path, *, existed: bool) -> None:
    for suffix in ("-wal", "-shm"):
        side = Path(f"{store}{suffix}")
        if side.exists() and not side.is_symlink():
            side.unlink()
    if not existed:
        if store.exists() and not store.is_symlink():
            store.unlink()
        return
    shutil.copy2(backup, store)


def _apply_pending(store: Path, pending: list[Path]) -> None:
    conn = sqlite3.connect(store)
    conn.isolation_level = None
    try:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations ("
            "version TEXT PRIMARY KEY, applied_at TEXT NOT NULL)"
        )
        for path in pending:
            try:
                statements = _split_sql(path.read_text(encoding="utf-8"))
            except UpdateError as exc:
                labelled = UpdateError(str(exc))
                labelled.migration_name = path.name  # type: ignore[attr-defined]
                raise labelled from exc
            stamp = datetime.now(UTC).isoformat()
            try:
                conn.execute("BEGIN")
                for statement in statements:
                    conn.execute(statement)
                conn.execute(
                    "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
                    (path.name, stamp),
                )
                conn.execute("COMMIT")
            except sqlite3.Error as exc:
                _rollback_quietly(conn)
                exc.migration_name = path.name  # type: ignore[attr-defined]
                raise
    finally:
        conn.close()


def _rollback_quietly(conn: sqlite3.Connection) -> None:
    try:
        conn.execute("ROLLBACK")
    except sqlite3.Error:
        pass


def _split_sql(script: str) -> list[str]:
    statements: list[str] = []
    buf: list[str] = []
    in_string = False
    index = 0
    length = len(script)
    while index < length:
        char = script[index]
        if in_string:
            buf.append(char)
            if char == "'":
                if index + 1 < length and script[index + 1] == "'":
                    buf.append("'")
                    index += 2
                    continue
                in_string = False
            index += 1
            continue
        if script.startswith("--", index):
            index = script.find("\n", index)
            if index < 0:
                break
            continue
        if char == "'":
            in_string = True
            buf.append(char)
            index += 1
            continue
        if char == ";":
            _push_statement(statements, "".join(buf))
            buf = []
            index += 1
            continue
        buf.append(char)
        index += 1
    _push_statement(statements, "".join(buf))
    return statements


def _push_statement(statements: list[str], raw: str) -> None:
    statement = raw.strip()
    if not statement:
        return
    first = statement.split(None, 1)[0].rstrip(";").upper()
    if first in _TRANSACTION_WORDS:
        raise UpdateError("Migration files must not manage transactions")
    statements.append(statement)


def _extract_archive(blob: bytes, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    root = dest.resolve()
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:") as archive:
        for member in archive.getmembers():
            if member.issym() or member.islnk() or member.isdev():
                raise UpdateError(f"Refusing archive member {member.name}")
            rel = Path(member.name)
            if rel.is_absolute() or ".." in rel.parts:
                raise UpdateError(f"Refusing archive path {member.name}")
            target = root.joinpath(*rel.parts).resolve()
            if target != root and root not in target.parents:
                raise UpdateError(f"Refusing archive path {member.name}")
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            extracted = archive.extractfile(member)
            if extracted is None:
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(extracted.read())
            mode = member.mode & 0o777
            if mode:
                target.chmod(mode)
