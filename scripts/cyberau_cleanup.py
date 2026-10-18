"""Prune only disposable distribution artefacts. Dry run unless --apply is set."""

from __future__ import annotations

import argparse
import fcntl
import json
import re
import sqlite3
import time
from pathlib import Path

DAY = 86400
PACKAGES = {"sigma_core.zip", "sigma_core+.zip", "sigma_emerging_threats_addon.zip"}


def safe(path: Path, root: Path) -> bool:
    """Never follow a symlink, including an intermediate directory."""
    return path.is_relative_to(root) and not any(
        part.is_symlink() for part in (path, *path.parents) if part != root.parent
    )


def older_files(directory: Path, pattern: str, now: float, *, keep: int = 7) -> list[Path]:
    if not directory.is_dir() or not safe(directory, directory):
        return []
    files = [
        p
        for p in directory.iterdir()
        if re.fullmatch(pattern, p.name) and p.is_file() and safe(p, directory)
    ]
    files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return [p for p in files[keep:] if p.stat().st_mtime < now - 30 * DAY]


def candidates(profile: Path, now: float) -> list[Path]:
    data = profile / "plugin-data" / "cyber-au"
    files = older_files(data / "backups", r"\d{8}T\d{6}Z-pre-migrate-intel(?:-\d+)?\.sqlite", now)
    files += older_files(
        profile / "intel" / "snapshots", r"public-\d{4}-\d{2}-\d{2}\.sqlite\.zst", now
    )
    # Sigma saves downloaded packages directly under CYBERAU_DATA_DIR/tag.
    releases = []
    if data.is_dir() and safe(data, profile):
        for directory in data.iterdir():
            if not directory.is_dir() or not safe(directory, profile):
                continue
            children = list(directory.iterdir())
            if children and all(
                p.name in PACKAGES and p.is_file() and safe(p, profile) for p in children
            ):
                releases.append((max(p.stat().st_mtime for p in children), children))
    releases.sort(key=lambda entry: entry[0], reverse=True)
    for modified, children in releases[2:]:
        if modified < now - 30 * DAY:
            files.extend(children)
    # Only script-only maintenance/ingest output is disposable. Briefings stay.
    for job in (
        "cyberau-store-expire",
        "cyberau-store-maintenance",
        "cyberau-ingest-asd",
        "cyberau-ingest-auscert",
        "cyberau-ingest-feodo",
        "cyberau-ingest-kev",
        "cyberau-ingest-epss",
    ):
        files += older_files(
            profile / "cron" / "output" / job, r"\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}\.md", now
        )
    return [p for p in files if safe(p, profile)]


def cleanup(profile: Path, *, apply: bool = False, now: float | None = None) -> dict:
    if profile.is_symlink():
        raise ValueError("profile must not be a symlink")
    # Resolve the caller-selected root (macOS /var is a system symlink), then
    # refuse all symlinks inside that boundary.
    profile = profile.resolve()
    moment = time.time() if now is None else now
    data = profile / "plugin-data" / "cyber-au"
    if not safe(data, profile):
        raise ValueError("data directory must not contain symlinks")
    data.mkdir(parents=True, exist_ok=True)
    lock = data / ".cleanup.lock"
    if not safe(lock, profile):
        raise ValueError("cleanup lock must not be a symlink")
    with lock.open("a") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        files = candidates(profile, moment)
        result = {
            "apply": apply,
            "files": len(files),
            "file_bytes": sum(p.stat().st_size for p in files),
            "cache_rows": 0,
            "cache_bytes_reclaimed": 0,
        }
        cache = data / "http_cache.sqlite"
        if cache.is_file():
            if not all(
                safe(Path(str(cache) + suffix), profile)
                for suffix in ("", "-wal", "-shm", "-journal")
            ):
                raise ValueError("cache must not contain symlinks")
            before = cache.stat().st_size
            # Preserve a week beyond TTL for offline/stale fallback. Only HTTP
            # responses are touched, never connector state or the intel store.
            uri = cache.as_uri() + ("?mode=rw" if apply else "?mode=ro")
            conn = sqlite3.connect(uri, uri=True, timeout=30)
            try:
                condition = "fetched_at + ttl + ? < ?"
                params = (7 * DAY, moment)
                result["cache_rows"] = conn.execute(
                    f"SELECT count(*) FROM http_cache WHERE {condition}", params
                ).fetchone()[0]
                if apply:
                    with conn:
                        conn.execute(f"DELETE FROM http_cache WHERE {condition}", params)
                    conn.execute("VACUUM")
                    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                    result["cache_bytes_reclaimed"] = max(0, before - cache.stat().st_size)
            finally:
                conn.close()
        if apply:
            for path in files:
                if not safe(path, profile):
                    raise ValueError("cleanup candidate became a symlink")
                path.unlink()
        return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile-home", type=Path, required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    print(json.dumps(cleanup(args.profile_home, apply=args.apply), sort_keys=True))
