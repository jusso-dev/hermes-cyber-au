"""Apply one profile overlay onto a Hermes home.

Hermes installs one home from a distribution. The five organisation roles are
overlays applied afterwards. This module does not edit a git checkout, and it
does not create or change skills.
"""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

from cyberau_hindsight.constants import CONNECTOR_KEYS, OVERLAY_FLAGS, ROLES


def apply_overlay(role: str, home: Path, distribution: Path) -> Path:
    if role not in ROLES:
        raise ValueError(f"unknown profile role {role}")
    home = Path(home).resolve()
    distribution = Path(distribution).resolve()
    if _is_git_checkout(home) or (
        home != distribution and _is_git_checkout(distribution) and _is_inside(home, distribution)
    ):
        raise ValueError("refusing to edit SOUL.md in a git checkout")
    overlay = _overlay_dir(distribution, role)
    _validate_overlay(role, overlay)
    home.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(overlay / "SOUL.md", home / "SOUL.md")
    cron = home / "cron"
    cron.mkdir(parents=True, exist_ok=True)
    shipped = json.loads((overlay / "cron" / "jobs.json").read_text(encoding="utf-8"))["jobs"]
    merged = _merge_jobs(home / "cron" / "jobs.json", shipped)
    (cron / "jobs.json").write_text(
        json.dumps({"jobs": merged}, indent=2) + "\n",
        encoding="utf-8",
    )
    shutil.copyfile(overlay / "env.template", home / ".env.EXAMPLE")
    marker = home / "plugin-data" / "cyber-au"
    marker.mkdir(parents=True, exist_ok=True)
    (marker / "profile-role").write_text(role + "\n", encoding="utf-8")
    return home


def validate_distribution(distribution: Path) -> None:
    root = Path(distribution)
    for role in ROLES:
        _validate_overlay(role, _overlay_dir(root, role))


def _validate_overlay(role: str, overlay: Path) -> None:
    flags = _flat_yaml((overlay / "overlay.yaml").read_text(encoding="utf-8"))
    expected = OVERLAY_FLAGS[role]
    if flags.get("role") != role:
        raise ValueError(f"{role} overlay.yaml names a different role")
    for key, value in expected.items():
        if flags.get(key) is not value:
            raise ValueError(f"{role} overlay.yaml {key} must be {value}")
    soul = (overlay / "SOUL.md").read_text(encoding="utf-8")
    if "\u2014" in soul or "\u2013" in soul:
        raise ValueError(f"{role} SOUL contains a dash character this slice does not use")
    template = (overlay / "env.template").read_text(encoding="utf-8")
    if f"CYBERAU_PROFILE_ROLE={role}" not in template:
        raise ValueError(f"{role} env template must name its role")
    for name in CONNECTOR_KEYS:
        present = name in template
        if expected["holds_connector_keys"] and not present:
            raise ValueError(f"watcher env template is missing {name}")
        if not expected["holds_connector_keys"] and present:
            raise ValueError(f"{role} must not carry connector key {name}")
    read_only_line = "HINDSIGHT_READ_ONLY=1" in template
    if expected["hindsight_read_only"] and not read_only_line:
        raise ValueError(f"{role} must set Hindsight read-only")
    if not expected["hindsight_read_only"] and read_only_line:
        raise ValueError(f"{role} must not set Hindsight read-only")
    jobs = json.loads((overlay / "cron" / "jobs.json").read_text(encoding="utf-8"))["jobs"]
    if len(jobs) != 1:
        raise ValueError(f"{role} must ship one job")
    job = jobs[0]
    if job.get("paused") is not True or job.get("enabled") is not False:
        raise ValueError(f"{role} job must arrive paused")
    deliver = job.get("deliver")
    if expected["may_deliver_to_owner"]:
        if deliver != "origin":
            raise ValueError("briefer job must deliver to the owner")
    elif deliver != "local":
        raise ValueError("only the briefer may deliver to the owner")
    prompt = str(job.get("prompt") or "")
    if "http://" in prompt or "https://" in prompt:
        raise ValueError(f"{role} job prompt must not carry a feed URL")


def _merge_jobs(path: Path, shipped: list[dict]) -> list[dict]:
    existing: list[dict] = []
    if path.exists():
        loaded = json.loads(path.read_text(encoding="utf-8"))
        existing = [item for item in loaded.get("jobs") or [] if isinstance(item, dict)]
    prior = {item["id"]: item for item in existing if "id" in item}
    merged = []
    seen = set()
    for job in shipped:
        seen.add(job["id"])
        item = dict(job)
        old = prior.get(job["id"])
        if old is None:
            item["paused"] = True
            item["enabled"] = False
        else:
            item["paused"] = bool(old.get("paused", True))
            item["enabled"] = bool(old.get("enabled", False))
        merged.append(item)
    for job in existing:
        if job.get("id") not in seen:
            merged.append(job)
    return merged


def _overlay_dir(distribution: Path, role: str) -> Path:
    overlay = Path(distribution) / "profiles" / "overlays" / role
    if not (overlay / "SOUL.md").is_file():
        raise ValueError(f"missing overlay for {role}")
    return overlay


def _flat_yaml(text: str) -> dict:
    data: dict = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        key, raw = stripped.split(":", 1)
        value = raw.strip().strip('"').strip("'")
        if value == "true":
            parsed: object = True
        elif value == "false":
            parsed = False
        else:
            parsed = value
        data[key.strip()] = parsed
    return data


def _is_git_checkout(path: Path) -> bool:
    return (path / ".git").exists()


def _is_inside(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _default_distribution() -> Path:
    root = Path(__file__).resolve().parents[4]
    if not (root / "distribution.yaml").is_file():
        raise ValueError("pass --distribution pointing at the hermes-cyber-au checkout")
    return root


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cyberau-profiles")
    parser.add_argument("--role", required=True, choices=ROLES)
    parser.add_argument("--home", required=True)
    parser.add_argument("--distribution", default=None)
    args = parser.parse_args(argv)
    distribution = Path(args.distribution) if args.distribution else _default_distribution()
    apply_overlay(args.role, Path(args.home), distribution)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
