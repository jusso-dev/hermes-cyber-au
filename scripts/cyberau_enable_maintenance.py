"""Enable safe local maintenance once; preserve later operator pause choices."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

JOBS = ("cyberau-store-expire", "cyberau-store-maintenance")
SEEDED_REASON = "Installed from a profile distribution; review it, then resume."


def enable(profile: Path, name: str) -> None:
    if profile.is_symlink():
        raise ValueError("profile must not be a symlink")
    profile = profile.resolve()
    state = profile / "plugin-data" / "cyber-au" / "maintenance-enabled.json"
    if any(p.is_symlink() for p in (state, *state.parents)):
        raise ValueError("maintenance state must not contain symlinks")
    done = set(json.loads(state.read_text()) if state.exists() else [])
    payload = json.loads((profile / "cron" / "jobs.json").read_text())
    jobs = payload.get("jobs", []) if isinstance(payload, dict) else payload
    for job in jobs:
        job_id = job["id"]
        if job_id not in JOBS or job_id in done:
            continue
        if (
            job.get("paused_reason") == SEEDED_REASON
            and not job.get("last_run_at")
            and job.get("no_agent") is True
            and job.get("deliver") == "local"
            and job.get("script") == job_id.replace("-", "_") + ".sh"
        ):
            selected = subprocess.run(
                ["hermes", "-p", name, "config", "path"],
                check=True,
                capture_output=True,
                text=True,
            )
            if Path(selected.stdout.strip()).parent.resolve() != profile:
                raise ValueError("Hermes profile selection does not match --profile-home")
            subprocess.run(["hermes", "-p", name, "cron", "resume", job_id], check=True)
        done.add(job_id)
        state.parent.mkdir(parents=True, exist_ok=True)
        temporary = state.with_suffix(".tmp")
        if temporary.is_symlink():
            raise ValueError("maintenance state must not be a symlink")
        temporary.write_text(json.dumps(sorted(done)) + "\n")
        temporary.replace(state)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile-home", type=Path, required=True)
    parser.add_argument("--profile", required=True)
    args = parser.parse_args()
    enable(args.profile_home, args.profile)
