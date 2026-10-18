"""Copy optional keys from the environment into the profile .env.

Codespaces secrets are environment variables. This writes only names listed in
``env_requires`` of distribution.yaml, creates the file with mode 600, and
prints names, never values. A name already set in the file is left alone.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

_NAME = re.compile(r"^\s*-\s*name:\s*([A-Z][A-Z0-9_]*)\s*$")
_SET = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\S")


def wanted_names(manifest: Path) -> list[str]:
    names = []
    for line in manifest.read_text(encoding="utf-8").splitlines():
        match = _NAME.match(line)
        if match:
            names.append(match.group(1))
    return names


def already_set(env_file: Path) -> set[str]:
    if not env_file.is_file():
        return set()
    found = set()
    for line in env_file.read_text(encoding="utf-8").splitlines():
        match = _SET.match(line)
        if match:
            found.add(match.group(1))
    return found


def main(argv: list[str]) -> int:
    manifest, env_file = Path(argv[0]), Path(argv[1])
    present = already_set(env_file)
    added = []
    lines = []
    for name in wanted_names(manifest):
        value = os.environ.get(name, "")
        if not value or name in present or "\n" in value:
            continue
        lines.append(f"{name}={value}\n")
        added.append(name)
    if not added:
        print("No Codespaces secrets to copy. The profile runs on public sources.")
        return 0
    old_umask = os.umask(0o077)
    try:
        with env_file.open("a", encoding="utf-8") as handle:
            handle.writelines(lines)
    finally:
        os.umask(old_umask)
    env_file.chmod(0o600)
    print("Copied into the profile .env: " + ", ".join(added))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
