"""``hermes cyber-au setup``: write org.yaml, pick connectors, render config, run doctor.

Interactive by default. ``--from-file answers.yaml`` runs without prompts for fleet installs
and tests. Key values are never asked for or written: setup records variable names only, and
the values stay in the profile ``.env``. Nothing here uses the network or contacts anyone.

Steps:

1. Read answers (prompts or file) and validate them with the org.yaml contract.
2. Note which connector key names are set in ``.env`` (names only) and pick connectors:
   keyless default-on connectors on, keyed ones only when every required name is present,
   licence-gated, paid and local-setup connectors left off.
3. Write ``plugin-data/cyber-au/org.yaml`` (mode 600). An existing file needs ``--force``.
4. Seed ``watchlists.yaml`` with the domains and brands, only if no watchlist exists.
5. Render ``config.yaml`` with ``install/render_config.py`` and run ``doctor --offline``.
"""

from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path

if __package__:
    from .store import org_setup
    from .store.org import OrgFileError, write_org
    from .store.org_context import build_context
    from .store.paths import profile_data_dir
else:
    from store import org_setup
    from store.org import OrgFileError, write_org
    from store.org_context import build_context
    from store.paths import profile_data_dir


def add_parser(subs) -> argparse.ArgumentParser:
    parser = subs.add_parser(
        "setup",
        help="Describe the organisation, write org.yaml and pick connectors",
        description=(
            "Ask about the organisation (sector, size, regulators, IT, OT or cloud, domains, "
            "brands and which key names you have), write org.yaml, render config and run "
            "doctor. Key values are never asked for."
        ),
    )
    parser.add_argument(
        "--from-file",
        type=Path,
        default=None,
        help="Answers YAML for a non-interactive run (see docs/getting-started/setup.md)",
    )
    parser.add_argument("--force", action="store_true", help="Replace an existing org.yaml")
    parser.add_argument("--no-render", action="store_true", help="Do not render config.yaml")
    parser.add_argument("--no-doctor", action="store_true", help="Do not run doctor afterwards")
    return parser


def _distribution_root(profile_home: Path) -> Path:
    """The profile home when it holds the distribution, else this checkout."""
    if (profile_home / "mcp" / "servers.yaml").is_file():
        return profile_home
    return Path(__file__).resolve().parents[2]


def _load_yaml(path: Path) -> object:
    import yaml

    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _render(root: Path, profile_home: Path) -> int:
    script = root / "install" / "render_config.py"
    if not script.is_file():
        print(f"render_config.py was not found under {root}; config.yaml not rendered")
        return 1
    spec = importlib.util.spec_from_file_location("cyberau_setup_render_config", script)
    if spec is None or spec.loader is None:
        return 1
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    data = profile_home / "plugin-data" / "cyber-au"
    return module.main(
        [
            "--profile-home",
            str(profile_home),
            "--servers",
            str(root / "mcp" / "servers.yaml"),
            "--config",
            str(profile_home / "config.yaml"),
            "--env-file",
            str(profile_home / ".env"),
            "--managed",
            str(data / "managed-servers.json"),
            "--status",
            str(data / "bootstrap-status.json"),
        ]
    )


def _doctor(root: Path, profile_home: Path) -> int:
    if __package__:
        from .doctor import execute, format_text
    else:
        from doctor import execute, format_text
    report = execute(root=root, home=profile_home, offline=True)
    sys.stdout.write(format_text(report))
    return report.exit_code()


def run(args: argparse.Namespace, *, profile_home: Path, ask=input) -> int:
    root = _distribution_root(profile_home)
    try:
        servers = (_load_yaml(root / "mcp" / "servers.yaml") or {}).get("servers") or {}
    except (OSError, ValueError) as exc:
        print(f"mcp/servers.yaml could not be read: {exc}", file=sys.stderr)
        return 1
    data_dir = profile_data_dir(profile_home)
    target = data_dir / "org.yaml"
    if target.exists() and not getattr(args, "force", False):
        print(f"{target} already exists. Pass --force to replace it.", file=sys.stderr)
        return 1
    env_set = org_setup.env_names(profile_home / ".env")

    source = getattr(args, "from_file", None)
    try:
        if source is not None:
            answers = _load_yaml(Path(source))
        elif sys.stdin is not None and sys.stdin.isatty():
            answers = org_setup.ask_answers(ask, servers, env_set)
        else:
            print("No terminal for prompts. Pass --from-file answers.yaml.", file=sys.stderr)
            return 2
        profile, warnings = org_setup.profile_from_answers(answers, servers=servers)
    except (OSError, ValueError) as exc:
        # OrgFileError and yaml.YAMLError are ValueErrors. Neither message echoes a value.
        print(f"Setup answers were not used: {exc}", file=sys.stderr)
        return 1
    except (EOFError, KeyboardInterrupt):
        print("\nSetup cancelled. Nothing was written.", file=sys.stderr)
        return 1

    profile = org_setup.finish_profile(profile, servers, env_set)
    selection = org_setup.select_connectors(servers, set(profile.keys_present))
    try:
        written = write_org(profile, target, force=bool(getattr(args, "force", False)))
    except (OrgFileError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(f"Wrote {written}")
    for line in warnings:
        print(f"warning: {line}")
    for line in org_setup.summary_lines(profile, selection, env_set):
        print(line)
    context = build_context(profile, root=root, data_dir=data_dir)
    for name in context.active.missing:
        print(f"warning: sector pack {name} is not installed")
    for problem in context.active.problems:
        print(f"warning: {problem}")
    seeded = org_setup.seed_watchlist(data_dir, profile)
    print(f"Watchlist: {seeded['detail']} ({seeded['path']})")

    if not getattr(args, "no_render", False):
        if _render(root, profile_home) != 0:
            return 1
        print(f"Rendered {profile_home / 'config.yaml'}")
    if not getattr(args, "no_doctor", False) and _doctor(root, profile_home) != 0:
        print("Doctor reported failures above. Setup itself completed; fix them and re-run doctor.")
    print(
        "Setup finished. Skills read org.yaml from now on. Run hermes cyber-au doctor to "
        "re-check, or setup --force to change the answers."
    )
    return 0
