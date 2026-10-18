"""cyber-au doctor, update, store migration, and audit commands."""

from __future__ import annotations

import argparse
import os
import shlex
import sys
from pathlib import Path

if __package__:
    from . import update_path
    from .doctor import execute, format_json, format_text
else:
    # install/bootstrap.sh runs this file directly, outside the plugin package.
    _PLUGIN_DIR = Path(__file__).resolve().parent
    if str(_PLUGIN_DIR) not in sys.path:
        sys.path.insert(0, str(_PLUGIN_DIR))
    import update_path
    from doctor import execute, format_json, format_text

try:
    from cyberau_common.audit import add_audit_parser
    from cyberau_common.audit import dispatch as audit_dispatch
except ImportError:  # bootstrap can run before the connector packages are installed
    add_audit_parser = None
    audit_dispatch = None

USAGE = "Usage: hermes cyber-au <doctor|update|migrate|audit>"


def register(ctx) -> None:
    ctx.register_cli_command(
        name="cyber-au",
        help="Check, update, migrate, or audit the cyber-au profile",
        setup_fn=setup_parser,
        handler_fn=handle,
        description="Doctor, update, store migration, and audit checks for the cyber-au profile.",
    )
    ctx.register_command(
        "cyber-au",
        handler=slash,
        description="Health check for the cyber-au profile",
        args_hint="doctor [--offline] [--json] [--fix]",
    )


def setup_parser(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--profile", default=os.environ.get("CYBERAU_PROFILE", "cyber-au"))
    parser.add_argument("--profile-home", type=Path, default=None)
    subs = parser.add_subparsers(dest="cyberau_command", required=True)

    doctor = subs.add_parser(
        "doctor",
        help="Show what works, what is missing and how to fix it",
    )
    doctor.add_argument("--offline", action="store_true", help="Skip live connector probes")
    doctor.add_argument("--json", action="store_true", help="Print the report as JSON")
    doctor.add_argument(
        "--fix",
        action="store_true",
        help="Create missing directories, chmod 600 .env, and re-run bootstrap",
    )

    update = subs.add_parser("update", help="Refresh this distribution, then bootstrap and doctor")
    update.add_argument("--source", type=Path, default=None, help="Local checkout to apply")
    update.add_argument("--to", dest="to_tag", default=None, help="Reinstall this git tag")
    update.add_argument(
        "--force-config",
        action="store_true",
        help="Replace config.yaml. Local edits are kept when this is omitted",
    )

    migrate = subs.add_parser("migrate", help="Apply intel store migrations")
    migrate.add_argument("--migrations", type=Path, default=None)
    # install/bootstrap.sh and the update docs put the profile flags after the
    # subcommand. SUPPRESS keeps a value given before the subcommand.
    for sub in (update, migrate):
        sub.add_argument("--profile", default=argparse.SUPPRESS)
        sub.add_argument("--profile-home", type=Path, default=argparse.SUPPRESS)
    if add_audit_parser is not None:
        add_audit_parser(subs)
    parser.set_defaults(func=handle)


def handle(args: argparse.Namespace) -> int:
    command = getattr(args, "cyberau_command", None) or getattr(args, "command", None)
    if command == "doctor":
        report = execute(
            offline=bool(getattr(args, "offline", False)),
            fix=bool(getattr(args, "fix", False)),
        )
        text = format_json(report) if getattr(args, "json", False) else format_text(report)
        sys.stdout.write(text)
        return report.exit_code()
    if command == "migrate":
        return _migrate(args)
    if command == "update":
        return _update(args)
    if command == "audit" and audit_dispatch is not None:
        return audit_dispatch(args)
    print(USAGE, file=sys.stderr)
    return 2


def _migrate(args: argparse.Namespace) -> int:
    home = getattr(args, "profile_home", None)
    if home is None:
        print("migrate needs --profile-home", file=sys.stderr)
        return 2
    try:
        update_path.migrate(home, getattr(args, "migrations", None))
    except update_path.MigrationFailure:
        return 1
    except update_path.UpdateError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


def _update(args: argparse.Namespace) -> int:
    profile = getattr(args, "profile", None) or os.environ.get("CYBERAU_PROFILE", "cyber-au")
    home = getattr(args, "profile_home", None) or update_path.default_profile_home(profile)
    try:
        return update_path.run_update(
            profile_home=home,
            profile=profile,
            source=getattr(args, "source", None),
            to_tag=getattr(args, "to_tag", None),
            force_config=bool(getattr(args, "force_config", False)),
        )
    except update_path.MigrationFailure:
        return 1
    except update_path.UpdateError as exc:
        print(str(exc), file=sys.stderr)
        return 1


def slash(raw_args: str) -> str:
    try:
        parts = shlex.split(raw_args or "")
    except ValueError:
        return "Usage: /cyber-au doctor [--offline] [--json] [--fix]"
    if not parts or parts[0] != "doctor":
        return "Usage: /cyber-au doctor [--offline] [--json] [--fix]"
    report = execute(offline="--offline" in parts, fix="--fix" in parts)
    rendered = format_json(report) if "--json" in parts else format_text(report)
    return rendered.rstrip("\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cyber-au")
    setup_parser(parser)
    args = parser.parse_args(argv)
    return handle(args)


if __name__ == "__main__":
    raise SystemExit(main())
