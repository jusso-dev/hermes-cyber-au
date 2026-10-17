"""cyber-au doctor command, for Hermes and for a direct invocation."""

from __future__ import annotations

import argparse
import shlex
import sys

from .doctor import execute, format_json, format_text

USAGE = "Usage: hermes cyber-au doctor [--offline] [--json] [--fix]"


def register(ctx) -> None:
    ctx.register_cli_command(
        name="cyber-au",
        help="Check the cyber-au profile, connectors, store and routines",
        setup_fn=setup_parser,
        handler_fn=handle,
        description="Report what works, what is missing and how to fix it.",
    )
    ctx.register_command(
        "cyber-au",
        handler=slash,
        description="Health check for the cyber-au profile",
        args_hint="doctor [--offline] [--json] [--fix]",
    )


def setup_parser(parser: argparse.ArgumentParser) -> None:
    subs = parser.add_subparsers(dest="cyberau_command", required=True)
    doctor = subs.add_parser(
        "doctor",
        help="Show what works, what is missing and how to fix it",
    )
    doctor.add_argument(
        "--offline",
        action="store_true",
        help="Skip live connector probes",
    )
    doctor.add_argument("--json", action="store_true", help="Print the report as JSON")
    doctor.add_argument(
        "--fix",
        action="store_true",
        help="Create missing directories, chmod 600 .env, and re-run bootstrap",
    )
    doctor.set_defaults(func=handle)


def handle(args: argparse.Namespace) -> int:
    if getattr(args, "cyberau_command", None) != "doctor":
        print(USAGE, file=sys.stderr)
        return 2
    report = execute(
        offline=bool(args.offline),
        fix=bool(args.fix),
    )
    text = format_json(report) if args.json else format_text(report)
    sys.stdout.write(text)
    return report.exit_code()


def slash(raw_args: str) -> str:
    try:
        parts = shlex.split(raw_args or "")
    except ValueError:
        return USAGE.replace("hermes ", "/")
    if not parts or parts[0] != "doctor":
        return "Usage: /cyber-au doctor [--offline] [--json] [--fix]"
    report = execute(
        offline="--offline" in parts,
        fix="--fix" in parts,
    )
    rendered = format_json(report) if "--json" in parts else format_text(report)
    return rendered.rstrip("\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cyber-au")
    setup_parser(parser)
    args = parser.parse_args(argv)
    return handle(args)


if __name__ == "__main__":
    raise SystemExit(main())
