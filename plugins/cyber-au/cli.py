"""`cyber-au update` and `cyber-au migrate`."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

_PLUGIN_DIR = Path(__file__).resolve().parent
if str(_PLUGIN_DIR) not in sys.path:
    sys.path.insert(0, str(_PLUGIN_DIR))

import update_path  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cyber-au")
    sub = parser.add_subparsers(dest="command", required=True)

    update = sub.add_parser("update", help="Refresh this distribution, then bootstrap and doctor")
    update.add_argument("--profile", default=os.environ.get("CYBERAU_PROFILE", "cyber-au"))
    update.add_argument("--profile-home", type=Path, default=None)
    update.add_argument("--source", type=Path, default=None, help="Local checkout to apply")
    update.add_argument("--to", dest="to_tag", default=None, help="Reinstall this git tag")
    update.add_argument(
        "--force-config",
        action="store_true",
        help="Replace config.yaml. Local edits are kept when this is omitted",
    )

    migrate = sub.add_parser("migrate", help="Apply intel store migrations")
    migrate.add_argument("--profile-home", type=Path, required=True)
    migrate.add_argument("--migrations", type=Path, default=None)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "migrate":
            update_path.migrate(args.profile_home, args.migrations)
            return 0
        home = args.profile_home or update_path.default_profile_home(args.profile)
        return update_path.run_update(
            profile_home=home,
            profile=args.profile,
            source=args.source,
            to_tag=args.to_tag,
            force_config=args.force_config,
        )
    except update_path.MigrationFailure:
        return 1
    except update_path.UpdateError as exc:
        print(str(exc), file=sys.stderr)
        return 1


def register(ctx) -> None:
    """Register the command Hermes exposes as `hermes cyber-au`."""

    def setup(subparser: argparse.ArgumentParser) -> None:
        subparser.add_argument("--profile", default=os.environ.get("CYBERAU_PROFILE", "cyber-au"))
        subparser.add_argument("--profile-home", type=Path, default=None)
        commands = subparser.add_subparsers(dest="cyber_au_command")
        update = commands.add_parser("update", help="Refresh this distribution")
        update.add_argument("--source", type=Path, default=None)
        update.add_argument("--to", dest="to_tag", default=None)
        update.add_argument("--force-config", action="store_true")
        migrate = commands.add_parser("migrate", help="Apply intel store migrations")
        migrate.add_argument("--migrations", type=Path, default=None)
        subparser.set_defaults(func=_hermes_handler)

    def _hermes_handler(args: argparse.Namespace) -> None:
        raise SystemExit(_run_namespace(args))

    ctx.register_cli_command(
        name="cyber-au",
        help="Update the cyber-au distribution, migrate the intel store, or roll back to a tag",
        setup_fn=setup,
        handler_fn=_hermes_handler,
    )


def _run_namespace(args: argparse.Namespace) -> int:
    command = getattr(args, "cyber_au_command", None) or getattr(args, "command", None)
    profile = getattr(args, "profile", None) or os.environ.get("CYBERAU_PROFILE", "cyber-au")
    home = getattr(args, "profile_home", None) or update_path.default_profile_home(profile)
    try:
        if command == "migrate":
            update_path.migrate(home, getattr(args, "migrations", None))
            return 0
        if command != "update":
            print("usage: hermes cyber-au <update|migrate>", file=sys.stderr)
            return 2
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


if __name__ == "__main__":
    raise SystemExit(main())
