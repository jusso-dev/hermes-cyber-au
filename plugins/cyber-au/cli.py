"""cyber-au CLI and slash commands. The subcommands are not installed yet."""

from __future__ import annotations

import argparse

COMMANDS = ("doctor", "bootstrap", "store", "export")

_MESSAGES = {
    "doctor": "cyber-au doctor is not installed yet.",
    "bootstrap": "cyber-au bootstrap is not installed yet.",
    "store": "The intel store is not installed yet.",
    "export": "STIX export is not installed yet.",
}
_USAGE = "Usage: cyber-au <doctor|bootstrap|store|export>. Those commands are not installed yet."


def command_message(name: str | None) -> str:
    """Return the stub message for one subcommand. The input is not echoed."""
    key = (name or "").strip().split(" ", 1)[0]
    return _MESSAGES.get(key, _USAGE)


def handle_cli(args, **kwargs) -> str:
    """Handle ``hermes cyber-au <command>``."""
    del kwargs
    message = command_message(getattr(args, "cyber_au_command", None))
    print(message)
    return message


def handle_slash(raw_args: str = "", **kwargs) -> str:
    """Handle ``/cyber-au <command>``."""
    del kwargs
    return command_message(raw_args)


def install_subcommands(subparser) -> None:
    """Attach doctor, bootstrap, store and export to the cyber-au CLI parser."""
    commands = subparser.add_subparsers(dest="cyber_au_command", required=False)
    helps = {
        "doctor": "Check the cyber-au profile",
        "bootstrap": "Prepare the cyber-au profile",
        "store": "Inspect the local intel store",
        "export": "Export intel from the local store",
    }
    for name in COMMANDS:
        # The real flags (for example doctor --offline --json) are not defined yet. A
        # prefix character that never appears in an argument makes argparse pass them
        # through, so the stub answers "not installed yet" instead of exiting with
        # a usage error.
        command = commands.add_parser(name, help=helps[name], add_help=False, prefix_chars="\0")
        command.add_argument("ignored", nargs="*", help=argparse.SUPPRESS)
    subparser.set_defaults(func=handle_cli)


def register_commands(ctx) -> None:
    """Register the CLI command and the matching slash command."""
    ctx.register_cli_command(
        name="cyber-au",
        help="cyber-au profile commands",
        setup_fn=install_subcommands,
        handler_fn=handle_cli,
        description="doctor, bootstrap, store and export",
    )
    ctx.register_command(
        "cyber-au",
        handler=handle_slash,
        description="cyber-au doctor, bootstrap, store and export",
        args_hint="doctor|bootstrap|store|export",
    )
