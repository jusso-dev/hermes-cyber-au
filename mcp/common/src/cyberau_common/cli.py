"""cyberau-mcp command line."""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

from cyberau_common.health import run_health
from cyberau_common.secrets import RedactFilter
from cyberau_common.server import build_server, get_connector


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cyberau-mcp")
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="Run one connector over stdio")
    serve.add_argument("name")

    health = sub.add_parser("health", help="Probe one connector")
    health.add_argument("name")
    health.add_argument("--live", action="store_true")
    health.add_argument("--offline", action="store_true")
    health.add_argument("--schema-drift", action="store_true")

    new = sub.add_parser("new", help="Create a connector skeleton")
    new.add_argument("key")
    new.add_argument("--server", required=True)
    new.add_argument("--hosts", required=True)

    for name in ("refresh", "regen", "parser-check", "store"):
        command = sub.add_parser(name)
        command.add_argument("rest", nargs=argparse.REMAINDER)

    args = parser.parse_args(argv)
    _configure_logging()
    if args.command == "new":
        from cyberau_common.scaffold import generate

        generate(Path.cwd(), args.key, args.server, args.hosts.split(","))
        return 0
    if args.command == "serve":
        connector = get_connector(args.name)
        build_server(connector).run(transport="stdio")
        return 0
    if args.command == "health":
        live = bool(args.live) and not args.offline
        probe = run_health(args.name, live=live, check_schema=bool(args.schema_drift))
        print(f"{probe.name} {'ok' if probe.ok else 'fail'} {probe.detail}")
        return 0 if probe.ok else 1
    print(
        f"{args.command} is not part of the shared library yet",
        file=sys.stderr,
    )
    return 2


def _configure_logging() -> None:
    level = os.environ.get("CYBERAU_LOG_LEVEL", "INFO").upper()
    handler = logging.StreamHandler(sys.stderr)
    handler.addFilter(RedactFilter())
    logging.basicConfig(level=level, handlers=[handler], force=True)


if __name__ == "__main__":
    raise SystemExit(main())
