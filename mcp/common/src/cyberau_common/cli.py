"""cyberau-mcp command line."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

from cyberau_common.health import collect_connector_health, run_health
from cyberau_common.secrets import (
    RedactFilter,
    check_env_mode,
    format_doctor,
    install_log_redaction,
)
from cyberau_common.server import build_server, get_connector


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cyberau-mcp")
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="Run one connector over stdio")
    serve.add_argument("name")

    health = sub.add_parser("health", help="Probe connectors")
    health.add_argument("name", nargs="?")
    health.add_argument("--all", action="store_true", help="Probe every connector in this checkout")
    health.add_argument("--live", action="store_true")
    health.add_argument("--offline", action="store_true")
    health.add_argument("--schema-drift", action="store_true")
    health.add_argument("--json", dest="json_path", help="Write a JSON report")

    new = sub.add_parser("new", help="Create a connector skeleton")
    new.add_argument("key")
    new.add_argument("--server", required=True)
    new.add_argument("--hosts", required=True)

    imported = sub.add_parser("import", help="Import a feed file downloaded in a browser")
    imported.add_argument("name")
    imported.add_argument("path")
    imported.add_argument("--feed", default="alerts")

    for name in ("refresh", "regen", "parser-check", "store"):
        command = sub.add_parser(name)
        command.add_argument("rest", nargs=argparse.REMAINDER)

    doctor = sub.add_parser("doctor", help="Warn when .env is not mode 600")
    doctor.add_argument("--env", default="", help="Profile .env path")

    args = parser.parse_args(argv)
    _configure_logging()
    if args.command == "doctor":
        target = Path(args.env) if args.env else Path.cwd() / ".env"
        print(format_doctor(check_env_mode(target)))
        return 0
    if args.command == "new":
        from cyberau_common.scaffold import generate

        generate(Path.cwd(), args.key, args.server, args.hosts.split(","))
        return 0
    if args.command == "serve":
        connector = get_connector(args.name)
        build_server(connector).run(transport="stdio")
        return 0
    if args.command == "health":
        if args.all and args.name:
            print("pass a connector name or --all, not both", file=sys.stderr)
            return 2
        if args.all:
            return _health_all(args)
        if not args.name:
            print("pass a connector name or --all", file=sys.stderr)
            return 2
        live = bool(args.live) and not args.offline
        probe = run_health(args.name, live=live, check_schema=bool(args.schema_drift))
        print(f"{probe.name} {'ok' if probe.ok else 'fail'} {probe.detail}")
        return 0 if probe.ok else 1
    if args.command == "import":
        return _import_feed(args.name, args.path, args.feed)
    print(
        f"{args.command} is not part of the shared library yet",
        file=sys.stderr,
    )
    return 2


def _health_all(args) -> int:
    live = bool(args.live) and not args.offline
    fixtures = os.environ.get("CYBERAU_HEALTH_FIXTURES")
    data_dir = os.environ.get("CYBERAU_DATA_DIR")
    report = collect_connector_health(
        live=live,
        check_schema=bool(args.schema_drift),
        fixtures=Path(fixtures) if fixtures else None,
        state_path=Path(data_dir) / "connector-health-state.json" if data_dir else None,
    )
    if args.json_path:
        Path(args.json_path).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    for row in report["connectors"]:
        print(f"{row['key']} {row['status']} {row['detail']}")
    failed = any(row["status"] == "fail" for row in report["connectors"])
    return 1 if failed else 0


def _import_feed(name: str, path: str, feed: str) -> int:
    if name != "asd":
        print(f"import does not support {name}", file=sys.stderr)
        return 2
    try:
        from cyberau_asd_acsc.source import import_feed
    except ModuleNotFoundError:
        print("asd connector is not installed", file=sys.stderr)
        return 2
    try:
        print(import_feed(path, feed))
    except (OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


def _configure_logging() -> None:
    level = os.environ.get("CYBERAU_LOG_LEVEL", "INFO").upper()
    handler = logging.StreamHandler(sys.stderr)
    handler.addFilter(RedactFilter())
    logging.basicConfig(level=level, handlers=[handler], force=True)
    install_log_redaction()


if __name__ == "__main__":
    raise SystemExit(main())
