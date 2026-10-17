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
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "store":
        _configure_logging()
        return _store_command(argv[1:])

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

    imported = sub.add_parser("import", help="Import a feed file downloaded in a browser")
    imported.add_argument("name")
    imported.add_argument("path")
    imported.add_argument("--feed", default="alerts")

    sub.add_parser("store", help="Query and update the local intel store")
    for name in ("refresh", "regen", "parser-check"):
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
    if args.command == "import":
        return _import_feed(args.name, args.path, args.feed)
    print(
        f"{args.command} is not part of the shared library yet",
        file=sys.stderr,
    )
    return 2


def _store_command(argv: list[str]) -> int:
    root = _plugin_root()
    if root is None:
        print("intel store is not installed", file=sys.stderr)
        return 2
    entry = str(root)
    if entry not in sys.path:
        sys.path.insert(0, entry)
    try:
        from store.cli import main as store_main
    except ModuleNotFoundError as exc:
        missing = exc.name or ""
        if missing == "store" or missing.startswith("store."):
            print("intel store is not installed", file=sys.stderr)
            return 2
        raise
    return store_main(argv)


def _plugin_root() -> Path | None:
    """Find ``plugins/cyber-au`` from the checkout, venv, or profile home."""
    candidates: list[Path] = []
    for key in ("CYBERAU_HOME", "HERMES_HOME"):
        value = os.environ.get(key)
        if value:
            candidates.append(Path(value) / "plugins" / "cyber-au")
    here = Path(__file__).resolve()
    candidates.extend(parent / "plugins" / "cyber-au" for parent in here.parents)
    candidates.append(Path.cwd() / "plugins" / "cyber-au")
    seen: set[Path] = set()
    for candidate in candidates:
        resolved = candidate.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        if (resolved / "store" / "api.py").is_file():
            return resolved
    return None


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


if __name__ == "__main__":
    raise SystemExit(main())
