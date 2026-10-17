"""``cyberau-mcp store`` command."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from datetime import date
from pathlib import Path

from .api import (
    export_records,
    ingest_kev_catalogue,
    table_counts,
    upsert_advisory,
    upsert_indicator,
    upsert_vulnerability,
)
from .db import open_store, resolve_db_path
from .maintenance import backup_store, restore_backup, snapshot_public, vacuum_store
from .stix import export_stix, import_stix_file
from .tools import intel_add_observation, intel_get, intel_search


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        code = exc.code
        return 2 if code is None else int(code)
    try:
        return args.func(args)
    except (OSError, ValueError, sqlite3.Error) as exc:
        print(str(exc), file=sys.stderr)
        return 1


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--path",
        help="Store file. Defaults to $CYBERAU_DATA_DIR/intel.sqlite",
    )
    parser = argparse.ArgumentParser(
        prog="cyberau-mcp store",
        description="Read and update the local threat intel store.",
    )
    sub = parser.add_subparsers(dest="store_command", required=True)

    init = sub.add_parser("init", parents=[common], help="Initialise the database file")
    init.set_defaults(func=_cmd_init)

    indicator = sub.add_parser(
        "indicator", parents=[common], help="Upsert one indicator observation"
    )
    indicator.add_argument("--type", required=True)
    indicator.add_argument("--value", required=True)
    indicator.add_argument("--source", required=True)
    indicator.add_argument("--observed-at", required=True)
    indicator.add_argument(
        "--raw", required=True, help="Upstream record text. Only its hash is stored."
    )
    indicator.add_argument("--verdict")
    indicator.add_argument("--confidence", type=int)
    indicator.add_argument("--tag", action="append", default=[])
    indicator.add_argument("--tlp", default="CLEAR")
    indicator.add_argument("--source-ref")
    indicator.add_argument("--note")
    indicator.set_defaults(func=_cmd_indicator)

    vulnerability = sub.add_parser("vulnerability", parents=[common], help="Upsert one CVE row")
    vulnerability.add_argument("cve_id")
    vulnerability.add_argument("--kev-date-added")
    vulnerability.add_argument("--kev-due-date")
    vulnerability.add_argument("--kev-ransomware")
    vulnerability.add_argument("--epss", type=float)
    vulnerability.add_argument("--epss-percentile", type=float)
    vulnerability.add_argument("--epss-date")
    vulnerability.add_argument("--cvss-v3", type=float)
    vulnerability.add_argument("--cvss-v4", type=float)
    vulnerability.add_argument("--cwe")
    vulnerability.add_argument("--updated-at")
    vulnerability.set_defaults(func=_cmd_vulnerability)

    advisory = sub.add_parser("advisory", parents=[common], help="Upsert one advisory")
    advisory.add_argument("--id", required=True)
    advisory.add_argument("--source", required=True)
    advisory.add_argument("--title", required=True)
    advisory.add_argument("--url", required=True)
    advisory.add_argument("--published-at")
    advisory.add_argument("--summary")
    advisory.add_argument("--content-sha256")
    advisory.set_defaults(func=_cmd_advisory)

    search = sub.add_parser("search", parents=[common], help="Full-text search")
    search.add_argument("query")
    search.add_argument("--kind", action="append", dest="kinds")
    search.add_argument("--since")
    search.add_argument("--limit", type=int, default=20)
    search.set_defaults(func=_cmd_search)

    get = sub.add_parser("get", parents=[common], help="Fetch one record by id or value")
    get.add_argument("id_or_value")
    get.add_argument("--type")
    get.set_defaults(func=_cmd_get)

    add = sub.add_parser(
        "add-observation",
        parents=[common],
        help="Record an analyst observation (source analyst, default TLP AMBER)",
    )
    add.add_argument("--type", required=True)
    add.add_argument("--value", required=True)
    add.add_argument("--verdict")
    add.add_argument("--confidence", type=int)
    add.add_argument("--tag", action="append", default=[])
    add.add_argument("--tlp")
    add.add_argument("--note")
    add.set_defaults(func=_cmd_add)

    export = sub.add_parser(
        "export",
        parents=[common],
        help="Export records or a STIX 2.1 bundle (stix21)",
    )
    export.add_argument(
        "--format",
        choices=("records", "stix21"),
        default="records",
        help="records (default) or stix21",
    )
    export.add_argument("--max-tlp")
    export.add_argument("--kind", action="append", dest="kinds")
    export.add_argument("--since", help="STIX export: records on or after this date")
    export.add_argument(
        "--output",
        help="STIX bundle .json file under plugin-data/cyber-au/exports/",
    )
    export.set_defaults(func=_cmd_export)

    imported = sub.add_parser(
        "import-stix",
        parents=[common],
        help="Import a STIX 2.1 bundle into the store",
    )
    imported.add_argument("file")
    imported.set_defaults(func=_cmd_import_stix)

    ingest = sub.add_parser(
        "ingest-kev", parents=[common], help="Load a CISA KEV catalogue JSON file"
    )
    ingest.add_argument("file")
    ingest.add_argument("--source", default="cisa-kev")
    ingest.set_defaults(func=_cmd_ingest_kev)

    counts = sub.add_parser("counts", parents=[common], help="Print table row counts")
    counts.set_defaults(func=_cmd_counts)

    backup = sub.add_parser(
        "backup",
        parents=[common],
        help="Online backup into plugin-data/cyber-au/backups (7 daily copies)",
    )
    backup.add_argument(
        "--restore",
        metavar="FILE",
        help="Replace the live store with this backup file",
    )
    backup.set_defaults(func=_cmd_backup)

    snapshot = sub.add_parser(
        "snapshot",
        parents=[common],
        help="Write a public TLP:CLEAR snapshot (requires --public)",
    )
    snapshot.add_argument(
        "--public",
        action="store_true",
        required=True,
        help="Include only public-source TLP:CLEAR data",
    )
    snapshot.add_argument(
        "--output",
        help="Directory or .sqlite.zst path. Default: intel/snapshots/",
    )
    snapshot.add_argument("--date", type=_date_arg, help="UTC date for the file name")
    snapshot.set_defaults(func=_cmd_snapshot)

    vacuum = sub.add_parser(
        "vacuum",
        parents=[common],
        help="Fold old observations into indicator counters, then VACUUM",
    )
    vacuum.set_defaults(func=_cmd_vacuum)
    return parser


def _cmd_init(args: argparse.Namespace) -> int:
    path = resolve_db_path(args.path)
    open_store(path)
    print(path)
    return 0


def _cmd_indicator(args: argparse.Namespace) -> int:
    record_id = upsert_indicator(
        args.type,
        args.value,
        source=args.source,
        observed_at=args.observed_at,
        raw=args.raw.encode(),
        verdict=args.verdict,
        confidence=args.confidence,
        tags=args.tag,
        tlp=args.tlp,
        source_ref=args.source_ref,
        note=args.note,
        path=args.path,
    )
    _emit({"id": record_id})
    return 0


def _cmd_vulnerability(args: argparse.Namespace) -> int:
    fields = {
        "kev_date_added": args.kev_date_added,
        "kev_due_date": args.kev_due_date,
        "kev_ransomware": args.kev_ransomware,
        "epss": args.epss,
        "epss_percentile": args.epss_percentile,
        "epss_date": args.epss_date,
        "cvss_v3": args.cvss_v3,
        "cvss_v4": args.cvss_v4,
        "cwe": args.cwe,
        "updated_at": args.updated_at,
    }
    present = {key: value for key, value in fields.items() if value is not None}
    upsert_vulnerability(args.cve_id, path=args.path, **present)
    _emit({"cve_id": args.cve_id.strip().upper()})
    return 0


def _cmd_advisory(args: argparse.Namespace) -> int:
    created = upsert_advisory(
        args.id,
        source=args.source,
        title=args.title,
        url=args.url,
        published_at=args.published_at,
        summary=args.summary,
        content_sha256=args.content_sha256,
        path=args.path,
    )
    _emit({"id": args.id, "created": created})
    return 0


def _cmd_search(args: argparse.Namespace) -> int:
    payload = intel_search(
        args.query,
        kinds=args.kinds,
        since=args.since,
        limit=args.limit,
        path=args.path,
    )
    _emit(payload)
    return 0


def _cmd_get(args: argparse.Namespace) -> int:
    _emit(intel_get(args.id_or_value, type=args.type, path=args.path))
    return 0


def _cmd_add(args: argparse.Namespace) -> int:
    kwargs = {
        "verdict": args.verdict,
        "confidence": args.confidence,
        "tags": args.tag,
        "note": args.note,
        "path": args.path,
    }
    if args.tlp is not None:
        kwargs["tlp"] = args.tlp
    _emit(
        intel_add_observation(
            args.type,
            args.value,
            **kwargs,
        )
    )
    return 0


def _cmd_export(args: argparse.Namespace) -> int:
    if args.format == "stix21":
        result = export_stix(
            since=args.since,
            kinds=args.kinds,
            max_tlp=args.max_tlp,
            output=args.output,
            store=args.path,
        )
        sys.stdout.write(result["text"])
        return 0
    if args.output or args.since:
        raise ValueError("--output and --since are only valid with --format stix21")
    kinds = args.kinds if args.kinds else ("indicator", "advisory", "vulnerability")
    records = export_records(kinds=kinds, max_tlp=args.max_tlp, path=args.path)
    _emit(
        {
            "untrusted": True,
            "max_tlp": "GREEN" if args.max_tlp is None else args.max_tlp,
            "explicit_max_tlp": args.max_tlp is not None,
            "records": records,
        }
    )
    return 0


def _cmd_import_stix(args: argparse.Namespace) -> int:
    _emit(import_stix_file(args.file, path=args.path))
    return 0


def _cmd_ingest_kev(args: argparse.Namespace) -> int:
    catalogue = json.loads(Path(args.file).read_text(encoding="utf-8"))
    loaded = ingest_kev_catalogue(catalogue, source=args.source, path=args.path)
    _emit({"loaded": loaded})
    return 0


def _cmd_counts(args: argparse.Namespace) -> int:
    _emit(table_counts(args.path))
    return 0


def _cmd_backup(args: argparse.Namespace) -> int:
    if args.restore:
        _emit(restore_backup(args.restore, args.path))
        return 0
    _emit(backup_store(args.path))
    return 0


def _cmd_snapshot(args: argparse.Namespace) -> int:
    _emit(snapshot_public(args.path, output=args.output, on=args.date))
    return 0


def _cmd_vacuum(args: argparse.Namespace) -> int:
    _emit(vacuum_store(args.path))
    return 0


def _date_arg(value: str) -> date:
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("date must be YYYY-MM-DD") from exc


def _emit(payload: object) -> None:
    print(json.dumps(payload, indent=2, ensure_ascii=False))
