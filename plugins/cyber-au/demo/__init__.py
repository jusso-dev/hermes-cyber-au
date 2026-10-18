"""Demo mode: synthetic sample data for a first look with no keys and no model.

Everything here is DEMO DATA. It is kept apart from real intelligence:

- ``triage`` reads only inputs marked ``"demo": true`` and matches them against
  the synthetic set in ``dataset.json``. It never opens the real intel store.
- ``load`` writes the synthetic set to its own file, ``demo/intel-demo.sqlite``
  under the plugin data directory, never to ``intel.sqlite``.
- Every output line is labelled as demo.
"""

from __future__ import annotations

import csv
import importlib
import ipaddress
import json
import os
import re
import shutil
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
DATASET = HERE / "dataset.json"
PROMPTS = HERE / "prompts.json"
EXAMPLES = HERE.parents[2] / "examples"
DEMO_ALERT = EXAMPLES / "edr-alert.json"
DEMO_ASSETS = EXAMPLES / "assets.csv"

BANNER = "DEMO MODE: synthetic data. Nothing below is real threat intelligence."
FOOTER = "END OF DEMO OUTPUT. Do not act on it, store it or share it as real intelligence."
DEMO_DB_NAME = "intel-demo.sqlite"
MARKER_NAME = "DEMO-DATA.txt"
MARKER_TEXT = (
    "This directory holds the cyber-au DEMO intel store. Every record in it is\n"
    "synthetic. It is not real threat intelligence. Delete it with\n"
    "`cyber-au demo clear`.\n"
)

_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_SHA256 = re.compile(r"\b[0-9a-fA-F]{64}\b")
_URL = re.compile(r"\bhttps?://[^\s\"'<>|]+", re.IGNORECASE)
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
_SEVERITY_SOURCE = "hermes-cyber-au incident-triage local severity, 0.1.0"
_ATTACK_SOURCE = "hermes-cyber-au incident-triage attack mapping, 0.1.0"


class DemoError(ValueError):
    """A demo command refused or could not run."""


# Dataset and prompts


def load_dataset(path: Path = DATASET) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("demo") is not True:
        raise DemoError(f"{path} is not marked as demo data")
    return data


def load_prompts(path: Path = PROMPTS) -> list[dict]:
    return json.loads(path.read_text(encoding="utf-8"))


def format_prompts(prompts: list[dict]) -> str:
    lines = [
        "Example prompts. Start a chat with `hermes -p cyber-au chat` and paste one.",
        "None of them needs a key. The files under examples/ are DEMO DATA.",
        "",
    ]
    for number, item in enumerate(prompts, start=1):
        lines.append(f"{number}. [{item['skill']}] {item['prompt']}")
    return "\n".join(lines) + "\n"


# Triage


def read_demo_alert(path: Path) -> dict:
    try:
        alert = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise DemoError(f"cannot read {path}: {exc.strerror or exc}") from exc
    except ValueError as exc:
        raise DemoError(f"{path} is not JSON") from exc
    if not isinstance(alert, dict) or alert.get("demo") is not True:
        raise DemoError(
            f'{path} is not marked "demo": true. Demo triage only reads demo inputs, so '
            "synthetic intel is never matched against a real alert. For a real alert, use "
            "the incident-triage skill in a chat, which uses live sources."
        )
    return alert


def extract_observables(alert: dict) -> list[tuple[str, str]]:
    """Return (type, value) pairs in first-seen order."""
    found: list[tuple[str, str]] = []

    def add(kind: str, value: str) -> None:
        pair = (kind, value)
        if pair not in found:
            found.append(pair)

    for key, text in _strings(alert):
        if key.lower() in {"label", "note", "title"}:
            continue
        for url in _URL.findall(text):
            url = url.rstrip(".,;)")
            add("url", url)
            host = url.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0].lower()
            if host and not _IPV4.fullmatch(host):
                add("domain", host)
        if "domain" in key.lower() and text.strip():
            add("domain", text.strip().lower())
        for value in _IPV4.findall(text):
            if _valid_ipv4(value):
                add("ipv4", value)
        for value in _SHA256.findall(text):
            add("sha256", value.lower())
        for value in _CVE.findall(text):
            add("cve", value.upper())
    return found


def triage(alert_path: Path = DEMO_ALERT, *, assets_path: Path | None = DEMO_ASSETS) -> dict:
    """Build a demo triage record. Pure: reads files, writes nothing."""
    dataset = load_dataset()
    alert = read_demo_alert(alert_path)
    index = {(row["type"], str(row["value"]).lower()): row for row in dataset.get("indicators", [])}
    observables = extract_observables(alert)
    matches = []
    for kind, value in observables:
        row = index.get((kind, value.lower()))
        if row is not None:
            matches.append(
                {
                    "type": kind,
                    "value": value,
                    "verdict": row["verdict"],
                    "confidence": row["confidence"],
                    "record": row["id"],
                    "note": row["note"],
                }
            )
    hostname = str((alert.get("host") or {}).get("hostname", ""))
    asset = _find_asset(assets_path, hostname)
    hostile = [m for m in matches if m["verdict"] in {"malicious", "suspicious"}]
    beacon = str(alert.get("category", "")).lower() == "beacon"
    malware = str(alert.get("malware_name", "")).strip()
    if beacon and malware and hostile:
        severity = "P1"
        reasons = [
            f"The EDR reports a beacon named as malware ({malware}).",
            f"{len(hostile)} observables match hostile records in the demo intel set.",
        ]
    elif hostile:
        severity = "P3"
        reasons = ["Observables match hostile demo records, but impact is not confirmed."]
    else:
        severity = "P4"
        reasons = ["No observable matched a hostile record in the demo intel set."]
    web_beacon = beacon and any(
        str(item.get("dst_port")) in {"80", "443"}
        for item in alert.get("network", [])
        if isinstance(item, dict)
    )
    cves = [value for kind, value in observables if kind == "cve"]
    return {
        "demo": True,
        "label": dataset["label"],
        "dataset_version": dataset["version"],
        "alert_id": alert.get("alert_id", ""),
        "alert_file": alert_path.name,
        "title": alert.get("title", ""),
        "detected_at": alert.get("detected_at", ""),
        "host": hostname,
        "asset": asset,
        "observables": [{"type": k, "value": v, "defanged": defang(v)} for k, v in observables],
        "matches": matches,
        "attack": (
            [{"id": "T1071.001", "name": "Application Layer Protocol: Web Protocols"}]
            if web_beacon
            else []
        ),
        "severity": severity,
        "severity_reasons": reasons,
        "cves": cves,
        "personal_information": str(alert.get("personal_information_on_host", "unknown")),
        "soci_asset": bool(asset and asset.get("soci_asset", "").lower() == "yes"),
        "retrieved": datetime.now(UTC).date().isoformat(),
        "dataset_source": dataset["source"]["name"],
    }


def format_triage(record: dict) -> str:
    out: list[str] = [BANNER, ""]
    out.append(f"DEMO triage record: {record['alert_id']} ({record['alert_file']})")
    out.append(f"DEMO alert: {record['title']}")
    out.append(f"Detected: {record['detected_at']} (Australia/Sydney). Status: open.")
    asset = record["asset"]
    if asset:
        out.append(
            f"Host: {record['host']}, {asset.get('role', '')}, criticality "
            f"{asset.get('criticality', '')}, SOCI asset {asset.get('soci_asset', '')} "
            "(from the DEMO asset list)."
        )
    else:
        out.append(f"Host: {record['host']} (not in the DEMO asset list).")
    out += ["", "Observables (defanged):"]
    for item in record["observables"]:
        out.append(f"  {item['type']:<7} {item['defanged']}")
    out += ["", "Matches in the DEMO intel set (synthetic records, not real intelligence):"]
    if record["matches"]:
        for item in record["matches"]:
            out.append(
                f"  {defang(item['value'])}: {item['verdict']}, confidence "
                f"{item['confidence']}, demo record {item['record']}"
            )
    else:
        out.append("  none")
    if record["cves"]:
        out += ["", "CVEs named in the alert were not checked in demo mode. In a chat, ask:"]
        for cve in record["cves"]:
            out.append(f"  Is {cve} in the CISA KEV catalogue, and what is its EPSS score?")
    out += ["", "ATT&CK:"]
    if record["attack"]:
        for item in record["attack"]:
            out.append(f"  {item['id']} {item['name']} (confidence low, mapping table only)")
    else:
        out.append("  no mapping from the local table")
    out += ["", "ACSC matrix version was not retrieved."]
    out.append(f"Local severity {record['severity']}:")
    for reason in record["severity_reasons"]:
        out.append(f"  {reason}")
    out += [
        "",
        "Containment (proposals only, nothing is run):",
        f"  Proposal: isolate {record['host']} with the EDR. Risk: user downtime. Reversible: yes.",
        "  Proposal: block the hostile demo indicators at the proxy and firewall. Risk: low. "
        "Reversible: yes.",
        "  Proposal: reset the user's password and revoke sessions. Risk: low. Reversible: no.",
        "",
        "Reporting triggers:",
    ]
    if record["personal_information"].lower() in {"yes", "unknown"}:
        out.append(
            "  NDB: possible. Personal information on the host is "
            f"{record['personal_information']}. Hand off to ndb-breach-notification."
        )
    else:
        out.append("  NDB: not indicated.")
    if record["soci_asset"]:
        out.append("  SOCI: possible. The host is a SOCI asset. Hand off to soci-reporting.")
    else:
        out.append("  SOCI: not indicated.")
    out.append("  Ransomware payment: not indicated. The s 27 clock has not started.")
    out += [
        "",
        f"Source: {record['dataset_source']}, {record['dataset_version']}, "
        f"retrieved {record['retrieved']}",
        f"Source: DEMO sample alert {record['alert_file']}, none, retrieved {record['retrieved']}",
        f"Source: {_SEVERITY_SOURCE}, retrieved {record['retrieved']}",
    ]
    if record["attack"]:
        out.append(f"Source: {_ATTACK_SOURCE}, retrieved {record['retrieved']}")
    out += [
        "",
        "This is guidance, not legal advice.",
        "Next: run `cyber-au demo prompts` for prompts that get live, sourced answers.",
        FOOTER,
    ]
    return "\n".join(out) + "\n"


def defang(value: str) -> str:
    if "[.]" in value or value.lower().startswith("hxxp"):
        return value
    text = re.sub(r"^http", "hxxp", value, flags=re.IGNORECASE)
    return text.replace("@", "[@]").replace(".", "[.]")


# Separate demo store


def real_data_dir() -> Path:
    """The plugin data directory, worked out the same way as the plugin."""
    override = os.environ.get("CYBERAU_DATA_DIR", "").strip()
    if override:
        return Path(override).expanduser()
    home = os.environ.get("HERMES_HOME", "").strip()
    root = Path(home).expanduser() if home else Path.home() / ".hermes"
    return root / "plugin-data" / "cyber-au"


def demo_dir(data_dir: Path | None = None) -> Path:
    return (data_dir or real_data_dir()) / "demo"


def demo_db_path(target: Path) -> Path:
    return target / DEMO_DB_NAME


def _check_target(target: Path) -> Path:
    target = target.expanduser().resolve()
    real = (real_data_dir() / "intel.sqlite").expanduser().resolve()
    db = demo_db_path(target)
    if db == real or target == real.parent:
        raise DemoError(f"refusing to write demo data next to the real intel store at {real}")
    if (target / "intel.sqlite").exists():
        raise DemoError(f"{target} holds a real intel store. Pick an empty directory.")
    if target.exists() and any(target.iterdir()) and not (target / MARKER_NAME).is_file():
        raise DemoError(f"{target} is not empty and has no {MARKER_NAME} marker. Refusing.")
    return target


def load(target: Path | None = None) -> dict:
    """Write the synthetic set to a demo-only store and return a summary."""
    target = _check_target(target or demo_dir())
    dataset = load_dataset()
    api = _store_api()
    target.mkdir(parents=True, exist_ok=True)
    (target / MARKER_NAME).write_text(MARKER_TEXT, encoding="utf-8")
    db = demo_db_path(target)
    source = dataset["source"]
    api.ensure_source(source["id"], name=source["name"], default_tlp="CLEAR", path=db)
    for row in dataset["indicators"]:
        tags = sorted(set(row.get("tags", [])) | {"demo"})
        api.upsert_indicator(
            row["type"],
            row["value"],
            source=source["id"],
            observed_at=row["observed_at"],
            raw=json.dumps(row, sort_keys=True).encode(),
            verdict=row["verdict"],
            confidence=row["confidence"],
            tags=tags,
            tlp="CLEAR",
            source_ref=row["id"],
            note=row["note"],
            path=db,
        )
    for row in dataset.get("advisories", []):
        api.upsert_advisory(
            row["id"],
            source=source["id"],
            title=row["title"],
            url=row["url"],
            published_at=row.get("published_at"),
            summary=row.get("summary"),
            content_sha256=None,
            path=db,
        )
    return {
        "demo": True,
        "path": str(db),
        "indicators": len(dataset["indicators"]),
        "advisories": len(dataset.get("advisories", [])),
    }


def clear(target: Path | None = None) -> bool:
    """Delete the demo directory. Only a directory with the demo marker is removed."""
    target = (target or demo_dir()).expanduser().resolve()
    if not target.exists():
        return False
    if not (target / MARKER_NAME).is_file() or (target / "intel.sqlite").exists():
        raise DemoError(f"{target} is not a demo directory. Nothing was deleted.")
    shutil.rmtree(target)
    return True


# Helpers


def _store_api():
    package = __package__ or ""
    if "." in package:
        return importlib.import_module("..store.api", package)
    return importlib.import_module("store.api")


def _strings(value: object, key: str = "") -> Iterator[tuple[str, str]]:
    if isinstance(value, dict):
        for child_key, child in value.items():
            yield from _strings(child, str(child_key))
    elif isinstance(value, list):
        for child in value:
            yield from _strings(child, key)
    elif isinstance(value, str):
        yield key, value


def _valid_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
    except ValueError:
        return False
    return True


def _find_asset(path: Path | None, hostname: str) -> dict | None:
    if path is None or not hostname or not path.is_file():
        return None
    with path.open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            if row.get("hostname", "").lower() == hostname.lower():
                return dict(row)
    return None


# Command line


def add_parser(subs) -> None:
    """Add ``demo`` to an argparse subparsers object."""
    demo = subs.add_parser(
        "demo",
        help="Try the profile on synthetic DEMO data with no keys and no model",
        description=BANNER,
    )
    actions = demo.add_subparsers(dest="demo_command", required=True)
    run = actions.add_parser("triage", help="Triage the DEMO sample alert offline")
    run.add_argument("--alert", type=Path, default=DEMO_ALERT, help="A JSON alert marked demo")
    run.add_argument("--assets", type=Path, default=DEMO_ASSETS, help="A DEMO asset list (CSV)")
    run.add_argument("--json", action="store_true", help="Print the record as JSON")
    prompts = actions.add_parser("prompts", help="Print example prompts that need no keys")
    prompts.add_argument("--json", action="store_true", help="Print the prompts as JSON")
    for name, text in (
        ("load", "Write the DEMO intel set to a separate demo store"),
        ("clear", "Delete the separate demo store"),
    ):
        action = actions.add_parser(name, help=text)
        action.add_argument(
            "--data-dir",
            type=Path,
            default=None,
            help="Demo directory. Defaults to plugin-data/cyber-au/demo",
        )


def dispatch(args, out=None, err=None) -> int:
    import sys

    out = out or sys.stdout
    err = err or sys.stderr
    command = getattr(args, "demo_command", None)
    try:
        if command == "triage":
            record = triage(args.alert, assets_path=args.assets)
            if args.json:
                out.write(json.dumps(record, indent=2, sort_keys=True) + "\n")
            else:
                out.write(format_triage(record))
            return 0
        if command == "prompts":
            prompts = load_prompts()
            text = json.dumps(prompts, indent=2) + "\n" if args.json else format_prompts(prompts)
            out.write(text)
            return 0
        if command == "load":
            summary = load(args.data_dir)
            out.write(
                f"{BANNER}\nLoaded {summary['indicators']} DEMO indicators and "
                f"{summary['advisories']} DEMO advisory into {summary['path']}.\n"
                "Your real intel store was not touched. Browse the demo store with:\n"
                f"  cyberau-mcp store search demo --path {summary['path']}\n"
                "Remove it with: cyber-au demo clear\n"
            )
            return 0
        if command == "clear":
            removed = clear(args.data_dir)
            out.write("Removed the demo store.\n" if removed else "No demo store to remove.\n")
            return 0
    except DemoError as exc:
        err.write(f"{exc}\n")
        return 1
    except ModuleNotFoundError as exc:
        err.write(
            f"demo {command} needs {exc.name}. Run it through Hermes "
            "(`hermes -p cyber-au cyber-au demo ...`) after install/bootstrap.sh.\n"
        )
        return 1
    err.write("Usage: cyber-au demo <triage|prompts|load|clear>\n")
    return 2
