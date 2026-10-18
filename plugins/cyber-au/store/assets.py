"""Asset inventory: import a CSV or CycloneDX SBOM and match vulnerabilities against it.

The inventory lives at ``plugin-data/cyber-au/assets.yaml`` on the profile. It is the
user's own file and is never shipped. The daily briefing, the KEV watch job and
``vuln-prioritisation`` read it.

The file is a flat list, one ``key: value`` per line, which is the shape the daily
briefing reader accepts:

    assets:
      - name: North gateway
        vendor: examplevendor
        product: edgegate
        exposure: internet
        owner: platform
        version: 3.0.1
        cpe: cpe:2.3:a:examplevendor:edgegate:3.0.1:*:*:*:*:*:*:*

Inventory data stays local. Nothing in this module opens a network connection, and no
connector is ever given an asset, hostname or owner.
"""

from __future__ import annotations

import csv
import io
import json
import os
import re
import tempfile
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import unquote

FILE_NAME = "assets.yaml"
TEMPLATE_PATH = Path(__file__).resolve().parent / "assets.example.yaml"
MAX_BYTES = 20 * 1024 * 1024
MAX_ASSETS = 50_000
MAX_VALUE = 200

REQUIRED = ("name", "vendor", "product", "exposure", "owner")
OPTIONAL = (
    "version",
    "cpe",
    "purl",
    "hostname",
    "service",
    "criticality",
    "environment",
    "source",
)
FIELDS = REQUIRED + OPTIONAL
EXPOSURES = ("internet", "internal")
CRITICALITIES = ("low", "medium", "high", "critical")
ENVIRONMENTS = ("it", "ot", "cloud")

# CSV header aliases, compared after lower-casing and turning spaces and dashes into _.
CSV_ALIASES: dict[str, tuple[str, ...]] = {
    "name": ("name", "asset", "asset_name", "display_name", "ci_name"),
    "hostname": ("hostname", "host", "fqdn", "host_name", "computer_name"),
    "service": ("service", "application", "app", "system"),
    "vendor": ("vendor", "manufacturer", "publisher", "supplier", "vendor_name"),
    "product": ("product", "software", "product_name", "software_name", "model"),
    "version": ("version", "product_version", "software_version"),
    "cpe": ("cpe", "cpe23", "cpe_2_3", "cpe_name"),
    "purl": ("purl", "package_url"),
    "owner": ("owner", "team", "owner_team", "support_group", "business_owner"),
    "criticality": ("criticality", "business_criticality", "tier", "priority"),
    "exposure": ("exposure", "internet_facing", "internet", "external", "public"),
    "environment": ("environment", "env", "domain", "zone"),
}
_TRUE = {"yes", "y", "true", "1", "internet", "external", "public", "internet-facing"}
_FALSE = {"no", "n", "false", "0", "internal", "private", "intranet"}
_CRIT_ALIASES = {
    "1": "critical",
    "2": "high",
    "3": "medium",
    "4": "low",
    "tier 1": "critical",
    "tier 2": "high",
    "tier 3": "medium",
    "tier 4": "low",
    "med": "medium",
    "crit": "critical",
}
_ENV_ALIASES = {
    "it": "it",
    "corporate": "it",
    "enterprise": "it",
    "ot": "ot",
    "ics": "ot",
    "scada": "ot",
    "operational technology": "ot",
    "cloud": "cloud",
    "saas": "cloud",
    "iaas": "cloud",
    "aws": "cloud",
    "azure": "cloud",
    "gcp": "cloud",
}
_SUFFIXES = frozenset(
    "ag co company corp corporation gmbh inc incorporated limited llc ltd plc pty".split()
)
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class InventoryError(ValueError):
    """The input file cannot be imported. ``problems`` lists each row that failed."""

    def __init__(self, message: str, problems: list[str] | None = None) -> None:
        super().__init__(message)
        self.problems = problems or []


@dataclass
class Asset:
    name: str
    vendor: str
    product: str
    exposure: str = "internal"
    owner: str = "unassigned"
    extra: dict[str, str] = field(default_factory=dict)

    def get(self, key: str) -> str:
        if key in REQUIRED:
            return str(getattr(self, key))
        return self.extra.get(key, "")

    def as_dict(self) -> dict[str, str]:
        out = {key: self.get(key) for key in REQUIRED}
        out.update({key: self.extra[key] for key in OPTIONAL if self.extra.get(key)})
        return out


@dataclass
class ImportResult:
    assets: list[Asset]
    skipped: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


# --- paths --------------------------------------------------------------------------


def default_path() -> Path | None:
    """``CYBERAU_DATA_DIR/assets.yaml``, else ``HERMES_HOME/plugin-data/cyber-au/assets.yaml``."""
    data_dir = os.environ.get("CYBERAU_DATA_DIR", "").strip()
    if data_dir:
        return Path(data_dir).expanduser() / FILE_NAME
    home = os.environ.get("HERMES_HOME", "").strip()
    if home:
        return Path(home).expanduser() / "plugin-data" / "cyber-au" / FILE_NAME
    return None


# --- value cleaning -----------------------------------------------------------------


def clean(value: object) -> str:
    """One line, no control characters, no ``#`` (the reader treats it as a comment)."""
    text = _CONTROL.sub(" ", unicodedata.normalize("NFKC", str(value or "")))
    text = " ".join(text.replace("#", " ").split())
    if len(text) > MAX_VALUE:
        text = text[:MAX_VALUE].rstrip()
    return text


def _exposure(value: str) -> str | None:
    text = value.strip().lower()
    if not text:
        return "internal"
    if text in _TRUE:
        return "internet"
    if text in _FALSE:
        return "internal"
    return None


def _criticality(value: str) -> str | None:
    text = value.strip().lower()
    if not text:
        return ""
    text = _CRIT_ALIASES.get(text, text)
    return text if text in CRITICALITIES else None


def _environment(value: str) -> str | None:
    text = value.strip().lower()
    if not text:
        return ""
    text = _ENV_ALIASES.get(text, text)
    return text if text in ENVIRONMENTS else None


def parse_cpe(cpe: str) -> tuple[str, str, str, str] | None:
    """(part, vendor, product, version) from a CPE 2.3 string, or None."""
    text = str(cpe or "").strip()
    if not text.lower().startswith("cpe:2.3:"):
        return None
    parts = re.split(r"(?<!\\):", text)
    if len(parts) < 6 or parts[2].lower() not in {"a", "o", "h"}:
        return None
    vendor, product, version = (item.replace("\\", "").lower() for item in parts[3:6])
    if vendor in ("", "*", "-") or product in ("", "*", "-"):
        return None
    return parts[2].lower(), vendor, product, version


def parse_purl(purl: str) -> tuple[str, str, str, str] | None:
    """(type, namespace, name, version) from a package URL, or None."""
    text = str(purl or "").strip()
    if not text.startswith("pkg:"):
        return None
    text = text[4:].split("#", 1)[0].split("?", 1)[0].strip("/")
    version = ""
    if "@" in text:
        text, version = text.rsplit("@", 1)
    pieces = [unquote(piece) for piece in text.split("/") if piece]
    if len(pieces) < 2:
        return None
    kind = pieces[0].lower()
    name = pieces[-1]
    namespace = "/".join(pieces[1:-1])
    if kind in {"pypi", "npm", "github", "golang", "bitbucket"}:
        name = name.lower()
        namespace = namespace.lower()
    return kind, namespace, name, unquote(version)


def purl_key(purl: str) -> str | None:
    parsed = parse_purl(purl)
    if parsed is None:
        return None
    kind, namespace, name, _version = parsed
    return f"{kind}/{namespace}/{name}" if namespace else f"{kind}/{name}"


def strip_purl(purl: str) -> str:
    """The purl without qualifiers or subpath, so it holds no ``#``."""
    text = str(purl or "").strip().split("#", 1)[0].split("?", 1)[0]
    return clean(text)


def _finish(fields: dict[str, str], where: str, problems: list[str]) -> Asset | None:
    """Validate one row. Missing vendor or product is filled from the CPE or purl."""
    cpe = parse_cpe(fields.get("cpe", ""))
    purl = parse_purl(fields.get("purl", ""))
    if fields.get("cpe") and cpe is None:
        problems.append(f"{where}: cpe is not a CPE 2.3 string")
        return None
    if fields.get("purl") and purl is None:
        problems.append(f"{where}: purl is not a package URL")
        return None
    if fields.get("purl"):
        fields["purl"] = strip_purl(fields["purl"])
    if not fields.get("vendor"):
        if cpe:
            fields["vendor"] = cpe[1]
        elif purl and purl[1]:
            fields["vendor"] = purl[1].rsplit("/", 1)[-1]
    if not fields.get("product"):
        if cpe:
            fields["product"] = cpe[2]
        elif purl:
            fields["product"] = purl[2]
    if not fields.get("version"):
        if cpe and cpe[3] not in ("", "*", "-"):
            fields["version"] = cpe[3]
        elif purl and purl[3]:
            fields["version"] = purl[3]
    if not fields.get("product"):
        problems.append(f"{where}: needs a product, cpe or purl")
        return None
    if not fields.get("vendor"):
        # Ecosystem packages often have no vendor. The product name is the closest match
        # key, and NVD often uses it as the vendor too.
        fields["vendor"] = fields["product"]
    exposure = _exposure(fields.get("exposure", ""))
    if exposure is None:
        problems.append(f"{where}: exposure must be internet or internal (or yes/no)")
        return None
    criticality = _criticality(fields.get("criticality", ""))
    if criticality is None:
        problems.append(f"{where}: criticality must be one of {', '.join(CRITICALITIES)}")
        return None
    environment = _environment(fields.get("environment", ""))
    if environment is None:
        problems.append(f"{where}: environment must be one of {', '.join(ENVIRONMENTS)}")
        return None
    name = (
        fields.get("name")
        or fields.get("hostname")
        or fields.get("service")
        or " ".join(item for item in (fields["product"], fields.get("version", "")) if item)
    )
    extra = {key: clean(fields.get(key, "")) for key in OPTIONAL}
    extra["criticality"] = criticality
    extra["environment"] = environment
    asset = Asset(
        name=clean(name),
        vendor=clean(fields["vendor"]),
        product=clean(fields["product"]),
        exposure=exposure,
        owner=clean(fields.get("owner") or "unassigned"),
        extra={key: value for key, value in extra.items() if value},
    )
    if not asset.name or not asset.vendor or not asset.product or not asset.owner:
        problems.append(f"{where}: a required value is empty after cleaning")
        return None
    return asset


# --- importers ----------------------------------------------------------------------


def _read(path: Path) -> str:
    size = path.stat().st_size
    if size > MAX_BYTES:
        raise InventoryError(f"{path.name} is larger than {MAX_BYTES // (1024 * 1024)} MB")
    data = path.read_bytes()
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise InventoryError(f"{path.name} is not UTF-8 text") from exc


def _header_map(headers: Iterable[str]) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for header in headers:
        key = re.sub(r"[\s\-]+", "_", str(header or "").strip().lower())
        for target, aliases in CSV_ALIASES.items():
            if key in aliases and target not in mapping.values():
                mapping[header] = target
                break
    return mapping


def import_csv(text: str, *, defaults: dict[str, str] | None = None) -> ImportResult:
    """Rows of a CMDB or asset CSV export. Column names are matched by alias."""
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise InventoryError("the CSV has no header row")
    mapping = _header_map(reader.fieldnames)
    if not {"product", "cpe", "purl"} & set(mapping.values()):
        raise InventoryError("the CSV needs a product, cpe or purl column")
    problems: list[str] = []
    assets: list[Asset] = []
    for number, row in enumerate(reader, start=2):
        if len(assets) >= MAX_ASSETS:
            raise InventoryError(f"more than {MAX_ASSETS} assets in one file")
        fields = dict(defaults or {})
        for header, target in mapping.items():
            value = clean(row.get(header) or "")
            if value:
                fields[target] = value
        if not any(row.values()):
            continue
        asset = _finish(fields, f"row {number}", problems)
        if asset is not None:
            assets.append(asset)
    return ImportResult(assets, skipped=problems)


def _component_vendor(component: dict) -> str:
    supplier = component.get("supplier")
    if isinstance(supplier, dict) and supplier.get("name"):
        return str(supplier["name"])
    for key in ("publisher", "author", "group"):
        if component.get(key):
            return str(component[key])
    manufacturer = component.get("manufacturer")
    if isinstance(manufacturer, dict) and manufacturer.get("name"):
        return str(manufacturer["name"])
    return ""


def _walk_components(items: object, depth: int = 0) -> Iterable[dict]:
    if not isinstance(items, list) or depth > 8:
        return
    for item in items:
        if isinstance(item, dict):
            yield item
            yield from _walk_components(item.get("components"), depth + 1)


def import_cyclonedx(text: str, *, defaults: dict[str, str] | None = None) -> ImportResult:
    """Components of a CycloneDX JSON SBOM (spec 1.2 to 1.6), nested ones included."""
    try:
        bom = json.loads(text)
    except ValueError as exc:
        raise InventoryError("the SBOM is not valid JSON") from exc
    if not isinstance(bom, dict) or str(bom.get("bomFormat", "")).lower() != "cyclonedx":
        raise InventoryError("the file is not a CycloneDX JSON SBOM (bomFormat is missing)")
    defaults = dict(defaults or {})
    metadata = bom.get("metadata") if isinstance(bom.get("metadata"), dict) else {}
    subject = metadata.get("component") if isinstance(metadata.get("component"), dict) else {}
    system = defaults.pop("system", "") or str(subject.get("name") or "")
    problems: list[str] = []
    assets: list[Asset] = []
    seen: set[tuple[str, str, str]] = set()
    for index, component in enumerate(_walk_components(bom.get("components")), start=1):
        if len(assets) >= MAX_ASSETS:
            raise InventoryError(f"more than {MAX_ASSETS} components in one SBOM")
        if str(component.get("type") or "library") in {"file", "data", "machine-learning-model"}:
            continue
        product = clean(component.get("name"))
        version = clean(component.get("version"))
        fields = dict(defaults)
        fields.update(
            {
                "product": product,
                "version": version,
                "vendor": clean(_component_vendor(component)),
                "cpe": clean(component.get("cpe")),
                "purl": clean(str(component.get("purl") or "").split("#", 1)[0]),
            }
        )
        label = " ".join(item for item in (product, version) if item)
        fields["name"] = f"{clean(system)}: {label}" if system and label else label
        if system:
            fields.setdefault("service", clean(system))
        fields = {key: value for key, value in fields.items() if value}
        asset = _finish(fields, f"component {index} ({label or 'unnamed'})", problems)
        if asset is None:
            continue
        key = (asset.name.casefold(), asset.get("purl"), asset.get("cpe"))
        if key in seen:
            continue
        seen.add(key)
        assets.append(asset)
    notes = []
    if system:
        notes.append(f"components named under system {clean(system)}")
    return ImportResult(assets, skipped=problems, notes=notes)


def detect_format(path: Path, text: str) -> str:
    if path.suffix.lower() == ".csv":
        return "csv"
    stripped = text.lstrip()
    if stripped.startswith("{"):
        return "cyclonedx"
    if stripped.startswith("<"):
        raise InventoryError("CycloneDX XML is not supported yet. Export the SBOM as JSON")
    return "csv"


def import_file(
    path: Path, *, fmt: str = "auto", defaults: dict[str, str] | None = None
) -> ImportResult:
    text = _read(path)
    kind = detect_format(path, text) if fmt == "auto" else fmt
    defaults = dict(defaults or {})
    defaults.setdefault("source", f"{'sbom' if kind == 'cyclonedx' else 'csv'}:{path.name}")
    if kind == "csv":
        defaults.pop("system", None)
        return import_csv(text, defaults=defaults)
    if kind == "cyclonedx":
        return import_cyclonedx(text, defaults=defaults)
    raise InventoryError(f"unknown format {fmt}")


# --- the inventory file -------------------------------------------------------------


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def load_inventory(text: str) -> list[Asset]:
    """Read assets.yaml in the flat shape the briefing reader accepts."""
    assets: list[Asset] = []
    current: dict[str, str] | None = None
    seen_key = False
    problems: list[str] = []

    def close() -> None:
        if current is not None:
            asset = _finish(dict(current), f"asset {len(assets) + 1}", problems)
            if asset is not None:
                assets.append(asset)

    for raw in text.splitlines():
        if "\t" in raw:
            raise InventoryError("assets.yaml must use spaces, not tabs")
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        body = line.strip()
        if not line.startswith(" ") and body == "assets:":
            seen_key = True
            continue
        if not seen_key:
            raise InventoryError("assets.yaml must start with an assets list")
        if body.startswith("- "):
            close()
            current = {}
            body = body[2:].strip()
            if not body:
                continue
        if current is None or ":" not in body:
            raise InventoryError(f"unreadable assets.yaml line: {body}")
        key, value = body.split(":", 1)
        current[key.strip()] = _unquote(value)
    close()
    if problems:
        raise InventoryError("assets.yaml has invalid entries", problems)
    return assets


def read_inventory(path: Path) -> list[Asset]:
    if not path.is_file():
        return []
    return load_inventory(path.read_text(encoding="utf-8"))


_YAML_WORDS = frozenset("y yes n no true false on off null ~".split())
_NUMBERISH = re.compile(r"[-+.\d][\d._:eE+-]*")


def _quote(value: str) -> str:
    """Quote a value a YAML reader would change. No escapes, so the plain reader agrees."""
    needs = (
        value[:1] in "\"'[]{}&*!|>%@`-?,"
        or ": " in value
        or value.endswith(":")
        or value.casefold() in _YAML_WORDS
        or bool(_NUMBERISH.fullmatch(value))
    )
    if not needs:
        return value
    return '"' + value.replace("\\", "/").replace('"', "'") + '"'


def dump_inventory(assets: list[Asset]) -> str:
    lines = [
        "# Asset inventory. Written by `cyberau-mcp assets import`. This file is yours:",
        "# it stays on this machine and is never committed, shipped or sent to a connector.",
        "assets:",
    ]
    for asset in assets:
        first = True
        for key, value in asset.as_dict().items():
            text = clean(value)
            if not text:
                continue
            prefix = "  - " if first else "    "
            lines.append(f"{prefix}{key}: {_quote(text)}")
            first = False
    return "\n".join(lines) + "\n"


def merge(existing: list[Asset], incoming: list[Asset]) -> list[Asset]:
    """Incoming assets replace existing ones with the same name. Order is kept."""
    by_name = {asset.name.casefold(): asset for asset in incoming}
    out = [by_name.pop(asset.name.casefold(), asset) for asset in existing]
    added = {asset.name.casefold() for asset in existing}
    for asset in incoming:
        if asset.name.casefold() not in added:
            out.append(asset)
            added.add(asset.name.casefold())
    return out


def write_inventory(path: Path, assets: list[Asset]) -> None:
    """Atomic write, mode 0600."""
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix=".assets-", suffix=".yaml", dir=path.parent)
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as out:
            out.write(dump_inventory(assets))
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


# --- matching -----------------------------------------------------------------------


def tokens(value: str) -> frozenset[str]:
    """The token rule in skills/daily-briefing/references/matching.md."""
    text = unicodedata.normalize("NFKC", str(value or "")).casefold().replace("&", " and ")
    parts = re.sub(r"[^\w]|_", " ", text).split()
    return frozenset(part for part in parts if len(part) >= 2 and part not in _SUFFIXES)


def field_match(left: str, right: str) -> bool:
    a, b = tokens(left), tokens(right)
    if not a or not b:
        return False
    return a == b or a < b or b < a


def _vendor_aliases() -> dict[str, tuple[str, ...]]:
    try:
        from .watchlists import VENDOR_ALIASES
    except Exception:  # the shared alias table is optional here
        return {}
    return VENDOR_ALIASES


def vendor_match(left: str, right: str) -> bool:
    if field_match(left, right):
        return True
    for canonical, aliases in _vendor_aliases().items():
        group = (canonical, *aliases)
        if any(field_match(left, item) for item in group) and any(
            field_match(right, item) for item in group
        ):
            return True
    return False


def _norm_cpe_name(value: str) -> str:
    return re.sub(r"[\s\-]+", "_", str(value or "").strip().casefold())


@dataclass
class Match:
    asset: Asset
    method: str
    detail: str

    def as_dict(self) -> dict[str, object]:
        return {"asset": self.asset.as_dict(), "method": self.method, "detail": self.detail}


def match(
    assets: list[Asset],
    *,
    cpes: Iterable[str] = (),
    purls: Iterable[str] = (),
    vendor: str = "",
    product: str = "",
) -> list[Match]:
    """Candidate assets for a vulnerability record, with the rule that matched.

    Rules, strongest first: ``cpe`` (the asset's CPE part, vendor and product equal the
    record's), ``purl`` (same package type, namespace and name), then the labelled
    fallback ``vendor-product-fuzzy`` (the token rule on vendor and product). Versions
    are not compared, because feeds give ranges; the detail names both versions.
    """
    record_cpes = [parsed for parsed in (parse_cpe(item) for item in cpes) if parsed]
    record_purls = {key for key in (purl_key(item) for item in purls) if key}
    found: list[Match] = []
    for asset in assets:
        hit: Match | None = None
        asset_cpe = parse_cpe(asset.get("cpe"))
        if asset_cpe:
            for part, cvendor, cproduct, cversion in record_cpes:
                if asset_cpe[:3] == (part, cvendor, cproduct):
                    hit = Match(
                        asset,
                        "cpe",
                        f"cpe {cvendor}:{cproduct} (record version {cversion or '*'}, "
                        f"asset version {asset.get('version') or 'not recorded'}). "
                        "Check the version by hand",
                    )
                    break
        if hit is None and record_purls:
            key = purl_key(asset.get("purl"))
            if key and key in record_purls:
                hit = Match(
                    asset,
                    "purl",
                    f"purl {key} (asset version {asset.get('version') or 'not recorded'}). "
                    "Check the version by hand",
                )
        if hit is None:
            pairs = [
                (cvendor, cproduct)
                for part, cvendor, cproduct, _v in record_cpes
                if asset_cpe is None or part == asset_cpe[0]
            ]
            if vendor or product:
                pairs.append((vendor, product))
            for pvendor, pproduct in pairs:
                left_product = _norm_cpe_name(pproduct).replace("_", " ")
                left_vendor = _norm_cpe_name(pvendor).replace("_", " ")
                if vendor_match(asset.vendor, left_vendor) and field_match(
                    asset.product, left_product
                ):
                    hit = Match(
                        asset,
                        "vendor-product-fuzzy",
                        f"name match {pvendor} / {pproduct} against "
                        f"{asset.vendor} / {asset.product}. Check the version by hand",
                    )
                    break
        if hit is not None:
            found.append(hit)
    return found


# --- command line -------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    """``cyberau-mcp assets import|list|match``. Local files only."""
    import argparse
    import sys

    parser = argparse.ArgumentParser(prog="cyberau-mcp assets")
    sub = parser.add_subparsers(dest="action", required=True)

    def add_path(command: argparse.ArgumentParser) -> None:
        command.add_argument(
            "--inventory",
            type=Path,
            default=None,
            help="assets.yaml path (default CYBERAU_DATA_DIR/assets.yaml)",
        )

    imp = sub.add_parser("import", help="Import a CSV or CycloneDX JSON SBOM into assets.yaml")
    imp.add_argument("file", type=Path)
    imp.add_argument("--format", choices=("auto", "csv", "cyclonedx"), default="auto")
    imp.add_argument("--replace", action="store_true", help="Replace the inventory, not merge")
    imp.add_argument("--dry-run", action="store_true", help="Validate and print, write nothing")
    imp.add_argument("--strict", action="store_true", help="Fail if any row is invalid")
    imp.add_argument("--owner", default="", help="Owner for rows without one")
    imp.add_argument("--exposure", choices=EXPOSURES, default=None, help="Default exposure")
    imp.add_argument("--environment", choices=ENVIRONMENTS, default=None)
    imp.add_argument("--criticality", choices=CRITICALITIES, default=None)
    imp.add_argument("--system", default="", help="SBOM: the system the components belong to")
    add_path(imp)

    show = sub.add_parser("list", help="Print the inventory as JSON")
    add_path(show)

    find = sub.add_parser("match", help="Which assets a CVE record affects, and how")
    find.add_argument("--cpe", action="append", default=[])
    find.add_argument("--purl", action="append", default=[])
    find.add_argument("--vendor", default="")
    find.add_argument("--product", default="")
    add_path(find)

    args = parser.parse_args(argv)
    path = args.inventory or default_path()
    if path is None:
        print("Set CYBERAU_DATA_DIR or HERMES_HOME, or pass --inventory.", file=sys.stderr)
        return 2
    try:
        if args.action == "list":
            print(json.dumps([asset.as_dict() for asset in read_inventory(path)], indent=2))
            return 0
        if args.action == "match":
            if not (args.cpe or args.purl or (args.vendor and args.product)):
                print("Pass --cpe, --purl, or --vendor with --product.", file=sys.stderr)
                return 2
            found = match(
                read_inventory(path),
                cpes=args.cpe,
                purls=args.purl,
                vendor=args.vendor,
                product=args.product,
            )
            print(json.dumps([item.as_dict() for item in found], indent=2))
            return 0
        defaults = {
            key: value
            for key, value in (
                ("owner", args.owner),
                ("exposure", args.exposure),
                ("environment", args.environment),
                ("criticality", args.criticality),
                ("system", args.system),
            )
            if value
        }
        result = import_file(args.file, fmt=args.format, defaults=defaults)
        existing = [] if args.replace else read_inventory(path)
    except InventoryError as exc:
        print(f"assets: {exc}", file=sys.stderr)
        for problem in exc.problems[:50]:
            print(f"  {problem}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"assets: cannot read {exc.filename}: {exc.strerror}", file=sys.stderr)
        return 1
    for problem in result.skipped[:50]:
        print(f"skipped {problem}", file=sys.stderr)
    if len(result.skipped) > 50:
        print(f"skipped {len(result.skipped) - 50} more", file=sys.stderr)
    if args.strict and result.skipped:
        print("assets: --strict and some rows are invalid; nothing written", file=sys.stderr)
        return 1
    if not result.assets:
        print("assets: no valid assets in the file; nothing written", file=sys.stderr)
        return 1
    combined = merge(existing, result.assets)
    if len(combined) > MAX_ASSETS:
        print(f"assets: more than {MAX_ASSETS} assets in total; nothing written", file=sys.stderr)
        return 1
    if args.dry_run:
        sys.stdout.write(dump_inventory(combined))
        return 0
    write_inventory(path, combined)
    print(
        f"imported {len(result.assets)} assets from {args.file.name} "
        f"({len(result.skipped)} skipped); {path} now holds {len(combined)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
