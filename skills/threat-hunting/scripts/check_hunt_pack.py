#!/usr/bin/env python3
"""Check a hunt query pack from hunt_queries.py offline. Nothing is run against a SIEM.

For every query:

- it is marked as an untested draft and cites its advisory, CVE or technique
- Sigma parses with pySigma and converts with the Kusto and Splunk backends
- KQL passes check_kql.py (bundled tables and columns, time bound, no management
  commands or outbound plugins) and has balanced quotes and brackets
- SPL is a single tstats search over a data model and fields in the bundled CIM
  extract, has balanced quotes and brackets, and uses no command that writes,
  sends or calls out

These checks are a lint. Passing them does not mean the query was tested.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path

import yaml

_HERE = Path(__file__).resolve().parent
_CITATION = re.compile(r"^Source: [^,]+, [^,]+, retrieved \d{4}-\d{2}-\d{2}$")
_ORIGIN = re.compile(r"^Source: (?:CVE Program CVE-|ASD ACSC advisory |MITRE ATT&CK T\d{4})")
_SPL_DATAMODEL = re.compile(r"\bfrom datamodel=([A-Za-z_]+)\.([A-Za-z_]+)\b")
_SPL_FIELD = re.compile(r"(?<![\w.\"*])([A-Z][A-Za-z_]*)\.([a-z_]+)\b")
# Any of these after a pipe writes data, sends it, or calls out. None belongs in a hunt draft.
_SPL_FORBIDDEN = {
    "collect",
    "delete",
    "map",
    "mcollect",
    "meventcollect",
    "outputcsv",
    "outputlookup",
    "rest",
    "run",
    "script",
    "sendalert",
    "sendemail",
    "tscollect",
}
_SPL_ALLOWED = {"tstats", "convert", "rename", "table", "sort", "where", "stats", "fields"}


def _load_check_kql():
    spec = importlib.util.spec_from_file_location("hunt_check_kql", _HERE / "check_kql.py")
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    spec.loader.exec_module(module)
    return module


check_kql = _load_check_kql()


def balance_errors(text: str, *, quotes: str) -> list[str]:
    """Report unbalanced brackets or an unterminated string. Backslash escapes in strings."""
    errors: list[str] = []
    pairs = {")": "(", "]": "[", "}": "{"}
    stack: list[str] = []
    quote: str | None = None
    escaped = False
    for char in text:
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in quotes:
            quote = char
        elif char in "([{":
            stack.append(char)
        elif char in pairs:
            if not stack or stack[-1] != pairs[char]:
                errors.append(f"unbalanced {char}")
                return errors
            stack.pop()
    if quote:
        errors.append("unterminated string literal")
    if stack:
        errors.append(f"unclosed {stack[-1]}")
    return errors


def check_kql_query(query: str, schemas: dict) -> list[str]:
    errors = balance_errors(query, quotes="\"'")
    result = check_kql.check_query(query, schemas)
    errors.extend(result["errors"])
    if not result["tables"]:
        errors.append("no known table name")
    return errors


def check_spl_query(query: str, cim: dict) -> list[str]:
    errors = balance_errors(query, quotes='"')
    text = query.strip()
    if not text.startswith("| tstats "):
        errors.append("SPL draft must be a single tstats search")
    commands = [part.strip().split(" ", 1)[0] for part in _split_pipes(text) if part.strip()]
    for command in commands:
        name = command.lower()
        if name in _SPL_FORBIDDEN:
            errors.append(f"command {name} writes, sends or calls out. It is not a hunt.")
        elif name not in _SPL_ALLOWED:
            errors.append(f"command {name} is not in the allowed hunt list")
    if "earliest=" not in text:
        errors.append("no earliest= time bound")
    models = cim["datamodels"]
    found = _SPL_DATAMODEL.findall(text)
    if len(found) != 1:
        errors.append("SPL draft must name exactly one datamodel=Model.Dataset")
        return errors
    model, dataset = found[0]
    if model not in models or dataset not in models[model]:
        errors.append(f"data model {model}.{dataset} is not in the bundled CIM extract")
        return errors
    known = set(models[model][dataset])
    for prefix, field in _SPL_FIELD.findall(_without_strings(text)):
        if prefix != dataset:
            errors.append(f"field {prefix}.{field} is not from dataset {dataset}")
        elif field not in known:
            errors.append(
                f"field {prefix}.{field} is not confirmed in the bundled CIM extract. "
                "Drop it or stop. Do not say Splunk lacks the field."
            )
    return errors


def _split_pipes(text: str) -> list[str]:
    """Split on pipes outside double-quoted strings."""
    parts: list[str] = []
    current: list[str] = []
    quote = False
    escaped = False
    for char in text:
        if quote:
            current.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quote = False
            continue
        if char == '"':
            quote = True
            current.append(char)
        elif char == "|":
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    parts.append("".join(current))
    return parts


def _without_strings(text: str) -> str:
    return re.sub(r'"(?:\\.|[^"\\])*"', '""', text)


def check_sigma_rule(text: str) -> tuple[list[str], dict]:
    """Parse with pySigma and convert with the Kusto and Splunk backends."""
    errors: list[str] = []
    conversions: dict[str, list[str]] = {}
    try:
        loaded = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        return [f"Sigma YAML could not be parsed: {exc}"], conversions
    if not isinstance(loaded, dict):
        return ["Sigma rule must be a mapping"], conversions
    for key in ("title", "id", "author", "logsource", "detection"):
        if not loaded.get(key):
            errors.append(f"Sigma rule needs {key}")
    try:
        from sigma.collection import SigmaCollection
    except ImportError:
        return errors + ["pySigma is not installed, so the rule was not parsed"], conversions
    try:
        collection = SigmaCollection.from_yaml(text)
    except Exception as exc:
        return errors + [f"pySigma could not parse the rule: {_short(exc)}"], conversions
    for name, backend in _backends():
        if backend is None:
            errors.append(f"pySigma {name} backend is not installed")
            continue
        try:
            output = [str(item) for item in backend.convert(collection)]
        except Exception as exc:
            errors.append(f"pySigma {name} conversion failed: {_short(exc)}")
            continue
        if not output or not all(item.strip() for item in output):
            errors.append(f"pySigma {name} conversion produced no query")
            continue
        quotes = "\"'" if name == "kusto" else '"'
        for item in output:
            errors.extend(
                f"pySigma {name} output: {e}" for e in balance_errors(item, quotes=quotes)
            )
        conversions[name] = output
    return errors, conversions


def _backends():
    out = []
    try:
        from sigma.backends.kusto import KustoBackend

        out.append(("kusto", KustoBackend()))
    except ImportError:
        out.append(("kusto", None))
    try:
        from sigma.backends.splunk import SplunkBackend

        out.append(("splunk", SplunkBackend()))
    except ImportError:
        out.append(("splunk", None))
    return out


def _short(exc: Exception) -> str:
    return f"{type(exc).__name__}: {str(exc).splitlines()[0][:200] if str(exc) else ''}"


def check_entry(entry: dict, schemas: dict, cim: dict) -> dict:
    errors: list[str] = []
    if entry.get("status") != "untested draft":
        errors.append("query is not marked as an untested draft")
    citations = entry.get("citations") or []
    if not citations:
        errors.append("query has no citation")
    for line in citations:
        if not _CITATION.fullmatch(line):
            errors.append(f"malformed citation: {line}")
    if not any(_ORIGIN.match(line) for line in citations):
        errors.append("query does not cite the advisory, CVE or technique it came from")
    if not entry.get("data_sources"):
        errors.append("query does not list the data sources it needs")
    if not entry.get("false_positives"):
        errors.append("query has no false positive notes")
    language = entry.get("language")
    query = entry.get("query") or ""
    conversions: dict = {}
    if language in {"kql_defender", "kql_sentinel"}:
        errors.extend(check_kql_query(query, schemas))
    elif language == "spl":
        errors.extend(check_spl_query(query, cim))
    elif language == "sigma":
        sigma_errors, conversions = check_sigma_rule(query)
        errors.extend(sigma_errors)
    else:
        errors.append(f"unknown language {language}")
    return {"id": entry.get("id"), "ok": not errors, "errors": errors, "pysigma": conversions}


def check_pack(pack: dict) -> dict:
    schemas = check_kql.load_schemas(check_kql.schema_dir())
    cim = yaml.safe_load((_HERE.parent / "references" / "splunk-cim.yaml").read_text("utf-8"))
    results = [check_entry(entry, schemas, cim) for entry in pack.get("queries", [])]
    problems = []
    if pack.get("executed") is not False:
        problems.append("pack does not say executed is false")
    if pack.get("status") != "untested draft":
        problems.append("pack is not marked as an untested draft")
    ok = not problems and all(item["ok"] for item in results)
    return {"ok": ok, "problems": problems, "queries": results}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Lint a hunt query pack offline.")
    parser.add_argument("path", nargs="?", type=Path, help="Pack JSON from hunt_queries.py")
    args = parser.parse_args(argv)
    try:
        text = args.path.read_text(encoding="utf-8") if args.path else sys.stdin.read()
        payload = check_pack(json.loads(text))
    except (OSError, ValueError, TypeError) as exc:
        payload = {"ok": False, "problems": [str(exc)], "queries": []}
    json.dump(payload, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0 if payload["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
